//! Endpoint Security client: realtime events straight from the kernel.
//!
//! Requires root, the `com.apple.developer.endpoint-security.client`
//! entitlement and Full Disk Access. [`start`] fails cleanly without them and
//! the daemon falls back to polling watchers.
//!
//! Two clients are used, because mute inversion is per client:
//! - **main**: exec, background items, sudo, SSH, screen sharing, lock/unlock, XProtect, TCC.
//! - **files**: `open` events, inverted so only opens of known secret stores arrive.

use std::ffi::OsStr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread;

use endpoint_sec::sys::{es_event_type_t, es_mute_inversion_type_t, es_mute_path_type_t};
use endpoint_sec::{Client, Event, Message, Process};
use vogter_detect::{SensitiveArea, assess_file_read, sensitive_areas};
use vogter_model::{Activity, ActivityKind, ExecInfo, Severity, SignatureKind, Signing};
use vogter_sensors::codesign;

/// What the clients report to the daemon.
#[derive(Debug, Clone)]
pub enum EsEvent {
    /// A program started (the daemon applies the exec rules).
    Exec(ExecInfo),
    Activity(Activity),
    /// Something changed that the periodic scan should look at now.
    Rescan(&'static str),
}

const MAIN_EVENTS: &[es_event_type_t] = &[
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_SUDO,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
    es_event_type_t::ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,
];

/// Start both clients. `home` is the user whose secrets to guard.
/// Returns once the clients are subscribed, or with the reason they could not be.
/// Lets the daemon re-target the secret-file watch when the console user changes.
pub struct EsHandle {
    home_tx: Sender<Option<String>>,
}

impl EsHandle {
    /// Guard this user's secrets from now on (`None` at the login window).
    pub fn set_home(&self, home: Option<String>) {
        let _ = self.home_tx.send(home);
    }
}

pub fn start(home: Option<&str>, tx: Sender<EsEvent>) -> Result<EsHandle, String> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let main_tx = tx.clone();
    let ready = ready_tx.clone();
    thread::Builder::new()
        .name("es-main".into())
        .spawn(move || {
            run(
                ready,
                |client| {
                    for ev in MAIN_EVENTS {
                        // Newer events fail on older macOS; keep the rest.
                        if let Err(e) = client.subscribe(&[*ev]) {
                            tracing::warn!(event = ?ev, "es subscribe failed: {e:?}");
                        }
                    }
                    Ok(())
                },
                move |msg| main_event(&msg, &main_tx),
                park_forever,
            )
        })
        .map_err(|e| e.to_string())?;

    let areas = Arc::new(RwLock::new(home.map(sensitive_areas).unwrap_or_default()));
    let (home_tx, home_rx) = std::sync::mpsc::channel::<Option<String>>();
    let file_tx = tx;
    thread::Builder::new()
        .name("es-files".into())
        .spawn(move || {
            let handler_areas = areas.clone();
            let initial: Vec<SensitiveArea> = areas.read().unwrap().clone();
            run(
                ready_tx,
                move |client| {
                    client
                        .invert_muting(es_mute_inversion_type_t::ES_MUTE_INVERSION_TYPE_TARGET_PATH)
                        .map_err(|e| format!("{e:?}"))?;
                    watch_only(client, &initial)?;
                    client
                        .subscribe(&[es_event_type_t::ES_EVENT_TYPE_NOTIFY_OPEN])
                        .map_err(|e| format!("{e:?}"))
                },
                move |msg| {
                    let areas = handler_areas.read().unwrap_or_else(|e| e.into_inner());
                    file_event(&msg, &areas, &file_tx)
                },
                move |client| {
                    // Follow logins and user switches: guard the new user's secrets.
                    for home in home_rx {
                        let next = home.as_deref().map(sensitive_areas).unwrap_or_default();
                        if let Err(e) = client.unmute_all_target_paths() {
                            tracing::warn!("es: unmuting target paths failed: {e:?}");
                            continue;
                        }
                        if let Err(e) = watch_only(client, &next) {
                            tracing::warn!("es: re-targeting secret files failed: {e}");
                        }
                        *areas.write().unwrap_or_else(|e| e.into_inner()) = next;
                        tracing::info!(home = ?home, "es: secret-file watch re-targeted");
                    }
                    park_forever(client);
                },
            )
        })
        .map_err(|e| e.to_string())?;

    for _ in 0..2 {
        ready_rx
            .recv()
            .map_err(|_| "Endpoint Security thread died".to_string())??;
    }
    Ok(EsHandle { home_tx })
}

/// Create a client, configure it, report readiness, then hand it to `idle`,
/// which keeps it alive (and may reconfigure it) for the life of the process.
fn run(
    ready: Sender<Result<(), String>>,
    setup: impl FnOnce(&mut Client<'_>) -> Result<(), String>,
    handler: impl Fn(Message) + std::panic::RefUnwindSafe + 'static,
    idle: impl FnOnce(&mut Client<'_>),
) {
    let me = std::process::id() as i32;
    let client = Client::new(move |_c: &mut Client<'_>, msg: Message| {
        if msg.process().audit_token().pid() != me {
            handler(msg);
        }
    });
    let mut client = match client {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(explain(&format!("{e:?}"))));
            return;
        }
    };
    let result = setup(&mut client);
    let failed = result.is_err();
    let _ = ready.send(result);
    if failed {
        return;
    }
    idle(&mut client);
}

fn park_forever(_: &mut Client<'_>) {
    loop {
        thread::park();
    }
}

/// Mute every path *except* the secret stores of `areas` (target-path muting is inverted).
fn watch_only(client: &mut Client<'_>, areas: &[SensitiveArea]) -> Result<(), String> {
    for a in areas {
        client
            .mute_path(
                OsStr::new(&a.prefix),
                es_mute_path_type_t::ES_MUTE_PATH_TYPE_TARGET_PREFIX,
            )
            .map_err(|e| format!("{e:?}"))?;
    }
    Ok(())
}

fn explain(err: &str) -> String {
    let hint = if err.contains("NotEntitled") {
        "the binary is not signed with the Endpoint Security entitlement"
    } else if err.contains("NotPrivileged") {
        "not running as root"
    } else if err.contains("NotPermitted") {
        "Full Disk Access has not been granted"
    } else {
        "see Apple's es_new_client documentation"
    };
    format!("Endpoint Security unavailable: {err} ({hint})")
}

fn s(os: &OsStr) -> String {
    os.to_string_lossy().into_owned()
}

/// Map the kernel's view of a process signature to ours.
fn signing(p: &Process<'_>) -> Signing {
    const CS_VALID: u32 = 0x1;
    const CS_ADHOC: u32 = 0x2;
    let flags = p.codesigning_flags();
    let identifier = Some(s(p.signing_id())).filter(|i| !i.is_empty());
    let team_id = Some(s(p.team_id())).filter(|t| !t.is_empty());
    let kind = if p.is_platform_binary() {
        SignatureKind::Apple
    } else if flags == 0 && identifier.is_none() {
        SignatureKind::Unsigned
    } else if flags & CS_VALID == 0 {
        SignatureKind::Invalid
    } else if flags & CS_ADHOC != 0 {
        SignatureKind::AdHoc
    } else if team_id.is_some() {
        SignatureKind::ThirdParty
    } else {
        SignatureKind::Untrusted
    };
    // Notarization isn't in the event; ask Security.framework (cached by path).
    let notarized = kind == SignatureKind::ThirdParty
        && codesign::for_path(&s(p.executable().path())).notarized;
    Signing {
        kind,
        identifier,
        team_id,
        notarized,
    }
}

fn exec_info(p: &Process<'_>, args: Vec<String>, parent_path: Option<String>) -> ExecInfo {
    let token = p.audit_token();
    ExecInfo {
        pid: token.pid(),
        ppid: p.ppid(),
        uid: token.euid(),
        path: s(p.executable().path()),
        args,
        signing: signing(p),
        parent_path,
    }
}

fn main_event(msg: &Message, tx: &Sender<EsEvent>) {
    let Some(event) = msg.event() else { return };
    let actor = msg.process();
    let send = |e| {
        let _ = tx.send(e);
    };
    match event {
        Event::NotifyExec(exec) => {
            let target = exec.target();
            let args = vogter_model::redact::redact_args(exec.args().map(s).collect());
            send(EsEvent::Exec(exec_info(
                &target,
                args,
                Some(s(actor.executable().path())),
            )));
        }
        Event::NotifyBtmLaunchItemAdd(add) => {
            let exe = s(add.executable_path());
            let who = add
                .instigator()
                .map(|p| s(p.executable().path()))
                .unwrap_or_else(|| "unknown".into());
            let mut a = Activity::new(
                ActivityKind::PersistenceChanged,
                Severity::Medium,
                format!("New background item: {exe}"),
            )
            .detail(format!("Added by {who}"));
            a.path = Some(exe);
            send(EsEvent::Activity(a));
            send(EsEvent::Rescan("background item added"));
        }
        Event::NotifySudo(sudo) => {
            let cmd = sudo.command().map(s).unwrap_or_default();
            let from = sudo.from_username().map(s).unwrap_or_else(|| "?".into());
            let (sev, what) = if sudo.success() {
                (Severity::Low, format!("{from} ran a command as root"))
            } else {
                let why = sudo
                    .reject_info()
                    .map(|r| s(r.failure_message()))
                    .unwrap_or_default();
                (Severity::Medium, format!("Failed sudo by {from}: {why}"))
            };
            send(EsEvent::Activity(
                Activity::new(ActivityKind::Sudo, sev, what).detail(cmd),
            ));
        }
        Event::NotifyOpensshLogin(login) => {
            let (sev, what) = if login.success() {
                (
                    Severity::High,
                    format!("SSH login as {}", s(login.username())),
                )
            } else {
                (
                    Severity::Medium,
                    format!("Failed SSH login as {}", s(login.username())),
                )
            };
            send(EsEvent::Activity(
                Activity::new(ActivityKind::RemoteLogin, sev, what)
                    .detail(format!("from {}", s(login.source_address()))),
            ));
        }
        Event::NotifyScreensharingAttach(ss) => {
            let user = s(ss.authentication_username());
            let what = if ss.success() {
                format!("Screen sharing session started ({user})")
            } else {
                format!("Failed screen sharing attempt ({user})")
            };
            send(EsEvent::Activity(
                Activity::new(ActivityKind::ScreenSharing, Severity::High, what)
                    .detail(format!("from {}", s(ss.source_address()))),
            ));
        }
        Event::NotifyLwSessionLock(l) => {
            send(EsEvent::Activity(Activity::new(
                ActivityKind::ScreenLocked,
                Severity::Info,
                format!("Screen locked ({})", s(l.username())),
            )));
        }
        Event::NotifyLwSessionUnlock(u) => {
            send(EsEvent::Activity(Activity::new(
                ActivityKind::ScreenUnlocked,
                Severity::Info,
                format!("Screen unlocked ({})", s(u.username())),
            )));
        }
        Event::NotifyXpMalwareDetected(m) => {
            let mut a = Activity::new(
                ActivityKind::MalwareDetected,
                Severity::Critical,
                format!("XProtect found {}", s(m.malware_identifier())),
            )
            .detail(s(m.detected_path()));
            a.path = Some(s(m.detected_path()));
            send(EsEvent::Activity(a));
        }
        Event::NotifyTccModify(t) => {
            let who = t
                .responsible()
                .or_else(|| t.instigator())
                .map(|p| s(p.executable().path()))
                .unwrap_or_default();
            send(EsEvent::Activity(
                Activity::new(
                    ActivityKind::PermissionChanged,
                    Severity::Low,
                    format!(
                        "Permission changed: {} for {}",
                        s(t.service()),
                        s(t.identity())
                    ),
                )
                .detail(format!("changed by {who}")),
            ));
            send(EsEvent::Rescan("permission changed"));
        }
        _ => {}
    }
}

fn file_event(msg: &Message, areas: &[SensitiveArea], tx: &Sender<EsEvent>) {
    let Some(Event::NotifyOpen(open)) = msg.event() else {
        return;
    };
    let path = s(open.file().path());
    let reader = exec_info(&msg.process(), Vec::new(), None);
    if let Some(a) = assess_file_read(&reader, &path, areas) {
        let _ = tx.send(EsEvent::Activity(a));
    }
}
