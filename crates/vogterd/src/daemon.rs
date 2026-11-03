use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::collections::{BTreeSet, HashMap};

use vogter_ipc::{Event, Message, PROTOCOL_VERSION, Realtime, Request, Status};
use vogter_model::{Activity, ActivityKind, AvState, Severity};

use crate::watch::Signal;
use vogter_store::Store;

/// Shared state of the running service.
pub struct Daemon {
    store: Mutex<Store>,
    live: Mutex<Live>,
    subscribers: Mutex<Vec<Sender<Message>>>,
    scan_tx: Mutex<Sender<()>>,
    away: Mutex<Away>,
    realtime: Mutex<Realtime>,
    interval: Duration,
    as_root: bool,
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

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panicked thread must not take the whole daemon down with poisoned locks.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Daemon {
    pub fn new(store: Store, interval: Duration, as_root: bool, scan_tx: Sender<()>) -> Self {
        Daemon {
            store: Mutex::new(store),
            live: Mutex::default(),
            subscribers: Mutex::default(),
            scan_tx: Mutex::new(scan_tx),
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
        };
        result.unwrap_or_else(|e| Message::Error {
            message: e.to_string(),
        })
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
                    if let Some(a) = vogter_detect::assess_exec(&exec) {
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

    fn activity(&self, a: Activity, recent: &mut HashMap<String, u64>) {
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
        let findings = vogter_detect::assess(&snap);
        let at = now();
        let diff = lock(&self.store).record_scan(at, &findings);
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
                .filter(|f| f.finding.severity >= EVENT_MIN_SEVERITY)
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
}
