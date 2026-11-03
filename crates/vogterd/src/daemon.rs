use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vogter_ipc::{Event, Message, PROTOCOL_VERSION, Request, Status};
use vogter_model::{AvState, Severity};
use vogter_store::Store;

/// Shared state of the running service.
pub struct Daemon {
    store: Mutex<Store>,
    live: Mutex<Live>,
    subscribers: Mutex<Vec<Sender<Message>>>,
    scan_tx: Mutex<Sender<()>>,
    interval: Duration,
    as_root: bool,
}

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
        }
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
