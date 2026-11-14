//! Watch startup-item folders, the permission databases and other footholds
//! (shell startup files, SSH keys, /etc/hosts, sudoers) with FSEvents.
//! A change triggers an immediate rescan instead of waiting for the timer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use notify::{EventKind, RecursiveMode, Watcher};
use vogter_model::{Activity, ActivityKind, Severity};

use super::Signal;
use super::footholds::Footholds;

/// Wait this long after the last change before acting (installers write in bursts).
const SETTLE: Duration = Duration::from_secs(2);
/// tccd touches its database often; don't rescan for it more than this.
const TCC_MIN_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Change {
    Added,
    Changed,
    Removed,
}

const SYSTEM_LAUNCH_DIRS: &[&str] = &["/Library/LaunchDaemons", "/Library/LaunchAgents"];
const SYSTEM_TCC_DIR: &str = "/Library/Application Support/com.apple.TCC";

/// The watched user's folders: (LaunchAgents, TCC).
fn user_dirs(home: &str) -> [PathBuf; 2] {
    let h = Path::new(home);
    [
        h.join("Library/LaunchAgents"),
        h.join("Library/Application Support/com.apple.TCC"),
    ]
}

fn current_home() -> Option<String> {
    vogter_sensors::user::target().map(|u| u.home)
}

/// Watches the system folders, plus those of whoever is at the console, and
/// follows logins, logouts and fast user switching.
pub fn spawn(tx: Sender<Signal>) -> Result<(), String> {
    let (etx, erx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(etx).map_err(|e| e.to_string())?;
    let mut watching = 0;
    for dir in SYSTEM_LAUNCH_DIRS.iter().copied().chain([SYSTEM_TCC_DIR]) {
        match watcher.watch(Path::new(dir), RecursiveMode::NonRecursive) {
            Ok(()) => watching += 1,
            Err(e) => tracing::debug!(dir, "not watching: {e}"),
        }
    }
    // Shell startup files, SSH keys, /etc/hosts, sudoers.
    let mut footholds = Footholds::default();
    watching += footholds.watch_system(&mut watcher);
    let mut home = current_home();
    if let Some(h) = &home {
        watching += watch_user(&mut watcher, h);
        footholds.watch_user(&mut watcher, h);
    }
    if watching == 0 {
        return Err("no folder could be watched".into());
    }

    thread::Builder::new()
        .name("fs-watch".into())
        .spawn(move || {
            let mut pending: BTreeMap<PathBuf, Change> = BTreeMap::new();
            let mut tcc_dirty = false;
            let mut last_tcc_scan: Option<Instant> = None;
            loop {
                // Follow the console user (checked whenever things are quiet).
                let now_home = current_home();
                if now_home != home {
                    if let Some(old) = &home {
                        for d in user_dirs(old) {
                            let _ = watcher.unwatch(&d);
                        }
                    }
                    footholds.unwatch_user(&mut watcher);
                    if let Some(new) = &now_home {
                        watch_user(&mut watcher, new);
                        footholds.watch_user(&mut watcher, new);
                    }
                    tracing::info!(from = ?home, to = ?now_home, "console user changed; watching their folders");
                    home = now_home;
                    let _ = tx.send(Signal::Rescan("console user changed"));
                }
                let is_tcc = |p: &Path| {
                    p.starts_with(SYSTEM_TCC_DIR) || home.as_deref().is_some_and(|h| p.starts_with(&user_dirs(h)[1]))
                };
                match erx.recv_timeout(SETTLE) {
                    Ok(Ok(event)) => {
                        let change = match event.kind {
                            EventKind::Create(_) => Change::Added,
                            EventKind::Remove(_) => Change::Removed,
                            EventKind::Modify(_) => Change::Changed,
                            _ => continue,
                        };
                        for path in event.paths {
                            if is_tcc(&path) {
                                tcc_dirty = true;
                            } else if path.extension().is_some_and(|e| e == "plist")
                                || footholds.classify(&path).is_some()
                            {
                                // A create followed by writes is still an addition.
                                let entry = pending.entry(path).or_insert(change);
                                if *entry != Change::Added {
                                    *entry = change;
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => tracing::warn!("fs watch: {e}"),
                    Err(RecvTimeoutError::Timeout) => {
                        let mut rescan = false;
                        for (path, change) in std::mem::take(&mut pending) {
                            // FSEvents coalesces flags, so trust the disk over the event kind.
                            let change = if !path.exists() {
                                Change::Removed
                            } else if change == Change::Removed {
                                Change::Changed
                            } else {
                                change
                            };
                            let activity = footholds
                                .describe(&path, change)
                                .unwrap_or_else(|| describe(&path, change));
                            let _ = tx.send(Signal::Activity(activity));
                            rescan = true;
                        }
                        if tcc_dirty
                            && last_tcc_scan.is_none_or(|t| t.elapsed() >= TCC_MIN_INTERVAL)
                        {
                            tcc_dirty = false;
                            last_tcc_scan = Some(Instant::now());
                            rescan = true;
                        }
                        if rescan {
                            let _ = tx.send(Signal::Rescan("files changed"));
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn watch_user(watcher: &mut notify::RecommendedWatcher, home: &str) -> usize {
    user_dirs(home)
        .iter()
        .filter(|d| match watcher.watch(d, RecursiveMode::NonRecursive) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(dir = %d.display(), "not watching: {e}");
                false
            }
        })
        .count()
}

fn describe(path: &Path, change: Change) -> Activity {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (severity, verb) = match change {
        // New auto-start entries are how malware survives a reboot.
        Change::Added => (Severity::Low, "added"),
        Change::Changed => (Severity::Info, "changed"),
        Change::Removed => (Severity::Info, "removed"),
    };
    let mut a = Activity::new(
        ActivityKind::PersistenceChanged,
        severity,
        format!("Startup item {verb}: {name}"),
    )
    .advice(
        "Startup items run automatically at login or boot. That's how apps keep helpers \
         running, and how malware survives a restart. Fine if you just installed or updated \
         something; Vogter rescans and shows what it runs under Findings.",
    );
    a.path = Some(path.display().to_string());
    a
}
