//! Watch startup-item folders and the permission databases (FSEvents).
//! A change triggers an immediate rescan instead of waiting for the timer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use notify::{EventKind, RecursiveMode, Watcher};
use vogter_model::{Activity, ActivityKind, Severity};

use super::Signal;

/// Wait this long after the last change before acting (installers write in bursts).
const SETTLE: Duration = Duration::from_secs(2);
/// tccd touches its database often; don't rescan for it more than this.
const TCC_MIN_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq)]
enum Change {
    Added,
    Changed,
    Removed,
}

pub fn spawn(tx: Sender<Signal>, home: Option<String>) -> Result<(), String> {
    let mut launch_dirs = vec![
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/Library/LaunchAgents"),
    ];
    let mut tcc_dirs = vec![PathBuf::from("/Library/Application Support/com.apple.TCC")];
    if let Some(h) = &home {
        launch_dirs.push(Path::new(h).join("Library/LaunchAgents"));
        tcc_dirs.push(Path::new(h).join("Library/Application Support/com.apple.TCC"));
    }

    let (etx, erx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(etx).map_err(|e| e.to_string())?;
    let mut watching = 0;
    for dir in launch_dirs.iter().chain(&tcc_dirs) {
        match watcher.watch(dir, RecursiveMode::NonRecursive) {
            Ok(()) => watching += 1,
            Err(e) => tracing::debug!(dir = %dir.display(), "not watching: {e}"),
        }
    }
    if watching == 0 {
        return Err("no folder could be watched".into());
    }

    thread::Builder::new()
        .name("fs-watch".into())
        .spawn(move || {
            let _keep_alive = watcher;
            let mut pending: BTreeMap<PathBuf, Change> = BTreeMap::new();
            let mut tcc_dirty = false;
            let mut last_tcc_scan: Option<Instant> = None;
            loop {
                match erx.recv_timeout(SETTLE) {
                    Ok(Ok(event)) => {
                        let change = match event.kind {
                            EventKind::Create(_) => Change::Added,
                            EventKind::Remove(_) => Change::Removed,
                            EventKind::Modify(_) => Change::Changed,
                            _ => continue,
                        };
                        for path in event.paths {
                            if tcc_dirs.iter().any(|d| path.starts_with(d)) {
                                tcc_dirty = true;
                            } else if path.extension().is_some_and(|e| e == "plist") {
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
                            let _ = tx.send(Signal::Activity(describe(&path, change)));
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
    );
    a.path = Some(path.display().to_string());
    a
}
