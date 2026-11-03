//! Rescan when a browser extension is installed or removed (FSEvents).
//!
//! Watches each Chromium profile's `Extensions` folder (a new extension is a
//! new folder there) and each Firefox profile's `extensions.json`. Profiles
//! and the console user are re-checked every minute.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use notify::{EventKind, RecursiveMode, Watcher};

use super::Signal;

/// Wait this long after the last change before rescanning (installs write in bursts).
const SETTLE: Duration = Duration::from_secs(2);
/// Browsers update extensions in the background; don't rescan more often than this.
const MIN_INTERVAL: Duration = Duration::from_secs(30);
/// How often to look for new profiles or a different console user.
const REFRESH: Duration = Duration::from_secs(60);

const CHROMIUM: &[&str] = &[
    "Google/Chrome",
    "Google/Chrome Beta",
    "Google/Chrome Canary",
    "BraveSoftware/Brave-Browser",
    "Microsoft Edge",
    "Arc/User Data",
    "Vivaldi",
    "Chromium",
    "com.operasoftware.Opera",
];

/// Folders to watch for the user with this home.
fn dirs(home: &str) -> Vec<PathBuf> {
    let support = Path::new(home).join("Library/Application Support");
    let children = |p: PathBuf| -> Vec<PathBuf> {
        std::fs::read_dir(p)
            .map(|e| e.flatten().map(|e| e.path()).collect())
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for b in CHROMIUM {
        let base = support.join(b);
        out.extend(
            children(base.clone())
                .into_iter()
                .chain([base])
                .map(|p| p.join("Extensions"))
                .filter(|p| p.is_dir()),
        );
    }
    out.extend(
        children(support.join("Firefox/Profiles"))
            .into_iter()
            .filter(|p| p.is_dir()),
    );
    out.sort();
    out
}

fn relevant(path: &Path) -> bool {
    let parent = path.parent().and_then(Path::file_name);
    parent.is_some_and(|n| n == "Extensions")
        || path.file_name().is_some_and(|n| n == "extensions.json")
}

pub fn spawn(tx: Sender<Signal>) -> Result<(), String> {
    thread::Builder::new()
        .name("browser-watch".into())
        .spawn(move || {
            let mut last_scan: Option<Instant> = None;
            loop {
                let home = vogter_sensors::user::target().map(|u| u.home);
                let watched = home.as_deref().map(dirs).unwrap_or_default();
                let (etx, erx) = mpsc::channel();
                let mut watcher = match notify::recommended_watcher(etx) {
                    Ok(w) => w,
                    Err(e) => return tracing::warn!("browser watch: {e}"),
                };
                for d in &watched {
                    if let Err(e) = watcher.watch(d, RecursiveMode::NonRecursive) {
                        tracing::debug!(dir = %d.display(), "not watching: {e}");
                    }
                }
                let mut checked = Instant::now();
                let mut dirty = false;
                loop {
                    match erx.recv_timeout(SETTLE) {
                        Ok(Ok(event)) => {
                            if matches!(
                                event.kind,
                                EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(_)
                            ) && event.paths.iter().any(|p| relevant(p))
                            {
                                dirty = true;
                            }
                        }
                        Ok(Err(e)) => tracing::debug!("browser watch: {e}"),
                        Err(RecvTimeoutError::Timeout) => {
                            if dirty && last_scan.is_none_or(|t| t.elapsed() >= MIN_INTERVAL) {
                                dirty = false;
                                last_scan = Some(Instant::now());
                                if tx
                                    .send(Signal::Rescan("browser extensions changed"))
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            if !dirty && checked.elapsed() >= REFRESH {
                                checked = Instant::now();
                                let now = vogter_sensors::user::target().map(|u| u.home);
                                if now != home
                                    || now.as_deref().map(dirs).unwrap_or_default() != watched
                                {
                                    break; // rebuild the watch list
                                }
                            }
                        }
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::relevant;
    use std::path::Path;

    #[test]
    fn only_extension_changes_count() {
        assert!(relevant(Path::new(
            "/u/Library/Application Support/Google/Chrome/Default/Extensions/abc"
        )));
        assert!(relevant(Path::new(
            "/u/Firefox/Profiles/x.default/extensions.json"
        )));
        assert!(!relevant(Path::new(
            "/u/Firefox/Profiles/x.default/places.sqlite-wal"
        )));
    }
}
