//! Watch the console user's Downloads and Desktop (FSEvents) and check apps,
//! disk images, installers, programs and scripts as they land, before anyone
//! opens them. Also looks at the top level of newly mounted volumes (an app
//! inside a disk image that was just opened).
//!
//! A file is only checked once it has settled: no events and an unchanged size
//! for [`SETTLE`]. Browsers write to `.crdownload`/`.download`/`.part` first and
//! rename at the end; those partial names are ignored, the final name is what
//! gets checked. The checks themselves (signature, Gatekeeper, pkgutil) run on
//! a separate thread so a slow `spctl` never holds up the watcher.

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use notify::{RecursiveMode, Watcher};
use vogter_sensors::downloads as dl;

use super::Signal;

/// Quiet time (no events, same size) before a file counts as finished.
const SETTLE: Duration = Duration::from_secs(2);
const TICK: Duration = Duration::from_secs(1);
/// How often to look for a different console user.
const USER_CHECK: Duration = Duration::from_secs(5);
const VOLUMES: &str = "/Volumes";
/// For tests: watch this folder instead of the console user's.
const DIR_OVERRIDE: &str = "VOGTER_DOWNLOADS_DIR";

struct Job {
    path: PathBuf,
    volume: Option<String>,
}

struct Pending {
    since: Instant,
    size: Option<u64>,
}

fn roots() -> Vec<PathBuf> {
    if let Some(dir) = std::env::var_os(DIR_OVERRIDE) {
        return vec![PathBuf::from(dir)];
    }
    match vogter_sensors::user::target() {
        Some(u) => {
            let h = Path::new(&u.home);
            vec![h.join("Downloads"), h.join("Desktop")]
        }
        None => Vec::new(),
    }
}

pub fn spawn(tx: Sender<Signal>) -> Result<(), String> {
    let (etx, erx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(etx).map_err(|e| e.to_string())?;
    let mut current = roots();
    let watching = watch_all(&mut watcher, &current);
    let volumes_watched = watcher
        .watch(Path::new(VOLUMES), RecursiveMode::NonRecursive)
        .is_ok();
    if watching == 0 && !volumes_watched {
        return Err("neither Downloads nor /Volumes could be watched".into());
    }
    tracing::info!(folders = ?current, "watching downloads");

    let (jtx, jrx) = mpsc::channel::<Job>();
    thread::Builder::new()
        .name("downloads-check".into())
        .spawn(move || {
            for job in jrx {
                let Some(facts) = dl::gather(&job.path, job.volume.as_deref()) else {
                    continue;
                };
                if let Some(a) = vogter_detect::downloads::assess_download(&facts) {
                    let _ = tx.send(Signal::Activity(a));
                }
            }
        })
        .map_err(|e| e.to_string())?;

    thread::Builder::new()
        .name("downloads-watch".into())
        .spawn(move || {
            let mut pending: HashMap<PathBuf, Pending> = HashMap::new();
            // What we already checked, by identity, so metadata updates (Finder,
            // Spotlight) don't trigger a second report.
            let mut done: HashMap<PathBuf, (u64, u64)> = HashMap::new();
            let mut known_volumes = list_volumes();
            let mut volumes_dirty: Option<Instant> = None;
            let mut last_user_check = Instant::now();
            loop {
                if last_user_check.elapsed() >= USER_CHECK {
                    last_user_check = Instant::now();
                    let now = roots();
                    if now != current {
                        for r in &current {
                            let _ = watcher.unwatch(r);
                        }
                        let watching = watch_all(&mut watcher, &now);
                        tracing::info!(folders = ?now, watching, "console user changed; watching their downloads");
                        current = now;
                        pending.clear();
                    }
                }
                match erx.recv_timeout(TICK) {
                    Ok(Ok(event)) => {
                        for path in event.paths {
                            if path.parent() == Some(Path::new(VOLUMES)) {
                                volumes_dirty = Some(Instant::now());
                            } else if let Some(c) = candidate(&path, &current) {
                                pending.insert(
                                    c,
                                    Pending {
                                        since: Instant::now(),
                                        size: None,
                                    },
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => tracing::debug!("downloads watch: {e}"),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }

                for path in settled(&mut pending) {
                    let Some(id) = identity(&path) else { continue };
                    if done.get(&path) == Some(&id) {
                        continue;
                    }
                    if done.len() > 5000 {
                        done.clear();
                    }
                    done.insert(path.clone(), id);
                    let _ = jtx.send(Job { path, volume: None });
                }

                if volumes_dirty.is_some_and(|t| t.elapsed() >= SETTLE) {
                    volumes_dirty = None;
                    let now = list_volumes();
                    for vol in now.difference(&known_volumes) {
                        for path in volume_items(vol) {
                            let volume = Some(vol.display().to_string());
                            let _ = jtx.send(Job { path, volume });
                        }
                    }
                    known_volumes = now;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn watch_all(watcher: &mut notify::RecommendedWatcher, dirs: &[PathBuf]) -> usize {
    dirs.iter()
        .filter(|d| match watcher.watch(d, RecursiveMode::Recursive) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(dir = %d.display(), "not watching: {e}");
                false
            }
        })
        .count()
}

/// The thing an event is about: a file directly in a watched folder, or the
/// `.app` bundle (top level, or one folder down as unzipping often leaves it)
/// that an event inside it belongs to. Deeper files are ignored so that
/// projects and build folders on the Desktop don't count as downloads.
fn candidate(path: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    let root = roots.iter().find(|r| path.starts_with(r))?;
    let rel: Vec<_> = path.strip_prefix(root).ok()?.components().collect();
    let mut out = root.clone();
    for (i, c) in rel.iter().enumerate() {
        let name = c.as_os_str().to_str()?;
        if dl::is_partial(name) {
            return None;
        }
        out.push(name);
        if name.to_ascii_lowercase().ends_with(".app") {
            return (i <= 1).then_some(out);
        }
    }
    (rel.len() == 1).then_some(out)
}

/// Pending paths that have been quiet for SETTLE with the same size twice in a row.
fn settled(pending: &mut HashMap<PathBuf, Pending>) -> Vec<PathBuf> {
    let mut ready = Vec::new();
    pending.retain(|path, p| {
        if p.since.elapsed() < SETTLE {
            return true;
        }
        if dl::classify(path).is_none() {
            // Gone, renamed, a document, or not written yet (a later event re-adds it).
            return false;
        }
        let size = dl::size_of(path);
        if size.is_some() && size == p.size {
            ready.push(path.clone());
            return false;
        }
        p.size = size;
        p.since = Instant::now();
        true
    });
    ready
}

fn identity(path: &Path) -> Option<(u64, u64)> {
    let m = std::fs::symlink_metadata(path).ok()?;
    Some((m.ino(), dl::size_of(path)?))
}

/// Mounted volumes (real directories; `Macintosh HD` is a symlink to `/`).
fn list_volumes() -> HashSet<PathBuf> {
    std::fs::read_dir(VOLUMES)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
                .collect()
        })
        .unwrap_or_default()
}

/// Apps, installers, programs and scripts at the top of a volume.
fn volume_items(vol: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(vol)
        .map(|rd| {
            rd.flatten()
                .take(200)
                .map(|e| e.path())
                .filter(|p| {
                    matches!(
                        dl::classify(p),
                        Some(
                            vogter_model::download::DownloadKind::App
                                | vogter_model::download::DownloadKind::Installer
                                | vogter_model::download::DownloadKind::Executable
                                | vogter_model::download::DownloadKind::Script
                        )
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates() {
        let roots = vec![PathBuf::from("/Users/me/Downloads")];
        let c = |p: &str| candidate(Path::new(p), &roots).map(|p| p.display().to_string());
        assert_eq!(
            c("/Users/me/Downloads/Zoom.dmg").as_deref(),
            Some("/Users/me/Downloads/Zoom.dmg")
        );
        assert_eq!(
            c("/Users/me/Downloads/Zoom.app/Contents/MacOS/zoom").as_deref(),
            Some("/Users/me/Downloads/Zoom.app")
        );
        assert_eq!(
            c("/Users/me/Downloads/Zoom/Zoom.app/Contents/Info.plist").as_deref(),
            Some("/Users/me/Downloads/Zoom/Zoom.app")
        );
        assert_eq!(c("/Users/me/Downloads/Zoom.dmg.crdownload"), None);
        assert_eq!(c("/Users/me/Downloads/Zoom.dmg.download/Zoom.dmg"), None);
        assert_eq!(c("/Users/me/Downloads/.DS_Store"), None);
        assert_eq!(c("/Users/me/Downloads/project/target/debug/tool"), None);
        assert_eq!(c("/Users/me/Downloads/a/b/X.app/Contents/x"), None);
        assert_eq!(c("/Users/me/Downloads"), None);
        assert_eq!(c("/Users/me/Documents/x.dmg"), None);
    }
}
