//! Files beyond startup plists whose change should trigger an immediate rescan:
//! shell startup files, SSH `authorized_keys`, `/etc/hosts` and sudoers.
//!
//! FSEvents reports resolved paths (`/private/etc/hosts`, a dotfile's symlink
//! target), so each watched path is remembered by its canonical form and
//! mapped back to the name the user knows.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use notify::{RecursiveMode, Watcher};
use vogter_model::{Activity, ActivityKind, Severity};
use vogter_sensors::takeover::{
    AUTHORIZED_KEYS, HOSTS, SUDOERS, SUDOERS_D, SYSTEM_SHELL_FILES, USER_SHELL_FILES,
};

use super::fs::Change;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Shell,
    Ssh,
    Hosts,
    Sudoers,
}

fn system_paths() -> Vec<(PathBuf, Kind, bool)> {
    let mut v: Vec<(PathBuf, Kind, bool)> = SYSTEM_SHELL_FILES
        .iter()
        .map(|p| (PathBuf::from(p), Kind::Shell, false))
        .collect();
    v.push((HOSTS.into(), Kind::Hosts, false));
    v.push((SUDOERS.into(), Kind::Sudoers, false));
    v.push((SUDOERS_D.into(), Kind::Sudoers, true));
    v.push(("/var/root/.ssh".into(), Kind::Ssh, true));
    v
}

fn user_paths(home: &str) -> Vec<(PathBuf, Kind, bool)> {
    let h = Path::new(home);
    let mut v: Vec<(PathBuf, Kind, bool)> = USER_SHELL_FILES
        .iter()
        .map(|f| (h.join(f), Kind::Shell, false))
        .collect();
    v.push((h.join(".ssh"), Kind::Ssh, true));
    v
}

/// What is being watched, keyed by canonical path: (path as configured, kind, is a folder).
#[derive(Default)]
pub struct Footholds {
    watched: HashMap<PathBuf, (PathBuf, Kind, bool)>,
    user: Vec<PathBuf>,
}

impl Footholds {
    pub fn watch_system(&mut self, w: &mut notify::RecommendedWatcher) -> usize {
        system_paths()
            .into_iter()
            .filter_map(|p| self.watch(w, p))
            .count()
    }

    pub fn watch_user(&mut self, w: &mut notify::RecommendedWatcher, home: &str) -> usize {
        let added: Vec<PathBuf> = user_paths(home)
            .into_iter()
            .filter_map(|p| self.watch(w, p))
            .collect();
        let n = added.len();
        self.user.extend(added);
        n
    }

    pub fn unwatch_user(&mut self, w: &mut notify::RecommendedWatcher) {
        for canon in std::mem::take(&mut self.user) {
            let _ = w.unwatch(&canon);
            self.watched.remove(&canon);
        }
    }

    /// Files that don't exist yet can't be watched; the timed scan still reads them.
    fn watch(
        &mut self,
        w: &mut notify::RecommendedWatcher,
        (path, kind, dir): (PathBuf, Kind, bool),
    ) -> Option<PathBuf> {
        let canon = std::fs::canonicalize(&path).ok()?;
        match w.watch(&canon, RecursiveMode::NonRecursive) {
            Ok(()) => {
                self.watched.insert(canon.clone(), (path, kind, dir));
                Some(canon)
            }
            Err(e) => {
                tracing::debug!(path = %path.display(), "not watching: {e}");
                None
            }
        }
    }

    /// The watched file an event is about, as the user knows it.
    pub fn classify(&self, event_path: &Path) -> Option<(Kind, PathBuf)> {
        if let Some((path, kind, false)) = self.watched.get(event_path) {
            return Some((*kind, path.clone()));
        }
        let parent = event_path.parent()?;
        let name = event_path.file_name()?.to_string_lossy();
        let (dir, kind, true) = self.watched.get(parent)? else {
            return None;
        };
        let relevant = match kind {
            // known_hosts changes with every new SSH server; only login keys matter.
            Kind::Ssh => AUTHORIZED_KEYS.contains(&name.as_ref()),
            // sudo ignores names with a '.' or ending in '~' (editor backups).
            Kind::Sudoers => !name.contains('.') && !name.ends_with('~'),
            _ => false,
        };
        relevant.then(|| (*kind, dir.join(name.as_ref())))
    }

    pub fn describe(&self, event_path: &Path, change: Change) -> Option<Activity> {
        let (kind, path) = self.classify(event_path)?;
        Some(describe(kind, &path, change))
    }
}

fn describe(kind: Kind, path: &Path, change: Change) -> Activity {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let verb = match change {
        Change::Added => "added",
        Change::Changed => "changed",
        Change::Removed => "removed",
    };
    let (what, severity, advice) = match kind {
        Kind::Shell => (
            format!("Shell startup file {verb}: {name}"),
            Severity::Info,
            "Shell startup files run every time you open a terminal. Installers such as \
             Homebrew, nvm or conda add lines here, and so does malware that wants to come back. \
             Vogter rescans and lists anything risky under Findings.",
        ),
        Kind::Ssh => (
            format!("SSH login keys {verb}: {name}"),
            Severity::Low,
            "authorized_keys lists who can log in to this Mac over SSH without a password. \
             Fine if you just added one of your own keys; Vogter rescans and lists the keys \
             under Findings.",
        ),
        Kind::Hosts => (
            format!("/etc/hosts {verb}"),
            Severity::Low,
            "/etc/hosts decides where website names lead. Developer tools and ad blockers \
             change it; malware changes it to send you to fake sites or block updates. \
             Vogter rescans and flags anything risky under Findings.",
        ),
        Kind::Sudoers => (
            format!("sudo rules {verb}: {name}"),
            Severity::Low,
            "sudo rules decide who can act as root and whether a password is needed. Some \
             tools (VPNs, virtual machines) add a rule for a helper; malware adds one to keep \
             root access. Vogter rescans and flags anything risky under Findings.",
        ),
    };
    let severity = if change == Change::Removed {
        Severity::Info
    } else {
        severity
    };
    let mut a = Activity::new(ActivityKind::PersistenceChanged, severity, what).advice(advice);
    a.path = Some(path.display().to_string());
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_canonical_path() {
        let dir = std::env::temp_dir().join(format!("vogter-footholds-{}", std::process::id()));
        let ssh = dir.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let rc = dir.join(".zshrc");
        std::fs::write(&rc, "export A=1\n").unwrap();
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut w = notify::recommended_watcher(tx).unwrap();
        let mut f = Footholds::default();
        assert_eq!(f.watch_user(&mut w, dir.to_str().unwrap()), 2);

        let canon_rc = std::fs::canonicalize(&rc).unwrap();
        let canon_ssh = std::fs::canonicalize(&ssh).unwrap();
        assert_eq!(f.classify(&canon_rc), Some((Kind::Shell, rc.clone())));
        assert_eq!(
            f.classify(&canon_ssh.join("authorized_keys")),
            Some((Kind::Ssh, ssh.join("authorized_keys")))
        );
        assert_eq!(f.classify(&canon_ssh.join("known_hosts")), None);
        let a = f.describe(&canon_rc, Change::Changed).unwrap();
        assert_eq!(a.kind, ActivityKind::PersistenceChanged);
        assert_eq!(a.summary, "Shell startup file changed: .zshrc");

        f.unwatch_user(&mut w);
        assert_eq!(f.classify(&canon_rc), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
