//! Fallback sudo watcher: follow sudo's own log lines in the unified log.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use vogter_model::{Activity, ActivityKind, Severity};

use super::Signal;

const PREDICATE: &str = r#"process == "sudo" AND eventMessage CONTAINS "COMMAND=""#;

pub fn spawn(tx: Sender<Signal>) -> std::io::Result<()> {
    thread::Builder::new()
        .name("sudo-watch".into())
        .spawn(move || {
            loop {
                let child = Command::new("/usr/bin/log")
                    .args(["stream", "--style", "ndjson", "--predicate", PREDICATE])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn();
                match child {
                    Ok(mut child) => {
                        let out = child.stdout.take().expect("piped");
                        for line in BufReader::new(out).lines().map_while(Result::ok) {
                            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                                continue;
                            };
                            let Some(msg) = v.get("eventMessage").and_then(|m| m.as_str()) else {
                                continue;
                            };
                            if let Some(a) = parse(msg)
                                && tx.send(Signal::Activity(a)).is_err()
                            {
                                let _ = child.kill();
                                return;
                            }
                        }
                        let _ = child.wait();
                    }
                    Err(e) => tracing::warn!("log stream: {e}"),
                }
                thread::sleep(Duration::from_secs(5));
            }
        })?;
    Ok(())
}

/// `me : TTY=ttys001 ; PWD=/x ; USER=root ; COMMAND=/usr/bin/true`
/// `me : 3 incorrect password attempts ; TTY=... ; COMMAND=...`
pub fn parse(msg: &str) -> Option<Activity> {
    let (user, rest) = msg.trim().split_once(" : ")?;
    let mut problem = None;
    let (mut target, mut command) = ("root", None);
    for part in rest.split(" ; ") {
        match part.split_once('=') {
            Some(("USER", v)) => target = v,
            Some(("COMMAND", v)) => command = Some(v),
            Some(_) => {}
            None => problem = Some(part.trim()),
        }
    }
    let command = command?;
    let user = user.trim();
    let (severity, summary) = match problem {
        None => (Severity::Low, format!("{user} ran a command as {target}")),
        Some(p) if p.contains("NOT in sudoers") => (
            Severity::High,
            format!("{user} tried sudo but is not allowed: {p}"),
        ),
        // `sudo -n` without cached credentials logs this; it's a failed attempt, not an attack.
        Some(p) => (Severity::Medium, format!("Failed sudo by {user}: {p}")),
    };
    Some(Activity::new(ActivityKind::Sudo, severity, summary).detail(command))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success() {
        let a = parse("    me : TTY=ttys001 ; PWD=/Users/me ; USER=root ; COMMAND=/usr/bin/true")
            .unwrap();
        assert_eq!(
            (a.severity, a.summary.as_str()),
            (Severity::Low, "me ran a command as root")
        );
        assert_eq!(a.detail.as_deref(), Some("/usr/bin/true"));
    }

    #[test]
    fn failure_as_seen_on_this_mac() {
        let a = parse("     me : a password is required ; PWD=/Users/me/projects/vogter ; USER=root ; COMMAND=/usr/bin/true").unwrap();
        assert_eq!(a.severity, Severity::Medium);
        assert!(a.summary.contains("a password is required"));
    }

    #[test]
    fn ignores_other_lines() {
        assert!(parse("Reading config").is_none());
    }
}
