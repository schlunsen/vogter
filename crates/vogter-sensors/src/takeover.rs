//! Other ways to keep a foothold or take over a Mac, beyond launchd and cron:
//! shell startup files, SSH `authorized_keys`, `/etc/hosts`, sudoers,
//! configuration profiles, login hooks, system/kernel extensions and
//! Background Task Management items.
//!
//! Everything here only reads. Checks that need root (sudoers, root's SSH keys
//! and login hook, computer-level profiles, `sfltool dumpbtm`) are skipped when
//! not running as root and reported as a [`SensorError`] instead. External
//! tools run with no stdin and a timeout, and the ones that would ask for an
//! administrator password (`sfltool`) are never started without root.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use plist::Value;
use sha2::{Digest, Sha256};
use vogter_model::SensorError;
use vogter_model::redact::{redact, redact_args};
use vogter_model::takeover::{
    BackgroundItem, ConfigProfile, HostsEntry, KernelExtension, LoginHook, NumberedLine, ShellFile,
    SshKey, SudoersLine, SystemExtension, Takeover,
};

use crate::{codesign, user};

/// Startup files in a home folder, read by zsh, bash or sh.
pub const USER_SHELL_FILES: &[&str] = &[
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".zlogout",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
    ".profile",
];
/// Startup files every user's shells read.
pub const SYSTEM_SHELL_FILES: &[&str] = &[
    "/etc/zshenv",
    "/etc/zprofile",
    "/etc/zshrc",
    "/etc/zlogin",
    "/etc/profile",
    "/etc/bashrc",
];
pub const AUTHORIZED_KEYS: &[&str] = &["authorized_keys", "authorized_keys2"];
pub const HOSTS: &str = "/etc/hosts";
pub const SUDOERS: &str = "/etc/sudoers";
pub const SUDOERS_D: &str = "/etc/sudoers.d";
pub const LOGINWINDOW_PLISTS: &[&str] = &[
    "/Library/Preferences/com.apple.loginwindow.plist",
    "/var/root/Library/Preferences/com.apple.loginwindow.plist",
];
const ROOT_SSH: &str = "/var/root/.ssh";
const TOOL_TIMEOUT: Duration = Duration::from_secs(10);
/// Don't read huge files into memory (a hosts blocklist can be big, but not this big).
const MAX_FILE: u64 = 8 * 1024 * 1024;

pub fn collect() -> (Takeover, Vec<SensorError>) {
    let mut errors = Vec::new();
    let mut err = |sensor: &str, covers: &str, source: Option<String>, message: String| {
        errors.push(SensorError {
            sensor: sensor.into(),
            message,
            covers: vec![covers.into()],
            source,
        });
    };
    let root = user::is_root();
    let target = user::target();
    let mut t = Takeover::default();

    // Shell startup files.
    let mut shell_paths: Vec<(String, bool)> = SYSTEM_SHELL_FILES
        .iter()
        .map(|p| (p.to_string(), true))
        .collect();
    if let Some(u) = &target {
        for f in USER_SHELL_FILES {
            shell_paths.push((format!("{}/{f}", u.home), false));
        }
    }
    for (path, system) in shell_paths {
        match read_optional(&path) {
            Ok(Some(text)) => t.shell_files.push(ShellFile {
                lines: shell_lines(&text),
                path,
                system,
            }),
            Ok(None) => {}
            Err(e) => err("shell", "persistence.shell", Some(path), e),
        }
    }

    // SSH keys.
    let mut ssh_dirs = Vec::new();
    if let Some(u) = &target {
        ssh_dirs.push((u.name.clone(), format!("{}/.ssh", u.home)));
    }
    if root {
        ssh_dirs.push(("root".into(), ROOT_SSH.into()));
    } else {
        err(
            "ssh",
            "persistence.ssh",
            Some(ROOT_SSH.into()),
            format!("root's SSH keys ({ROOT_SSH}) can only be read by the root service"),
        );
    }
    for (who, dir) in ssh_dirs {
        for name in AUTHORIZED_KEYS {
            let path = format!("{dir}/{name}");
            match read_optional(&path) {
                Ok(Some(text)) => t.ssh_keys.extend(parse_authorized_keys(&who, &path, &text)),
                Ok(None) => {}
                Err(e) => err("ssh", "persistence.ssh", Some(path), e),
            }
        }
    }

    // /etc/hosts
    match read_optional(HOSTS) {
        Ok(Some(text)) => t.hosts = parse_hosts(HOSTS, &text),
        Ok(None) => {}
        Err(e) => err("hosts", "persistence.hosts", Some(HOSTS.into()), e),
    }

    // sudoers
    if root {
        let mut errs = Vec::new();
        t.sudoers = sudoers(&mut errs);
        for (src, e) in errs {
            err("sudoers", "persistence.sudoers", Some(src), e);
        }
    } else {
        err(
            "sudoers",
            "persistence.sudoers",
            None,
            "sudo rules (/etc/sudoers) can only be read by the root service".into(),
        );
    }

    // Configuration profiles: as a user, `profiles` only lists that user's own.
    match run("/usr/bin/profiles", &["show", "-output", "stdout-xml"]) {
        Ok(out) => match parse_profiles(&out) {
            Ok(p) => t.profiles = p,
            Err(e) => err("profiles", "persistence.profile", None, e),
        },
        Err(e) => err("profiles", "persistence.profile", None, e),
    }
    if !root {
        err(
            "profiles",
            "persistence.profile",
            Some("profiles:computer".into()),
            "Mac-wide configuration profiles can only be listed by the root service".into(),
        );
    }

    // Login and logout hooks.
    for plist in LOGINWINDOW_PLISTS {
        match login_hooks(plist) {
            Ok(h) => t.login_hooks.extend(h),
            Err(_) if !root && plist.starts_with("/var/root/") => err(
                "login_hook",
                "persistence.hook",
                Some(plist.to_string()),
                format!("root's login hooks ({plist}) can only be read by the root service"),
            ),
            Err(e) => err("login_hook", "persistence.hook", Some(plist.to_string()), e),
        }
    }

    // System and kernel extensions.
    match run("/usr/bin/systemextensionsctl", &["list"]) {
        Ok(out) => t.system_extensions = parse_system_extensions(&out),
        Err(e) => err(
            "system_extensions",
            "persistence.extension",
            Some("systemextensions".into()),
            e,
        ),
    }
    match run("/usr/bin/kmutil", &["showloaded", "--list-only"]) {
        Ok(out) => t.kernel_extensions = parse_kexts(&out),
        Err(e) => err(
            "kernel_extensions",
            "persistence.extension",
            Some("kexts".into()),
            e,
        ),
    }

    // Background Task Management. `sfltool` asks for an administrator password
    // when not root, so it must never be started otherwise.
    if root {
        match run("/usr/bin/sfltool", &["dumpbtm"]) {
            Ok(out) => {
                t.background_items = parse_btm(&out);
                for item in &mut t.background_items {
                    item.signing = item
                        .executable
                        .as_deref()
                        .or(item.url.as_deref().and_then(file_url_path))
                        .filter(|p| Path::new(p).exists())
                        .map(codesign::for_path);
                }
            }
            Err(e) => err("btm", "persistence.background_item", None, e),
        }
    } else {
        err(
            "btm",
            "persistence.background_item",
            None,
            "login and background items (Background Task Management) can only be listed by the root service".into(),
        );
    }

    (t, errors)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// `Ok(None)` if the file doesn't exist; `Err` if it exists but can't be read.
fn read_optional(path: &str) -> Result<Option<String>, String> {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{path}: {e}")),
    };
    let mut buf = Vec::new();
    f.by_ref()
        .take(MAX_FILE)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{path}: {e}"))?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// Commands in a shell file: comments and blank lines dropped, `\` continuations
/// joined (numbered by their first line), secrets redacted.
pub fn shell_lines(text: &str) -> Vec<NumberedLine> {
    let mut out = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let (start, mut acc) = pending.take().unwrap_or((i + 1, String::new()));
        let line = raw.trim();
        if acc.is_empty() && (line.is_empty() || line.starts_with('#')) {
            continue;
        }
        if let Some(cont) = line.strip_suffix('\\') {
            acc.push_str(cont);
            acc.push(' ');
            pending = Some((start, acc));
            continue;
        }
        acc.push_str(line);
        out.push(NumberedLine {
            line: start,
            text: redact_line(acc.trim()),
        });
    }
    if let Some((start, acc)) = pending
        && !acc.trim().is_empty()
    {
        out.push(NumberedLine {
            line: start,
            text: redact_line(acc.trim()),
        });
    }
    out
}

/// Redact a whole shell line: the string-level rules (Bearer, URLs, token
/// prefixes), then word by word (`--password VALUE`, `TOKEN=…`, `X=ghp_…`).
pub fn redact_line(line: &str) -> String {
    let whole = redact(line);
    let words: Vec<String> = whole.split(' ').map(str::to_string).collect();
    redact_args(words)
        .into_iter()
        .map(|w| {
            let bare = w.trim_matches(|c| c == '"' || c == '\'');
            let Some((name, value)) = bare.split_once('=') else {
                return w;
            };
            let r = redact(bare);
            if r != bare {
                return w.replace(bare, &r);
            }
            let v = redact(value.trim_matches(|c| c == '"' || c == '\''));
            if v.contains("[redacted]") {
                w.replace(bare, &format!("{name}={v}"))
            } else {
                w
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn parse_authorized_keys(user: &str, file: &str, text: &str) -> Vec<SshKey> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (options, rest) = if is_key_type(line.split_whitespace().next().unwrap_or("")) {
            (None, line)
        } else {
            // Options run to the first whitespace outside double quotes.
            let mut quoted = false;
            let mut end = line.len();
            for (j, c) in line.char_indices() {
                match c {
                    '"' => quoted = !quoted,
                    c if c.is_whitespace() && !quoted => {
                        end = j;
                        break;
                    }
                    _ => {}
                }
            }
            (Some(&line[..end]), line[end..].trim_start())
        };
        let mut words = rest.split_whitespace();
        let (Some(key_type), blob) = (words.next(), words.next()) else {
            continue;
        };
        if !is_key_type(key_type) {
            continue;
        }
        let comment = words.collect::<Vec<_>>().join(" ");
        out.push(SshKey {
            user: user.into(),
            file: file.into(),
            line: i + 1,
            key_type: key_type.into(),
            fingerprint: blob.and_then(fingerprint),
            comment: (!comment.is_empty()).then(|| redact(&comment)),
            options: options.map(|o| o.split(",").map(redact_line).collect::<Vec<_>>().join(",")),
        });
    }
    out
}

fn is_key_type(w: &str) -> bool {
    w.starts_with("ssh-") || w.starts_with("ecdsa-sha2-") || w.starts_with("sk-")
}

/// `SHA256:<base64 without padding>` of the decoded key, like `ssh-keygen -l`.
pub fn fingerprint(blob: &str) -> Option<String> {
    let bytes = base64_decode(blob)?;
    if bytes.len() < 8 {
        return None;
    }
    let digest = Sha256::digest(&bytes);
    Some(format!("SHA256:{}", base64_encode(&digest)))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

pub fn parse_hosts(file: &str, text: &str) -> Vec<HostsEntry> {
    text.lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let line = raw.split('#').next().unwrap_or("");
            let mut words = line.split_whitespace();
            let address = words.next()?;
            let names: Vec<String> = words.map(|w| w.to_ascii_lowercase()).collect();
            (!names.is_empty()).then(|| HostsEntry {
                file: file.into(),
                line: i + 1,
                address: address.into(),
                names,
            })
        })
        .collect()
}

/// `/etc/sudoers` plus included files and `/etc/sudoers.d`.
fn sudoers(errors: &mut Vec<(String, String)>) -> Vec<SudoersLine> {
    let mut files = vec![SUDOERS.to_string()];
    let mut dirs = vec![SUDOERS_D.to_string()];
    let mut out = Vec::new();
    let mut i = 0;
    while i < files.len() {
        let file = files[i].clone();
        i += 1;
        let text = match read_optional(&file) {
            Ok(Some(t)) => t,
            Ok(None) => continue,
            Err(e) => {
                errors.push((file, e));
                continue;
            }
        };
        let (lines, includes) = sudoers_lines(&file, &text);
        out.extend(lines);
        for inc in includes {
            match inc {
                Include::File(f) if !files.contains(&f) => files.push(f),
                Include::Dir(d) if !dirs.contains(&d) => dirs.push(d),
                _ => {}
            }
        }
        // Directories are read after the main file, like sudo does.
        if i == files.len() {
            for dir in std::mem::take(&mut dirs) {
                match std::fs::read_dir(&dir) {
                    Ok(entries) => {
                        let mut names: Vec<String> = entries
                            .flatten()
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            // sudo skips names with a '.' or ending in '~'.
                            .filter(|n| !n.contains('.') && !n.ends_with('~'))
                            .collect();
                        names.sort();
                        for n in names {
                            let f = format!("{dir}/{n}");
                            if !files.contains(&f) {
                                files.push(f);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => errors.push((dir.clone(), format!("{dir}: {e}"))),
                }
            }
        }
    }
    out
}

#[derive(Debug, PartialEq)]
pub enum Include {
    File(String),
    Dir(String),
}

/// Rules and settings in one sudoers file, plus the files it includes.
pub fn sudoers_lines(file: &str, text: &str) -> (Vec<SudoersLine>, Vec<Include>) {
    let norm = |p: &str| {
        p.trim_matches('"')
            .strip_prefix("/private")
            .filter(|r| r.starts_with("/etc/"))
            .unwrap_or(p.trim_matches('"'))
            .to_string()
    };
    let mut lines = Vec::new();
    let mut includes = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let (start, mut acc) = pending.take().unwrap_or((i + 1, String::new()));
        let line = raw.trim();
        if acc.is_empty() {
            for (prefix, dir) in [
                ("#includedir ", true),
                ("@includedir ", true),
                ("#include ", false),
                ("@include ", false),
            ] {
                if let Some(p) = line.strip_prefix(prefix) {
                    let p = norm(p.trim());
                    includes.push(if dir {
                        Include::Dir(p)
                    } else {
                        Include::File(p)
                    });
                }
            }
            if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
                continue;
            }
        }
        if let Some(cont) = line.strip_suffix('\\') {
            acc.push_str(cont);
            acc.push(' ');
            pending = Some((start, acc));
            continue;
        }
        // Trailing comments.
        let line = line.split(" #").next().unwrap_or(line);
        acc.push_str(line);
        lines.push(SudoersLine {
            file: file.into(),
            line: start,
            text: acc.split_whitespace().collect::<Vec<_>>().join(" "),
        });
    }
    (lines, includes)
}

fn login_hooks(plist: &str) -> Result<Vec<LoginHook>, String> {
    let value = match Value::from_file(plist) {
        Ok(v) => v,
        Err(e)
            if e.as_io()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(Vec::new());
        }
        Err(e) => return Err(format!("{plist}: {e}")),
    };
    Ok(hooks_in(plist, &value)
        .into_iter()
        .map(|mut h| {
            let program = h.command.split_whitespace().next().unwrap_or("");
            h.exists = Path::new(program).exists();
            h.signing = h.exists.then(|| codesign::for_path(program));
            h
        })
        .collect())
}

pub fn hooks_in(plist: &str, value: &Value) -> Vec<LoginHook> {
    let Some(dict) = value.as_dictionary() else {
        return Vec::new();
    };
    ["LoginHook", "LogoutHook"]
        .iter()
        .filter_map(|k| {
            let cmd = dict.get(k)?.as_string()?.trim();
            (!cmd.is_empty()).then(|| LoginHook {
                kind: k.to_string(),
                plist: plist.into(),
                command: redact_line(cmd),
                exists: false,
                signing: None,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// Run a tool with no stdin and a timeout; stdout on success.
fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd}: {e}"))?;
    let drain = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out = drain(child.stdout.take().map(|s| Box::new(s) as _));
    let err = drain(child.stderr.take().map(|s| Box::new(s) as _));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if started.elapsed() > TOOL_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{cmd}: timed out"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("{cmd}: {e}")),
        }
    };
    let (out, err) = (
        out.join().unwrap_or_default(),
        err.join().unwrap_or_default(),
    );
    if status.success() {
        Ok(out)
    } else {
        Err(format!("{cmd}: {}", err.trim()))
    }
}

/// `profiles show -output stdout-xml`: `{ "_computerlevel": [..], "<user>": [..] }`.
pub fn parse_profiles(xml: &str) -> Result<Vec<ConfigProfile>, String> {
    let trimmed = xml.trim();
    if trimmed.is_empty() || !trimmed.contains("<plist") {
        // "There are no configuration profiles installed" and similar.
        return Ok(Vec::new());
    }
    let value: Value =
        plist::from_bytes(trimmed.as_bytes()).map_err(|e| format!("profiles: {e}"))?;
    let Some(dict) = value.as_dictionary() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (scope, list) in dict {
        let scope = if scope == "_computerlevel" {
            "computer"
        } else {
            scope.as_str()
        };
        for p in list.as_array().into_iter().flatten() {
            let Some(p) = p.as_dictionary() else {
                continue;
            };
            let s = |k: &str| p.get(k).and_then(Value::as_string).map(str::to_string);
            let mut payload_types: Vec<String> = p
                .get("ProfileItems")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|i| i.as_dictionary()?.get("PayloadType")?.as_string())
                .map(str::to_string)
                .collect();
            payload_types.sort();
            payload_types.dedup();
            let removal_disallowed = match p.get("ProfileRemovalDisallowed") {
                Some(Value::Boolean(b)) => *b,
                Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
                _ => false,
            };
            let identifier = s("ProfileIdentifier").unwrap_or_default();
            out.push(ConfigProfile {
                scope: scope.to_string(),
                name: s("ProfileDisplayName").unwrap_or_else(|| identifier.clone()),
                identifier,
                organization: s("ProfileOrganization").filter(|o| !o.is_empty()),
                payload_types,
                removal_disallowed,
            });
        }
    }
    Ok(out)
}

/// `systemextensionsctl list`: a `--- <category>` line, a header, then tab-separated rows
/// `enabled  active  teamID  bundleID (version)  name  [state]`.
pub fn parse_system_extensions(out: &str) -> Vec<SystemExtension> {
    let mut category = String::new();
    let mut exts = Vec::new();
    for line in out.lines() {
        if let Some(c) = line.strip_prefix("--- ") {
            category = c.split_whitespace().next().unwrap_or("").to_string();
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 6 || cols[0] == "enabled" {
            continue;
        }
        let (bundle_id, version) = match cols[3].split_once(" (") {
            Some((b, v)) => (b.trim(), Some(v.trim_end_matches(')').to_string())),
            None => (cols[3].trim(), None),
        };
        let team = cols[2].trim();
        exts.push(SystemExtension {
            category: category.clone(),
            team_id: (!team.is_empty() && team != "-").then(|| team.to_string()),
            bundle_id: bundle_id.to_string(),
            version,
            name: cols[4].trim().to_string(),
            state: cols[5..]
                .join(" ")
                .trim()
                .trim_matches(['[', ']'])
                .to_string(),
            enabled: cols[0].trim() == "*",
            active: cols[1].trim() == "*",
        });
    }
    exts
}

/// `kmutil showloaded --list-only` (same columns as `kextstat`): loaded non-Apple kexts.
pub fn parse_kexts(out: &str) -> Vec<KernelExtension> {
    let mut kexts = Vec::new();
    for line in out.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        // Index Refs Address Size Wired Name (Version) UUID <Linked Against>
        let Some(pos) = words
            .iter()
            .position(|w| w.contains('.') && !w.starts_with("0x") && !w.starts_with('('))
        else {
            continue;
        };
        if pos < 2 || !words[0].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let id = words[pos];
        if id.starts_with("com.apple.") {
            continue;
        }
        kexts.push(KernelExtension {
            bundle_id: id.to_string(),
            version: words
                .get(pos + 1)
                .filter(|v| v.starts_with('('))
                .map(|v| v.trim_matches(['(', ')']).to_string()),
        });
    }
    kexts
}

/// `sfltool dumpbtm`: per-user record sections with numbered items of `Key: value` lines.
pub fn parse_btm(out: &str) -> Vec<BackgroundItem> {
    let mut items = Vec::new();
    let mut uid = None;
    let mut cur: Option<BackgroundItem> = None;
    let mut in_embedded = false;
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Records for UID ") {
            if let Some(i) = cur.take() {
                items.push(i);
            }
            uid = rest
                .split(|c: char| c.is_whitespace() || c == ':')
                .next()
                .and_then(|n| n.parse().ok());
            continue;
        }
        // An item starts with a bare `#N:`; embedded item lists look like `#1: id`.
        if t.starts_with('#')
            && t.ends_with(':')
            && t[1..t.len() - 1].chars().all(|c| c.is_ascii_digit())
        {
            if let Some(i) = cur.take() {
                items.push(i);
            }
            cur = Some(BackgroundItem {
                uid,
                ..Default::default()
            });
            in_embedded = false;
            continue;
        }
        let Some(item) = cur.as_mut() else { continue };
        let Some((key, value)) = t.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if key.starts_with('#') && in_embedded {
            continue;
        }
        let opt = || (!value.is_empty() && value != "(null)").then(|| value.to_string());
        in_embedded = false;
        match key.trim() {
            "Name" => item.name = value.to_string(),
            "Developer Name" => item.developer = opt(),
            "Team Identifier" => item.team_id = opt(),
            "Type" => item.kind = value.split(" (").next().unwrap_or(value).trim().to_string(),
            "Disposition" => {
                item.enabled = value.contains("enabled") && !value.contains("disabled")
            }
            "Identifier" => item.identifier = opt(),
            "URL" => item.url = opt(),
            "Executable Path" => item.executable = opt(),
            "Embedded Item Identifiers" => in_embedded = true,
            _ => {}
        }
    }
    if let Some(i) = cur {
        items.push(i);
    }
    items
}

fn file_url_path(url: &str) -> Option<&str> {
    url.strip_prefix("file://")
        .map(|p| p.trim_end_matches('/'))
        .filter(|p| p.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_lines_drop_comments_and_join_continuations() {
        let text = "# comment\n\nexport A=1\n  # indented\ncurl -fsSL x \\\n  | sh\nexport GITHUB_TOKEN=ghp_abcdefghijklmnop\n";
        let lines = shell_lines(text);
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0],
            NumberedLine {
                line: 3,
                text: "export A=1".into()
            }
        );
        assert_eq!(lines[1].line, 5);
        assert!(lines[1].text.contains("curl -fsSL x") && lines[1].text.contains("| sh"));
        assert!(!lines[2].text.contains("ghp_"));
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        // A throwaway key; `ssh-keygen -lf` prints this fingerprint for it.
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIF3gAqntvO19WKdVabRDfm6Y0jEwOHvJ0uuX2AbJqdfE";
        assert_eq!(
            fingerprint(blob).as_deref(),
            Some("SHA256:h0ATTnZh26mMnLbtlEqAGLqDgxp/sb0rY+YrMAzZB0w")
        );
        assert!(fingerprint("not base64!").is_none());
        assert_eq!(base64_encode(b"hello"), "aGVsbG8");
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn authorized_keys_with_options() {
        let text = "# keys\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3gAqntvO19WKdVabRDfm6Y0jEwOHvJ0uuX2AbJqdfE me@laptop\n\
command=\"/usr/bin/backup --token=abc\",from=\"10.0.0.0/8\",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ backup key\n\
garbage line\n";
        let keys = parse_authorized_keys("me", "/Users/me/.ssh/authorized_keys", text);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].comment.as_deref(), Some("me@laptop"));
        assert_eq!(keys[0].line, 2);
        assert!(keys[0].options.is_none());
        assert_eq!(keys[1].key_type, "ssh-rsa");
        assert_eq!(keys[1].comment.as_deref(), Some("backup key"));
        let opts = keys[1].options.as_deref().unwrap();
        assert!(opts.starts_with("command=") && opts.contains("from=") && !opts.contains("abc"));
    }

    #[test]
    fn hosts_parsing() {
        let text = "##\n# Host Database\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n::1             localhost\n10.0.0.5 MyApp.test api.myapp.test # dev\n";
        let h = parse_hosts("/etc/hosts", text);
        assert_eq!(h.len(), 4);
        assert_eq!(h[3].names, ["myapp.test", "api.myapp.test"]);
        assert_eq!(h[3].line, 6);
    }

    #[test]
    fn sudoers_parsing() {
        let text = "Defaults\tenv_reset\nDefaults\tenv_keep += \"BLOCKSIZE\"\n\
root\tALL = (ALL) ALL\n%admin\tALL = (ALL) ALL\n\
## Read drop-in files\n#includedir /private/etc/sudoers.d\n\
bob ALL=(ALL) NOPASSWD: /usr/bin/true, \\\n  /bin/ls # trailing\n";
        let (lines, inc) = sudoers_lines("/etc/sudoers", text);
        assert_eq!(inc, [Include::Dir("/etc/sudoers.d".into())]);
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[4].line, 7);
        assert_eq!(
            lines[4].text,
            "bob ALL=(ALL) NOPASSWD: /usr/bin/true, /bin/ls"
        );
    }

    #[test]
    fn profiles_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>_computerlevel</key>
  <array>
    <dict>
      <key>ProfileDisplayName</key><string>Company Wi-Fi</string>
      <key>ProfileIdentifier</key><string>com.example.wifi</string>
      <key>ProfileOrganization</key><string>Example Inc</string>
      <key>ProfileRemovalDisallowed</key><string>TRUE</string>
      <key>ProfileItems</key>
      <array>
        <dict><key>PayloadType</key><string>com.apple.wifi.managed</string></dict>
        <dict><key>PayloadType</key><string>com.apple.security.root</string></dict>
      </array>
    </dict>
  </array>
</dict>
</plist>"#;
        let p = parse_profiles(xml).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].scope, "computer");
        assert_eq!(p[0].name, "Company Wi-Fi");
        assert_eq!(p[0].organization.as_deref(), Some("Example Inc"));
        assert_eq!(
            p[0].payload_types,
            ["com.apple.security.root", "com.apple.wifi.managed"]
        );
        assert!(p[0].removal_disallowed);
        let empty = "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict/>\n</plist>\n";
        assert!(parse_profiles(empty).unwrap().is_empty());
        assert!(
            parse_profiles("There are no configuration profiles installed")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn login_hook_plist() {
        let mut d = plist::Dictionary::new();
        d.insert(
            "LoginHook".into(),
            Value::String("/Library/.x/hook.sh".into()),
        );
        d.insert("GuestEnabled".into(), Value::Boolean(false));
        let h = hooks_in(
            "/var/root/Library/Preferences/com.apple.loginwindow.plist",
            &Value::Dictionary(d),
        );
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].kind, "LoginHook");
        assert_eq!(h[0].command, "/Library/.x/hook.sh");
    }

    #[test]
    fn system_extensions_list() {
        let out = "2 extension(s)\n\
--- com.apple.system_extension.driver_extension (Go to 'System Settings > General > Login Items & Extensions > Driver Extensions' to modify these system extension(s))\n\
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\
*\t*\t5JZGQTGU4W\tcn.wch.CH34xVCPDriver (1.0/1)\tcn.wch.CH34xVCPDriver\t[activated enabled]\n\
--- com.apple.system_extension.network_extension\n\
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\
\t\tVR3CR5QXV9\tcom.objective-see.lulu.extension (2.6.2/2.6.2)\tLuLu\t[terminated waiting to uninstall on reboot]\n";
        let e = parse_system_extensions(out);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].category, "com.apple.system_extension.driver_extension");
        assert_eq!(e[0].team_id.as_deref(), Some("5JZGQTGU4W"));
        assert_eq!(e[0].bundle_id, "cn.wch.CH34xVCPDriver");
        assert_eq!(e[0].version.as_deref(), Some("1.0/1"));
        assert_eq!(e[0].state, "activated enabled");
        assert!(e[0].enabled && e[0].active);
        assert!(!e[1].enabled && !e[1].active);
        assert_eq!(
            e[1].category,
            "com.apple.system_extension.network_extension"
        );
    }

    #[test]
    fn kext_list() {
        let out = "No variant specified, falling back to release\n\
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>\n\
    1  158 0                  0          0          com.apple.kpi.bsd (25.0.0) 5A8B-UUID <>\n\
  180    0 0xfffffe0007a1c000 0x8000     0x8000     com.vmware.kext.vmx86 (2.0.4) AB12-UUID <8 6 5 3 1>\n";
        let k = parse_kexts(out);
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].bundle_id, "com.vmware.kext.vmx86");
        assert_eq!(k[0].version.as_deref(), Some("2.0.4"));
    }

    #[test]
    fn btm_dump() {
        let out = "========================\n Records for UID 501 : 7B5D-UUID\n========================\n\
 ServiceManagement migrated: true\n\n Items:\n\n #1:\n\
                 UUID: 1111\n                 Name: Docker\n       Developer Name: Docker Inc\n\
      Team Identifier: 9BNSXJN65R\n                 Type: app (0x2)\n\
          Disposition: [enabled, allowed, visible, notified] (0xb)\n\
           Identifier: 2.com.docker.docker\n                  URL: file:///Applications/Docker.app/\n\
    Embedded Item Identifiers:\n       #1: 16.com.docker.helper\n\
 #2:\n                 Name: helper\n                 Type: agent (0x8)\n\
          Disposition: [disabled, allowed, visible, notified] (0xa)\n\
                  URL: Contents/Library/LaunchAgents/com.x.helper.plist\n\
      Executable Path: /Applications/X.app/Contents/MacOS/helper\n\
========================\n Records for UID -2 : FFFF\n========================\n Items:\n #1:\n\
                 Name: vmnetd\n                 Type: legacy daemon (0x10010)\n\
          Disposition: [enabled, allowed, visible, notified] (0xb)\n\
                  URL: file:///Library/LaunchDaemons/com.docker.vmnetd.plist\n\
      Executable Path: /Library/PrivilegedHelperTools/com.docker.vmnetd\n";
        let items = parse_btm(out);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].uid, Some(501));
        assert_eq!(items[0].name, "Docker");
        assert_eq!(items[0].kind, "app");
        assert_eq!(items[0].team_id.as_deref(), Some("9BNSXJN65R"));
        assert_eq!(
            items[0].url.as_deref(),
            Some("file:///Applications/Docker.app/")
        );
        assert!(items[0].enabled);
        assert_eq!(items[1].kind, "agent");
        assert!(!items[1].enabled);
        assert_eq!(
            items[1].executable.as_deref(),
            Some("/Applications/X.app/Contents/MacOS/helper")
        );
        assert_eq!(items[2].uid, Some(-2));
        assert_eq!(items[2].kind, "legacy daemon");
        assert_eq!(
            file_url_path("file:///Applications/Docker.app/"),
            Some("/Applications/Docker.app")
        );
    }
}
