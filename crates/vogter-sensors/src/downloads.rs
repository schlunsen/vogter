//! Facts about a downloaded file: what it is, who signed it, whether Apple
//! notarized it, the "downloaded from the internet" (quarantine) flag and the
//! URL it came from.
//!
//! `spctl`, `pkgutil` and `zipinfo` are run with a timeout. Call [`gather`]
//! off any latency-sensitive thread: Gatekeeper may take a few seconds.

use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use vogter_model::download::{DownloadFacts, DownloadKind};
use vogter_model::{SignatureKind, Signing};

const QUARANTINE: &str = "com.apple.quarantine";
const WHERE_FROMS: &str = "com.apple.metadata:kMDItemWhereFroms";
/// How long `spctl` / `pkgutil` / `zipinfo` may take.
const TOOL_TIMEOUT: Duration = Duration::from_secs(20);
/// Files a browser is still writing.
const PARTIAL_SUFFIXES: &[&str] = &[
    ".crdownload",
    ".download",
    ".part",
    ".partial",
    ".opdownload",
    ".tmp",
    ".filepart",
];

/// True for in-progress downloads (`foo.dmg.crdownload`, Safari's `foo.download`).
pub fn is_partial(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with('.') || PARTIAL_SUFFIXES.iter().any(|s| n.ends_with(s))
}

/// What kind of runnable thing `path` is, or `None` for documents and folders.
pub fn classify(path: &Path) -> Option<DownloadKind> {
    let name = path.file_name()?.to_str()?;
    if is_partial(name) {
        return None;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.is_dir() {
        return (ext.as_deref() == Some("app")).then_some(DownloadKind::App);
    }
    if !meta.is_file() {
        return None;
    }
    match ext.as_deref() {
        Some("dmg") => return Some(DownloadKind::DiskImage),
        Some("pkg" | "mpkg") => return Some(DownloadKind::Installer),
        Some("zip") => return Some(DownloadKind::Archive),
        Some("command" | "sh" | "scpt" | "applescript") => {
            return Some(DownloadKind::Script);
        }
        _ => {}
    }
    let mut head = [0u8; 8];
    let n = std::fs::File::open(path).ok()?.read(&mut head).ok()?;
    if n >= 2 && head.starts_with(b"#!") {
        return Some(DownloadKind::Script);
    }
    (n >= 8 && is_mach_o(&head)).then_some(DownloadKind::Executable)
}

fn is_mach_o(head: &[u8; 8]) -> bool {
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    match magic {
        0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe => true,
        // Universal binary; Java class files share this magic but have a
        // large version number where the architecture count goes.
        0xcafe_babe => {
            let count = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
            (1..20).contains(&count)
        }
        _ => false,
    }
}

/// Raw extended attribute, or `None` if absent/unreadable. Doesn't follow symlinks.
pub fn xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let p = CString::new(path.as_os_str().as_bytes()).ok()?;
    let n = CString::new(name).ok()?;
    // SAFETY: valid C strings; a null buffer asks for the size.
    let size = unsafe {
        libc::getxattr(
            p.as_ptr(),
            n.as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if size < 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` has room for `size` bytes.
    let got = unsafe {
        libc::getxattr(
            p.as_ptr(),
            n.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if got < 0 {
        return None;
    }
    buf.truncate(got as usize);
    Some(buf)
}

/// The quarantine flag, if set: `Some(agent)` where agent is the app that
/// downloaded it (`0081;6720a1b3;Safari;UUID` → "Safari"), possibly empty.
pub fn quarantine(path: &Path) -> Option<Option<String>> {
    let raw = xattr(path, QUARANTINE)?;
    Some(parse_quarantine_agent(&String::from_utf8_lossy(&raw)))
}

fn parse_quarantine_agent(value: &str) -> Option<String> {
    value
        .trim_end_matches('\0')
        .split(';')
        .nth(2)
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
}

/// Download origin URLs (file URL first, then the page it was linked from).
pub fn where_froms(path: &Path) -> Vec<String> {
    xattr(path, WHERE_FROMS)
        .map(|b| parse_where_froms(&b))
        .unwrap_or_default()
}

/// Parse a `kMDItemWhereFroms` value (a plist array of strings, usually binary)
/// and remove secrets from the URLs.
pub fn parse_where_froms(bytes: &[u8]) -> Vec<String> {
    let Ok(value) = plist::Value::from_reader(std::io::Cursor::new(bytes)) else {
        return Vec::new();
    };
    let items = match value {
        plist::Value::Array(a) => a,
        plist::Value::String(s) => vec![plist::Value::String(s)],
        _ => return Vec::new(),
    };
    items
        .into_iter()
        .filter_map(|v| v.into_string())
        .map(|s| clean_url(s.trim()))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Drop the query and fragment (signed download links carry tokens there) and
/// any `user:password@`.
pub fn clean_url(url: &str) -> String {
    let (base, cut) = match url.find(['?', '#']) {
        Some(i) => (&url[..i], true),
        None => (url, false),
    };
    let mut out = vogter_model::redact::redact(base);
    // `user@host` without a password is still personal: keep only the host.
    if let Some(scheme_end) = out.find("://") {
        let rest = &out[scheme_end + 3..];
        let auth_end = rest.find('/').unwrap_or(rest.len());
        if let Some(at) = rest[..auth_end].rfind('@') {
            out = format!("{}{}", &out[..scheme_end + 3], &rest[at + 1..]);
        }
    }
    if cut {
        out.push_str("?…");
    }
    out
}

/// What `pkgutil --check-signature` says about an installer.
#[derive(Debug, Clone, PartialEq)]
pub struct PkgSignature {
    pub signing: Signing,
    /// "NXTGN Music Technology GmbH" from "Developer ID Installer: NXTGN … (9PRN6T272N)".
    pub developer: Option<String>,
}

pub fn parse_pkgutil(output: &str) -> PkgSignature {
    let status = output
        .lines()
        .find_map(|l| l.trim().strip_prefix("Status:"))
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let notarized = output.lines().any(|l| {
        l.trim()
            .strip_prefix("Notarization:")
            .is_some_and(|n| n.contains("trusted by the Apple notary service"))
    });
    // First certificate in the chain is the signer: "1. Developer ID Installer: Name (TEAM)".
    let leaf = output
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("1. "))
        .map(str::to_string);
    let (developer, team_id) = leaf.as_deref().map(split_identity).unwrap_or((None, None));
    let kind = if status.is_empty() {
        SignatureKind::Unknown
    } else if status.contains("no signature") {
        SignatureKind::Unsigned
    } else if status.contains("invalid") || status.contains("revoked") {
        SignatureKind::Invalid
    } else if status.contains("signed apple software") {
        SignatureKind::Apple
    } else if status.contains("developer certificate issued by apple")
        || status.contains("signed by a certificate trusted")
    {
        SignatureKind::ThirdParty
    } else if status.starts_with("signed") {
        SignatureKind::Untrusted
    } else {
        SignatureKind::Unknown
    };
    PkgSignature {
        signing: Signing {
            kind,
            identifier: None,
            team_id: team_id.filter(|_| kind == SignatureKind::ThirdParty),
            notarized: notarized && kind == SignatureKind::ThirdParty,
        },
        developer: developer.filter(|_| kind == SignatureKind::ThirdParty),
    }
}

/// "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)" → (Some("Anthropic PBC"), Some("Q6L2SF6YDW")).
fn split_identity(s: &str) -> (Option<String>, Option<String>) {
    let s = s.trim();
    let after_role = s.split_once(": ").map(|(_, r)| r).unwrap_or(s);
    match after_role.rsplit_once(" (") {
        Some((name, team)) if team.ends_with(')') => (
            Some(name.trim().to_string()),
            Some(team.trim_end_matches(')').to_string()),
        ),
        _ => (Some(after_role.to_string()), None),
    }
}

/// Gatekeeper's verdict from `spctl --assess -vv`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Gatekeeper {
    pub accepted: bool,
    /// e.g. "Notarized Developer ID", "Unnotarized Developer ID", "no usable signature".
    pub source: Option<String>,
    pub developer: Option<String>,
    pub team_id: Option<String>,
}

impl Gatekeeper {
    pub fn notarized(&self) -> bool {
        self.source.as_deref().is_some_and(|s| {
            s.starts_with("Notarized") || s == "Apple System" || s == "Mac App Store"
        })
    }
}

pub fn parse_spctl(output: &str) -> Gatekeeper {
    let mut g = Gatekeeper::default();
    for line in output.lines().map(str::trim) {
        if let Some(src) = line.strip_prefix("source=") {
            g.source = Some(src.to_string());
        } else if let Some(origin) = line.strip_prefix("origin=") {
            (g.developer, g.team_id) = split_identity(origin);
        } else if line.ends_with(": accepted") {
            g.accepted = true;
        }
    }
    g
}

/// Run a tool, giving up after `timeout`. Returns (success, stdout + stderr).
pub fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<(bool, String)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    // Drain the pipes on their own threads so a chatty tool can't block on a full pipe.
    let mut out = child.stdout.take()?;
    let mut err = child.stderr.take()?;
    let out_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let mut text = out_t.join().unwrap_or_default();
    text.push_str(&err_t.join().unwrap_or_default());
    Some((status.success(), text))
}

fn spctl(path: &str, kind: DownloadKind) -> Option<Gatekeeper> {
    let args: &[&str] = match kind {
        DownloadKind::App => &["--assess", "--type", "execute", "-vv", path],
        DownloadKind::DiskImage => &[
            "--assess",
            "--type",
            "open",
            "--context",
            "context:primary-signature",
            "-vv",
            path,
        ],
        _ => return None,
    };
    run_with_timeout("/usr/sbin/spctl", args, TOOL_TIMEOUT).map(|(_, out)| parse_spctl(&out))
}

/// Name of an `.app` inside a zip (from its directory listing, not unpacked).
pub fn zip_app(path: &str) -> Option<String> {
    let (_, out) = run_with_timeout("/usr/bin/zipinfo", &["-1", path], TOOL_TIMEOUT)?;
    out.lines().find_map(app_in_zip_entry)
}

fn app_in_zip_entry(entry: &str) -> Option<String> {
    if entry.starts_with("__MACOSX/") {
        return None;
    }
    entry
        .split('/')
        .find(|c| c.to_ascii_lowercase().ends_with(".app"))
        .map(str::to_string)
}

/// Do other files modified in the last two weeks in `dir` carry the quarantine flag?
pub fn others_quarantined(dir: &Path, except: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let recent = SystemTime::now() - Duration::from_secs(14 * 86_400);
    entries
        .flatten()
        .take(500)
        .map(|e| e.path())
        .filter(|p| p != except)
        .filter(|p| {
            std::fs::symlink_metadata(p)
                .and_then(|m| m.modified())
                .is_ok_and(|t| t >= recent)
        })
        .any(|p| xattr(&p, QUARANTINE).is_some())
}

/// Everything known about a download. `volume` is set for items found on a
/// newly mounted disk image. `None` if it isn't a kind of file we assess.
pub fn gather(path: &Path, volume: Option<&str>) -> Option<DownloadFacts> {
    let kind = classify(path)?;
    let path_str = path.to_str()?.to_string();
    let name = path.file_name()?.to_string_lossy().into_owned();

    let mut developer = None;
    let signing = match kind {
        DownloadKind::Installer => run_with_timeout(
            "/usr/sbin/pkgutil",
            &["--check-signature", &path_str],
            TOOL_TIMEOUT,
        )
        .map(|(_, out)| {
            let p = parse_pkgutil(&out);
            developer = p.developer;
            p.signing
        })
        .unwrap_or_else(Signing::unknown),
        DownloadKind::Archive => unsigned(),
        DownloadKind::Script => {
            // Compiled AppleScripts can carry a signature; plain scripts can't.
            let s = crate::codesign::for_path(&path_str);
            if s.kind == SignatureKind::Unknown {
                unsigned()
            } else {
                s
            }
        }
        DownloadKind::App | DownloadKind::DiskImage | DownloadKind::Executable => {
            let mut s = crate::codesign::for_path(&path_str);
            // A DMG that SecStaticCode can't open is just an unsigned image.
            if kind == DownloadKind::DiskImage && s.kind == SignatureKind::Unknown {
                s = unsigned();
            }
            if s.kind == SignatureKind::ThirdParty
                && let Some(g) = spctl(&path_str, kind)
            {
                s.notarized |= g.notarized();
                if g.team_id.is_none() || g.team_id == s.team_id {
                    developer = g.developer;
                }
            }
            s
        }
    };

    let q = quarantine(path);
    let others = q.is_none()
        && volume.is_none()
        && path
            .parent()
            .is_some_and(|dir| others_quarantined(dir, path));
    Some(DownloadFacts {
        path: path_str.clone(),
        name,
        kind,
        signing,
        developer,
        quarantined: q.is_some(),
        quarantine_agent: q.flatten(),
        where_from: where_froms(path),
        others_quarantined: others,
        archive_app: (kind == DownloadKind::Archive)
            .then(|| zip_app(&path_str))
            .flatten(),
        volume: volume.map(str::to_string),
    })
}

fn unsigned() -> Signing {
    Signing {
        kind: SignatureKind::Unsigned,
        identifier: None,
        team_id: None,
        notarized: false,
    }
}

/// Total size of a file, or of everything in a bundle (capped walk), for
/// "has it finished being written?" checks.
pub fn size_of(path: &Path) -> Option<u64> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_dir() {
        return Some(meta.len());
    }
    let mut total = 0u64;
    let mut count = 0usize;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).ok()?.flatten() {
            count += 1;
            if count > 50_000 {
                return Some(total);
            }
            let Ok(m) = e.path().symlink_metadata() else {
                continue;
            };
            if m.is_dir() {
                stack.push(e.path());
            } else {
                total += m.len();
            }
        }
    }
    Some(total + count as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn where_froms_binary_plist() {
        let urls = plist::Value::Array(vec![
            plist::Value::String(
                "https://dl.example.com/Zoom.dmg?X-Amz-Signature=abc123&token=s3cret".into(),
            ),
            plist::Value::String("https://me:hunter2@example.com/download#frag".into()),
        ]);
        let mut bytes = Vec::new();
        urls.to_writer_binary(&mut bytes).unwrap();
        assert_eq!(
            parse_where_froms(&bytes),
            vec![
                "https://dl.example.com/Zoom.dmg?…".to_string(),
                "https://example.com/download?…".to_string(),
            ]
        );
        // XML plists parse too; garbage gives nothing.
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><array><string>https://a.example/x.pkg</string></array></plist>"#;
        assert_eq!(parse_where_froms(xml), vec!["https://a.example/x.pkg"]);
        assert!(parse_where_froms(b"not a plist").is_empty());
    }

    #[test]
    fn urls_lose_credentials() {
        assert_eq!(clean_url("https://bob@host/x"), "https://host/x");
        assert_eq!(clean_url("https://host/a/b.dmg"), "https://host/a/b.dmg");
    }

    #[test]
    fn quarantine_agent() {
        assert_eq!(
            parse_quarantine_agent("0081;6720a1b3;Safari;A1B2C3D4-0000"),
            Some("Safari".into())
        );
        assert_eq!(parse_quarantine_agent("0081;6720a1b3;;"), None);
        assert_eq!(parse_quarantine_agent("0081"), None);
    }

    #[test]
    fn pkgutil_developer_notarized() {
        let out = r#"Package "Virtual Drummer DEEP 2.1.1 (131).pkg":
   Status: signed by a developer certificate issued by Apple for distribution
   Notarization: trusted by the Apple notary service
   Signed with a trusted timestamp on: 2021-01-27 11:42:35 +0000
   Certificate Chain:
    1. Developer ID Installer: NXTGN Music Technology GmbH (9PRN6T272N)
       SHA256 Fingerprint:
           3A 84 C2 DD
       ------------------------------------------------------------------------
    2. Developer ID Certification Authority
"#;
        let p = parse_pkgutil(out);
        assert_eq!(p.signing.kind, SignatureKind::ThirdParty);
        assert!(p.signing.notarized);
        assert_eq!(p.signing.team_id.as_deref(), Some("9PRN6T272N"));
        assert_eq!(p.developer.as_deref(), Some("NXTGN Music Technology GmbH"));
    }

    #[test]
    fn pkgutil_other_statuses() {
        let unsigned = parse_pkgutil("Package \"x.pkg\":\n   Status: no signature\n");
        assert_eq!(unsigned.signing.kind, SignatureKind::Unsigned);
        assert_eq!(unsigned.developer, None);

        let apple = parse_pkgutil(
            "Package \"CLTools.pkg\":\n   Status: signed Apple Software\n   Certificate Chain:\n    1. Software Update\n",
        );
        assert_eq!(apple.signing.kind, SignatureKind::Apple);

        let not_notarized = parse_pkgutil(
            "Package \"y.pkg\":\n   Status: signed by a developer certificate issued by Apple for distribution\n   Certificate Chain:\n    1. Developer ID Installer: Some Dev (ABCDE12345)\n",
        );
        assert_eq!(not_notarized.signing.kind, SignatureKind::ThirdParty);
        assert!(!not_notarized.signing.notarized);

        let bad = parse_pkgutil(
            "Package \"z.pkg\":\n   Status: package is invalid (checksum did not verify)\n",
        );
        assert_eq!(bad.signing.kind, SignatureKind::Invalid);

        let untrusted = parse_pkgutil(
            "Package \"u.pkg\":\n   Status: signed by untrusted certificate\n   Certificate Chain:\n    1. Self Signed (NOPE)\n",
        );
        assert_eq!(untrusted.signing.kind, SignatureKind::Untrusted);
        assert_eq!(untrusted.signing.team_id, None);

        assert_eq!(parse_pkgutil("").signing.kind, SignatureKind::Unknown);
    }

    #[test]
    fn spctl_output() {
        let g = parse_spctl(
            "/Users/me/Downloads/Claude.dmg: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\n",
        );
        assert!(g.accepted && g.notarized());
        assert_eq!(g.developer.as_deref(), Some("Anthropic PBC"));
        assert_eq!(g.team_id.as_deref(), Some("Q6L2SF6YDW"));
        let r = parse_spctl("/x.dmg: rejected\nsource=no usable signature\n");
        assert!(!r.accepted && !r.notarized());
        let u = parse_spctl("/x.app: rejected\nsource=Unnotarized Developer ID\n");
        assert!(!u.notarized());
    }

    #[test]
    fn zip_listing() {
        assert_eq!(
            app_in_zip_entry("Zoom.app/Contents/MacOS/zoom"),
            Some("Zoom.app".into())
        );
        assert_eq!(app_in_zip_entry("__MACOSX/Zoom.app/._x"), None);
        assert_eq!(app_in_zip_entry("docs/readme.txt"), None);
    }

    #[test]
    fn classifies_files() {
        let dir = std::env::temp_dir().join(format!("vogter-dl-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("Thing.app/Contents")).unwrap();
        std::fs::write(dir.join("run"), b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::write(dir.join("notes.txt"), b"hello").unwrap();
        std::fs::write(dir.join("x.dmg.crdownload"), b"partial").unwrap();
        std::fs::copy("/bin/ls", dir.join("ls")).unwrap();
        std::fs::write(dir.join("Setup.PKG"), b"xar!").unwrap();
        assert_eq!(classify(&dir.join("Thing.app")), Some(DownloadKind::App));
        assert_eq!(classify(&dir.join("run")), Some(DownloadKind::Script));
        assert_eq!(classify(&dir.join("notes.txt")), None);
        assert_eq!(classify(&dir.join("x.dmg.crdownload")), None);
        assert_eq!(classify(&dir.join("ls")), Some(DownloadKind::Executable));
        assert_eq!(
            classify(&dir.join("Setup.PKG")),
            Some(DownloadKind::Installer)
        );
        assert_eq!(classify(&dir), None);
        assert!(size_of(&dir.join("Thing.app")).is_some());

        let facts = gather(&dir.join("ls"), None).unwrap();
        assert_eq!(facts.signing.kind, SignatureKind::Apple);
        assert!(!facts.quarantined);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
