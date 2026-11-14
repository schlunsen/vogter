//! Rules for a file that just landed in Downloads: an app, disk image,
//! installer, program or script. Most Mac malware arrives this way, often with
//! instructions to "right-click → Open" past Gatekeeper, so the point is to
//! say something *before* it's opened.

use vogter_model::download::{DownloadFacts, DownloadKind};
use vogter_model::{Activity, ActivityKind, Severity, SignatureKind};

/// Popular apps that fake installers like to pretend to be. Matched against the
/// start of the file name, ignoring case, spaces and punctuation.
const MIMICKED: &[(&str, &str)] = &[
    ("googlechrome", "Google Chrome"),
    ("zoom", "Zoom"),
    ("telegram", "Telegram"),
    ("ledgerlive", "Ledger Live"),
    ("ledger", "Ledger Live"),
    ("trezorsuite", "Trezor Suite"),
    ("exodus", "Exodus"),
    ("bitwarden", "Bitwarden"),
    ("1password", "1Password"),
    ("microsoftteams", "Microsoft Teams"),
    ("slack", "Slack"),
    ("discord", "Discord"),
    ("whatsapp", "WhatsApp"),
    ("signal", "Signal"),
    ("firefox", "Firefox"),
    ("chatgpt", "ChatGPT"),
    ("notion", "Notion"),
    ("spotify", "Spotify"),
];

const ADVICE_UNSIGNED: &str = "Nothing vouches for this file: it has no developer signature. \
macOS will block it when you open it. If a website tells you to right-click → Open, or to run a \
Terminal command to get around that, that's how malware gets installed. Fine if it's a tool you \
expected from a developer you trust; otherwise delete it.";
const ADVICE_INVALID: &str = "The signature on this file is broken: it was changed after its \
developer signed it, or the certificate was revoked. Don't open it. Delete it and, if you need \
the app, download it again from the developer's own website.";
const ADVICE_NOT_NOTARIZED: &str = "It's signed by a registered developer, but Apple hasn't \
checked it for malware (notarized), so macOS will warn before it opens. Most real apps are \
notarized. Open it only if you trust where it came from.";
const ADVICE_SIGNED: &str = "Signed by its developer and checked by Apple. Nothing to do.";
const ADVICE_DMG_UNSIGNED: &str = "Many disk images aren't signed; what counts is the app \
inside. Vogter checks it when you open the image. Be wary if the window tells you to \
right-click → Open, or to paste a command into Terminal.";
const ADVICE_SCRIPT: &str = "Double-clicking this runs commands on your Mac in Terminal, \
outside of macOS's app checks. Fake installers use this trick. Don't open it unless you know \
exactly what it does.";
const ADVICE_SCRIPT_LOW: &str = "A script can do anything you can. Look inside before running \
it (open it in a text editor), and only run it if you know where it came from.";
const ADVICE_ARCHIVE: &str = "Vogter checks what's inside when it's unpacked here.";
const ADVICE_UNKNOWN: &str = "Vogter couldn't check this file's signature. Be careful opening \
it unless you know where it came from.";

/// `None` when nothing about this download is worth recording.
pub fn assess_download(f: &DownloadFacts) -> Option<Activity> {
    let name = f.name.as_str();
    let sig = &f.signing;
    let by = f
        .developer
        .clone()
        .or_else(|| sig.team_id.clone())
        .unwrap_or_else(|| "a developer".into());
    let signed_ok = matches!(sig.kind, SignatureKind::Apple | SignatureKind::ThirdParty);
    let mimics = match f.kind {
        DownloadKind::App | DownloadKind::DiskImage | DownloadKind::Installer => mimicked_app(name),
        // A zip isn't signed itself; the app inside is checked when it's unpacked.
        DownloadKind::Archive | DownloadKind::Executable | DownloadKind::Script => None,
    };

    if let Some(app) = mimics
        && !signed_ok
        && sig.kind != SignatureKind::Invalid
    {
        let advice = format!(
            "The real {app} is signed by its developer. Fake copies of popular apps are a common \
way Mac malware spreads. Don't open it; delete it and get {app} from its official website."
        );
        return Some(finish(
            f,
            Severity::High,
            format!("looks like {app} but isn't signed"),
            &advice,
        ));
    }

    let (severity, why, advice): (Severity, String, &str) = match (sig.kind, f.kind) {
        (SignatureKind::Invalid, _) => (
            Severity::High,
            "has a broken signature".into(),
            ADVICE_INVALID,
        ),
        (SignatureKind::Apple, _) => (Severity::Info, "signed by Apple".into(), ADVICE_SIGNED),
        (SignatureKind::ThirdParty, _) if sig.notarized => (
            Severity::Info,
            format!("signed by {by}, notarized"),
            ADVICE_SIGNED,
        ),
        (SignatureKind::ThirdParty, _) => (
            Severity::Low,
            format!("signed by {by}, not notarized"),
            ADVICE_NOT_NOTARIZED,
        ),
        (_, DownloadKind::Archive) => match &f.archive_app {
            Some(app) => (
                Severity::Low,
                format!("archive containing {app}"),
                ADVICE_ARCHIVE,
            ),
            None => (Severity::Info, "archive".into(), ADVICE_ARCHIVE),
        },
        (_, DownloadKind::Script) if name.to_lowercase().ends_with(".command") => (
            Severity::Medium,
            "a double-clickable Terminal script".into(),
            ADVICE_SCRIPT,
        ),
        (_, DownloadKind::Script) => (Severity::Low, "a script".into(), ADVICE_SCRIPT_LOW),
        (SignatureKind::Unknown, _) => (
            Severity::Low,
            "signature couldn't be checked".into(),
            ADVICE_UNKNOWN,
        ),
        (_, DownloadKind::DiskImage) => (
            Severity::Low,
            "disk image isn't signed".into(),
            ADVICE_DMG_UNSIGNED,
        ),
        // Unsigned, ad-hoc or untrusted app, installer or program.
        (kind, _) => (
            Severity::Medium,
            match kind {
                SignatureKind::AdHoc => "ad-hoc signed (no developer)".into(),
                SignatureKind::Untrusted => "signed by a certificate Apple doesn't know".into(),
                _ => "unsigned".into(),
            },
            ADVICE_UNSIGNED,
        ),
    };
    Some(finish(f, severity, why, advice))
}

fn finish(f: &DownloadFacts, severity: Severity, why: String, advice: &str) -> Activity {
    let what = match (&f.volume, f.kind) {
        (Some(_), _) => "Disk image contains",
        (None, DownloadKind::Installer) => "Downloaded installer",
        (None, DownloadKind::DiskImage) => "Downloaded disk image",
        (None, _) => "Downloaded",
    };
    let mut detail = Vec::new();
    if let Some(v) = &f.volume {
        detail.push(format!("On the newly mounted volume {v}."));
    }
    match (f.where_from.first(), &f.quarantine_agent) {
        (Some(url), Some(agent)) => detail.push(format!("From {url} (via {agent}).")),
        (Some(url), None) => detail.push(format!("From {url}.")),
        (None, Some(agent)) => detail.push(format!("Downloaded by {agent}.")),
        (None, None) => {}
    }
    if let Some(referrer) = f.where_from.get(1) {
        detail.push(format!("Linked from {referrer}."));
    }
    if f.kind != DownloadKind::Archive {
        detail.push(format!("Signed: {}.", f.signing.describe()));
    }
    if let Some(app) = &f.archive_app {
        detail.push(format!("Contains {app}."));
    }
    // Only worth saying when the file itself is worth a look.
    if !f.quarantined && severity > Severity::Info {
        if f.others_quarantined {
            detail.push(
                "It has no \"downloaded from the internet\" flag, although other downloads here \
do. Something may have removed it, so macOS won't check this file before it runs."
                    .into(),
            );
        } else if f.volume.is_none() {
            detail.push(
                "It has no \"downloaded from the internet\" flag, so macOS won't check it before \
it runs (normal for files you copied or built yourself; downloads by curl or Terminal \
don't get it either)."
                    .into(),
            );
        }
    }
    let mut a = Activity::new(
        ActivityKind::Download,
        severity,
        format!("{what} {}: {why}", f.name),
    )
    .advice(advice)
    .detail(detail.join(" "));
    a.path = Some(f.path.clone());
    a.signing = Some(f.signing.clone());
    a
}

/// The well-known app this file name is pretending to be, if any.
fn mimicked_app(name: &str) -> Option<&'static str> {
    let normal: String = name
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    MIMICKED
        .iter()
        .find(|(key, _)| normal.starts_with(key))
        .map(|(_, app)| *app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::Signing;

    fn facts(name: &str, kind: DownloadKind, sig: SignatureKind, notarized: bool) -> DownloadFacts {
        DownloadFacts {
            path: format!("/Users/me/Downloads/{name}"),
            name: name.into(),
            kind,
            signing: Signing {
                kind: sig,
                identifier: None,
                team_id: (sig == SignatureKind::ThirdParty).then(|| "TEAM123".into()),
                notarized,
            },
            developer: None,
            quarantined: true,
            quarantine_agent: Some("Safari".into()),
            where_from: vec!["https://example.com/app.dmg".into()],
            others_quarantined: true,
            archive_app: None,
            volume: None,
        }
    }

    fn sev(f: &DownloadFacts) -> Severity {
        assess_download(f).unwrap().severity
    }

    #[test]
    fn notarized_developer_is_info() {
        let mut f = facts(
            "Claude.dmg",
            DownloadKind::DiskImage,
            SignatureKind::ThirdParty,
            true,
        );
        f.developer = Some("Anthropic PBC".into());
        let a = assess_download(&f).unwrap();
        assert_eq!(a.severity, Severity::Info);
        assert_eq!(a.kind, ActivityKind::Download);
        assert_eq!(
            a.summary,
            "Downloaded disk image Claude.dmg: signed by Anthropic PBC, notarized"
        );
        let d = a.detail.unwrap();
        assert!(
            d.contains("From https://example.com/app.dmg (via Safari)"),
            "{d}"
        );
        assert!(!d.contains("flag"), "{d}");
        assert_eq!(a.path.as_deref(), Some("/Users/me/Downloads/Claude.dmg"));
        assert!(a.signing.is_some());
    }

    #[test]
    fn signed_not_notarized_is_low() {
        let f = facts(
            "Tool.app",
            DownloadKind::App,
            SignatureKind::ThirdParty,
            false,
        );
        let a = assess_download(&f).unwrap();
        assert_eq!(a.severity, Severity::Low);
        assert!(a.summary.contains("signed by TEAM123, not notarized"));
    }

    #[test]
    fn apple_is_info() {
        let f = facts("Xcode.app", DownloadKind::App, SignatureKind::Apple, false);
        assert_eq!(sev(&f), Severity::Info);
    }

    #[test]
    fn unsigned_app_pkg_and_program_are_medium() {
        for (name, kind, sig) in [
            ("Tool.app", DownloadKind::App, SignatureKind::Unsigned),
            (
                "Setup.pkg",
                DownloadKind::Installer,
                SignatureKind::Unsigned,
            ),
            ("helper", DownloadKind::Executable, SignatureKind::AdHoc),
            ("Thing.app", DownloadKind::App, SignatureKind::Untrusted),
        ] {
            let a = assess_download(&facts(name, kind, sig, false)).unwrap();
            assert_eq!(a.severity, Severity::Medium, "{name}");
            assert!(a.advice.unwrap().contains("right-click → Open"));
        }
    }

    #[test]
    fn invalid_signature_is_high() {
        let f = facts("Tool.app", DownloadKind::App, SignatureKind::Invalid, false);
        let a = assess_download(&f).unwrap();
        assert_eq!(a.severity, Severity::High);
        assert!(a.summary.contains("broken signature"));
    }

    #[test]
    fn unsigned_lookalike_is_high() {
        for name in [
            "Zoom.app",
            "Google Chrome.dmg",
            "Ledger-Live-2.80.pkg",
            "1Password 8.dmg",
        ] {
            let kind = match name.rsplit('.').next() {
                Some("app") => DownloadKind::App,
                Some("pkg") => DownloadKind::Installer,
                _ => DownloadKind::DiskImage,
            };
            let a = assess_download(&facts(name, kind, SignatureKind::Unsigned, false)).unwrap();
            assert_eq!(a.severity, Severity::High, "{name}");
            assert!(a.summary.contains("looks like"), "{}", a.summary);
        }
        // Ad-hoc counts as unsigned too.
        let f = facts(
            "Telegram.app",
            DownloadKind::App,
            SignatureKind::AdHoc,
            false,
        );
        assert_eq!(sev(&f), Severity::High);
        // The real, signed thing is fine.
        let f = facts(
            "Zoom.pkg",
            DownloadKind::Installer,
            SignatureKind::ThirdParty,
            true,
        );
        assert_eq!(sev(&f), Severity::Info);
        // A lookalike name on a script is judged as a script.
        let f = facts(
            "zoom-fix.sh",
            DownloadKind::Script,
            SignatureKind::Unsigned,
            false,
        );
        assert_eq!(sev(&f), Severity::Low);
    }

    #[test]
    fn disk_images_scripts_and_archives() {
        let f = facts(
            "Tool.dmg",
            DownloadKind::DiskImage,
            SignatureKind::Unsigned,
            false,
        );
        assert_eq!(sev(&f), Severity::Low);
        let f = facts(
            "Install.command",
            DownloadKind::Script,
            SignatureKind::Unsigned,
            false,
        );
        assert_eq!(sev(&f), Severity::Medium);
        let f = facts(
            "setup.sh",
            DownloadKind::Script,
            SignatureKind::Unsigned,
            false,
        );
        assert_eq!(sev(&f), Severity::Low);
        let mut f = facts(
            "stuff.zip",
            DownloadKind::Archive,
            SignatureKind::Unsigned,
            false,
        );
        assert_eq!(sev(&f), Severity::Info);
        f.archive_app = Some("Stuff.app".into());
        assert_eq!(sev(&f), Severity::Low);
        // Only the unpacked app can tell whether it's the real one.
        f.name = "Zoom.zip".into();
        f.archive_app = Some("Zoom.app".into());
        assert_eq!(sev(&f), Severity::Low);
        let f = facts(
            "thing",
            DownloadKind::Executable,
            SignatureKind::Unknown,
            false,
        );
        assert_eq!(sev(&f), Severity::Low);
    }

    #[test]
    fn missing_quarantine_is_mentioned() {
        let mut f = facts(
            "Tool.app",
            DownloadKind::App,
            SignatureKind::Unsigned,
            false,
        );
        f.quarantined = false;
        f.quarantine_agent = None;
        let d = assess_download(&f).unwrap().detail.unwrap();
        assert!(d.contains("other downloads here do"), "{d}");
        f.others_quarantined = false;
        let d = assess_download(&f).unwrap().detail.unwrap();
        assert!(d.contains("copied or built yourself"), "{d}");
        // Not mentioned for files that are fine anyway.
        let mut f = facts("ls", DownloadKind::Executable, SignatureKind::Apple, false);
        f.quarantined = false;
        let d = assess_download(&f).unwrap().detail.unwrap();
        assert!(!d.contains("flag"), "{d}");
    }

    #[test]
    fn mounted_volume_wording() {
        let mut f = facts(
            "Zoom.app",
            DownloadKind::App,
            SignatureKind::ThirdParty,
            true,
        );
        f.volume = Some("/Volumes/Zoom".into());
        let a = assess_download(&f).unwrap();
        assert!(a.summary.starts_with("Disk image contains Zoom.app"));
        assert!(a.detail.unwrap().contains("/Volumes/Zoom"));
    }

    #[test]
    fn lookalike_names() {
        assert_eq!(mimicked_app("Google Chrome.dmg"), Some("Google Chrome"));
        assert_eq!(mimicked_app("zoomusInstallerFull.pkg"), Some("Zoom"));
        assert_eq!(mimicked_app("Ledger Live.app"), Some("Ledger Live"));
        assert_eq!(mimicked_app("Bambu_Studio.dmg"), None);
        assert_eq!(mimicked_app("Chromium.app"), None);
    }
}
