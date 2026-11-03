//! Facts about a file that just landed in Downloads (or on a freshly mounted
//! disk image). Gathered by `vogter-sensors::downloads`, judged by
//! `vogter-detect::downloads`.

use serde::{Deserialize, Serialize};

use crate::Signing;

/// What kind of runnable thing a download is. Ordinary documents aren't assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadKind {
    /// An `.app` bundle.
    App,
    /// A `.dmg` disk image.
    DiskImage,
    /// A `.pkg` / `.mpkg` installer.
    Installer,
    /// A bare Mach-O program.
    Executable,
    /// A shell/AppleScript file (`.command`, `.sh`, `.scpt`, `#!…`).
    Script,
    /// A `.zip` (not unpacked).
    Archive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DownloadFacts {
    pub path: String,
    /// File name, e.g. `Zoom.dmg`.
    pub name: String,
    pub kind: DownloadKind,
    /// Code signature. For installers it comes from `pkgutil`; `notarized`
    /// also reflects Gatekeeper's (`spctl`) verdict when that was available.
    pub signing: Signing,
    /// Developer name from the certificate, e.g. "Anthropic PBC".
    pub developer: Option<String>,
    /// Has the `com.apple.quarantine` ("downloaded from the internet") flag.
    pub quarantined: bool,
    /// App that downloaded it, from the quarantine flag (e.g. "Safari").
    pub quarantine_agent: Option<String>,
    /// Download origin (`kMDItemWhereFroms`), secrets already removed.
    pub where_from: Vec<String>,
    /// Other recent files in the same folder carry the quarantine flag
    /// (so a missing one on this file stands out).
    pub others_quarantined: bool,
    /// For archives: the name of an `.app` inside, if one was listed.
    pub archive_app: Option<String>,
    /// Found at the top of a newly mounted volume (e.g. `/Volumes/Zoom`).
    pub volume: Option<String>,
}
