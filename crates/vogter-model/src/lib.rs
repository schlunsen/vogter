//! Shared data types for Vogter.
//!
//! Sensors fill a [`Snapshot`] with raw facts about the machine; the detection
//! layer turns a snapshot into [`Finding`]s. Everything here is plain data so it
//! can cross process boundaries (daemon -> app) as JSON.

pub mod redact;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl Severity {
    /// One level less severe (Info stays Info).
    pub fn lower(self) -> Severity {
        match self {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low | Severity::Info => Severity::Info,
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unknown severity '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Something that can read keystrokes.
    Keylogger,
    /// Privacy permission (TCC) grants: camera, mic, screen, files...
    Privacy,
    Process,
    Persistence,
    Network,
    SystemHealth,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    /// Stable identifier of the check that produced this finding, e.g. `keylogger.event_tap`.
    pub check: String,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
    /// Where the fact came from (a permission database, a startup plist), so a
    /// failure to read that source doesn't make the finding look resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Finding {
    /// Identity across scans: the same problem on the same thing gets the same
    /// key, so we can tell "new" from "still there". PIDs are left out on purpose.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.check,
            self.path.as_deref().unwrap_or(""),
            self.title
        )
    }
}

// ---------------------------------------------------------------------------
// Code signing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    /// Signed by Apple (part of the OS or an Apple app).
    Apple,
    /// Signed with an Apple-issued developer certificate (Developer ID / App Store / Apple Development).
    ThirdParty,
    /// Ad-hoc signature: no identity at all. Normal for locally built binaries.
    AdHoc,
    /// Signed by a certificate that does not chain to Apple.
    Untrusted,
    Unsigned,
    /// Signature present but broken (binary modified after signing, revoked, ...).
    Invalid,
    /// We could not check (no permission, file vanished, ...).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signing {
    pub kind: SignatureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    pub notarized: bool,
}

impl Signing {
    pub fn unknown() -> Self {
        Signing {
            kind: SignatureKind::Unknown,
            identifier: None,
            team_id: None,
            notarized: false,
        }
    }

    pub fn is_apple(&self) -> bool {
        self.kind == SignatureKind::Apple
    }

    /// Unsigned, ad-hoc, untrusted or broken: nothing vouches for this code.
    pub fn is_weak(&self) -> bool {
        matches!(
            self.kind,
            SignatureKind::AdHoc
                | SignatureKind::Untrusted
                | SignatureKind::Unsigned
                | SignatureKind::Invalid
        )
    }

    pub fn describe(&self) -> String {
        let base = match self.kind {
            SignatureKind::Apple => "Apple".to_string(),
            SignatureKind::ThirdParty => match &self.team_id {
                Some(t) => format!(
                    "developer {t}{}",
                    if self.notarized {
                        ", notarized"
                    } else {
                        ", not notarized"
                    }
                ),
                None => "developer certificate".to_string(),
            },
            SignatureKind::AdHoc => "ad-hoc signed (no identity)".to_string(),
            SignatureKind::Untrusted => "signed by non-Apple certificate".to_string(),
            SignatureKind::Unsigned => "unsigned".to_string(),
            SignatureKind::Invalid => "INVALID signature".to_string(),
            SignatureKind::Unknown => "signature unknown".to_string(),
        };
        match &self.identifier {
            Some(id) => format!("{base} [{id}]"),
            None => base,
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot: raw facts gathered by sensors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// Unix timestamp (seconds).
    pub taken_at: u64,
    /// Whether the scan ran as root (root sees more).
    pub as_root: bool,
    pub processes: Vec<ProcessInfo>,
    pub event_taps: Vec<EventTap>,
    pub tcc_grants: Vec<TccGrant>,
    pub launch_items: Vec<LaunchItem>,
    pub cron_entries: Vec<CronEntry>,
    pub listeners: Vec<Listener>,
    pub health: Health,
    /// Sensors that failed or ran with reduced visibility.
    pub sensor_errors: Vec<SensorError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(check: &str, source: Option<&str>) -> Finding {
        Finding {
            severity: Severity::Low,
            category: Category::Persistence,
            check: check.into(),
            title: "t".into(),
            detail: "d".into(),
            pid: None,
            path: None,
            signing: None,
            source: source.map(str::to_string),
        }
    }

    #[test]
    fn sensor_error_scope() {
        let whole = SensorError {
            sensor: "process".into(),
            message: String::new(),
            covers: vec!["process.".into()],
            source: None,
        };
        assert!(whole.affects(&f("process.weak_signature", None)));
        assert!(!whole.affects(&f("tcc.camera", None)));

        let dir = SensorError {
            sensor: "launchd".into(),
            message: String::new(),
            covers: vec!["persistence.".into()],
            source: Some("/Users/me/Library/LaunchAgents".into()),
        };
        assert!(dir.affects(&f(
            "persistence.launch_item",
            Some("/Users/me/Library/LaunchAgents/x.plist")
        )));
        assert!(!dir.affects(&f(
            "persistence.launch_item",
            Some("/Library/LaunchDaemons/y.plist")
        )));
        // Prefix match is per path component, not per string.
        assert!(!dir.affects(&f(
            "persistence.launch_item",
            Some("/Users/me/Library/LaunchAgentsX/z.plist")
        )));
        assert!(!dir.affects(&f("persistence.cron", None)));
    }
}

impl Snapshot {
    pub fn process(&self, pid: i32) -> Option<&ProcessInfo> {
        self.processes.iter().find(|p| p.pid == pid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorError {
    pub sensor: String,
    pub message: String,
    /// Check-id prefixes whose findings this failure leaves unknown (e.g. `tcc.`).
    #[serde(default)]
    pub covers: Vec<String>,
    /// Only findings from this source (or under this path) are affected; all if `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl SensorError {
    /// Whether this failure means we can't tell if `f` still holds.
    pub fn affects(&self, f: &Finding) -> bool {
        self.covers.iter().any(|c| f.check.starts_with(c.as_str()))
            && match &self.source {
                None => true,
                Some(src) => f
                    .source
                    .as_deref()
                    .is_some_and(|fs| fs == src || fs.starts_with(&format!("{src}/"))),
            }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// False when the executable was deleted after launch (a classic malware trick).
    pub exe_exists: bool,
    pub signing: Signing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TapPoint {
    /// Where HID events enter the window server: sees everything, needs root or Input Monitoring.
    Hid,
    Session,
    AnnotatedSession,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTap {
    pub id: u32,
    pub tap_point: TapPoint,
    /// Listen-only taps can observe but not modify events — the typical keylogger shape.
    pub listen_only: bool,
    pub enabled: bool,
    pub events_of_interest: u64,
    /// Tap receives key down / key up / modifier events.
    pub keyboard: bool,
    pub tapping_pid: i32,
    /// 0 means "all processes" (a global tap).
    pub target_pid: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TccScope {
    System,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccGrant {
    pub scope: TccScope,
    /// Raw service name, e.g. `kTCCServiceListenEvent`.
    pub service: String,
    /// Bundle id or absolute path, depending on `client_is_path`.
    pub client: String,
    pub client_is_path: bool,
    /// auth_value: 0 denied, 2 allowed, 3 limited.
    pub allowed: bool,
    pub last_modified: i64,
    /// On-disk location of the client, if it could be resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchKind {
    /// /Library/LaunchDaemons — runs as root at boot.
    SystemDaemon,
    /// /Library/LaunchAgents — runs in every user session.
    SystemAgent,
    /// ~/Library/LaunchAgents — runs in this user's session.
    UserAgent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchItem {
    pub kind: LaunchKind,
    pub plist_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Program or ProgramArguments[0].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    pub arguments: Vec<String>,
    pub run_at_load: bool,
    pub keep_alive: bool,
    pub disabled: bool,
    pub program_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEntry {
    pub user: String,
    pub line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    pub pid: i32,
    pub process: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Health {
    pub sip_enabled: Option<bool>,
    pub gatekeeper_enabled: Option<bool>,
    pub filevault_enabled: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub xprotect_version: Option<String>,
    /// Remote Login (SSH) is accepting connections.
    pub remote_login: Option<bool>,
    /// Screen Sharing / Remote Management is accepting connections.
    pub screen_sharing: Option<bool>,
}

// ---------------------------------------------------------------------------
// History and live state (daemon)
// ---------------------------------------------------------------------------

/// A finding as tracked across scans by the daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredFinding {
    pub key: String,
    #[serde(flatten)]
    pub finding: Finding,
    /// Unix seconds.
    pub first_seen: u64,
    pub last_seen: u64,
    /// The user said "I know about this one".
    pub acknowledged: bool,
}

/// A process currently recording from an audio input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioClient {
    pub pid: i32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvState {
    pub microphone_in_use: bool,
    /// Who is using the microphone (macOS 14+).
    pub microphone_clients: Vec<AudioClient>,
    pub camera_in_use: bool,
}

// ---------------------------------------------------------------------------
// Live activity
// ---------------------------------------------------------------------------

/// A program that just started, with what we know about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecInfo {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub path: String,
    pub args: Vec<String>,
    pub signing: Signing,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_path: Option<String>,
}

impl ExecInfo {
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn command_line(&self) -> String {
        if self.args.is_empty() {
            self.path.clone()
        } else {
            self.args.join(" ")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    ProcessStarted,
    SensitiveFileRead,
    PersistenceChanged,
    PermissionChanged,
    Sudo,
    RemoteLogin,
    ScreenSharing,
    ScreenLocked,
    ScreenUnlocked,
    /// Apple's XProtect found malware.
    MalwareDetected,
    /// Summary of what happened while the screen was locked.
    AwaySummary,
}

/// Something that happened, as opposed to a [`Finding`] (a state that exists).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Activity {
    pub kind: ActivityKind,
    pub severity: Severity,
    pub summary: String,
    /// What this means and what to do about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advice: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
}

impl Activity {
    pub fn new(kind: ActivityKind, severity: Severity, summary: impl Into<String>) -> Self {
        Activity {
            kind,
            severity,
            summary: summary.into(),
            advice: None,
            detail: None,
            pid: None,
            process: None,
            path: None,
            signing: None,
        }
    }

    pub fn advice(mut self, a: impl Into<String>) -> Self {
        self.advice = Some(a.into());
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }

    pub fn from_exec(mut self, e: &ExecInfo) -> Self {
        self.pid = Some(e.pid);
        self.process = Some(e.name().to_string());
        self.path = Some(e.path.clone());
        self.signing = Some(e.signing.clone());
        self
    }
}

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

/// What a trust rule vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TrustSubject {
    /// Code signed by this developer (and, if given, with this identifier).
    /// The signature must be valid, so this can't be forged by a lookalike.
    Developer {
        team_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        identifier: Option<String>,
    },
    /// This exact file. With a hash, trust ends if the file's contents change.
    File {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        sha256: Option<String>,
    },
    /// One specific finding or activity, when there is nothing more distinctive
    /// to trust (e.g. an Apple tool running a script).
    Exact { key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRule {
    pub id: i64,
    /// A check id (`keylogger.event_tap`, `activity.process_started`) or `*` for all.
    pub check: String,
    pub subject: TrustSubject,
    /// Human description, e.g. "Raycast (developer SY64MV22J9)".
    pub label: String,
    pub created_at: u64,
}

impl Activity {
    /// Check id used by trust rules for activities.
    pub fn check(&self) -> String {
        let kind = serde_json::to_value(self.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        format!("activity.{kind}")
    }

    /// Identity for repeat suppression and exact trust.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.check(),
            self.summary,
            self.path.as_deref().unwrap_or("")
        )
    }
}
