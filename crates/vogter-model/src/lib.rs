//! Shared data types for Vogter.
//!
//! Sensors fill a [`Snapshot`] with raw facts about the machine; the detection
//! layer turns a snapshot into [`Finding`]s. Everything here is plain data so it
//! can cross process boundaries (daemon -> app) as JSON.

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

impl Snapshot {
    pub fn process(&self, pid: i32) -> Option<&ProcessInfo> {
        self.processes.iter().find(|p| p.pid == pid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorError {
    pub sensor: String,
    pub message: String,
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
}
