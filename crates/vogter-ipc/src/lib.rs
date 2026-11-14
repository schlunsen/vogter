//! Wire protocol between `vogterd` and its clients (the menu bar app, the CLI).
//!
//! Newline-delimited JSON over a Unix socket. Every object carries a `type`
//! tag. Clients send [`Request`]s; the daemon answers each with one
//! [`Message`], and after `subscribe` also pushes [`Message::Event`]s.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vogter_model::{AvState, Severity, Signing, StoredFinding};

pub const PROTOCOL_VERSION: u32 = 1;

/// Longest note a user can put on an event, in characters.
pub const MAX_NOTE_CHARS: usize = 2000;

/// Socket used by a root daemon.
pub const SYSTEM_SOCKET: &str = "/var/run/vogter.sock";

/// Socket used by a daemon running as a normal user (development).
pub fn user_socket() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library/Application Support/Vogter/vogter.sock"))
}

/// Where clients should look, in order.
pub fn socket_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(p) = std::env::var_os("VOGTER_SOCKET") {
        v.push(PathBuf::from(p));
    }
    v.push(PathBuf::from(SYSTEM_SOCKET));
    v.extend(user_socket());
    v
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Status,
    Findings {
        #[serde(default)]
        include_acknowledged: bool,
    },
    Events {
        #[serde(default = "default_limit")]
        limit: u32,
    },
    ScanNow,
    Acknowledge {
        key: String,
    },
    /// Start receiving pushed events on this connection.
    Subscribe,
    /// Trust whatever a finding (by key) or activity event (by id) is about.
    Trust {
        #[serde(default)]
        finding_key: Option<String>,
        #[serde(default)]
        event_id: Option<i64>,
        /// Trust it for every check, not just the one that fired.
        #[serde(default)]
        all_checks: bool,
    },
    TrustRules,
    Untrust {
        id: i64,
    },
    /// Logged events matching a query, newest first, one page at a time.
    History(HistoryQuery),
    /// Event counts per local calendar day, for a calendar or sparkline.
    HistoryDays {
        #[serde(default)]
        since: Option<u64>,
        #[serde(default)]
        until: Option<u64>,
    },
    /// Findings including resolved ones, most recently seen first.
    FindingHistory(HistoryQuery),
    /// Screen locked -> unlocked intervals overlapping a time range.
    AwayPeriods {
        #[serde(default)]
        since: Option<u64>,
        #[serde(default)]
        until: Option<u64>,
    },
    /// Everything known about one program: familiarity, signature, findings, alerts.
    ProgramProfile {
        path: String,
    },
    /// What appeared and went away since a moment.
    ChangesSince {
        since: u64,
        /// Findings below this are left out [default: low].
        #[serde(default)]
        min_severity: Option<Severity>,
    },
    /// Set (or, when empty, clear) the note on an event.
    Annotate {
        event_id: i64,
        note: String,
    },
    SetReviewed {
        event_id: i64,
        reviewed: bool,
    },
}

/// Filters shared by `history` and `finding_history`. Every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryQuery {
    /// Unix seconds, inclusive.
    pub since: Option<u64>,
    /// Unix seconds, exclusive.
    pub until: Option<u64>,
    /// Cursor: only events with a smaller id (`next_before_id` of the previous page).
    pub before_id: Option<i64>,
    /// Page size [default 100, at most 500]. For `finding_history`, also see `offset`.
    pub limit: Option<u32>,
    /// `finding_history` only: skip this many (findings have no numeric id).
    pub offset: Option<u32>,
    /// Lowest severity; events without one (scans, mic on/off) count as info.
    pub min_severity: Option<Severity>,
    /// Match any of these: an event kind (`new_finding`, `microphone_on`), an
    /// activity kind (`sudo`, `process_started`) or a finding category (`persistence`).
    pub kinds: Vec<String>,
    /// Case-insensitive text in the summary, title, detail, process or path.
    pub search: Option<String>,
    /// Only events or findings about the program at this path.
    pub program: Option<String>,
    /// Only events not yet marked reviewed.
    pub unreviewed_only: bool,
    /// `finding_history` only: leave out findings that are still active.
    pub resolved_only: bool,
    /// Echoed back in the reply, so a client can drop answers to old queries.
    pub token: Option<u64>,
}

/// One local calendar day of history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaySummary {
    /// `YYYY-MM-DD` in the daemon's local time zone.
    pub day: String,
    /// Unix seconds of that day's local midnight.
    pub start: u64,
    /// All events that day.
    pub events: u32,
    /// Events per severity: [info, low, medium, high, critical]. Events without
    /// a severity (scans, mic and camera) count as info.
    pub counts: [u32; 5],
}

/// The screen was locked from `from` until `until` (None: not unlocked yet).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AwayPeriod {
    pub from: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// How familiar a program is on this Mac (the store's `programs` table).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgramRecord {
    /// `team:<team id>:<identifier>` for developer-signed code, else `path:<path>`.
    pub identity: String,
    pub label: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub runs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgramProfile {
    pub path: String,
    pub name: String,
    /// Still on disk.
    pub exists: bool,
    /// Its signature now (or as last recorded, if it's gone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
    /// None if Vogter has never seen it start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub familiarity: Option<ProgramRecord>,
    /// Active findings about it: permissions, startup items, keyboard taps, listeners.
    pub findings: Vec<StoredFinding>,
    /// Findings about it that went away.
    pub past_findings: Vec<StoredFinding>,
    /// Its most recent events (up to 50), newest first.
    pub events: Vec<LoggedEvent>,
    /// All its events still in history.
    pub event_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Changes {
    pub since: u64,
    /// Findings that appeared since then (some may have gone again).
    pub new_findings: Vec<StoredFinding>,
    /// Findings that went away since then.
    pub resolved_findings: Vec<StoredFinding>,
    /// Programs that ran here for the first time.
    pub new_programs: Vec<ProgramRecord>,
}

fn default_limit() -> u32 {
    100
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Status(Status),
    Findings {
        findings: Vec<StoredFinding>,
    },
    Events {
        events: Vec<LoggedEvent>,
    },
    Trusted {
        rule: vogter_model::TrustRule,
    },
    TrustRules {
        rules: Vec<vogter_model::TrustRule>,
    },
    Ok,
    Error {
        message: String,
    },
    Event(LoggedEvent),
    History {
        events: Vec<LoggedEvent>,
        /// Pass as `before_id` for the next (older) page; None at the end.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_before_id: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<u64>,
    },
    HistoryDays {
        days: Vec<DaySummary>,
    },
    FindingHistory {
        findings: Vec<StoredFinding>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<u64>,
    },
    AwayPeriods {
        periods: Vec<AwayPeriod>,
    },
    ProgramProfile(ProgramProfile),
    Changes(Changes),
    /// An event's note and review state after `annotate` / `set_reviewed`.
    Annotation {
        event_id: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reviewed_at: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub protocol: u32,
    pub version: String,
    pub as_root: bool,
    pub scanning: bool,
    /// Unix seconds of the last completed scan.
    pub last_scan: Option<u64>,
    pub scan_interval_secs: u64,
    /// Unacknowledged active findings per severity: [info, low, medium, high, critical].
    pub open_counts: [u32; 5],
    pub av: AvState,
    /// Sensors with reduced visibility in the last scan.
    pub sensor_errors: Vec<String>,
    pub realtime: Realtime,
    /// Until then, first runs of programs are learned silently (Unix seconds).
    pub learning_until: u64,
    pub trust_rules: u32,
}

/// Which live sources are running.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Realtime {
    pub endpoint_security: bool,
    /// Why Endpoint Security is off, when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_security_error: Option<String>,
    /// Names of active watchers, e.g. `process_poll`, `fs_events`.
    pub sources: Vec<String>,
}

/// Something that happened, with its time and a database id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggedEvent {
    pub id: i64,
    /// Unix seconds.
    pub at: u64,
    #[serde(flatten)]
    pub event: Event,
    /// The user's note on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When the user marked it reviewed (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<u64>,
}

impl LoggedEvent {
    pub fn new(id: i64, at: u64, event: Event) -> Self {
        LoggedEvent {
            id,
            at,
            event,
            note: None,
            reviewed_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// `baseline` is true for the very first scan: everything is "new", so don't alarm.
    ScanCompleted {
        findings: u32,
        new: u32,
        resolved: u32,
        baseline: bool,
    },
    NewFinding {
        finding: StoredFinding,
    },
    Resolved {
        key: String,
        title: String,
    },
    /// Something happened: a suspicious program started, a secret was read, sudo was used...
    Activity {
        activity: vogter_model::Activity,
    },
    MicrophoneOn {
        clients: Vec<vogter_model::AudioClient>,
    },
    MicrophoneOff,
    CameraOn,
    CameraOff,
}

pub fn write_line<T: Serialize>(w: &mut impl Write, value: &T) -> io::Result<()> {
    let mut buf = serde_json::to_vec(value)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// Read one JSON line. `Ok(None)` on clean EOF.
pub fn read_line<T: for<'de> Deserialize<'de>>(r: &mut impl BufRead) -> io::Result<Option<T>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    serde_json::from_str(line.trim_end())
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format() {
        let r: Request = serde_json::from_str(r#"{"type":"acknowledge","key":"k"}"#).unwrap();
        assert_eq!(r, Request::Acknowledge { key: "k".into() });
        let r: Request = serde_json::from_str(r#"{"type":"findings"}"#).unwrap();
        assert_eq!(
            r,
            Request::Findings {
                include_acknowledged: false
            }
        );
    }

    #[test]
    fn event_wire_format() {
        let m = Message::Event(LoggedEvent::new(7, 1, Event::CameraOn));
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"type":"event","id":7,"at":1,"kind":"camera_on"}"#
        );
    }

    #[test]
    fn history_wire_format() {
        let r: Request = serde_json::from_str(
            r#"{"type":"history","since":10,"min_severity":"medium","kinds":["sudo"],"token":3}"#,
        )
        .unwrap();
        assert_eq!(
            r,
            Request::History(HistoryQuery {
                since: Some(10),
                min_severity: Some(Severity::Medium),
                kinds: vec!["sudo".into()],
                token: Some(3),
                ..Default::default()
            })
        );
        let r: Request = serde_json::from_str(r#"{"type":"finding_history"}"#).unwrap();
        assert_eq!(r, Request::FindingHistory(HistoryQuery::default()));
        let r: Request =
            serde_json::from_str(r#"{"type":"set_reviewed","event_id":4,"reviewed":true}"#)
                .unwrap();
        assert_eq!(
            r,
            Request::SetReviewed {
                event_id: 4,
                reviewed: true
            }
        );

        let mut e = LoggedEvent::new(7, 1, Event::CameraOn);
        e.note = Some("my webcam test".into());
        e.reviewed_at = Some(5);
        let m = Message::History {
            events: vec![e],
            next_before_id: Some(7),
            token: None,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            json,
            r#"{"type":"history","events":[{"id":7,"at":1,"kind":"camera_on","note":"my webcam test","reviewed_at":5}],"next_before_id":7}"#
        );
        assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), m);
    }
}
