//! Wire protocol between `vogterd` and its clients (the menu bar app, the CLI).
//!
//! Newline-delimited JSON over a Unix socket. Every object carries a `type`
//! tag. Clients send [`Request`]s; the daemon answers each with one
//! [`Message`], and after `subscribe` also pushes [`Message::Event`]s.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vogter_model::{AvState, StoredFinding};

pub const PROTOCOL_VERSION: u32 = 1;

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
}

fn default_limit() -> u32 {
    100
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Status(Status),
    Findings { findings: Vec<StoredFinding> },
    Events { events: Vec<LoggedEvent> },
    Trusted { rule: vogter_model::TrustRule },
    TrustRules { rules: Vec<vogter_model::TrustRule> },
    Ok,
    Error { message: String },
    Event(LoggedEvent),
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
        let m = Message::Event(LoggedEvent {
            id: 7,
            at: 1,
            event: Event::CameraOn,
        });
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            r#"{"type":"event","id":7,"at":1,"kind":"camera_on"}"#
        );
    }
}
