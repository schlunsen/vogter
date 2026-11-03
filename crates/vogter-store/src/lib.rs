//! Durable history: which findings are active, when they were first seen,
//! which the user acknowledged, and a log of events.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use vogter_ipc::{Event, LoggedEvent};
use vogter_model::{Finding, Severity, StoredFinding, TrustRule, TrustSubject};

pub type Result<T> = rusqlite::Result<T>;

pub struct Store {
    conn: Connection,
}

/// What changed in a scan compared to the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHistory {
    pub first_seen: u64,
    pub runs: u64,
}

#[derive(Debug, Default)]
pub struct ScanDiff {
    pub new: Vec<StoredFinding>,
    pub resolved: Vec<StoredFinding>,
    /// First scan ever recorded.
    pub baseline: bool,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS findings (
    key          TEXT PRIMARY KEY,
    severity     INTEGER NOT NULL,
    data         TEXT NOT NULL,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    resolved_at  INTEGER,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scans (
    id       INTEGER PRIMARY KEY,
    at       INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    new      INTEGER NOT NULL,
    resolved INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id   INTEGER PRIMARY KEY,
    at   INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trust (
    id         INTEGER PRIMARY KEY,
    check_id   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    label      TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS programs (
    identity   TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    runs       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('created_at', ?1)",
            [now.to_string()],
        )?;
        Ok(Store { conn })
    }

    /// When this database was first created (start of the learning period).
    pub fn created_at(&self) -> Result<u64> {
        let v: String =
            self.conn
                .query_row("SELECT value FROM meta WHERE key = 'created_at'", [], |r| {
                    r.get(0)
                })?;
        Ok(v.parse().unwrap_or(0))
    }

    /// Raw connection, for tests in other crates.
    #[doc(hidden)]
    pub fn conn_for_tests(&self) -> &Connection {
        &self.conn
    }

    #[cfg(test)]
    fn set_created_at(&self, at: u64) {
        self.conn
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'created_at'",
                [at.to_string()],
            )
            .unwrap();
    }

    // ---- trust ------------------------------------------------------------

    pub fn add_trust(
        &self,
        check: &str,
        subject: &TrustSubject,
        label: &str,
        at: u64,
    ) -> Result<TrustRule> {
        let data = serde_json::to_string(subject).expect("subject serializes");
        self.conn.execute(
            "INSERT INTO trust (check_id, subject, label, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![check, data, label, at],
        )?;
        Ok(TrustRule {
            id: self.conn.last_insert_rowid(),
            check: check.into(),
            subject: subject.clone(),
            label: label.into(),
            created_at: at,
        })
    }

    pub fn trust_rules(&self) -> Result<Vec<TrustRule>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, check_id, subject, label, created_at FROM trust ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            let data: String = r.get(2)?;
            let subject = serde_json::from_str(&data).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, e.into())
            })?;
            Ok(TrustRule {
                id: r.get(0)?,
                check: r.get(1)?,
                subject,
                label: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Returns false if there was no such rule.
    pub fn remove_trust(&self, id: i64) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM trust WHERE id = ?1", [id])? > 0)
    }

    // ---- program familiarity ---------------------------------------------

    /// Record a run of a program; returns what was known *before* this run.
    pub fn record_program(
        &self,
        identity: &str,
        label: &str,
        at: u64,
    ) -> Result<Option<ProgramHistory>> {
        let prior = self
            .conn
            .query_row(
                "SELECT first_seen, runs FROM programs WHERE identity = ?1",
                [identity],
                |r| {
                    Ok(ProgramHistory {
                        first_seen: r.get(0)?,
                        runs: r.get(1)?,
                    })
                },
            )
            .optional()?;
        self.conn.execute(
            "INSERT INTO programs (identity, label, first_seen, last_seen, runs) VALUES (?1, ?2, ?3, ?3, 1)
             ON CONFLICT(identity) DO UPDATE SET last_seen = ?3, runs = runs + 1, label = ?2",
            params![identity, label, at],
        )?;
        Ok(prior)
    }

    /// A stored finding by key (active or not).
    pub fn finding(&self, key: &str) -> Result<Option<StoredFinding>> {
        load(&self.conn, key)
    }

    pub fn event(&self, id: i64) -> Result<Option<LoggedEvent>> {
        self.conn
            .query_row("SELECT id, at, data FROM events WHERE id = ?1", [id], |r| {
                let data: String = r.get(2)?;
                let event = serde_json::from_str(&data).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        e.into(),
                    )
                })?;
                Ok(LoggedEvent {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    event,
                })
            })
            .optional()
    }

    /// Merge one scan's findings into history and report the differences.
    pub fn record_scan(&mut self, at: u64, findings: &[Finding]) -> Result<ScanDiff> {
        let tx = self.conn.transaction()?;
        let baseline = tx.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get::<_, i64>(0))? == 0;

        // Findings active before this scan.
        let mut active: HashSet<String> = {
            let mut stmt = tx.prepare("SELECT key FROM findings WHERE resolved_at IS NULL")?;
            stmt.query_map([], |r| r.get(0))?.collect::<Result<_>>()?
        };

        let mut diff = ScanDiff {
            baseline,
            ..Default::default()
        };
        let mut seen = HashSet::new();
        for f in findings {
            let key = f.key();
            if !seen.insert(key.clone()) {
                continue;
            }
            let data = serde_json::to_string(f).expect("finding serializes");
            if active.remove(&key) {
                tx.execute(
                    "UPDATE findings SET severity = ?2, data = ?3, last_seen = ?4 WHERE key = ?1",
                    params![key, severity_rank(f.severity), data, at],
                )?;
            } else {
                // Brand new, or came back after being resolved: either way it's news.
                tx.execute(
                    "INSERT INTO findings (key, severity, data, first_seen, last_seen, resolved_at, acknowledged)
                     VALUES (?1, ?2, ?3, ?4, ?4, NULL, 0)
                     ON CONFLICT(key) DO UPDATE SET severity = ?2, data = ?3, first_seen = ?4,
                         last_seen = ?4, resolved_at = NULL, acknowledged = 0",
                    params![key, severity_rank(f.severity), data, at],
                )?;
                diff.new.push(StoredFinding {
                    key,
                    finding: f.clone(),
                    first_seen: at,
                    last_seen: at,
                    acknowledged: false,
                });
            }
        }

        // Whatever is left in `active` disappeared in this scan.
        for key in active {
            tx.execute(
                "UPDATE findings SET resolved_at = ?2 WHERE key = ?1",
                params![key, at],
            )?;
            if let Some(sf) = load(&tx, &key)? {
                diff.resolved.push(sf);
            }
        }

        tx.execute(
            "INSERT INTO scans (at, findings, new, resolved) VALUES (?1, ?2, ?3, ?4)",
            params![
                at,
                seen.len() as i64,
                diff.new.len() as i64,
                diff.resolved.len() as i64
            ],
        )?;
        tx.commit()?;
        Ok(diff)
    }

    /// Active findings, most severe first.
    pub fn active(&self, include_acknowledged: bool) -> Result<Vec<StoredFinding>> {
        let mut stmt = self.conn.prepare(
            "SELECT key, data, first_seen, last_seen, acknowledged FROM findings
             WHERE resolved_at IS NULL AND (?1 OR acknowledged = 0)
             ORDER BY severity DESC, first_seen DESC",
        )?;
        let rows = stmt.query_map([include_acknowledged], row_to_stored)?;
        rows.collect()
    }

    /// Returns false if no active finding has this key.
    pub fn acknowledge(&self, key: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE findings SET acknowledged = 1 WHERE key = ?1 AND resolved_at IS NULL",
            [key],
        )?;
        Ok(n > 0)
    }

    pub fn last_scan(&self) -> Result<Option<u64>> {
        self.conn
            .query_row("SELECT MAX(at) FROM scans", [], |r| r.get(0))
    }

    pub fn log_event(&self, at: u64, event: Event) -> Result<LoggedEvent> {
        let data = serde_json::to_string(&event).expect("event serializes");
        self.conn.execute(
            "INSERT INTO events (at, data) VALUES (?1, ?2)",
            params![at, data],
        )?;
        Ok(LoggedEvent {
            id: self.conn.last_insert_rowid(),
            at,
            event,
        })
    }

    /// Newest first.
    pub fn recent_events(&self, limit: u32) -> Result<Vec<LoggedEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, at, data FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit], |r| {
            let data: String = r.get(2)?;
            let event = serde_json::from_str(&data).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, e.into())
            })?;
            Ok(LoggedEvent {
                id: r.get(0)?,
                at: r.get(1)?,
                event,
            })
        })?;
        rows.collect()
    }
}

fn load(conn: &Connection, key: &str) -> Result<Option<StoredFinding>> {
    conn.query_row(
        "SELECT key, data, first_seen, last_seen, acknowledged FROM findings WHERE key = ?1",
        [key],
        row_to_stored,
    )
    .optional()
}

fn row_to_stored(r: &rusqlite::Row) -> Result<StoredFinding> {
    let data: String = r.get(1)?;
    let finding = serde_json::from_str(&data).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, e.into())
    })?;
    Ok(StoredFinding {
        key: r.get(0)?,
        finding,
        first_seen: r.get(2)?,
        last_seen: r.get(3)?,
        acknowledged: r.get(4)?,
    })
}

fn severity_rank(s: Severity) -> i64 {
    s as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_model::Category;

    fn finding(title: &str) -> Finding {
        Finding {
            severity: Severity::High,
            category: Category::Keylogger,
            check: "keylogger.event_tap".into(),
            title: title.into(),
            detail: "d".into(),
            pid: Some(1),
            path: Some("/x".into()),
            signing: None,
        }
    }

    #[test]
    fn tracks_new_and_resolved() {
        let mut s = Store::in_memory().unwrap();
        let d = s.record_scan(1, &[finding("a"), finding("b")]).unwrap();
        assert!(d.baseline);
        assert_eq!(d.new.len(), 2);

        let d = s.record_scan(2, &[finding("b"), finding("c")]).unwrap();
        assert!(!d.baseline);
        assert_eq!(
            d.new
                .iter()
                .map(|f| f.finding.title.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        assert_eq!(
            d.resolved
                .iter()
                .map(|f| f.finding.title.as_str())
                .collect::<Vec<_>>(),
            ["a"]
        );

        let active = s.active(false).unwrap();
        assert_eq!(active.len(), 2);
        let b = active.iter().find(|f| f.finding.title == "b").unwrap();
        assert_eq!((b.first_seen, b.last_seen), (1, 2));
    }

    #[test]
    fn acknowledge_hides_until_it_comes_back() {
        let mut s = Store::in_memory().unwrap();
        s.record_scan(1, &[finding("a")]).unwrap();
        let key = finding("a").key();
        assert!(s.acknowledge(&key).unwrap());
        assert!(s.active(false).unwrap().is_empty());
        assert_eq!(s.active(true).unwrap().len(), 1);

        // Still there next scan: stays acknowledged.
        assert!(s.record_scan(2, &[finding("a")]).unwrap().new.is_empty());
        assert!(s.active(false).unwrap().is_empty());

        // Goes away, then returns: it's news again.
        s.record_scan(3, &[]).unwrap();
        let d = s.record_scan(4, &[finding("a")]).unwrap();
        assert_eq!(d.new.len(), 1);
        assert_eq!(s.active(false).unwrap().len(), 1);
    }

    #[test]
    fn trust_rules_round_trip() {
        let s = Store::in_memory().unwrap();
        let subject = TrustSubject::Developer {
            team_id: "T".into(),
            identifier: None,
        };
        let r = s
            .add_trust("keylogger.event_tap", &subject, "App (developer T)", 9)
            .unwrap();
        assert_eq!(s.trust_rules().unwrap(), vec![r.clone()]);
        assert!(s.remove_trust(r.id).unwrap());
        assert!(!s.remove_trust(r.id).unwrap());
        assert!(s.trust_rules().unwrap().is_empty());
    }

    #[test]
    fn program_history() {
        let s = Store::in_memory().unwrap();
        assert_eq!(s.record_program("path:/x", "x", 10).unwrap(), None);
        assert_eq!(
            s.record_program("path:/x", "x", 20).unwrap(),
            Some(ProgramHistory {
                first_seen: 10,
                runs: 1
            })
        );
        assert_eq!(
            s.record_program("path:/x", "x", 30).unwrap(),
            Some(ProgramHistory {
                first_seen: 10,
                runs: 2
            })
        );
        s.set_created_at(5);
        assert_eq!(s.created_at().unwrap(), 5);
    }

    #[test]
    fn events_round_trip() {
        let s = Store::in_memory().unwrap();
        s.log_event(5, Event::CameraOn).unwrap();
        s.log_event(6, Event::CameraOff).unwrap();
        let ev = s.recent_events(10).unwrap();
        assert_eq!(ev[0].event, Event::CameraOff);
        assert_eq!(ev[1].at, 5);
    }
}
