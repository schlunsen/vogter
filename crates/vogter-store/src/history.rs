//! Looking back: history queries over the event log and findings, day
//! summaries, away periods, notes and review marks, and retention.
//!
//! Events are stored as JSON (`events.data`), so filters use SQLite's JSON
//! functions; the expressions used for filtering by program and by activity
//! kind have their own indexes.
//!
//! Day boundaries are computed by SQLite's `localtime` modifier, i.e. in the
//! time zone of the process that opens the store (the daemon). Each
//! [`DaySummary`] carries the day's local midnight as Unix seconds, so a
//! client never has to guess.

use rusqlite::types::Value;
use rusqlite::{OptionalExtension, Row, params, params_from_iter};
use vogter_ipc::{AwayPeriod, Changes, DaySummary, HistoryQuery, LoggedEvent, ProgramRecord};
use vogter_model::{Severity, StoredFinding};

use crate::{Result, Store, row_to_stored};

const DAY: u64 = 86_400;
/// Info-level events (and events without a severity: scans, mic/camera,
/// lock/unlock) are kept this long...
pub const INFO_EVENT_RETENTION_SECS: u64 = 90 * DAY;
/// ...everything else this long.
pub const EVENT_RETENTION_SECS: u64 = 365 * DAY;
/// Findings that went away are forgotten this long after they did. Active
/// findings, trust rules and program familiarity are never removed.
pub const RESOLVED_FINDING_RETENTION_SECS: u64 = 365 * DAY;
/// Scan records (the latest one is always kept: it marks the baseline as done).
pub const SCAN_RETENTION_SECS: u64 = 365 * DAY;

const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 500;

/// Indexes and tables added for history. Idempotent, applied on every open.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS event_notes (
    event_id    INTEGER PRIMARY KEY,
    note        TEXT,
    reviewed_at INTEGER,
    updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_at ON events(at);
CREATE INDEX IF NOT EXISTS events_path ON events(
    coalesce(json_extract(data, '$.activity.path'), json_extract(data, '$.finding.path')));
CREATE INDEX IF NOT EXISTS events_activity_kind ON events(json_extract(data, '$.activity.kind'));
CREATE INDEX IF NOT EXISTS findings_resolved_at ON findings(resolved_at);
CREATE INDEX IF NOT EXISTS findings_first_seen ON findings(first_seen);
CREATE INDEX IF NOT EXISTS programs_first_seen ON programs(first_seen);
CREATE INDEX IF NOT EXISTS scans_at ON scans(at);
";

/// Must match the `events_path` index expression exactly.
const EVENT_PATH: &str =
    "coalesce(json_extract(data, '$.activity.path'), json_extract(data, '$.finding.path'))";
/// Must match the `events_activity_kind` index expression exactly.
const ACTIVITY_KIND: &str = "json_extract(data, '$.activity.kind')";
/// Severity rank of an event; events without one count as info (0).
const EVENT_SEVERITY: &str = "(CASE coalesce(json_extract(data, '$.activity.severity'), \
     json_extract(data, '$.finding.severity')) \
     WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 ELSE 0 END)";
const EVENT_TEXT: &str = "lower(coalesce(json_extract(data, '$.activity.summary'), '') || char(10) || \
     coalesce(json_extract(data, '$.activity.detail'), '') || char(10) || \
     coalesce(json_extract(data, '$.activity.process'), '') || char(10) || \
     coalesce(json_extract(data, '$.activity.path'), '') || char(10) || \
     coalesce(json_extract(data, '$.finding.title'), '') || char(10) || \
     coalesce(json_extract(data, '$.finding.detail'), '') || char(10) || \
     coalesce(json_extract(data, '$.finding.path'), '') || char(10) || \
     coalesce(json_extract(data, '$.title'), ''))";

/// Columns for [`row_to_event`].
pub(crate) const EVENT_SELECT: &str = "SELECT events.id, events.at, events.data, n.note, n.reviewed_at \
     FROM events LEFT JOIN event_notes n ON n.event_id = events.id";

const FINDING_SELECT: &str =
    "SELECT key, data, first_seen, last_seen, acknowledged, resolved_at FROM findings";

pub(crate) fn row_to_event(r: &Row) -> Result<LoggedEvent> {
    let data: String = r.get(2)?;
    let event = serde_json::from_str(&data).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, e.into())
    })?;
    let mut e = LoggedEvent::new(r.get(0)?, r.get(1)?, event);
    e.note = r.get(3)?;
    e.reviewed_at = r.get(4)?;
    Ok(e)
}

fn row_to_program(r: &Row) -> Result<ProgramRecord> {
    Ok(ProgramRecord {
        identity: r.get(0)?,
        label: r.get(1)?,
        first_seen: r.get(2)?,
        last_seen: r.get(3)?,
        runs: r.get(4)?,
    })
}

/// A WHERE clause under construction, with its positional parameters.
#[derive(Default)]
struct Where {
    clauses: Vec<String>,
    params: Vec<Value>,
}

impl Where {
    fn add(&mut self, clause: impl Into<String>, params: impl IntoIterator<Item = Value>) {
        self.clauses.push(clause.into());
        self.params.extend(params);
    }

    fn sql(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.clauses.join(" AND "))
        }
    }
}

fn int(v: u64) -> Value {
    Value::Integer(v.min(i64::MAX as u64) as i64)
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

/// The search text, lowercased, or None if blank.
fn needle(q: &HistoryQuery) -> Option<String> {
    q.search
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
}

fn limit(q: &HistoryQuery) -> u32 {
    q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

/// What a cleanup removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cleanup {
    pub events: usize,
    pub findings: usize,
    pub scans: usize,
    pub notes: usize,
}

impl Store {
    /// One page of events matching `q`, newest first, and the cursor for the
    /// next (older) page if there is one.
    pub fn history(&self, q: &HistoryQuery) -> Result<(Vec<LoggedEvent>, Option<i64>)> {
        let mut w = Where::default();
        if let Some(since) = q.since {
            w.add("events.at >= ?", [int(since)]);
        }
        if let Some(until) = q.until {
            w.add("events.at < ?", [int(until)]);
        }
        if let Some(before) = q.before_id {
            w.add("events.id < ?", [Value::Integer(before)]);
        }
        if let Some(min) = q.min_severity.filter(|&s| s > Severity::Info) {
            w.add(
                format!("{EVENT_SEVERITY} >= ?"),
                [Value::Integer(min as i64)],
            );
        }
        if !q.kinds.is_empty() {
            let kinds = text(&serde_json::to_string(&q.kinds).expect("strings serialize"));
            w.add(
                format!(
                    "(json_extract(data, '$.kind') IN (SELECT value FROM json_each(?)) \
                     OR {ACTIVITY_KIND} IN (SELECT value FROM json_each(?)) \
                     OR json_extract(data, '$.finding.category') IN (SELECT value FROM json_each(?)))"
                ),
                [kinds.clone(), kinds.clone(), kinds],
            );
        }
        if let Some(s) = needle(q) {
            w.add(format!("instr({EVENT_TEXT}, ?) > 0"), [Value::Text(s)]);
        }
        if let Some(p) = &q.program {
            w.add(format!("{EVENT_PATH} = ?"), [text(p)]);
        }
        if q.unreviewed_only {
            w.add("n.reviewed_at IS NULL", []);
        }
        let limit = limit(q);
        let sql = format!(
            "{EVENT_SELECT}{} ORDER BY events.id DESC LIMIT {}",
            w.sql(),
            limit + 1
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut events = stmt
            .query_map(params_from_iter(w.params.iter()), row_to_event)?
            .collect::<Result<Vec<_>>>()?;
        let next = if events.len() > limit as usize {
            events.truncate(limit as usize);
            events.last().map(|e| e.id)
        } else {
            None
        };
        Ok((events, next))
    }

    /// All events about the program at `path` still in history.
    pub fn program_event_count(&self, path: &str) -> Result<u32> {
        self.conn.query_row(
            &format!("SELECT COUNT(*) FROM events WHERE {EVENT_PATH} = ?1"),
            [path],
            |r| r.get(0),
        )
    }

    /// Events per local calendar day in `[since, until)`, oldest first. Days
    /// without events are left out.
    pub fn day_summaries(&self, since: Option<u64>, until: Option<u64>) -> Result<Vec<DaySummary>> {
        self.day_summaries_in(since, until, "localtime", "utc")
    }

    /// `to_day` turns a UTC instant into the wanted calendar; `from_day` turns
    /// that calendar's midnight back into UTC. Tests use UTC both ways.
    fn day_summaries_in(
        &self,
        since: Option<u64>,
        until: Option<u64>,
        to_day: &str,
        from_day: &str,
    ) -> Result<Vec<DaySummary>> {
        let sql = format!(
            "SELECT day, CAST(strftime('%s', day, ?2) AS INTEGER), COUNT(*),
                    SUM(sev = 0), SUM(sev = 1), SUM(sev = 2), SUM(sev = 3), SUM(sev = 4)
             FROM (SELECT date(at, 'unixepoch', ?1) AS day, {EVENT_SEVERITY} AS sev
                   FROM events WHERE at >= ?3 AND at < ?4)
             GROUP BY day ORDER BY day"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![
                to_day,
                from_day,
                int(since.unwrap_or(0)),
                int(until.unwrap_or(u64::MAX))
            ],
            |r| {
                Ok(DaySummary {
                    day: r.get(0)?,
                    start: r.get(1)?,
                    events: r.get(2)?,
                    counts: [r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?],
                })
            },
        )?;
        rows.collect()
    }

    /// Screen locked -> unlocked intervals overlapping `[since, until)`, oldest
    /// first. A lock followed by another lock (the service restarted while
    /// locked) starts over at the later one; the last lock may still be open.
    pub fn away_periods(&self, since: Option<u64>, until: Option<u64>) -> Result<Vec<AwayPeriod>> {
        let since = since.unwrap_or(0);
        let until = until.unwrap_or(u64::MAX);
        // Start from the last lock before the range: it may reach into it.
        let sql = format!(
            "SELECT at, {ACTIVITY_KIND} FROM events
             WHERE {ACTIVITY_KIND} IN ('screen_locked', 'screen_unlocked')
               AND at < ?2
               AND at >= coalesce((SELECT MAX(at) FROM events
                                   WHERE {ACTIVITY_KIND} = 'screen_locked' AND at < ?1), 0)
             ORDER BY at, id"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let marks = stmt
            .query_map(params![int(since), int(until)], |r| {
                Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>>>()?;
        let mut periods = Vec::new();
        let mut locked: Option<u64> = None;
        for (at, kind) in marks {
            match kind.as_str() {
                "screen_locked" => locked = Some(at),
                _ => {
                    if let Some(from) = locked.take() {
                        periods.push(AwayPeriod {
                            from,
                            until: Some(at),
                        });
                    }
                }
            }
        }
        if let Some(from) = locked {
            // Still locked at the end of the range: the next mark after it decides.
            let next: Option<(String, u64)> = self
                .conn
                .query_row(
                    &format!(
                        "SELECT {ACTIVITY_KIND}, at FROM events
                         WHERE {ACTIVITY_KIND} IN ('screen_locked', 'screen_unlocked') AND at >= ?1
                         ORDER BY at, id LIMIT 1"
                    ),
                    [int(until)],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match next {
                Some((kind, at)) if kind == "screen_unlocked" => periods.push(AwayPeriod {
                    from,
                    until: Some(at),
                }),
                // Locked again without an unlock: this period was abandoned.
                Some(_) => {}
                None => periods.push(AwayPeriod { from, until: None }),
            }
        }
        periods.retain(|p| p.until.is_none_or(|u| u > since) && p.from < until);
        Ok(periods)
    }

    /// Findings including resolved ones, most recently seen first. `since` and
    /// `until` keep findings that existed at some point in that range.
    pub fn finding_history(&self, q: &HistoryQuery) -> Result<Vec<StoredFinding>> {
        let mut w = Where::default();
        if let Some(since) = q.since {
            w.add("coalesce(resolved_at, last_seen) >= ?", [int(since)]);
        }
        if let Some(until) = q.until {
            w.add("first_seen < ?", [int(until)]);
        }
        if let Some(min) = q.min_severity {
            w.add("severity >= ?", [Value::Integer(min as i64)]);
        }
        if !q.kinds.is_empty() {
            let kinds = text(&serde_json::to_string(&q.kinds).expect("strings serialize"));
            w.add(
                "(json_extract(data, '$.category') IN (SELECT value FROM json_each(?)) \
                 OR json_extract(data, '$.check') IN (SELECT value FROM json_each(?)))",
                [kinds.clone(), kinds],
            );
        }
        if let Some(s) = needle(q) {
            w.add(
                "instr(lower(coalesce(json_extract(data, '$.title'), '') || char(10) || \
                 coalesce(json_extract(data, '$.detail'), '') || char(10) || \
                 coalesce(json_extract(data, '$.path'), '')), ?) > 0",
                [Value::Text(s)],
            );
        }
        if let Some(p) = &q.program {
            w.add("json_extract(data, '$.path') = ?", [text(p)]);
        }
        if q.resolved_only {
            w.add("resolved_at IS NOT NULL", []);
        }
        let sql = format!(
            "{FINDING_SELECT}{} ORDER BY coalesce(resolved_at, last_seen) DESC, key LIMIT {} OFFSET {}",
            w.sql(),
            limit(q),
            q.offset.unwrap_or(0)
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(w.params.iter()), row_to_stored)?;
        rows.collect()
    }

    /// Active findings about the program at `path`, most severe first.
    pub fn active_for_path(&self, path: &str) -> Result<Vec<StoredFinding>> {
        let mut stmt = self.conn.prepare(&format!(
            "{FINDING_SELECT} WHERE resolved_at IS NULL AND json_extract(data, '$.path') = ?1
             ORDER BY severity DESC, first_seen DESC"
        ))?;
        let rows = stmt.query_map([path], row_to_stored)?;
        rows.collect()
    }

    /// What appeared and went away since `since`, findings at `min` or above.
    pub fn changes_since(&self, since: u64, min: Severity) -> Result<Changes> {
        let findings = |cond: &str, order: &str| -> Result<Vec<StoredFinding>> {
            let mut stmt = self.conn.prepare(&format!(
                "{FINDING_SELECT} WHERE {cond} >= ?1 AND severity >= ?2 ORDER BY {order} DESC LIMIT 500"
            ))?;
            let rows = stmt.query_map(params![int(since), min as i64], row_to_stored)?;
            rows.collect()
        };
        let new_findings = findings("first_seen", "first_seen")?;
        let resolved_findings = findings("resolved_at", "resolved_at")?;
        let mut stmt = self.conn.prepare(
            "SELECT identity, label, first_seen, last_seen, runs FROM programs
             WHERE first_seen >= ?1 ORDER BY first_seen DESC LIMIT 500",
        )?;
        let new_programs = stmt
            .query_map([int(since)], row_to_program)?
            .collect::<Result<_>>()?;
        Ok(Changes {
            since,
            new_findings,
            resolved_findings,
            new_programs,
        })
    }

    /// What is known about a program by its identity (see `record_program`).
    pub fn program(&self, identity: &str) -> Result<Option<ProgramRecord>> {
        self.conn
            .query_row(
                "SELECT identity, label, first_seen, last_seen, runs FROM programs WHERE identity = ?1",
                [identity],
                row_to_program,
            )
            .optional()
    }

    // ---- notes and review marks -------------------------------------------

    /// Set an event's note (`None` clears it). Returns None if there is no such
    /// event, else its note and review mark afterwards.
    pub fn annotate(
        &self,
        event_id: i64,
        note: Option<&str>,
        at: u64,
    ) -> Result<Option<(Option<String>, Option<u64>)>> {
        self.update_note(
            event_id,
            "INSERT INTO event_notes (event_id, note, reviewed_at, updated_at) VALUES (?1, ?2, NULL, ?3)
             ON CONFLICT(event_id) DO UPDATE SET note = ?2, updated_at = ?3",
            params![event_id, note, int(at)],
        )
    }

    /// Mark an event reviewed (at `at`) or not. Same return as [`annotate`](Self::annotate).
    pub fn set_reviewed(
        &self,
        event_id: i64,
        reviewed: bool,
        at: u64,
    ) -> Result<Option<(Option<String>, Option<u64>)>> {
        let when = if reviewed { int(at) } else { Value::Null };
        self.update_note(
            event_id,
            "INSERT INTO event_notes (event_id, note, reviewed_at, updated_at) VALUES (?1, NULL, ?2, ?3)
             ON CONFLICT(event_id) DO UPDATE SET reviewed_at = ?2, updated_at = ?3",
            params![event_id, when, int(at)],
        )
    }

    fn update_note(
        &self,
        event_id: i64,
        upsert: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<(Option<String>, Option<u64>)>> {
        let exists = self
            .conn
            .query_row("SELECT 1 FROM events WHERE id = ?1", [event_id], |_| Ok(()))
            .optional()?
            .is_some();
        if !exists {
            return Ok(None);
        }
        self.conn.execute(upsert, params)?;
        self.conn.execute(
            "DELETE FROM event_notes WHERE event_id = ?1 AND note IS NULL AND reviewed_at IS NULL",
            [event_id],
        )?;
        let state = self
            .conn
            .query_row(
                "SELECT note, reviewed_at FROM event_notes WHERE event_id = ?1",
                [event_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(Some(state.unwrap_or((None, None))))
    }

    // ---- retention ----------------------------------------------------------

    /// Forget old history (see the `*_RETENTION_SECS` constants). Never touches
    /// active findings, trust rules or program familiarity.
    pub fn cleanup(&mut self, now: u64) -> Result<Cleanup> {
        let before = |secs: u64| int(now.saturating_sub(secs));
        let tx = self.conn.transaction()?;
        let mut events = tx.execute(
            "DELETE FROM events WHERE at < ?1",
            [before(EVENT_RETENTION_SECS)],
        )?;
        // Info-level events go sooner, unless the user wrote a note on them.
        events += tx.execute(
            &format!(
                "DELETE FROM events WHERE at < ?1 AND {EVENT_SEVERITY} = 0
                 AND id NOT IN (SELECT event_id FROM event_notes WHERE note IS NOT NULL)"
            ),
            [before(INFO_EVENT_RETENTION_SECS)],
        )?;
        let findings = tx.execute(
            "DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ?1",
            [before(RESOLVED_FINDING_RETENTION_SECS)],
        )?;
        // Keep the latest scan: an empty table means "next scan is the baseline".
        let scans = tx.execute(
            "DELETE FROM scans WHERE at < ?1 AND id < (SELECT MAX(id) FROM scans)",
            [before(SCAN_RETENTION_SECS)],
        )?;
        let notes = tx.execute(
            "DELETE FROM event_notes WHERE event_id NOT IN (SELECT id FROM events)",
            [],
        )?;
        tx.commit()?;
        Ok(Cleanup {
            events,
            findings,
            scans,
            notes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vogter_ipc::Event;
    use vogter_model::{Activity, ActivityKind, Category, Finding, TrustSubject};

    fn act(kind: ActivityKind, severity: Severity, summary: &str, path: Option<&str>) -> Event {
        let mut a = Activity::new(kind, severity, summary);
        a.path = path.map(str::to_string);
        Event::Activity { activity: a }
    }

    fn finding(title: &str, category: Category, severity: Severity, path: &str) -> Finding {
        Finding {
            severity,
            category,
            check: "persistence.script".into(),
            title: title.into(),
            detail: "starts when you log in".into(),
            pid: None,
            path: Some(path.into()),
            signing: None,
            source: None,
        }
    }

    /// A small mixed history: ids 1..=8.
    fn sample() -> Store {
        let s = Store::in_memory().unwrap();
        let sudo = |sev, text| act(ActivityKind::Sudo, sev, text, None);
        s.log_event(100, sudo(Severity::Low, "me ran a command as root"))
            .unwrap();
        s.log_event(200, Event::CameraOn).unwrap();
        s.log_event(
            300,
            act(
                ActivityKind::ProcessStarted,
                Severity::High,
                "Helper: runs from a temp folder",
                Some("/tmp/Helper"),
            ),
        )
        .unwrap();
        s.log_event(400, sudo(Severity::Medium, "Failed sudo by me"))
            .unwrap();
        s.log_event(
            500,
            act(
                ActivityKind::ProcessStarted,
                Severity::Info,
                "First run of Helper",
                Some("/tmp/Helper"),
            ),
        )
        .unwrap();
        s.log_event(
            600,
            Event::NewFinding {
                finding: StoredFinding {
                    key: "k".into(),
                    finding: finding(
                        "Launch item com.example.helper",
                        Category::Persistence,
                        Severity::Medium,
                        "/tmp/Helper",
                    ),
                    first_seen: 600,
                    last_seen: 600,
                    acknowledged: false,
                    resolved_at: None,
                },
            },
        )
        .unwrap();
        s.log_event(700, Event::MicrophoneOff).unwrap();
        s.log_event(800, sudo(Severity::Critical, "Something odd"))
            .unwrap();
        s
    }

    fn ids(events: &[LoggedEvent]) -> Vec<i64> {
        events.iter().map(|e| e.id).collect()
    }

    fn query(f: impl FnOnce(&mut HistoryQuery)) -> HistoryQuery {
        let mut q = HistoryQuery::default();
        f(&mut q);
        q
    }

    #[test]
    fn history_newest_first_with_time_range() {
        let s = sample();
        let (all, next) = s.history(&HistoryQuery::default()).unwrap();
        assert_eq!(ids(&all), [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(next, None);
        let (range, _) = s
            .history(&query(|q| {
                q.since = Some(300);
                q.until = Some(600);
            }))
            .unwrap();
        assert_eq!(ids(&range), [5, 4, 3]);
    }

    #[test]
    fn history_pages_with_a_cursor() {
        let s = sample();
        let mut q = query(|q| q.limit = Some(3));
        let mut pages = Vec::new();
        loop {
            let (page, next) = s.history(&q).unwrap();
            pages.push(ids(&page));
            match next {
                Some(id) => q.before_id = Some(id),
                None => break,
            }
        }
        assert_eq!(pages, [vec![8, 7, 6], vec![5, 4, 3], vec![2, 1]]);
    }

    #[test]
    fn history_filters() {
        let s = sample();
        let get = |f: fn(&mut HistoryQuery)| ids(&s.history(&query(f)).unwrap().0);
        // Severity: events without one count as info.
        assert_eq!(
            get(|q| q.min_severity = Some(Severity::Medium)),
            [8, 6, 4, 3]
        );
        assert_eq!(get(|q| q.min_severity = Some(Severity::Info)).len(), 8);
        // Kinds match the event kind, the activity kind or the finding category.
        assert_eq!(get(|q| q.kinds = vec!["sudo".into()]), [8, 4, 1]);
        assert_eq!(
            get(|q| q.kinds = vec!["camera_on".into(), "microphone_off".into()]),
            [7, 2]
        );
        assert_eq!(get(|q| q.kinds = vec!["persistence".into()]), [6]);
        // Free text, case-insensitive, over summaries, titles and paths.
        assert_eq!(get(|q| q.search = Some("FAILED".into())), [4]);
        assert_eq!(get(|q| q.search = Some("helper".into())), [6, 5, 3]);
        assert_eq!(get(|q| q.search = Some("  ".into())).len(), 8);
        // A program, through activities and findings alike.
        assert_eq!(get(|q| q.program = Some("/tmp/Helper".into())), [6, 5, 3]);
        assert_eq!(s.program_event_count("/tmp/Helper").unwrap(), 3);
        // Combined.
        assert_eq!(
            get(|q| {
                q.program = Some("/tmp/Helper".into());
                q.min_severity = Some(Severity::High);
            }),
            [3]
        );
        // Quotes and LIKE wildcards are just text.
        assert!(get(|q| q.search = Some("%' OR 1=1 --".into())).is_empty());
    }

    #[test]
    fn notes_and_review_marks() {
        let s = sample();
        assert_eq!(s.annotate(99, Some("x"), 1).unwrap(), None);
        assert_eq!(
            s.annotate(4, Some("that was me, typo"), 900).unwrap(),
            Some((Some("that was me, typo".into()), None))
        );
        assert_eq!(
            s.set_reviewed(4, true, 901).unwrap(),
            Some((Some("that was me, typo".into()), Some(901)))
        );
        s.set_reviewed(8, true, 902).unwrap();
        let e = s.event(4).unwrap().unwrap();
        assert_eq!(
            (e.note.as_deref(), e.reviewed_at),
            (Some("that was me, typo"), Some(901))
        );
        assert_eq!(s.recent_events(10).unwrap()[0].reviewed_at, Some(902));

        let unreviewed = ids(&s.history(&query(|q| q.unreviewed_only = true)).unwrap().0);
        assert_eq!(unreviewed, [7, 6, 5, 3, 2, 1]);

        // Clearing both removes the row.
        s.annotate(4, None, 903).unwrap();
        assert_eq!(s.set_reviewed(4, false, 904).unwrap(), Some((None, None)));
        let n: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM event_notes WHERE event_id = 4",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn day_buckets() {
        let s = Store::in_memory().unwrap();
        let d0 = 1_793_750_400; // 2026-11-04 00:00 UTC
        s.log_event(d0 - 10, Event::CameraOn).unwrap();
        s.log_event(
            d0 + 10,
            act(ActivityKind::Sudo, Severity::Medium, "a", None),
        )
        .unwrap();
        s.log_event(d0 + 20, act(ActivityKind::Sudo, Severity::High, "b", None))
            .unwrap();
        s.log_event(d0 + DAY + 5, Event::CameraOff).unwrap();
        let days = s
            .day_summaries_in(None, None, "+0 seconds", "+0 seconds")
            .unwrap();
        assert_eq!(
            days,
            [
                DaySummary {
                    day: "2026-11-03".into(),
                    start: d0 - DAY,
                    events: 1,
                    counts: [1, 0, 0, 0, 0]
                },
                DaySummary {
                    day: "2026-11-04".into(),
                    start: d0,
                    events: 2,
                    counts: [0, 0, 1, 1, 0]
                },
                DaySummary {
                    day: "2026-11-05".into(),
                    start: d0 + DAY,
                    events: 1,
                    counts: [1, 0, 0, 0, 0]
                },
            ]
        );
        let ranged = s
            .day_summaries_in(Some(d0), Some(d0 + DAY), "+0 seconds", "+0 seconds")
            .unwrap();
        assert_eq!(ranged.len(), 1);

        // Local days: every event lands in the day whose [start, start + ~1 day) holds it.
        for d in s.day_summaries(None, None).unwrap() {
            assert!(
                d.start <= d0 + DAY + 5 && d.start + 25 * 3600 > d0 - 10,
                "{d:?}"
            );
        }
        assert_eq!(
            s.day_summaries(None, None)
                .unwrap()
                .iter()
                .map(|d| d.events)
                .sum::<u32>(),
            4
        );
    }

    #[test]
    fn away_periods_pair_locks_and_unlocks() {
        let s = Store::in_memory().unwrap();
        let lock = || {
            act(
                ActivityKind::ScreenLocked,
                Severity::Info,
                "Screen locked",
                None,
            )
        };
        let unlock = || {
            act(
                ActivityKind::ScreenUnlocked,
                Severity::Info,
                "Screen unlocked",
                None,
            )
        };
        s.log_event(100, lock()).unwrap();
        s.log_event(200, unlock()).unwrap();
        s.log_event(250, unlock()).unwrap(); // stray unlock: ignored
        s.log_event(300, lock()).unwrap();
        s.log_event(350, lock()).unwrap(); // restarted while locked: starts over
        s.log_event(400, unlock()).unwrap();
        s.log_event(500, lock()).unwrap(); // still locked
        let p = |from, until| AwayPeriod { from, until };
        assert_eq!(
            s.away_periods(None, None).unwrap(),
            [p(100, Some(200)), p(350, Some(400)), p(500, None)]
        );
        // A lock before the range that ends inside it is included.
        assert_eq!(
            s.away_periods(Some(150), Some(380)).unwrap(),
            [p(100, Some(200)), p(350, Some(400))]
        );
        assert_eq!(s.away_periods(Some(410), Some(450)).unwrap(), []);
        assert_eq!(s.away_periods(Some(600), None).unwrap(), [p(500, None)]);
    }

    #[test]
    fn finding_history_includes_resolved() {
        let mut s = Store::in_memory().unwrap();
        let a = finding(
            "Launch item a",
            Category::Persistence,
            Severity::Medium,
            "/opt/a",
        );
        let b = finding(
            "Firewall is off",
            Category::SystemHealth,
            Severity::Low,
            "/b",
        );
        s.record_scan(10, &[a.clone(), b.clone()]).unwrap();
        s.record_scan(20, std::slice::from_ref(&b)).unwrap();
        s.record_scan(30, std::slice::from_ref(&b)).unwrap();

        let all = s.finding_history(&HistoryQuery::default()).unwrap();
        let summary: Vec<_> = all
            .iter()
            .map(|f| {
                (
                    f.finding.title.as_str(),
                    f.first_seen,
                    f.last_seen,
                    f.resolved_at,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("Firewall is off", 10, 30, None),
                ("Launch item a", 10, 10, Some(20))
            ]
        );

        let get = |f: fn(&mut HistoryQuery)| {
            s.finding_history(&query(f))
                .unwrap()
                .into_iter()
                .map(|f| f.finding.title)
                .collect::<Vec<_>>()
        };
        assert_eq!(get(|q| q.resolved_only = true), ["Launch item a"]);
        assert_eq!(
            get(|q| q.min_severity = Some(Severity::Medium)),
            ["Launch item a"]
        );
        assert_eq!(
            get(|q| q.kinds = vec!["system_health".into()]),
            ["Firewall is off"]
        );
        assert_eq!(get(|q| q.search = Some("LAUNCH".into())), ["Launch item a"]);
        assert_eq!(
            get(|q| q.program = Some("/opt/a".into())),
            ["Launch item a"]
        );
        assert_eq!(get(|q| q.since = Some(25)), ["Firewall is off"]);
        assert_eq!(get(|q| q.until = Some(10)), Vec::<String>::new());
        assert_eq!(
            get(|q| {
                q.limit = Some(1);
                q.offset = Some(1)
            }),
            ["Launch item a"]
        );
        assert_eq!(s.active_for_path("/b").unwrap().len(), 1);
        assert!(s.active_for_path("/opt/a").unwrap().is_empty());
        // `finding` reports when it went away; active ones have no resolved_at.
        assert_eq!(s.finding(&a.key()).unwrap().unwrap().resolved_at, Some(20));
        assert_eq!(s.active(true).unwrap()[0].resolved_at, None);
    }

    #[test]
    fn changes_since_a_moment() {
        let mut s = Store::in_memory().unwrap();
        let a = finding(
            "Launch item a",
            Category::Persistence,
            Severity::Medium,
            "/a",
        );
        let b = finding("Permission b", Category::Privacy, Severity::Low, "/b");
        let quiet = finding("Listener", Category::Network, Severity::Info, "/c");
        s.record_scan(10, std::slice::from_ref(&a)).unwrap();
        s.record_program("path:/old", "old", 5).unwrap();
        s.record_scan(100, &[b.clone(), quiet.clone()]).unwrap();
        s.record_program("team:T:com.example.new", "new", 120)
            .unwrap();

        let c = s.changes_since(50, Severity::Low).unwrap();
        let titles = |v: &[StoredFinding]| {
            v.iter()
                .map(|f| f.finding.title.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(titles(&c.new_findings), ["Permission b"]);
        assert_eq!(titles(&c.resolved_findings), ["Launch item a"]);
        assert_eq!(c.new_programs.len(), 1);
        assert_eq!(c.new_programs[0].identity, "team:T:com.example.new");
        assert_eq!(
            s.changes_since(50, Severity::Info)
                .unwrap()
                .new_findings
                .len(),
            2
        );
        assert_eq!(s.program("path:/old").unwrap().unwrap().runs, 1);
        assert_eq!(s.program("path:/nope").unwrap(), None);
    }

    #[test]
    fn retention_keeps_what_matters() {
        let mut s = Store::in_memory().unwrap();
        let now = 1000 * DAY;
        let ago = |days: u64| now - days * DAY;
        let info = || {
            act(
                ActivityKind::ScreenLocked,
                Severity::Info,
                "Screen locked",
                None,
            )
        };
        let alert = || act(ActivityKind::Sudo, Severity::Medium, "Failed sudo", None);
        let old_info = s.log_event(ago(100), info()).unwrap().id;
        let noted_info = s.log_event(ago(100), info()).unwrap().id;
        s.annotate(noted_info, Some("I locked it myself"), ago(99))
            .unwrap();
        let old_mic = s.log_event(ago(95), Event::MicrophoneOff).unwrap().id;
        let recent_info = s.log_event(ago(10), info()).unwrap().id;
        let alert_200 = s.log_event(ago(200), alert()).unwrap().id;
        let alert_400 = s.log_event(ago(400), alert()).unwrap().id;
        s.set_reviewed(alert_400, true, ago(399)).unwrap();

        // An active finding first seen long ago, and two resolved ones.
        let keep = finding("Still here", Category::Persistence, Severity::Low, "/keep");
        let gone_old = finding(
            "Gone long ago",
            Category::Persistence,
            Severity::Low,
            "/old",
        );
        let gone_new = finding("Gone lately", Category::Persistence, Severity::Low, "/new");
        s.record_scan(
            ago(500),
            &[keep.clone(), gone_old.clone(), gone_new.clone()],
        )
        .unwrap();
        s.record_scan(ago(400), &[keep.clone(), gone_new.clone()])
            .unwrap();
        s.record_scan(ago(30), std::slice::from_ref(&keep)).unwrap();
        s.add_trust("*", &TrustSubject::Exact { key: "x".into() }, "x", ago(600))
            .unwrap();
        s.record_program("path:/x", "x", ago(700)).unwrap();

        let c = s.cleanup(now).unwrap();
        assert_eq!(
            c,
            Cleanup {
                events: 3,
                findings: 1,
                scans: 2,
                notes: 1
            }
        );
        let left = ids(&s.history(&HistoryQuery::default()).unwrap().0);
        assert_eq!(left, [alert_200, recent_info, noted_info]);
        assert!(
            !left.contains(&old_info) && !left.contains(&old_mic) && !left.contains(&alert_400)
        );
        assert_eq!(s.active(true).unwrap().len(), 1);
        assert!(s.finding(&gone_old.key()).unwrap().is_none());
        assert!(s.finding(&gone_new.key()).unwrap().is_some());
        assert_eq!(s.trust_rules().unwrap().len(), 1);
        assert!(s.program("path:/x").unwrap().is_some());
        // The latest scan stays, so the next one isn't mistaken for a baseline.
        assert_eq!(s.last_scan().unwrap(), Some(ago(30)));
        assert!(!s.record_scan(now, &[keep]).unwrap().baseline);

        // Even when every scan is old.
        s.cleanup(now + 2000 * DAY).unwrap();
        assert!(s.last_scan().unwrap().is_some());
        // Nothing left to do the second time round.
        assert_eq!(s.cleanup(now).unwrap(), Cleanup::default());
    }

    #[test]
    fn old_databases_upgrade_in_place() {
        let dir = std::env::temp_dir().join(format!("vogter-store-upgrade-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.db");
        let _ = std::fs::remove_file(&path);
        {
            // The 0.1.1 schema with some data, no history tables or indexes.
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(crate::SCHEMA).unwrap();
            conn.execute(
                "INSERT INTO events (at, data) VALUES (5, '{\"kind\":\"camera_on\"}')",
                [],
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(ids(&s.history(&HistoryQuery::default()).unwrap().0), [1]);
        assert!(s.set_reviewed(1, true, 6).unwrap().is_some());
        drop(s);
        // And again: the migration is idempotent.
        let s = Store::open(&path).unwrap();
        assert_eq!(s.event(1).unwrap().unwrap().reviewed_at, Some(6));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
