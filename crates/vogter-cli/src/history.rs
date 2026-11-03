//! `vogter history`, `vogter changes`, `vogter program`, `vogter note`, `vogter review`.

use anyhow::{Result, bail};
use vogter_ipc::{HistoryQuery, LoggedEvent, Message, Request};
use vogter_model::{Severity, StoredFinding};

use crate::client::{Conn, describe_event, reply};

const DAY: u64 = 86_400;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Broken-down local time of a Unix timestamp.
fn local(t: u64) -> libc::tm {
    let t = t as libc::time_t;
    // SAFETY: tm is plain data; localtime_r only writes into it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    tm
}

/// Local midnight of the given calendar date (normalised, so day 0 or 32 are fine).
fn local_midnight(year: i32, month: i32, day: i32) -> u64 {
    // SAFETY: tm is plain data; mktime reads and normalises it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_isdst = -1;
    (unsafe { libc::mktime(&mut tm) }).max(0) as u64
}

fn start_of_day(t: u64, days_later: i32) -> u64 {
    let tm = local(t);
    local_midnight(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday + days_later)
}

pub fn date(t: u64) -> String {
    let tm = local(t);
    format!(
        "{:04}-{:02}-{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    )
}

pub fn date_time(t: u64) -> String {
    let tm = local(t);
    format!("{} {:02}:{:02}", date(t), tm.tm_hour, tm.tm_min)
}

/// `2026-11-01` (local midnight; with `end_of_day`, the midnight after it),
/// `today`, `yesterday`, `7d` / `12h` / `30m` / `2w` ago, or Unix seconds.
pub fn parse_time(s: &str, end_of_day: bool) -> Result<u64> {
    let s = s.trim();
    let shift = if end_of_day { 1 } else { 0 };
    match s {
        "now" => return Ok(now()),
        "today" => return Ok(start_of_day(now(), shift)),
        "yesterday" => return Ok(start_of_day(now(), shift - 1)),
        _ => {}
    }
    let parts: Vec<&str> = s.split('-').collect();
    if let [y, m, d] = parts[..]
        && let (Ok(y), Ok(m), Ok(d)) = (y.parse(), m.parse(), d.parse())
        && (1..=12).contains(&m)
        && (1..=31).contains(&d)
    {
        return Ok(local_midnight(y, m, d + shift));
    }
    if let Some(unit) = s.chars().last().filter(char::is_ascii_alphabetic) {
        let n: u64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| anyhow::anyhow!("can't read '{s}' as a time"))?;
        let secs = match unit {
            'm' => 60,
            'h' => 3600,
            'd' => DAY,
            'w' => 7 * DAY,
            _ => bail!("can't read '{s}': use m, h, d or w (like 7d)"),
        };
        return Ok(now().saturating_sub(n * secs));
    }
    s.parse().map_err(|_| {
        anyhow::anyhow!("can't read '{s}': use 2026-11-01, 7d, yesterday or Unix seconds")
    })
}

pub struct HistoryArgs {
    pub query: HistoryQuery,
    pub days: Option<u32>,
    pub findings: bool,
    pub away: bool,
    pub json: bool,
}

pub fn history(args: HistoryArgs) -> Result<()> {
    let mut conn = Conn::open()?;
    if let Some(n) = args.days {
        return days(&mut conn, n.max(1), args.json);
    }
    if args.away {
        return away(&mut conn, &args.query, args.json);
    }
    if args.findings {
        let findings = reply!(
            conn.call(Request::FindingHistory(args.query))?,
            Message::FindingHistory { findings, .. } => findings
        );
        if args.json {
            println!("{}", serde_json::to_string_pretty(&findings)?);
        } else {
            print_findings(&findings);
        }
        return Ok(());
    }
    let (events, next) = reply!(
        conn.call(Request::History(args.query))?,
        Message::History { events, next_before_id, .. } => (events, next_before_id)
    );
    if args.json {
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }
    if events.is_empty() {
        println!("Nothing in history matches.");
    }
    let mut last_day = String::new();
    for e in &events {
        let day = date(e.at);
        if day != last_day {
            println!("\n{day}");
            last_day = day;
        }
        print_event(e);
    }
    if let Some(id) = next {
        println!("\n(older events: add --before {id})");
    }
    Ok(())
}

fn print_event(e: &LoggedEvent) {
    let tm = local(e.at);
    let mark = if e.reviewed_at.is_some() { "✓" } else { " " };
    let line = describe_event(&e.event).replace('\n', "\n                    ");
    println!(
        "  {:02}:{:02} {mark} #{:<6} {line}",
        tm.tm_hour, tm.tm_min, e.id
    );
    if let Some(note) = &e.note {
        println!(
            "                    note: {}",
            note.replace('\n', "\n                          ")
        );
    }
}

fn print_findings(findings: &[StoredFinding]) {
    if findings.is_empty() {
        println!("No findings in history match.");
    }
    for f in findings {
        let span = match f.resolved_at {
            Some(r) => format!("{} → gone {}", date_time(f.first_seen), date_time(r)),
            None => format!("{} → still here", date_time(f.first_seen)),
        };
        println!(
            "[{:^8}] {}\n           {span}",
            f.finding.severity.as_str().to_uppercase(),
            f.finding.title
        );
    }
}

fn days(conn: &mut Conn, n: u32, json: bool) -> Result<()> {
    let since = start_of_day(now(), 1 - n as i32);
    let days = reply!(
        conn.call(Request::HistoryDays { since: Some(since), until: None })?,
        Message::HistoryDays { days } => days
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&days)?);
        return Ok(());
    }
    let today = date(now());
    for i in 0..n as i32 {
        let start = start_of_day(now(), -i);
        let day = date(start);
        let label = if day == today {
            "today".to_string()
        } else if i == 1 {
            "yesterday".to_string()
        } else {
            day.clone()
        };
        let Some(d) = days.iter().find(|d| d.day == day) else {
            println!("{label:<11}    0 events  quiet");
            continue;
        };
        let [_, low, medium, high, critical] = d.counts;
        let important = high + critical;
        let mood = match (important, medium) {
            (0, 0) => "all calm".to_string(),
            (0, m) => format!("{m} worth a look"),
            (i, 0) => format!("{i} important"),
            (i, m) => format!("{i} important, {m} worth a look"),
        };
        let bar: String = "●".repeat((high + critical).min(10) as usize)
            + &"◐".repeat(medium.min(10) as usize)
            + &"·".repeat(low.min(10) as usize);
        println!("{label:<11} {:>4} events  {mood:<28} {bar}", d.events);
    }
    Ok(())
}

fn away(conn: &mut Conn, q: &HistoryQuery, json: bool) -> Result<()> {
    let periods = reply!(
        conn.call(Request::AwayPeriods { since: q.since, until: q.until })?,
        Message::AwayPeriods { periods } => periods
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&periods)?);
        return Ok(());
    }
    if periods.is_empty() {
        println!("No time away in that range.");
    }
    for p in periods.iter().rev() {
        match p.until {
            Some(u) => {
                let secs = u.saturating_sub(p.from);
                println!(
                    "{} → {}  away {}h {:02}m",
                    date_time(p.from),
                    date_time(u),
                    secs / 3600,
                    secs % 3600 / 60
                );
            }
            None => println!("{} → (still locked)", date_time(p.from)),
        }
    }
    Ok(())
}

pub fn changes(since: u64, min: Option<Severity>, json: bool) -> Result<()> {
    let c = reply!(
        Conn::open()?.call(Request::ChangesSince { since, min_severity: min })?,
        Message::Changes(c) => c
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&c)?);
        return Ok(());
    }
    println!("Since {}:", date_time(since));
    if c.new_findings.is_empty() && c.resolved_findings.is_empty() && c.new_programs.is_empty() {
        println!("  nothing changed");
    }
    for (title, list) in [("New", &c.new_findings), ("Gone", &c.resolved_findings)] {
        if list.is_empty() {
            continue;
        }
        println!("\n{title}:");
        for f in list.iter() {
            let when = if title == "New" {
                f.first_seen
            } else {
                f.resolved_at.unwrap_or(f.last_seen)
            };
            println!(
                "  {}  [{}] {}",
                date_time(when),
                f.finding.severity.as_str(),
                f.finding.title
            );
        }
    }
    if !c.new_programs.is_empty() {
        println!("\nPrograms that ran for the first time:");
        for p in &c.new_programs {
            println!(
                "  {}  {} ({} run{})",
                date_time(p.first_seen),
                p.label,
                p.runs,
                if p.runs == 1 { "" } else { "s" }
            );
        }
    }
    Ok(())
}

pub fn program(path: String, json: bool) -> Result<()> {
    let p = reply!(
        Conn::open()?.call(Request::ProgramProfile { path })?,
        Message::ProgramProfile(p) => p
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&p)?);
        return Ok(());
    }
    println!(
        "{}  {}",
        p.name,
        if p.exists { "" } else { "(no longer on disk)" }
    );
    println!("location:  {}", p.path);
    if let Some(s) = &p.signing {
        println!("signature: {}", s.describe());
    }
    match &p.familiarity {
        Some(f) => println!(
            "seen:      first {}, last {}, {} runs",
            date_time(f.first_seen),
            date_time(f.last_seen),
            f.runs
        ),
        None => println!("seen:      Vogter hasn't seen it start"),
    }
    if !p.findings.is_empty() {
        println!("\nRight now:");
        print_findings(&p.findings);
    }
    if !p.past_findings.is_empty() {
        println!("\nIn the past:");
        print_findings(&p.past_findings);
    }
    println!("\nActivity ({} in history):", p.event_count);
    for e in &p.events {
        print!("{}", date(e.at));
        print_event(e);
    }
    Ok(())
}

pub fn note(event_id: i64, note: String) -> Result<()> {
    annotation(Request::Annotate { event_id, note })
}

pub fn review(event_id: i64, reviewed: bool) -> Result<()> {
    annotation(Request::SetReviewed { event_id, reviewed })
}

fn annotation(req: Request) -> Result<()> {
    let (id, note, reviewed) = reply!(
        Conn::open()?.call(req)?,
        Message::Annotation { event_id, note, reviewed_at } => (event_id, note, reviewed_at)
    );
    println!(
        "#{id}: {}{}",
        match reviewed {
            Some(t) => format!("reviewed {}", date_time(t)),
            None => "not reviewed".into(),
        },
        note.map(|n| format!(", note: {n}")).unwrap_or_default()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let t = parse_time("2026-11-01", false).unwrap();
        assert_eq!(date(t), "2026-11-01");
        assert_eq!(local(t).tm_hour, 0);
        assert_eq!(date(parse_time("2026-11-01", true).unwrap()), "2026-11-02");
        let week = parse_time("7d", false).unwrap();
        assert!(now() - week >= 7 * DAY && now() - week < 7 * DAY + 5);
        assert_eq!(parse_time("1793750400", false).unwrap(), 1_793_750_400);
        assert!(parse_time("soon", false).is_err());
        assert!(parse_time("7y", false).is_err());
        assert!(parse_time("yesterday", false).unwrap() < parse_time("today", false).unwrap());
    }
}
