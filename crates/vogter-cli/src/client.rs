//! Talk to a running `vogterd`.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use vogter_ipc::{Event, LoggedEvent, Message, Request, read_line, write_line};

struct Conn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Conn {
    fn open() -> Result<Self> {
        for path in vogter_ipc::socket_candidates() {
            if let Ok(s) = UnixStream::connect(&path) {
                return Ok(Conn {
                    writer: s.try_clone()?,
                    reader: BufReader::new(s),
                });
            }
        }
        bail!("vogterd is not running (start it with `cargo run -p vogterd`)")
    }

    fn call(&mut self, req: Request) -> Result<Message> {
        write_line(&mut self.writer, &req)?;
        self.next()
    }

    fn next(&mut self) -> Result<Message> {
        read_line(&mut self.reader)?.context("vogterd closed the connection")
    }
}

fn expect_ok(msg: Message) -> Result<()> {
    match msg {
        Message::Ok => Ok(()),
        Message::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}

pub fn status() -> Result<()> {
    let Message::Status(s) = Conn::open()?.call(Request::Status)? else {
        bail!("unexpected reply")
    };
    println!(
        "vogterd {} (protocol {}){}",
        s.version,
        s.protocol,
        if s.as_root { ", root" } else { "" }
    );
    match s.last_scan {
        Some(t) => println!(
            "last scan: {} ago, every {}s{}",
            ago(t),
            s.scan_interval_secs,
            if s.scanning { " (scanning now)" } else { "" }
        ),
        None => println!("no scan yet"),
    }
    let [info, low, medium, high, critical] = s.open_counts;
    println!(
        "open findings: {critical} critical, {high} high, {medium} medium, {low} low, {info} info"
    );
    let mic = if s.av.microphone_in_use {
        let who: Vec<_> =
            s.av.microphone_clients
                .iter()
                .map(|c| c.name.as_str())
                .collect();
        format!(
            "ON ({})",
            if who.is_empty() {
                "unknown app".into()
            } else {
                who.join(", ")
            }
        )
    } else {
        "off".into()
    };
    println!(
        "microphone: {mic}   camera: {}",
        if s.av.camera_in_use { "ON" } else { "off" }
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if s.learning_until > now {
        println!(
            "learning what's normal: {} days left",
            (s.learning_until - now).div_ceil(86_400)
        );
    }
    println!("trust rules: {}", s.trust_rules);
    let rt = &s.realtime;
    println!(
        "realtime: {}",
        if rt.sources.is_empty() {
            "none".into()
        } else {
            rt.sources.join(", ")
        }
    );
    if let Some(e) = &rt.endpoint_security_error {
        println!("  {e}");
    }
    for e in &s.sensor_errors {
        println!("limited: {e}");
    }
    Ok(())
}

pub fn findings(all: bool) -> Result<()> {
    let Message::Findings { findings } = Conn::open()?.call(Request::Findings {
        include_acknowledged: all,
    })?
    else {
        bail!("unexpected reply")
    };
    for f in findings {
        let ack = if f.acknowledged {
            " (acknowledged)"
        } else {
            ""
        };
        println!(
            "[{:^8}] {}{ack}",
            f.finding.severity.as_str().to_uppercase(),
            f.finding.title
        );
        println!("           {}", f.finding.detail);
        println!(
            "           first seen {} ago — key: {}",
            ago(f.first_seen),
            f.key
        );
    }
    Ok(())
}

pub fn ack(key: String) -> Result<()> {
    expect_ok(Conn::open()?.call(Request::Acknowledge { key })?)
}

pub fn scan_now() -> Result<()> {
    expect_ok(Conn::open()?.call(Request::ScanNow)?)
}

pub fn events(limit: u32) -> Result<()> {
    let Message::Events { events } = Conn::open()?.call(Request::Events { limit })? else {
        bail!("unexpected reply")
    };
    for e in events.iter().rev() {
        println!("#{:<5} {}", e.id, describe(e));
    }
    Ok(())
}

pub fn show(id: i64) -> Result<()> {
    let Message::Events { events } = Conn::open()?.call(Request::Events { limit: 1000 })? else {
        bail!("unexpected reply")
    };
    let Some(e) = events.into_iter().find(|e| e.id == id) else {
        bail!("no event #{id} among the last 1000")
    };
    println!("#{} {}", e.id, describe(&e));
    if let Event::Activity { activity: a } = &e.event {
        if let Some(advice) = &a.advice {
            println!("\nWhat this means:\n  {advice}");
        }
        println!();
        if let Some(p) = &a.process {
            println!(
                "program:   {p}{}",
                a.pid.map(|p| format!(" (pid {p})")).unwrap_or_default()
            );
        }
        if let Some(s) = &a.signing {
            println!("signature: {}", s.describe());
        }
        if let Some(p) = &a.path {
            println!("location:  {p}");
        }
        println!("\nTrust it:  vogter trust --event {id}");
    }
    Ok(())
}

pub fn trust(finding_key: Option<String>, event_id: Option<i64>, all_checks: bool) -> Result<()> {
    if finding_key.is_none() && event_id.is_none() {
        bail!("give a finding key (vogter findings) or --event <id> (vogter events)");
    }
    match Conn::open()?.call(Request::Trust {
        finding_key,
        event_id,
        all_checks,
    })? {
        Message::Trusted { rule } => {
            println!("trusted #{}: {} (for {})", rule.id, rule.label, rule.check);
            Ok(())
        }
        Message::Error { message } => bail!(message),
        other => bail!("unexpected reply: {other:?}"),
    }
}

pub fn trusted() -> Result<()> {
    let Message::TrustRules { rules } = Conn::open()?.call(Request::TrustRules)? else {
        bail!("unexpected reply")
    };
    if rules.is_empty() {
        println!("no trust rules");
    }
    for r in rules {
        println!(
            "#{:<4} {}  — for {}, added {} ago",
            r.id,
            r.label,
            r.check,
            ago(r.created_at)
        );
    }
    Ok(())
}

pub fn untrust(id: i64) -> Result<()> {
    expect_ok(Conn::open()?.call(Request::Untrust { id })?)
}

pub fn watch() -> Result<()> {
    let mut conn = Conn::open()?;
    expect_ok(conn.call(Request::Subscribe)?)?;
    println!("watching vogterd events (ctrl-c to stop)");
    loop {
        if let Message::Event(e) = conn.next()? {
            println!("{}", describe(&e));
        }
    }
}

fn describe(e: &LoggedEvent) -> String {
    let what = match &e.event {
        Event::ScanCompleted {
            findings,
            new,
            resolved,
            baseline,
        } => {
            format!(
                "scan: {findings} findings, {new} new, {resolved} resolved{}",
                if *baseline { " (baseline)" } else { "" }
            )
        }
        Event::NewFinding { finding } => format!(
            "NEW [{}] {}",
            finding.finding.severity.as_str(),
            finding.finding.title
        ),
        Event::Resolved { title, .. } => format!("gone: {title}"),
        Event::Activity { activity: a } => {
            let mut line = format!("[{}] {}", a.severity.as_str(), a.summary);
            if let Some(d) = &a.detail {
                line.push_str(&format!("\n      {}", d.replace('\n', "\n      ")));
            }
            line
        }
        Event::MicrophoneOn { clients } => {
            let who: Vec<_> = clients
                .iter()
                .map(|c| format!("{} ({})", c.name, c.pid))
                .collect();
            format!(
                "MICROPHONE ON: {}",
                if who.is_empty() {
                    "unknown app".into()
                } else {
                    who.join(", ")
                }
            )
        }
        Event::MicrophoneOff => "microphone off".into(),
        Event::CameraOn => "CAMERA ON".into(),
        Event::CameraOff => "camera off".into(),
    };
    format!("{} {what}", ago(e.at))
}

fn ago(t: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(t);
    let s = now.saturating_sub(t);
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86400),
    }
}
