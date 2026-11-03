use std::io::IsTerminal;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use vogter_model::{Finding, Severity, Snapshot};

#[derive(Parser)]
#[command(
    name = "vogter",
    version,
    about = "Watch this Mac for malware, keyloggers and misuse"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan the Mac and report findings.
    Scan {
        /// Lowest severity to show.
        #[arg(long, short = 's', default_value = "low")]
        min_severity: Severity,
        /// Print findings as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Dump raw sensor data as JSON (everything, or one section).
    Inventory {
        #[arg(value_enum)]
        section: Option<Section>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Section {
    Processes,
    Taps,
    Tcc,
    Launchd,
    Cron,
    Listeners,
    Health,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Scan { min_severity, json } => {
            let snap = vogter_sensors::snapshot();
            let findings: Vec<_> = vogter_detect::assess(&snap)
                .into_iter()
                .filter(|f| f.severity >= min_severity)
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                print_report(&snap, &findings, min_severity);
            }
        }
        Command::Inventory { section } => {
            let snap = vogter_sensors::snapshot();
            let value = match section {
                None => serde_json::to_value(&snap)?,
                Some(Section::Processes) => serde_json::to_value(&snap.processes)?,
                Some(Section::Taps) => serde_json::to_value(&snap.event_taps)?,
                Some(Section::Tcc) => serde_json::to_value(&snap.tcc_grants)?,
                Some(Section::Launchd) => serde_json::to_value(&snap.launch_items)?,
                Some(Section::Cron) => serde_json::to_value(&snap.cron_entries)?,
                Some(Section::Listeners) => serde_json::to_value(&snap.listeners)?,
                Some(Section::Health) => serde_json::to_value(&snap.health)?,
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
    }
    Ok(())
}

fn print_report(snap: &Snapshot, findings: &[Finding], min: Severity) {
    let color = std::io::stdout().is_terminal();
    let paint = |sev: Severity, text: &str| -> String {
        if !color {
            return text.to_string();
        }
        let code = match sev {
            Severity::Critical => "1;97;41",
            Severity::High => "1;31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    };

    println!(
        "Vogter scan: {} processes, {} event taps, {} permission grants, {} launch items, {} listeners{}",
        snap.processes.len(),
        snap.event_taps.len(),
        snap.tcc_grants.len(),
        snap.launch_items.len(),
        snap.listeners.len(),
        if snap.as_root { " (root)" } else { "" },
    );
    if let Some(v) = &snap.health.xprotect_version {
        println!("XProtect signatures: v{v}");
    }
    println!();

    if findings.is_empty() {
        println!("No findings at severity {} or above.", min.as_str());
    }
    for f in findings {
        let tag = format!("[{:^8}]", f.severity.as_str().to_uppercase());
        println!("{} {}", paint(f.severity, &tag), f.title);
        println!("           {}", f.detail);
        if let (Some(pid), Some(path)) = (f.pid, &f.path) {
            println!("           pid {pid}  {path}");
        } else if let Some(path) = &f.path {
            println!("           {path}");
        }
        println!();
    }

    if !snap.sensor_errors.is_empty() {
        println!("Limited visibility:");
        for e in &snap.sensor_errors {
            println!("  - {}: {}", e.sensor, e.message);
        }
    }
    if !snap.as_root {
        println!("Tip: `sudo vogter scan` also checks root processes and their sockets.");
    }
}
