mod client;

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
    /// Show the background service's status (requires vogterd running).
    Status,
    /// List the service's open findings.
    Findings {
        /// Include findings you acknowledged.
        #[arg(long)]
        all: bool,
    },
    /// Stream live events from the service.
    Watch,
    /// Mark a finding as known so it stops alerting (key from `vogter findings`).
    Ack { key: String },
    /// Ask the service to scan right away.
    ScanNow,
    /// Recent activity with ids (use an id with `vogter trust --event`).
    Events {
        #[arg(short = 'n', long, default_value_t = 30)]
        limit: u32,
    },
    /// Everything known about one event (id from `vogter events`).
    Show { id: i64 },
    /// Trust what a finding or activity is about, so it stops alerting.
    Trust {
        /// Finding key from `vogter findings`.
        key: Option<String>,
        /// Activity id from `vogter events`.
        #[arg(long, conflicts_with = "key")]
        event: Option<i64>,
        /// Trust it for every check, not just this one.
        #[arg(long)]
        all_checks: bool,
    },
    /// List trust rules.
    Trusted,
    /// Remove a trust rule (id from `vogter trusted`).
    Untrust { id: i64 },
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
    /// Shell startup files (commands only, secrets redacted).
    Shell,
    /// SSH authorized_keys.
    Ssh,
    Hosts,
    /// sudo rules (root only).
    Sudoers,
    /// Configuration profiles (Mac-wide ones need root).
    Profiles,
    /// Login and logout hooks.
    Hooks,
    /// System and kernel extensions.
    Extensions,
    /// Background Task Management items (root only).
    Btm,
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
                Some(Section::Shell) => serde_json::to_value(&snap.takeover.shell_files)?,
                Some(Section::Ssh) => serde_json::to_value(&snap.takeover.ssh_keys)?,
                Some(Section::Hosts) => serde_json::to_value(&snap.takeover.hosts)?,
                Some(Section::Sudoers) => serde_json::to_value(&snap.takeover.sudoers)?,
                Some(Section::Profiles) => serde_json::to_value(&snap.takeover.profiles)?,
                Some(Section::Hooks) => serde_json::to_value(&snap.takeover.login_hooks)?,
                Some(Section::Extensions) => serde_json::json!({
                    "system": snap.takeover.system_extensions,
                    "kernel": snap.takeover.kernel_extensions,
                }),
                Some(Section::Btm) => serde_json::to_value(&snap.takeover.background_items)?,
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::Status => client::status()?,
        Command::Findings { all } => client::findings(all)?,
        Command::Watch => client::watch()?,
        Command::Ack { key } => client::ack(key)?,
        Command::ScanNow => client::scan_now()?,
        Command::Events { limit } => client::events(limit)?,
        Command::Show { id } => client::show(id)?,
        Command::Trust {
            key,
            event,
            all_checks,
        } => client::trust(key, event, all_checks)?,
        Command::Trusted => client::trusted()?,
        Command::Untrust { id } => client::untrust(id)?,
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
