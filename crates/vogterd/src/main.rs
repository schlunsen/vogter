//! `vogterd`: the Vogter background service.
//!
//! Rescans the Mac on a timer, keeps history in SQLite, watches the microphone
//! and camera, and serves clients (the menu bar app, `vogter status`) over a
//! Unix socket. Runs as root in production (LaunchDaemon) or as your user
//! during development.

mod daemon;
mod server;

use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use daemon::Daemon;
use vogter_store::Store;

#[derive(Parser)]
#[command(name = "vogterd", version, about = "Vogter background service")]
struct Args {
    /// Unix socket to listen on [default: /var/run/vogter.sock as root, else ~/Library/Application Support/Vogter/vogter.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    /// SQLite database [default: <data dir>/vogter.db]
    #[arg(long)]
    db: Option<PathBuf>,
    /// Seconds between full scans.
    #[arg(long, default_value_t = 300)]
    interval: u64,
    /// Milliseconds between microphone/camera checks.
    #[arg(long, default_value_t = 1000)]
    av_poll_ms: u64,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let args = Args::parse();

    // SAFETY: geteuid has no preconditions.
    let as_root = unsafe { libc::geteuid() } == 0;
    let data_dir = if as_root {
        PathBuf::from("/Library/Application Support/Vogter")
    } else {
        PathBuf::from(std::env::var("HOME").context("HOME not set")?)
            .join("Library/Application Support/Vogter")
    };
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating {}", data_dir.display()))?;
    let socket = args.socket.unwrap_or_else(|| {
        if as_root {
            PathBuf::from(vogter_ipc::SYSTEM_SOCKET)
        } else {
            data_dir.join("vogter.sock")
        }
    });
    let db = args.db.unwrap_or_else(|| data_dir.join("vogter.db"));

    let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
    let (scan_tx, scan_rx) = mpsc::channel();
    let daemon = Arc::new(Daemon::new(
        store,
        Duration::from_secs(args.interval),
        as_root,
        scan_tx,
    ));
    tracing::info!(db = %db.display(), socket = %socket.display(), as_root, "vogterd starting");

    let d = daemon.clone();
    thread::Builder::new()
        .name("scanner".into())
        .spawn(move || d.scan_loop(scan_rx))?;
    let d = daemon.clone();
    let poll = Duration::from_millis(args.av_poll_ms);
    thread::Builder::new()
        .name("av".into())
        .spawn(move || d.av_loop(poll))?;

    server::run(&socket, daemon)
}
