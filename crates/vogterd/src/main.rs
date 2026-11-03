//! `vogterd`: the Vogter background service.
//!
//! Rescans the Mac on a timer, keeps history in SQLite, watches the microphone
//! and camera, and serves clients (the menu bar app, `vogter status`) over a
//! Unix socket. Runs as root in production (LaunchDaemon) or as your user
//! during development.

mod daemon;
mod server;
mod watch;

use std::path::{Path, PathBuf};
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
    /// Milliseconds between new-process checks (fallback watcher, without Endpoint Security).
    #[arg(long, default_value_t = 1000)]
    proc_poll_ms: u64,
    /// Don't try Endpoint Security, use the fallback watchers.
    #[arg(long)]
    no_endpoint_security: bool,
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
    // Monitoring history is sensitive: nothing we create may be readable by others.
    // SAFETY: umask has no preconditions.
    unsafe { libc::umask(0o077) };
    secure_dir(&data_dir)?;
    let socket = args.socket.clone().unwrap_or_else(|| {
        if as_root {
            PathBuf::from(vogter_ipc::SYSTEM_SOCKET)
        } else {
            data_dir.join("vogter.sock")
        }
    });
    let db = args
        .db
        .clone()
        .unwrap_or_else(|| data_dir.join("vogter.db"));

    let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
    secure_db_files(&db)?;
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

    let (signal_tx, signal_rx) = mpsc::channel();
    let d = daemon.clone();
    thread::Builder::new()
        .name("signals".into())
        .spawn(move || d.signal_loop(signal_rx))?;
    daemon.set_realtime(start_realtime(signal_tx, &args));

    server::run(&socket, daemon)
}

/// Create (or tighten) a private data directory: 0700, owned by us, not a symlink.
fn secure_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let meta = std::fs::symlink_metadata(dir)?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != me {
        anyhow::bail!(
            "{} must be a real directory owned by uid {me}; refusing to use it",
            dir.display()
        );
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing {}", dir.display()))
}

/// The database and SQLite's sidecar files must be private (0600).
fn secure_db_files(db: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let p = PathBuf::from(format!("{}{suffix}", db.display()));
        if p.exists() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("securing {}", p.display()))?;
        }
    }
    Ok(())
}

/// Start live sources: Endpoint Security when possible, polling fallbacks otherwise.
fn start_realtime(tx: mpsc::Sender<watch::Signal>, args: &Args) -> vogter_ipc::Realtime {
    let home = vogter_sensors::user::target().map(|u| u.home);
    let mut rt = vogter_ipc::Realtime::default();

    if args.no_endpoint_security {
        rt.endpoint_security_error = Some("disabled with --no-endpoint-security".into());
    } else {
        let (es_tx, es_rx) = mpsc::channel::<vogter_es::EsEvent>();
        match vogter_es::start(home.as_deref(), es_tx) {
            Ok(handle) => {
                // Re-target the secret-file watch when someone else logs in at the console.
                let mut current = home.clone();
                thread::spawn(move || {
                    loop {
                        thread::sleep(Duration::from_secs(5));
                        let now = vogter_sensors::user::target().map(|u| u.home);
                        if now != current {
                            handle.set_home(now.clone());
                            current = now;
                        }
                    }
                });
                let tx = tx.clone();
                thread::spawn(move || es_rx.into_iter().for_each(|e| drop(tx.send(e.into()))));
                rt.endpoint_security = true;
                rt.sources.push("endpoint_security".into());
            }
            Err(e) => {
                tracing::warn!("{e}; using fallback watchers");
                rt.endpoint_security_error = Some(e);
            }
        }
    }

    let mut start = |name: &str, result: Result<(), String>| match result {
        Ok(()) => rt.sources.push(name.into()),
        Err(e) => tracing::warn!(source = name, "not started: {e}"),
    };
    start("fs_events", watch::fs::spawn(tx.clone()));
    start("browser_extensions", watch::browser::spawn(tx.clone()));
    if !rt.endpoint_security {
        let every = Duration::from_millis(args.proc_poll_ms);
        start(
            "process_poll",
            watch::procs::spawn(tx.clone(), every).map_err(|e| e.to_string()),
        );
        start("session_notify", watch::session::spawn(tx.clone()));
        start(
            "sudo_log",
            watch::sudo::spawn(tx).map_err(|e| e.to_string()),
        );
    }
    tracing::info!(sources = ?rt.sources, "realtime sources");
    rt
}
