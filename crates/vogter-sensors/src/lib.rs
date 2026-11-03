//! Sensors that gather raw facts about this Mac into a [`Snapshot`].
//!
//! Everything here works without the Endpoint Security entitlement. Running as
//! root (and with Full Disk Access) increases visibility.

pub mod av;
pub mod codesign;
pub mod eventtap;
pub mod health;
pub mod network;
pub mod persistence;
pub mod process;
pub mod tcc;
pub mod user;

use std::time::{SystemTime, UNIX_EPOCH};
use vogter_model::{SensorError, Snapshot};

pub fn snapshot() -> Snapshot {
    let mut snap = Snapshot {
        taken_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        // SAFETY: geteuid has no preconditions.
        as_root: unsafe { libc::geteuid() } == 0,
        ..Default::default()
    };
    let mut fail = |sensor: &str, message: String| {
        snap.sensor_errors.push(SensorError {
            sensor: sensor.into(),
            message,
        });
    };

    let processes = process::collect().unwrap_or_else(|e| {
        fail("process", e);
        Vec::new()
    });
    let event_taps = eventtap::collect().unwrap_or_else(|e| {
        fail("event_tap", e);
        Vec::new()
    });

    let mut errs = Vec::new();
    let tcc_grants = tcc::collect(&mut errs);
    errs.drain(..).for_each(|e| fail("tcc", e));
    let launch_items = persistence::launch_items(&mut errs);
    errs.drain(..).for_each(|e| fail("launchd", e));

    snap.listeners = network::collect(&processes);
    snap.processes = processes;
    snap.event_taps = event_taps;
    snap.tcc_grants = tcc_grants;
    snap.launch_items = launch_items;
    snap.cron_entries = persistence::cron();
    snap.health = health::collect();
    snap
}
