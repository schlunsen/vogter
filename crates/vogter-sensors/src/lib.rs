//! Sensors that gather raw facts about this Mac into a [`Snapshot`].
//!
//! Everything here works without the Endpoint Security entitlement. Running as
//! root (and with Full Disk Access) increases visibility.

pub mod av;
pub mod codesign;
pub mod downloads;
pub mod eventtap;
pub mod hash;
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
    let mut errors = Vec::new();
    let mut fail = |sensor: &str, message: String, covers: &[&str], source: Option<String>| {
        errors.push(SensorError {
            sensor: sensor.into(),
            message,
            covers: covers.iter().map(|c| c.to_string()).collect(),
            source,
        });
    };

    let processes = process::collect().unwrap_or_else(|e| {
        // Taps and listeners are attributed through the process list, so they're unknown too.
        fail(
            "process",
            e,
            &["process.", "keylogger.event_tap", "network."],
            None,
        );
        Vec::new()
    });
    let event_taps = eventtap::collect().unwrap_or_else(|e| {
        fail("event_tap", e, &["keylogger.event_tap"], None);
        Vec::new()
    });

    let mut errs = Vec::new();
    let tcc_grants = tcc::collect(&mut errs);
    // TCC checks are `tcc.<service>`; Input Monitoring etc. are among them.
    errs.drain(..)
        .for_each(|(src, e)| fail("tcc", e, &["tcc."], Some(src)));
    let launch_items = persistence::launch_items(&mut errs);
    errs.drain(..)
        .for_each(|(src, e)| fail("launchd", e, &["persistence."], Some(src)));
    let cron_entries = persistence::cron().unwrap_or_else(|e| {
        fail("cron", e, &["persistence.cron"], None);
        Vec::new()
    });
    let health = health::collect();
    for (known, check) in [
        (health.sip_enabled.is_some(), "health.sip"),
        (health.gatekeeper_enabled.is_some(), "health.gatekeeper"),
        (health.filevault_enabled.is_some(), "health.filevault"),
        (health.firewall_enabled.is_some(), "health.firewall"),
        (health.remote_login.is_some(), "health.remote_login"),
        (health.screen_sharing.is_some(), "health.screen_sharing"),
    ] {
        if !known {
            fail(
                "health",
                format!("{check} could not be determined"),
                &[check],
                None,
            );
        }
    }

    snap.sensor_errors = errors;
    snap.listeners = network::collect(&processes);
    snap.processes = processes;
    snap.event_taps = event_taps;
    snap.tcc_grants = tcc_grants;
    snap.launch_items = launch_items;
    snap.cron_entries = cron_entries;
    snap.health = health;
    snap
}
