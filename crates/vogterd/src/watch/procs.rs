//! Fallback process watcher: notice new processes by polling the process list.
//! Misses programs that live shorter than the poll interval; Endpoint Security doesn't.

use std::collections::HashSet;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use libproc::processes::{ProcFilter, pids_by_type};

use super::Signal;

fn pids() -> HashSet<i32> {
    pids_by_type(ProcFilter::All)
        .map(|v| v.into_iter().map(|p| p as i32).filter(|&p| p > 0).collect())
        .unwrap_or_default()
}

pub fn spawn(tx: Sender<Signal>, every: Duration) -> std::io::Result<()> {
    thread::Builder::new()
        .name("proc-watch".into())
        .spawn(move || {
            // Whatever runs at startup is the periodic scan's job.
            let mut seen = pids();
            loop {
                thread::sleep(every);
                let now = pids();
                for &pid in now.difference(&seen) {
                    if let Some(info) = vogter_sensors::process::exec_info(pid)
                        && tx.send(Signal::Exec(info)).is_err()
                    {
                        return;
                    }
                }
                seen = now;
            }
        })?;
    Ok(())
}
