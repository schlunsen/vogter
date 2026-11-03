//! Live sources. Each runs on its own thread and reports [`Signal`]s.
//!
//! With Endpoint Security available, it supplies process, session and sudo
//! events directly; otherwise the polling fallbacks here cover the same ground
//! with less fidelity (short-lived processes can be missed).

pub mod fs;
pub mod procs;
pub mod session;
pub mod sudo;

use vogter_es::EsEvent;
use vogter_model::{Activity, ExecInfo};

#[derive(Debug, Clone)]
pub enum Signal {
    Exec(ExecInfo),
    Activity(Activity),
    Rescan(&'static str),
}

impl From<EsEvent> for Signal {
    fn from(e: EsEvent) -> Self {
        match e {
            EsEvent::Exec(x) => Signal::Exec(x),
            EsEvent::Activity(a) => Signal::Activity(a),
            EsEvent::Rescan(r) => Signal::Rescan(r),
        }
    }
}
