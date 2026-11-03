//! Running processes with their code-signing status.

use libproc::bsd_info::BSDInfo;
use libproc::proc_pid::{name, pidinfo, pidpath};
use libproc::processes::{ProcFilter, pids_by_type};
use vogter_model::ProcessInfo;

use crate::codesign;

pub fn collect() -> Result<Vec<ProcessInfo>, String> {
    let pids = pids_by_type(ProcFilter::All).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(pids.len());
    for pid in pids.into_iter().map(|p| p as i32).filter(|&p| p > 0) {
        let Ok(info) = pidinfo::<BSDInfo>(pid, 0) else {
            continue;
        };
        let path = pidpath(pid).ok().filter(|p| !p.is_empty());
        let exe_exists = path
            .as_deref()
            .is_some_and(|p| std::path::Path::new(p).exists());
        let name = name(pid).ok().filter(|n| !n.is_empty()).unwrap_or_else(|| {
            path.as_deref()
                .and_then(|p| p.rsplit('/').next())
                .unwrap_or("?")
                .to_string()
        });
        let signing = codesign::for_pid(pid, path.as_deref().filter(|_| exe_exists));
        out.push(ProcessInfo {
            pid,
            ppid: info.pbi_ppid as i32,
            uid: info.pbi_uid,
            name,
            path,
            exe_exists,
            signing,
        });
    }
    Ok(out)
}
