//! Running processes with their code-signing status.

use libproc::bsd_info::BSDInfo;
use libproc::proc_pid::{name, pidinfo, pidpath};
use libproc::processes::{ProcFilter, pids_by_type};
use vogter_model::{ExecInfo, ProcessInfo};

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

/// Command-line arguments of a running process (KERN_PROCARGS2).
/// Needs root for other users' processes.
pub fn args(pid: i32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: size query with a null buffer.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    let mut buf = vec![0u8; size];
    // SAFETY: `buf` has `size` bytes.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    buf.truncate(size);
    parse_procargs(&buf)
}

/// Layout: argc (i32), exec path, NUL padding, argv[0..argc], env...
fn parse_procargs(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let mut rest = &buf[4..];
    let path_end = rest.iter().position(|&b| b == 0)?;
    rest = &rest[path_end..];
    let start = rest.iter().position(|&b| b != 0)?;
    rest = &rest[start..];
    Some(
        rest.split(|&b| b == 0)
            .take(argc)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect(),
    )
}

/// Everything the exec rules need about a running process.
pub fn exec_info(pid: i32) -> Option<ExecInfo> {
    let info = pidinfo::<BSDInfo>(pid, 0).ok()?;
    let path = pidpath(pid).ok().filter(|p| !p.is_empty())?;
    let exists = std::path::Path::new(&path).exists();
    let ppid = info.pbi_ppid as i32;
    Some(ExecInfo {
        pid,
        ppid,
        uid: info.pbi_uid,
        signing: codesign::for_pid(pid, exists.then_some(path.as_str())),
        args: args(pid).unwrap_or_default(),
        parent_path: pidpath(ppid).ok().filter(|p| !p.is_empty()),
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_own_args() {
        let me = args(std::process::id() as i32).expect("own args readable");
        assert!(me[0].contains("vogter_sensors"), "{me:?}");
    }

    #[test]
    fn parses_layout() {
        let mut buf = 2i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/bin/echo\0\0\0echo\0hi\0HOME=/x\0");
        assert_eq!(parse_procargs(&buf).unwrap(), ["echo", "hi"]);
    }

    #[test]
    fn exec_info_for_self() {
        let e = exec_info(std::process::id() as i32).unwrap();
        assert!(e.path.contains("vogter_sensors"));
        assert!(e.parent_path.is_some());
    }
}
