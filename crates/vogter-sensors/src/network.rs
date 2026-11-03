//! Listening TCP/UDP sockets per process (what is accepting connections on this Mac).

use libproc::bsd_info::BSDInfo;
use libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
use libproc::net_info::{SocketFDInfo, SocketInfoKind, TcpSIState};
use libproc::proc_pid::{listpidinfo, pidinfo};
use std::net::{Ipv4Addr, Ipv6Addr};
use vogter_model::{Listener, ProcessInfo};

const INI_IPV4: u8 = 0x1;

pub fn collect(processes: &[ProcessInfo]) -> Vec<Listener> {
    let mut out = Vec::new();
    for p in processes {
        let Ok(info) = pidinfo::<BSDInfo>(p.pid, 0) else {
            continue;
        };
        let Ok(fds) = listpidinfo::<ListFDs>(p.pid, info.pbi_nfiles as usize) else {
            continue;
        };
        for fd in fds {
            if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                continue;
            }
            let Ok(sock) = pidfdinfo::<SocketFDInfo>(p.pid, fd.proc_fd) else {
                continue;
            };
            let si = &sock.psi;
            let (protocol, ini) = match SocketInfoKind::from(si.soi_kind) {
                SocketInfoKind::Tcp => {
                    // SAFETY: soi_kind says the union holds TCP info.
                    let tcp = unsafe { si.soi_proto.pri_tcp };
                    if !matches!(TcpSIState::from(tcp.tcpsi_state), TcpSIState::Listen) {
                        continue;
                    }
                    ("tcp", tcp.tcpsi_ini)
                }
                // Unconnected UDP sockets with a bound port are "listening".
                // SAFETY: soi_kind says the union holds generic inet info.
                SocketInfoKind::In if si.soi_protocol == libc::IPPROTO_UDP => {
                    let ini = unsafe { si.soi_proto.pri_in };
                    if ini.insi_fport != 0 {
                        continue;
                    }
                    ("udp", ini)
                }
                _ => continue,
            };
            let port = u16::from_be(ini.insi_lport as u16);
            if port == 0 {
                continue;
            }
            // SAFETY: insi_vflag selects which union member is valid.
            let address = unsafe {
                if ini.insi_vflag & INI_IPV4 != 0 {
                    Ipv4Addr::from(u32::from_be(ini.insi_laddr.ina_46.i46a_addr4.s_addr))
                        .to_string()
                } else {
                    Ipv6Addr::from(ini.insi_laddr.ina_6.s6_addr).to_string()
                }
            };
            out.push(Listener {
                pid: p.pid,
                process: p.name.clone(),
                protocol: protocol.into(),
                address,
                port,
            });
        }
    }
    out.sort_by(|a, b| (a.port, a.pid, &a.protocol).cmp(&(b.port, b.pid, &b.protocol)));
    out.dedup_by(|a, b| {
        a.port == b.port && a.pid == b.pid && a.protocol == b.protocol && a.address == b.address
    });
    out
}
