//! Unix-socket server with peer authorization.
//!
//! A peer must be root, the daemon's own user, or the user logged in at the
//! console. When the daemon itself carries a developer Team ID (a signed
//! release), the peer must be signed by the same team, so other software on
//! the Mac cannot read findings or acknowledge them away.

use std::io::{BufReader, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::thread;

use anyhow::{Context, Result, bail};
use vogter_ipc::{Message, Request, read_line, write_line};
use vogter_model::{SignatureKind, Signing};
use vogter_sensors::codesign;

use crate::daemon::Daemon;

const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;

pub fn run(path: &Path, daemon: Arc<Daemon>) -> Result<()> {
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            bail!("another vogterd is already listening on {}", path.display());
        }
        std::fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // Root daemon: anyone may connect, authorization happens per connection.
    let mode = if daemon_is_root() { 0o666 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;

    let policy = Policy::current();
    tracing::info!(team = ?policy.team_id, "listening");
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("accept: {e}");
                continue;
            }
        };
        match policy.authorize(&stream) {
            Ok(peer) => {
                tracing::debug!(%peer, "client connected");
                let d = daemon.clone();
                thread::spawn(move || serve(stream, d));
            }
            Err(e) => tracing::warn!("rejected client: {e}"),
        }
    }
    Ok(())
}

fn serve(stream: UnixStream, daemon: Arc<Daemon>) {
    let Ok(mut writer) = stream.try_clone() else {
        return;
    };
    let (tx, rx) = mpsc::channel::<Message>();
    // One writer per connection so replies and pushed events never interleave.
    thread::spawn(move || {
        for msg in rx {
            if write_line(&mut writer, &msg).is_err() {
                break;
            }
        }
    });

    let mut reader = BufReader::new(&stream);
    loop {
        let reply = match read_line::<Request>(&mut reader) {
            Ok(Some(Request::Subscribe)) => {
                daemon.subscribe(tx.clone());
                Message::Ok
            }
            Ok(Some(req)) => daemon.handle(req),
            Ok(None) => break,
            Err(e) if e.kind() == ErrorKind::Other => Message::Error {
                message: format!("bad request: {e}"),
            },
            Err(_) => break,
        };
        if tx.send(reply).is_err() {
            break;
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

struct Policy {
    own_uid: u32,
    team_id: Option<String>,
}

impl Policy {
    fn current() -> Self {
        // SAFETY: no preconditions.
        let own_uid = unsafe { libc::geteuid() };
        let me = codesign::for_pid(std::process::id() as i32, None);
        let team_id = (me.kind == SignatureKind::ThirdParty)
            .then_some(me.team_id)
            .flatten();
        Policy { own_uid, team_id }
    }

    fn authorize(&self, stream: &UnixStream) -> Result<String> {
        let fd = stream.as_raw_fd();
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: valid socket fd and out-pointers.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            bail!("getpeereid: {}", std::io::Error::last_os_error());
        }
        if uid != 0 && uid != self.own_uid && Some(uid) != console_uid() {
            bail!("uid {uid} is not allowed");
        }

        let mut token = [0u8; 32];
        let mut len = token.len() as libc::socklen_t;
        // SAFETY: `token` is a 32-byte audit_token_t buffer.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        };
        let signing = if rc == 0 {
            codesign::for_audit_token(&token)
        } else {
            Signing::unknown()
        };

        if let Some(team) = &self.team_id {
            check_team(team, &signing).map_err(|why| anyhow::anyhow!("uid {uid}: {why}"))?;
        }
        Ok(format!("uid {uid}, {}", signing.describe()))
    }
}

/// A signed daemon only talks to peers with a *valid* developer signature from
/// its own team. The Team ID alone isn't enough: an invalid or untrusted
/// signature can still carry the team identifier it claims.
fn check_team(team: &str, peer: &Signing) -> std::result::Result<(), String> {
    if peer.kind != SignatureKind::ThirdParty {
        return Err(format!(
            "peer is {}, not validly signed by team {team}",
            peer.describe()
        ));
    }
    if peer.team_id.as_deref() != Some(team) {
        return Err(format!("peer is {}, expected team {team}", peer.describe()));
    }
    Ok(())
}

fn daemon_is_root() -> bool {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Owner of /dev/console, i.e. the user logged in at the screen.
fn console_uid() -> Option<u32> {
    std::fs::metadata("/dev/console").ok().map(|m| m.uid())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(kind: SignatureKind, team: Option<&str>) -> Signing {
        Signing {
            kind,
            identifier: None,
            team_id: team.map(str::to_string),
            notarized: false,
        }
    }

    #[test]
    fn team_check_requires_valid_signature() {
        assert!(check_team("T", &sig(SignatureKind::ThirdParty, Some("T"))).is_ok());
        assert!(check_team("T", &sig(SignatureKind::ThirdParty, Some("X"))).is_err());
        // Claimed team on a broken or non-Apple-anchored signature must not pass.
        assert!(check_team("T", &sig(SignatureKind::Invalid, Some("T"))).is_err());
        assert!(check_team("T", &sig(SignatureKind::Untrusted, Some("T"))).is_err());
        assert!(check_team("T", &sig(SignatureKind::AdHoc, Some("T"))).is_err());
        assert!(check_team("T", &sig(SignatureKind::Unknown, None)).is_err());
    }
}
