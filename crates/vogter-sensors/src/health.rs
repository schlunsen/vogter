//! Status of macOS' built-in protections.

use std::process::Command;
use vogter_model::Health;

const XPROTECT_PLIST: &str =
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";

pub fn collect() -> Health {
    let listening = listening_ports();
    let has = |ports: &[u16]| {
        listening
            .as_ref()
            .map(|l| ports.iter().any(|p| l.contains(p)))
    };
    Health {
        remote_login: has(&[22]),
        screen_sharing: has(&[5900, 3283]),
        sip_enabled: run("/usr/bin/csrutil", &["status"]).map(|o| o.contains("enabled.")),
        gatekeeper_enabled: run("/usr/sbin/spctl", &["--status"])
            .map(|o| o.contains("assessments enabled")),
        filevault_enabled: run("/usr/bin/fdesetup", &["status"])
            .map(|o| o.contains("FileVault is On")),
        firewall_enabled: run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
        )
        .map(|o| o.contains("enabled")),
        xprotect_version: plist::Value::from_file(XPROTECT_PLIST).ok().and_then(|v| {
            v.as_dictionary()?
                .get("CFBundleShortVersionString")?
                .as_string()
                .map(str::to_string)
        }),
    }
}

/// TCP ports with a listening socket, from `netstat` (sees root-owned sockets
/// such as launchd's on-demand sshd without needing root).
fn listening_ports() -> Option<Vec<u16>> {
    let out = run("/usr/sbin/netstat", &["-anp", "tcp"])?;
    Some(parse_listening(&out))
}

fn parse_listening(netstat: &str) -> Vec<u16> {
    netstat
        .lines()
        .filter(|l| l.split_whitespace().last() == Some("LISTEN"))
        .filter_map(|l| l.split_whitespace().nth(3))
        .filter_map(|addr| addr.rsplit('.').next()?.parse().ok())
        .collect()
}

/// Run a command and return stdout+stderr, or None if it could not run.
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_netstat() {
        let out = "Active Internet connections (including servers)\n\
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
tcp4       0      0  *.22                   *.*                    LISTEN\n\
tcp6       0      0  *.5900                 *.*                    LISTEN\n\
tcp4       0      0  192.168.1.2.51000      17.1.1.1.443           ESTABLISHED\n";
        assert_eq!(super::parse_listening(out), [22, 5900]);
    }
}
