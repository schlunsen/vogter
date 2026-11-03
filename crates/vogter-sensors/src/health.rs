//! Status of macOS' built-in protections.

use std::process::Command;
use vogter_model::Health;

const XPROTECT_PLIST: &str =
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist";

pub fn collect() -> Health {
    Health {
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

/// Run a command and return stdout+stderr, or None if it could not run.
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(s)
}
