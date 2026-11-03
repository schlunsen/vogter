//! Privacy permission grants from the TCC databases.
//!
//! Reading these databases requires Full Disk Access for the process doing the
//! scan (your terminal, or later the Vogter daemon).

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::TCFType;
use core_foundation::error::CFErrorRef;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::CFURL;
use rusqlite::{Connection, OpenFlags};
use vogter_model::{TccGrant, TccScope};

use crate::codesign;

const SYSTEM_DB: &str = "/Library/Application Support/com.apple.TCC/TCC.db";

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSCopyApplicationURLsForBundleIdentifier(
        bundle_id: CFStringRef,
        error: *mut CFErrorRef,
    ) -> CFArrayRef;
}

pub fn collect(errors: &mut Vec<String>) -> Vec<TccGrant> {
    let mut grants = Vec::new();
    let user_db = std::env::var("HOME")
        .map(|h| format!("{h}/Library/Application Support/com.apple.TCC/TCC.db"));
    let dbs = [
        (TccScope::System, Ok(SYSTEM_DB.to_string())),
        (TccScope::User, user_db),
    ];
    for (scope, path) in dbs {
        let Ok(path) = path else { continue };
        match read_db(&path, scope) {
            Ok(mut g) => grants.append(&mut g),
            Err(e) => errors.push(format!(
                "{path}: {e} (grant Full Disk Access to your terminal to read it)"
            )),
        }
    }
    for g in &mut grants {
        g.resolved_path = if g.client_is_path {
            Some(g.client.clone())
        } else {
            bundle_path(&g.client)
        };
        g.signing = g
            .resolved_path
            .as_deref()
            .filter(|p| std::path::Path::new(p).exists())
            .map(codesign::for_path);
    }
    grants
}

fn read_db(path: &str, scope: TccScope) -> Result<Vec<TccGrant>, String> {
    let conn = Connection::open_with_flags(
        format!("file:{path}?mode=ro"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT service, client, client_type, auth_value, last_modified FROM access")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(TccGrant {
                scope,
                service: r.get(0)?,
                client: r.get(1)?,
                client_is_path: r.get::<_, i64>(2)? == 1,
                allowed: matches!(r.get::<_, i64>(3)?, 2 | 3),
                last_modified: r.get(4)?,
                resolved_path: None,
                signing: None,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}

/// Resolve a bundle identifier to an installed app path via LaunchServices.
fn bundle_path(bundle_id: &str) -> Option<String> {
    let id = CFString::new(bundle_id);
    // SAFETY: valid CFString; null error pointer is allowed. Returns +1 array or null.
    let arr = unsafe {
        LSCopyApplicationURLsForBundleIdentifier(id.as_concrete_TypeRef(), std::ptr::null_mut())
    };
    if arr.is_null() {
        return None;
    }
    // SAFETY: Copy-rule return value.
    let arr: CFArray<CFURL> = unsafe { CFArray::wrap_under_create_rule(arr) };
    arr.iter()
        .next()
        .and_then(|u| u.to_path())
        .map(|p| p.display().to_string())
}

/// Human name for a TCC service.
pub fn service_label(service: &str) -> &str {
    match service {
        "kTCCServiceListenEvent" => "Input Monitoring",
        "kTCCServicePostEvent" => "Keystroke injection",
        "kTCCServiceAccessibility" => "Accessibility",
        "kTCCServiceScreenCapture" => "Screen Recording",
        "kTCCServiceSystemPolicyAllFiles" => "Full Disk Access",
        "kTCCServiceMicrophone" => "Microphone",
        "kTCCServiceCamera" => "Camera",
        "kTCCServiceAppleEvents" => "Automation",
        "kTCCServiceDeveloperTool" => "Developer Tool",
        "kTCCServiceEndpointSecurityClient" => "Endpoint Security",
        other => other.strip_prefix("kTCCService").unwrap_or(other),
    }
}
