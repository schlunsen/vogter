//! Code-signature classification via Security.framework.
//!
//! Two entry points: [`for_pid`] asks the kernel about a *running* process
//! (cheap, and reflects what is actually executing), [`for_path`] checks a file
//! or bundle on disk. Results for paths are cached.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use core_foundation::base::{CFType, CFTypeRef, OSStatus, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::{CFURL, CFURLRef};
use vogter_model::{SignatureKind, Signing};

type SecCodeRef = *mut c_void;
type SecRequirementRef = *mut c_void;

const ERR_SUCCESS: OSStatus = 0;
const ERR_SEC_CS_UNSIGNED: OSStatus = -67062;
/// kSecCSSigningInformation
const CS_SIGNING_INFORMATION: u32 = 1 << 1;
/// kSecCSDoNotValidateResources: verify the signature and the executable's
/// contents, but skip hashing every resource file in a bundle (slow for big apps).
const CS_SKIP_RESOURCES: u32 = 1 << 2;
/// kSecCodeSignatureAdhoc
const SIG_FLAG_ADHOC: i64 = 0x2;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: CFStringRef;
    static kSecGuestAttributeAudit: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;

    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: SecRequirementRef,
    ) -> OSStatus;
    fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: u32, code: *mut SecCodeRef) -> OSStatus;
    fn SecStaticCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: SecRequirementRef,
    ) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        info: *mut CFDictionaryRef,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> OSStatus;
}

/// Compiled code requirements, created once. CF objects are immutable and safe to share.
struct Requirements {
    apple: SecRequirementRef,
    apple_generic: SecRequirementRef,
    notarized: SecRequirementRef,
}
unsafe impl Send for Requirements {}
unsafe impl Sync for Requirements {}

fn requirements() -> &'static Requirements {
    static REQS: OnceLock<Requirements> = OnceLock::new();
    REQS.get_or_init(|| {
        let make = |text: &str| {
            let s = CFString::new(text);
            let mut req: SecRequirementRef = std::ptr::null_mut();
            // SAFETY: valid CFString in, out-pointer to a local. Leaked on purpose (lives for the process).
            let status =
                unsafe { SecRequirementCreateWithString(s.as_concrete_TypeRef(), 0, &mut req) };
            if status == ERR_SUCCESS {
                req
            } else {
                std::ptr::null_mut()
            }
        };
        Requirements {
            apple: make("anchor apple"),
            apple_generic: make("anchor apple generic"),
            notarized: make("notarized"),
        }
    })
}

/// Owns a SecCode/SecStaticCode reference.
struct Code {
    raw: SecCodeRef,
    dynamic: bool,
}

impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: we own one retain count on `raw`.
        unsafe { core_foundation::base::CFRelease(self.raw as CFTypeRef) }
    }
}

impl Code {
    fn check(&self, req: SecRequirementRef) -> OSStatus {
        // SAFETY: `raw` is a live SecCode/SecStaticCode; `req` is null or a live requirement.
        unsafe {
            if self.dynamic {
                SecCodeCheckValidity(self.raw, 0, req)
            } else {
                SecStaticCodeCheckValidity(self.raw, CS_SKIP_RESOURCES, req)
            }
        }
    }

    fn satisfies(&self, req: SecRequirementRef) -> bool {
        !req.is_null() && self.check(req) == ERR_SUCCESS
    }

    fn classify(&self) -> Signing {
        let validity = self.check(std::ptr::null_mut());
        if validity == ERR_SEC_CS_UNSIGNED {
            return Signing {
                kind: SignatureKind::Unsigned,
                identifier: None,
                team_id: None,
                notarized: false,
            };
        }

        let (identifier, team_id, flags) = self.info();
        let mut signing = Signing {
            kind: SignatureKind::Invalid,
            identifier,
            team_id,
            notarized: false,
        };
        if validity != ERR_SUCCESS {
            return signing;
        }

        let reqs = requirements();
        signing.kind = if flags & SIG_FLAG_ADHOC != 0 {
            SignatureKind::AdHoc
        } else if self.satisfies(reqs.apple) {
            SignatureKind::Apple
        } else if self.satisfies(reqs.apple_generic) {
            signing.notarized = self.satisfies(reqs.notarized);
            SignatureKind::ThirdParty
        } else {
            SignatureKind::Untrusted
        };
        signing
    }

    fn info(&self) -> (Option<String>, Option<String>, i64) {
        let mut dict: CFDictionaryRef = std::ptr::null();
        // SAFETY: `raw` is live; on success we receive a +1 dictionary we wrap below.
        let status =
            unsafe { SecCodeCopySigningInformation(self.raw, CS_SIGNING_INFORMATION, &mut dict) };
        if status != ERR_SUCCESS || dict.is_null() {
            return (None, None, 0);
        }
        // SAFETY: Copy-rule return value, so we take ownership.
        let dict: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(dict) };
        let string = |key: CFStringRef| {
            // SAFETY: key is a framework-provided constant.
            let key = unsafe { CFString::wrap_under_get_rule(key) };
            dict.find(&key)
                .and_then(|v| v.downcast::<CFString>())
                .map(|s| s.to_string())
        };
        // SAFETY: framework constant.
        let flags_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) };
        let flags = dict
            .find(&flags_key)
            .and_then(|v| v.downcast::<CFNumber>())
            .and_then(|n| n.to_i64())
            .unwrap_or(0);
        // SAFETY: framework constants.
        unsafe {
            (
                string(kSecCodeInfoIdentifier),
                string(kSecCodeInfoTeamIdentifier),
                flags,
            )
        }
    }
}

/// Signature of a running process, as the kernel sees it. Falls back to the
/// on-disk executable if the dynamic lookup is refused.
///
/// A failed *dynamic* check is not proof of tampering: it also fails for a
/// process caught mid-launch or while exiting (seen on valid Apple tools such
/// as `git` and `sysctl`). So "invalid" is only reported when the file on disk
/// fails too.
pub fn for_pid(pid: i32, path: Option<&str>) -> Signing {
    // SAFETY: framework constant.
    let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
    let dynamic = guest(key, CFNumber::from(pid).as_CFType());
    match (dynamic, path) {
        (Some(d), Some(p)) if matches!(d.kind, SignatureKind::Invalid | SignatureKind::Unknown) => {
            let on_disk = for_path(p);
            if on_disk.kind == SignatureKind::Unknown {
                d
            } else {
                on_disk
            }
        }
        (Some(d), _) => d,
        (None, Some(p)) => for_path(p),
        (None, None) => Signing::unknown(),
    }
}

/// Signature of the process behind an audit token (e.g. a socket peer's
/// `LOCAL_PEERTOKEN`). Unlike a PID, a token cannot be recycled by another process.
pub fn for_audit_token(token: &[u8; 32]) -> Signing {
    // SAFETY: framework constant.
    let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributeAudit) };
    guest(key, CFData::from_buffer(token).as_CFType()).unwrap_or_else(Signing::unknown)
}

fn guest(key: CFString, value: CFType) -> Option<Signing> {
    let attrs = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value)]);
    let mut raw: SecCodeRef = std::ptr::null_mut();
    // SAFETY: valid dictionary in, out-pointer to a local.
    let status = unsafe {
        SecCodeCopyGuestWithAttributes(
            std::ptr::null_mut(),
            attrs.as_concrete_TypeRef(),
            0,
            &mut raw,
        )
    };
    (status == ERR_SUCCESS && !raw.is_null()).then(|| Code { raw, dynamic: true }.classify())
}

/// Signature of a file or bundle on disk (cached by path).
pub fn for_path(path: &str) -> Signing {
    static CACHE: OnceLock<Mutex<HashMap<String, Signing>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().unwrap().get(path) {
        return hit.clone();
    }

    let signing = match CFURL::from_path(path, std::path::Path::new(path).is_dir()) {
        Some(url) => {
            let mut raw: SecCodeRef = std::ptr::null_mut();
            // SAFETY: valid URL in, out-pointer to a local.
            let status =
                unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut raw) };
            if status == ERR_SUCCESS && !raw.is_null() {
                Code {
                    raw,
                    dynamic: false,
                }
                .classify()
            } else {
                Signing::unknown()
            }
        }
        None => Signing::unknown(),
    };
    cache
        .lock()
        .unwrap()
        .insert(path.to_string(), signing.clone());
    signing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_binary_is_apple() {
        assert_eq!(for_path("/bin/ls").kind, SignatureKind::Apple);
    }

    #[test]
    fn modified_binary_is_invalid() {
        let dir = std::env::temp_dir().join(format!("vogter-cs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("ls");
        std::fs::copy("/bin/ls", &copy).unwrap();
        // Flip a byte in the middle of every arm64 slice of this universal binary.
        // Only the slice this Mac runs is checked, and there can be several
        // (arm64e, arm64e.x1), so tamper with all of them.
        let mut bytes = std::fs::read(&copy).unwrap();
        let be = |b: &[u8], o: usize| u32::from_be_bytes(b[o..o + 4].try_into().unwrap()) as usize;
        assert_eq!(be(&bytes, 0), 0xcafe_babe, "expected a universal binary");
        let targets: Vec<usize> = (0..be(&bytes, 4))
            .map(|n| 8 + n * 20)
            .filter(|&o| be(&bytes, o) == 0x0100_000c) // CPU_TYPE_ARM64
            .map(|o| be(&bytes, o + 8) + be(&bytes, o + 12) / 2)
            .collect();
        assert!(!targets.is_empty(), "no arm64 slice");
        for i in targets {
            bytes[i] ^= 0xff;
        }
        std::fs::write(&copy, bytes).unwrap();
        assert_eq!(
            for_path(copy.to_str().unwrap()).kind,
            SignatureKind::Invalid
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn self_is_signed_somehow() {
        // Test binaries are linker-ad-hoc-signed on Apple Silicon.
        let me = for_pid(std::process::id() as i32, None);
        assert_ne!(me.kind, SignatureKind::Unknown);
    }
}
