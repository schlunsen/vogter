//! Code-signature classification via Security.framework.
//!
//! Two entry points: [`for_pid`] asks the kernel about a *running* process
//! (cheap, and reflects what is actually executing), [`for_path`] checks a file
//! or bundle on disk. Results for paths are cached.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use core_foundation::base::{CFType, CFTypeRef, OSStatus, TCFType};
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
/// kSecCSBasicValidateOnly: check the signature itself, skip hashing every resource.
const CS_BASIC_VALIDATE_ONLY: u32 = (1 << 1) | (1 << 2);
/// kSecCodeSignatureAdhoc
const SIG_FLAG_ADHOC: i64 = 0x2;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: CFStringRef;
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
                SecStaticCodeCheckValidity(self.raw, CS_BASIC_VALIDATE_ONLY, req)
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
pub fn for_pid(pid: i32, path: Option<&str>) -> Signing {
    // SAFETY: framework constant.
    let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
    let attrs =
        CFDictionary::from_CFType_pairs(&[(key.as_CFType(), CFNumber::from(pid).as_CFType())]);
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
    if status == ERR_SUCCESS && !raw.is_null() {
        return Code { raw, dynamic: true }.classify();
    }
    match path {
        Some(p) => for_path(p),
        None => Signing::unknown(),
    }
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
    fn self_is_signed_somehow() {
        // Test binaries are linker-ad-hoc-signed on Apple Silicon.
        let me = for_pid(std::process::id() as i32, None);
        assert_ne!(me.kind, SignatureKind::Unknown);
    }
}
