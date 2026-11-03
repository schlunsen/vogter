//! Is the microphone or camera on right now, and who is recording audio?
//!
//! Microphone: CoreAudio's process objects (macOS 14+) say per process whether
//! it is capturing input. Camera: CoreMediaIO only says *that* a camera is in
//! use, not by whom; attribution needs Endpoint Security or the unified log.

use std::ffi::c_void;
use std::mem::size_of;

use vogter_model::{AudioClient, AvState};

type ObjectId = u32;
type OsStatus = i32;

#[repr(C)]
struct PropertyAddress {
    selector: u32,
    scope: u32,
    element: u32,
}

const fn fourcc(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

const SYSTEM_OBJECT: ObjectId = 1;
const SCOPE_GLOBAL: u32 = fourcc(b"glob");
const ELEMENT_MAIN: u32 = 0;

// CoreAudio selectors
const HW_PROCESS_OBJECT_LIST: u32 = fourcc(b"prs#");
const PROCESS_PID: u32 = fourcc(b"ppid");
const PROCESS_BUNDLE_ID: u32 = fourcc(b"pbid");
const PROCESS_IS_RUNNING_INPUT: u32 = fourcc(b"piri");
const HW_DEFAULT_INPUT_DEVICE: u32 = fourcc(b"dIn ");
const DEVICE_IS_RUNNING_SOMEWHERE: u32 = fourcc(b"gone");

// CoreMediaIO selectors
const CMIO_HW_DEVICES: u32 = fourcc(b"dev#");

#[link(name = "CoreAudio", kind = "framework")]
unsafe extern "C" {
    fn AudioObjectGetPropertyDataSize(
        object: ObjectId,
        address: *const PropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        size: *mut u32,
    ) -> OsStatus;
    fn AudioObjectGetPropertyData(
        object: ObjectId,
        address: *const PropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        size: *mut u32,
        data: *mut c_void,
    ) -> OsStatus;
}

#[link(name = "CoreMediaIO", kind = "framework")]
unsafe extern "C" {
    fn CMIOObjectGetPropertyDataSize(
        object: ObjectId,
        address: *const PropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        size: *mut u32,
    ) -> OsStatus;
    fn CMIOObjectGetPropertyData(
        object: ObjectId,
        address: *const PropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        size: u32,
        used: *mut u32,
        data: *mut c_void,
    ) -> OsStatus;
}

fn addr(selector: u32) -> PropertyAddress {
    PropertyAddress {
        selector,
        scope: SCOPE_GLOBAL,
        element: ELEMENT_MAIN,
    }
}

fn audio_scalar<T: Default + Copy>(object: ObjectId, selector: u32) -> Option<T> {
    let mut value = T::default();
    let mut size = size_of::<T>() as u32;
    // SAFETY: `value` is a properly sized out-buffer for a scalar property.
    let status = unsafe {
        AudioObjectGetPropertyData(
            object,
            &addr(selector),
            0,
            std::ptr::null(),
            &mut size,
            (&raw mut value).cast(),
        )
    };
    (status == 0).then_some(value)
}

fn audio_objects(object: ObjectId, selector: u32) -> Vec<ObjectId> {
    let a = addr(selector);
    let mut size = 0u32;
    // SAFETY: size query only.
    if unsafe { AudioObjectGetPropertyDataSize(object, &a, 0, std::ptr::null(), &mut size) } != 0 {
        return Vec::new();
    }
    let mut ids = vec![0 as ObjectId; size as usize / size_of::<ObjectId>()];
    // SAFETY: `ids` holds `size` bytes.
    let status = unsafe {
        AudioObjectGetPropertyData(
            object,
            &a,
            0,
            std::ptr::null(),
            &mut size,
            ids.as_mut_ptr().cast(),
        )
    };
    if status != 0 {
        return Vec::new();
    }
    ids.truncate(size as usize / size_of::<ObjectId>());
    ids
}

fn audio_string(object: ObjectId, selector: u32) -> Option<String> {
    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    let s: CFStringRef = audio_scalar::<usize>(object, selector)? as CFStringRef;
    if s.is_null() {
        return None;
    }
    // SAFETY: CoreAudio returns a +1 CFString for string properties.
    let s = unsafe { CFString::wrap_under_create_rule(s) }.to_string();
    (!s.is_empty()).then_some(s)
}

/// `None` when this macOS has no per-process audio objects (before 14).
fn microphone_clients() -> Option<Vec<AudioClient>> {
    let procs = audio_objects(SYSTEM_OBJECT, HW_PROCESS_OBJECT_LIST);
    if procs.is_empty() {
        return None;
    }
    let clients = procs
        .into_iter()
        .filter(|&p| audio_scalar::<u32>(p, PROCESS_IS_RUNNING_INPUT).unwrap_or(0) != 0)
        .filter_map(|p| {
            let pid = audio_scalar::<i32>(p, PROCESS_PID)?;
            let name = libproc::proc_pid::name(pid).unwrap_or_else(|_| format!("pid {pid}"));
            Some(AudioClient {
                pid,
                name,
                bundle_id: audio_string(p, PROCESS_BUNDLE_ID),
            })
        })
        .collect();
    Some(clients)
}

fn default_input_running() -> bool {
    audio_scalar::<u32>(SYSTEM_OBJECT, HW_DEFAULT_INPUT_DEVICE)
        .filter(|&d| d != 0)
        .and_then(|d| audio_scalar::<u32>(d, DEVICE_IS_RUNNING_SOMEWHERE))
        .is_some_and(|v| v != 0)
}

fn camera_in_use() -> bool {
    let a = addr(CMIO_HW_DEVICES);
    let mut size = 0u32;
    // SAFETY: size query only.
    if unsafe { CMIOObjectGetPropertyDataSize(SYSTEM_OBJECT, &a, 0, std::ptr::null(), &mut size) }
        != 0
    {
        return false;
    }
    let mut devices = vec![0 as ObjectId; size as usize / size_of::<ObjectId>()];
    let mut used = 0u32;
    // SAFETY: `devices` holds `size` bytes.
    let status = unsafe {
        CMIOObjectGetPropertyData(
            SYSTEM_OBJECT,
            &a,
            0,
            std::ptr::null(),
            size,
            &mut used,
            devices.as_mut_ptr().cast(),
        )
    };
    if status != 0 {
        return false;
    }
    devices.truncate(used as usize / size_of::<ObjectId>());
    devices.into_iter().any(|d| {
        let mut running = 0u32;
        let mut used = 0u32;
        // SAFETY: scalar u32 out-buffer.
        let status = unsafe {
            CMIOObjectGetPropertyData(
                d,
                &addr(DEVICE_IS_RUNNING_SOMEWHERE),
                0,
                std::ptr::null(),
                size_of::<u32>() as u32,
                &mut used,
                (&raw mut running).cast(),
            )
        };
        status == 0 && running != 0
    })
}

pub fn collect() -> AvState {
    // Prefer per-process state. The device-level "running" flag is also true when
    // a combined input/output device (USB interface, headset) is only playing audio.
    let (microphone_in_use, microphone_clients) = match microphone_clients() {
        Some(clients) => (!clients.is_empty(), clients),
        None => (default_input_running(), Vec::new()),
    };
    AvState {
        microphone_in_use,
        microphone_clients,
        camera_in_use: camera_in_use(),
    }
}

/// Print every CoreAudio process object (for `cargo run --example audio_debug`).
pub fn debug_dump() {
    const RUNNING_OUTPUT: u32 = fourcc(b"piro");
    let procs = audio_objects(SYSTEM_OBJECT, HW_PROCESS_OBJECT_LIST);
    println!("{} audio process objects", procs.len());
    for p in procs {
        let pid = audio_scalar::<i32>(p, PROCESS_PID).unwrap_or(-1);
        let input = audio_scalar::<u32>(p, PROCESS_IS_RUNNING_INPUT);
        let output = audio_scalar::<u32>(p, RUNNING_OUTPUT);
        let name = libproc::proc_pid::name(pid).unwrap_or_default();
        println!(
            "obj {p:>4} pid {pid:>6} {name:<28} input={input:?} output={output:?} bundle={:?}",
            audio_string(p, PROCESS_BUNDLE_ID)
        );
    }
    println!(
        "default input device running somewhere: {}",
        default_input_running()
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn collect_does_not_crash() {
        let s = super::collect();
        eprintln!("{s:?}");
    }
}
