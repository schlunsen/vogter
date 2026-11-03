//! Enumerates Quartz event taps — the standard way a user-space keylogger
//! reads keystrokes on macOS. Same technique as Objective-See's ReiKey.

use vogter_model::{EventTap, TapPoint};

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CGEventTapInformation {
    event_tap_id: u32,
    tap_point: u32,
    options: u32,
    events_of_interest: u64,
    tapping_process: i32,
    process_being_tapped: i32,
    enabled: bool,
    min_usec_latency: f32,
    avg_usec_latency: f32,
    max_usec_latency: f32,
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGGetEventTapList(max: u32, list: *mut CGEventTapInformation, count: *mut u32) -> i32;
}

const KEY_DOWN: u64 = 10;
const KEY_UP: u64 = 11;
const FLAGS_CHANGED: u64 = 12;
const KEYBOARD_MASK: u64 = (1 << KEY_DOWN) | (1 << KEY_UP) | (1 << FLAGS_CHANGED);
const OPTION_LISTEN_ONLY: u32 = 1;

pub fn collect() -> Result<Vec<EventTap>, String> {
    let mut count = 0u32;
    // SAFETY: a null list with max 0 only asks for the count.
    let err = unsafe { CGGetEventTapList(0, std::ptr::null_mut(), &mut count) };
    if err != 0 {
        return Err(format!("CGGetEventTapList failed ({err})"));
    }
    let mut list = vec![CGEventTapInformation::default(); count as usize];
    // SAFETY: `list` has room for `count` entries.
    let err = unsafe { CGGetEventTapList(count, list.as_mut_ptr(), &mut count) };
    if err != 0 {
        return Err(format!("CGGetEventTapList failed ({err})"));
    }
    list.truncate(count as usize);

    Ok(list
        .into_iter()
        .map(|t| EventTap {
            id: t.event_tap_id,
            tap_point: match t.tap_point {
                0 => TapPoint::Hid,
                1 => TapPoint::Session,
                2 => TapPoint::AnnotatedSession,
                _ => TapPoint::Unknown,
            },
            listen_only: t.options == OPTION_LISTEN_ONLY,
            enabled: t.enabled,
            events_of_interest: t.events_of_interest,
            keyboard: t.events_of_interest & KEYBOARD_MASK != 0,
            tapping_pid: t.tapping_process,
            target_pid: t.process_being_tapped,
        })
        .collect())
}
