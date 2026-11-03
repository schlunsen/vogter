//! Fallback lock/unlock detection via the BSD notifications loginwindow posts.

use std::ffi::{CString, c_char, c_int};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use vogter_model::{Activity, ActivityKind, Severity};

use super::Signal;

const LOCKED: &str = "com.apple.sessionagent.screenIsLocked";
const UNLOCKED: &str = "com.apple.sessionagent.screenIsUnlocked";

unsafe extern "C" {
    fn notify_register_check(name: *const c_char, out_token: *mut c_int) -> u32;
    fn notify_check(token: c_int, check: *mut c_int) -> u32;
}

/// A registered notification name we can poll.
pub struct Notification(c_int);

impl Notification {
    pub fn register(name: &str) -> Option<Self> {
        let name = CString::new(name).ok()?;
        let mut token = 0;
        // SAFETY: valid C string and out-pointer.
        if unsafe { notify_register_check(name.as_ptr(), &mut token) } != 0 {
            return None;
        }
        let n = Notification(token);
        n.fired(); // the first check always reports "changed"
        Some(n)
    }

    /// True if posted since the last call.
    pub fn fired(&self) -> bool {
        let mut check = 0;
        // SAFETY: token from notify_register_check.
        unsafe { notify_check(self.0, &mut check) == 0 && check != 0 }
    }
}

pub fn spawn(tx: Sender<Signal>) -> Result<(), String> {
    let locked = Notification::register(LOCKED).ok_or("notify_register_check failed")?;
    let unlocked = Notification::register(UNLOCKED).ok_or("notify_register_check failed")?;
    thread::Builder::new()
        .name("session-watch".into())
        .spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(1));
                for (n, kind, text) in [
                    (&locked, ActivityKind::ScreenLocked, "Screen locked"),
                    (&unlocked, ActivityKind::ScreenUnlocked, "Screen unlocked"),
                ] {
                    if n.fired()
                        && tx
                            .send(Signal::Activity(Activity::new(kind, Severity::Info, text)))
                            .is_err()
                    {
                        return;
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn notify_post(name: *const c_char) -> u32;
    }

    #[test]
    fn sees_a_posted_notification() {
        let name = format!("com.vogter.test.{}", std::process::id());
        let n = Notification::register(&name).unwrap();
        assert!(!n.fired());
        let c = CString::new(name).unwrap();
        // SAFETY: valid C string.
        unsafe { notify_post(c.as_ptr()) };
        // Delivery goes through notifyd, so it is not instantaneous.
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !n.fired() {
            assert!(
                std::time::Instant::now() < deadline,
                "notification never arrived"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!n.fired());
    }
}
