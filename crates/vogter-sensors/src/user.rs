//! Whose Mac are we guarding? As root, the user at the console; otherwise ourselves.

use std::ffi::CStr;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub name: String,
    pub home: String,
}

pub fn is_root() -> bool {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// The user whose home folder (permissions, launch agents, secrets) we watch.
pub fn target() -> Option<User> {
    let uid = if is_root() {
        // Owner of /dev/console is whoever is logged in at the screen (root at the login window).
        let uid = std::fs::metadata("/dev/console").ok()?.uid();
        if uid == 0 {
            return None;
        }
        uid
    } else {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() }
    };
    by_uid(uid)
}

fn by_uid(uid: u32) -> Option<User> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r with caller-owned storage.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success the fields point into `buf`.
    let (name, home) = unsafe { (CStr::from_ptr(pwd.pw_name), CStr::from_ptr(pwd.pw_dir)) };
    Some(User {
        uid,
        name: name.to_string_lossy().into_owned(),
        home: home.to_string_lossy().into_owned(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_current_user() {
        let u = super::target().expect("a user");
        assert!(u.home.starts_with('/'));
        assert!(!u.name.is_empty());
    }
}
