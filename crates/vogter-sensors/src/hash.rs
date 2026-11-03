//! File content hashes, cached by (path, size, mtime).

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

type Stamp = (u64, SystemTime);

/// SHA-256 of a file as lowercase hex, or None if it can't be read.
pub fn sha256_file(path: &str) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Stamp, String)>>> = OnceLock::new();
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let stamp = (meta.len(), meta.modified().ok()?);
    let cache = CACHE.get_or_init(Default::default);
    if let Some((s, h)) = cache.lock().unwrap().get(path)
        && *s == stamp
    {
        return Some(h.clone());
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hex = hex::encode(hasher.finalize());
    cache
        .lock()
        .unwrap()
        .insert(path.to_string(), (stamp, hex.clone()));
    Some(hex)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hashes_and_notices_changes() {
        let dir = std::env::temp_dir().join(format!("vogter-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, b"abc").unwrap();
        let path = p.to_str().unwrap();
        assert_eq!(
            super::sha256_file(path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::write(&p, b"abcd").unwrap();
        assert_ne!(
            super::sha256_file(path).unwrap().as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
