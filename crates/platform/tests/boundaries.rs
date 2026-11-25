// SPDX-License-Identifier: MIT
//! Strict JSON decoding and descriptor walks that refuse symlinks and special files.
use enzimos_platform::{files, json};
use serde_json::json as value;
use std::time::{Duration, Instant};

#[test]
fn strict_json_refuses_ambiguous_authority_at_every_depth() {
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":{"uid":1,"uid":2}}"#,
        r#"{"uid":NaN}"#,
        r#"{} trailing"#,
    ] {
        assert!(json::decode(input.as_bytes(), 4096).is_err());
    }
    assert!(json::decode(&vec![b' '; 4097], 4096).is_err());
    assert!(json::decode("[".repeat(2000).as_bytes(), 4096).is_err());
    assert_eq!(
        json::canonical(&value!({"z":"é😀","a":1})).unwrap(),
        br#"{"a":1,"z":"\u00e9\ud83d\ude00"}"#
    );
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (mkfifo).")]
fn descriptor_walk_refuses_symlinks_and_special_files_without_blocking() {
    let path = std::env::temp_dir().join(format!(
        "enzimos-platform-test-{}",
        files::random_hex(16).unwrap()
    ));
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("regular"), b"{}").unwrap();
    std::os::unix::fs::symlink(path.join("regular"), path.join("link")).unwrap();
    std::os::unix::fs::symlink(&path, path.join("ancestor")).unwrap();
    let fifo = std::ffi::CString::new(path.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: `fifo` is a NUL-terminated CString.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let started = Instant::now();
    for name in ["link", "ancestor/regular", "fifo"] {
        assert!(files::read(&path.join(name), 4096, None, false).is_err());
    }
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        files::read(&path.join("regular"), 4096, None, false).unwrap(),
        b"{}"
    );
    files::atomic(&path.join("receipt"), b"first", 0o600, None, false).unwrap();
    assert!(files::atomic(&path.join("receipt"), b"replay", 0o600, None, false).is_err());
    assert_eq!(std::fs::read(path.join("receipt")).unwrap(), b"first");
    files::atomic(&path.join("receipt"), b"complete", 0o600, None, true).unwrap();
    assert_eq!(std::fs::read(path.join("receipt")).unwrap(), b"complete");
    std::fs::remove_dir_all(path).unwrap();
}
