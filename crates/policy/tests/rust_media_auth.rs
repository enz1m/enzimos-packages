// SPDX-License-Identifier: MIT
use std::{
    io::Write,
    process::{Command, Stdio},
};
const HASH: &str = "$6$enzimOSfixture$npH0rF9W1/OhzJhIGxFD6dXGUBCbY35Lao6aq81V.cmUokbHdWj3AvueGuJBhc50hQqk13cMZarOazYglIIDv0";
#[test]
fn actual_confined_native_password_child_accepts_only_matching_bounded_frames() {
    let frame = |password: &[u8]| [password, b"\0", HASH.as_bytes(), b"\0"].concat();
    for (body, success) in [
        (frame(b"fixture-pass"), true),
        (frame(b"wrong"), false),
        (frame(&[b'x'; 512]), false),
        (b"malformed".to_vec(), false),
        (vec![b'x'; 1025], false),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_enzimos-media-auth"))
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&body).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.success(), success);
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
}
