// SPDX-License-Identifier: MIT
//! UKI payload binding to the selected boot artifacts.
use enzimos_policy::secure_artifacts;
fn fixture() -> Vec<u8> {
    let mut body = vec![0; 512];
    body[..2].copy_from_slice(b"MZ");
    body[60..64].copy_from_slice(&64u32.to_le_bytes());
    body[64..68].copy_from_slice(b"PE\0\0");
    body[70..72].copy_from_slice(&3u16.to_le_bytes());
    for (i, name) in [b".linux".as_slice(), b".initrd", b".cmdline"]
        .iter()
        .enumerate()
    {
        let p = 88 + i * 40;
        body[p..p + name.len()].copy_from_slice(name);
        body[p + 8..p + 12].copy_from_slice(&4u32.to_le_bytes());
        body[p + 16..p + 20].copy_from_slice(&8u32.to_le_bytes());
        body[p + 20..p + 24].copy_from_slice(&(256u32 + i as u32 * 8).to_le_bytes());
        body[256 + i * 8..260 + i * 8].copy_from_slice(b"data");
    }
    body
}
#[test]
fn authenticated_uki_payloads_must_match_all_three_selected_artifacts() {
    let body = fixture();
    let digest = enzimos_platform::json::sha256(b"data");
    secure_artifacts::verify_payload(&body, &digest, &digest, "data").unwrap();
    for (kernel, initrd, options) in [
        (&"0".repeat(64), &digest, "data"),
        (&digest, &"0".repeat(64), "data"),
        (&digest, &digest, "different"),
    ] {
        assert!(secure_artifacts::verify_payload(&body, kernel, initrd, options).is_err());
    }
    let mut padded = body;
    padded[176..180].copy_from_slice(&7u32.to_le_bytes());
    padded[272..279].copy_from_slice(b"data\n\0\0");
    secure_artifacts::verify_payload(&padded, &digest, &digest, "data").unwrap();
    padded[274] = b'x';
    assert!(secure_artifacts::verify_payload(&padded, &digest, &digest, "data").is_err());
}
