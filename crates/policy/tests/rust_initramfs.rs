// SPDX-License-Identifier: MIT
use enzimos_policy::initramfs;
fn base(body: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(
        initramfs::newc("init", body, 0o100755).unwrap().as_slice(),
        3,
    )
    .unwrap()
}
#[test]
fn private_key_append_keeps_key_only_in_a_ram_archive_with_private_mode() {
    let key = zeroize::Zeroizing::new(b"fixture-unlock-secret".to_vec());
    let base = base(b"native fixture");
    let appended =
        initramfs::append_private(&base, "enzimos-recovery-unlock.key", &key, 0o100600).unwrap();
    let start = base.len().next_multiple_of(4);
    let archive = &appended[start..];
    assert_eq!(&archive[14..22], b"00008180");
    assert!(archive.windows(key.len()).any(|s| s == key.as_slice()));
    assert_eq!(&appended[..base.len()], base.as_slice());
}
