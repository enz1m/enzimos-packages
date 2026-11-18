// SPDX-License-Identifier: MIT
use enzimos_policy::{generation_stage, initramfs};
#[test]
fn native_initrd_inventory_refuses_other_releases_hidden_frames_and_truncation() {
    let first = initramfs::newc(
        "usr/lib/modules/6.18.1/kernel/test.ko",
        b"module",
        libc::S_IFREG | 0o644,
    )
    .unwrap();
    let body = zstd::stream::encode_all(first.as_slice(), 3).unwrap();
    generation_stage::initrd_release(&body, "6.18.1").unwrap();
    assert!(generation_stage::initrd_release(&body, "6.12.9").is_err());
    let mut hidden = body.clone();
    hidden.extend_from_slice(&body);
    assert!(generation_stage::initrd_release(&hidden, "6.18.1").is_err());
    let trailer = first
        .windows(b"TRAILER!!!".len())
        .position(|part| part == b"TRAILER!!!")
        .unwrap()
        - 110;
    let mut mixed = first[..trailer].to_vec();
    mixed.extend_from_slice(
        &initramfs::newc(
            "usr/lib/modules/6.12.9/kernel/other.ko",
            b"module",
            libc::S_IFREG | 0o644,
        )
        .unwrap(),
    );
    let mixed = zstd::stream::encode_all(mixed.as_slice(), 3).unwrap();
    assert!(generation_stage::initrd_release(&mixed, "6.18.1").is_err());
    assert!(generation_stage::initrd_release(&body[..body.len() / 2], "6.18.1").is_err());
}
