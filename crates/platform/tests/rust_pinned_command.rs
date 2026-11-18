// SPDX-License-Identifier: MIT
use enzimos_platform::process;
use std::{fs::File, os::unix::fs::PermissionsExt, time::Duration};
#[test]
fn native_commands_execute_retained_bytes_even_after_their_filename_is_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("image");
    std::fs::copy("/usr/bin/false", &image).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
    let retained = File::open(&image).unwrap();
    std::fs::rename(&image, directory.path().join("retained-old")).unwrap();
    std::fs::copy("/usr/bin/true", &image).unwrap();
    let result = process::run_pinned(
        "/usr/bin/false",
        &retained,
        &[],
        &[],
        Duration::from_secs(2),
        1024,
        &[],
    )
    .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(
        process::run_pinned(
            "/unregistered/native",
            &retained,
            &[],
            &[],
            Duration::from_secs(2),
            1024,
            &[]
        )
        .is_err()
    );
    let script = directory.path().join("script");
    std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        process::run_pinned(
            "/usr/bin/false",
            &File::open(script).unwrap(),
            &[],
            &[],
            Duration::from_secs(2),
            1024,
            &[]
        )
        .is_err()
    );
}
