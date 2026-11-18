// SPDX-License-Identifier: MIT
use enzimos_platform::{files, json, stream_copy};
use std::{
    io::Cursor,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn streams_empty_and_executable_members_with_actual_modes_and_refuses_false_digests() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        ))
        .unwrap();
    let owner = unsafe { libc::geteuid() };
    let parent = files::directory(temp.path(), Some(owner)).unwrap();
    let file = stream_copy::verified_reader(
        &mut Cursor::new(b"executable"),
        &parent,
        "app",
        10,
        &json::sha256(b"executable"),
        0o755,
        owner,
        false,
    )
    .unwrap();
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o755);
    stream_copy::verified_reader(
        &mut Cursor::new(b""),
        &parent,
        "empty",
        0,
        &json::sha256(b""),
        0o644,
        owner,
        false,
    )
    .unwrap();
    assert!(
        stream_copy::verified_reader(
            &mut Cursor::new(b"evil"),
            &parent,
            "bad",
            4,
            &json::sha256(b"good"),
            0o644,
            owner,
            false
        )
        .is_err()
    );
    assert!(!temp.path().join("bad").exists());
    for mode in [0o400, 0o440, 0o444] {
        let name = format!("readonly-{mode:o}");
        let output = stream_copy::verified_reader(
            &mut Cursor::new(b"restricted"),
            &parent,
            &name,
            10,
            &json::sha256(b"restricted"),
            mode,
            owner,
            false,
        )
        .unwrap();
        assert_eq!(output.metadata().unwrap().mode() & 0o7777, mode);
        assert_eq!(
            std::fs::read(temp.path().join(name)).unwrap(),
            b"restricted"
        );
    }
    for mode in [0o666, 0o775, 0o4755, 0o2644] {
        let name = format!("unsafe-{mode:o}");
        assert!(
            stream_copy::verified_reader(
                &mut Cursor::new(b"restricted"),
                &parent,
                &name,
                10,
                &json::sha256(b"restricted"),
                mode,
                owner,
                false,
            )
            .is_err()
        );
        assert!(!temp.path().join(name).exists());
    }
}
