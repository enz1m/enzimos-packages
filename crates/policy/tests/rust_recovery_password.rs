// SPDX-License-Identifier: MIT
//! Actual renderer and refusal boundaries using synthetic immutable inputs only.
use enzimos_platform::memfile;
use enzimos_policy::backup_recovery_save;
use std::{
    io::{Seek, SeekFrom},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
};
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (lseek).")]
fn save_refuses_installed_filesystem_and_existing_output_before_copying_or_changing_offset() {
    let work = std::path::Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    let mut source = memfile::sealed("synthetic-save-password", b"Synthetic42").unwrap();
    source.seek(SeekFrom::Start(3)).unwrap();
    let observer = source.try_clone().unwrap();
    assert!(
        backup_recovery_save::save(
            source,
            dir.path(),
            "password.txt",
            "11111111-1111-4111-8111-111111111111"
        )
        .is_err()
    );
    assert!(!dir.path().join("password.txt").exists());
    assert_eq!(
        unsafe { libc::lseek(observer.as_raw_fd(), 0, libc::SEEK_CUR) },
        3
    );
    let existing = dir.path().join("existing");
    std::fs::write(&existing, b"untouched").unwrap();
    let source = memfile::sealed("synthetic-save-existing", b"Synthetic42").unwrap();
    assert!(
        backup_recovery_save::save(
            source,
            dir.path(),
            "existing",
            "11111111-1111-4111-8111-111111111111"
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&existing).unwrap(), b"untouched");
    let source = memfile::sealed("synthetic-save-traversal", b"Synthetic42").unwrap();
    assert!(
        backup_recovery_save::save(
            source,
            dir.path(),
            "../output",
            "11111111-1111-4111-8111-111111111111"
        )
        .is_err()
    );
}
