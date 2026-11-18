// SPDX-License-Identifier: MIT
use super::*;
use std::os::unix::fs::PermissionsExt;
fn fixture() -> tempfile::TempDir {
    let work = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap()
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn interrupted_original_setup_jobs_become_uncertain_and_never_replay() {
    let _fork_guard = crate::LOCK_FIXTURE_GUARD.lock().unwrap();
    let dir = fixture();
    let owner = unsafe { libc::geteuid() };
    let id = record::tests::ID;
    let mut store = SetupStore::open_owned(dir.path(), owner, || Ok(())).unwrap();
    let (review, created) = store
        .admit_review(id, 1000, &"a".repeat(64), "initialize")
        .unwrap();
    assert!(created);
    let (duplicate, created) = store
        .admit_review(id, 1000, &"a".repeat(64), "initialize")
        .unwrap();
    assert!(!created);
    assert_eq!(review, duplicate);
    assert!(
        store
            .admit_review(id, 1000, &"b".repeat(64), "initialize")
            .is_err()
    );
    let sha = review["plan_sha256"].as_str().unwrap();
    store.change(id, 1000, sha, "reviewing").unwrap();
    drop(store);
    let mut store = SetupStore::open_owned(dir.path(), owner, || Ok(())).unwrap();
    assert_eq!(store.status(id, 1000).unwrap()["state"], "uncertain");
    assert!(store.change(id, 1000, sha, "reviewing").is_err());
    assert!(store.status(id, 1001).is_err());
    assert_eq!(
        store
            .plan_review(id, 1000, &"a".repeat(64), "initialize")
            .unwrap()["state"],
        "uncertain"
    );
}
