use super::*;
fn work() -> PathBuf {
    PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
}
fn protected_temp() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work())
        .unwrap()
}
const ID: &str = "11111111111111111111111111111111";
#[test]
fn restart_preserves_uncertainty_and_never_queues_the_original_plan_again() {
    let _fork_guard = crate::LOCK_FIXTURE_GUARD.lock().unwrap();
    let temp = protected_temp();
    let owner = enzimos_platform::process_identity::effective_uid();
    let mut store = Store::open_owned(temp.path(), owner, || Ok(())).unwrap();
    let planned = store
        .plan(ID, owner, "backup-create", || Ok(value!({"server":"made"})))
        .unwrap();
    let sha = planned["plan_sha256"].as_str().unwrap();
    store
        .advance(ID, owner, sha, "queued", "queued", Value::Null)
        .unwrap();
    drop(store);
    let mut store = Store::open_owned(temp.path(), owner, || Ok(())).unwrap();
    assert_eq!(store.status(ID, owner).unwrap()["state"], "uncertain");
    assert!(
        store
            .advance(ID, owner, sha, "queued", "queued", Value::Null)
            .is_err()
    );
    assert!(store.status(ID, owner + 1).is_err());
    assert_eq!(
        store
            .plan(ID, owner, "backup-create", || panic!("never replay plan"))
            .unwrap()["state"],
        "uncertain"
    );
}
