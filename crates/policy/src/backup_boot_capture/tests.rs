use super::*;

#[test]
fn actual_tree_copy_preserves_empty_files_and_refuses_changed_names_and_replay() {
    let work = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let temp = tempfile::tempdir_in(work).unwrap();
    let uid = enzimos_platform::process_identity::effective_uid();
    std::fs::create_dir(temp.path().join("source")).unwrap();
    std::fs::create_dir(temp.path().join("target")).unwrap();
    let src = temp.path().join("source");
    std::fs::create_dir(src.join("EFI")).unwrap();
    std::fs::write(src.join("EFI/boot.efi"), b"synthetic boot artifact").unwrap();
    std::fs::write(src.join("empty"), b"").unwrap();
    let source = files::directory(&src, Some(uid)).unwrap();
    let target = files::directory(&temp.path().join("target"), Some(uid)).unwrap();
    let original = Tree::scan(&source, uid, &mut || Ok(())).unwrap();
    let hashes = copy_tree(&original, &target, &mut || Ok(())).unwrap();
    assert_eq!(
        std::fs::read(temp.path().join("target/EFI/boot.efi")).unwrap(),
        b"synthetic boot artifact"
    );
    assert_eq!(
        std::fs::metadata(temp.path().join("target/empty"))
            .unwrap()
            .len(),
        0
    );
    assert!(hashes["EFI/boot.efi"].as_str().is_some());
    let original_time = std::fs::metadata(src.join("EFI/boot.efi")).unwrap();
    let copied_time = std::fs::metadata(temp.path().join("target/EFI/boot.efi")).unwrap();
    assert_eq!(
        (original_time.mtime(), original_time.mtime_nsec()),
        (copied_time.mtime(), copied_time.mtime_nsec())
    );
    assert!(copy_tree(&original, &target, &mut || Ok(())).is_err());
    std::fs::rename(src.join("EFI/boot.efi"), src.join("EFI/original")).unwrap();
    std::fs::write(src.join("EFI/boot.efi"), b"synthetic boot artifact").unwrap();
    assert!(original.recheck().is_err());
}
