// SPDX-License-Identifier: MIT
//! File overlay review and extraction.
use enzimos_platform::{files, json};
use enzimos_policy::file_overlay;
use serde_json::json as v;
use std::{
    fs::File,
    io::Cursor,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
fn archive(path: &Path, duplicate: bool, link: Option<&str>) -> File {
    let mut builder = tar::Builder::new(Vec::new());
    for _ in 0..if duplicate { 2 } else { 1 } {
        let mut header = tar::Header::new_gnu();
        header.set_size(7);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "./usr/bin/demo", Cursor::new(b"example"))
            .expect("test fixture");
    }
    if let Some(target) = link {
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_cksum();
        builder
            .append_link(&mut header, "./usr/bin/demo-link", target)
            .expect("test fixture");
    }
    builder.finish().expect("test fixture");
    let body =
        zstd::stream::encode_all(Cursor::new(builder.into_inner().expect("test fixture")), 1)
            .expect("test fixture");
    std::fs::write(path, body).expect("test fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("test fixture");
    File::open(path).expect("test fixture")
}
#[test]
fn reviews_complete_archive_then_streams_executable_and_internal_link_into_owned_target() {
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(PathBuf::from(
            std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        ))
        .unwrap();
    let input = archive(&temp.path().join("overlay.zst"), false, Some("demo"));
    let declared = v!({"usr/bin/demo":json::sha256(b"example")});
    let review = file_overlay::review(&input, &declared).unwrap();
    let target = temp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let owner = enzimos_platform::process_identity::effective_uid();
    let root = files::directory(&target, Some(owner)).unwrap();
    let receipt =
        file_overlay::extract(&input, &declared, &review, &root, owner, &mut || Ok(())).unwrap();
    assert_eq!(
        std::fs::read(target.join("usr/bin/demo")).unwrap(),
        b"example"
    );
    assert_eq!(
        std::fs::metadata(target.join("usr/bin/demo"))
            .unwrap()
            .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(
        std::fs::read_link(target.join("usr/bin/demo-link")).unwrap(),
        Path::new("demo")
    );
    assert_eq!(receipt["files"].as_object().unwrap().len(), 1);
    assert_eq!(receipt["schema"], 2);
    let (original, row) = file_overlay::capture(&root, "usr/bin/demo-link", owner).unwrap();
    assert_eq!(row, receipt["links"][0]);
    // Keep the old inode alive so an identical target cannot disguise replacement.
    std::fs::rename(
        target.join("usr/bin/demo-link"),
        target.join("usr/bin/old-link"),
    )
    .unwrap();
    std::os::unix::fs::symlink("demo", target.join("usr/bin/demo-link")).unwrap();
    let (_, replaced) = file_overlay::capture(&root, "usr/bin/demo-link", owner).unwrap();
    assert_eq!(row["target"], replaced["target"]);
    assert_ne!(row["inode"], replaced["inode"]);
    assert_eq!(
        original.metadata().unwrap().ino(),
        row["inode"][1].as_u64().unwrap()
    );
    // Observation of a known systemd mask remains no-follow, including /dev/null.
    std::os::unix::fs::symlink("/dev/null", target.join("usr/bin/mask")).unwrap();
    let (_, mask) = file_overlay::capture(&root, "usr/bin/mask", owner).unwrap();
    assert_eq!(mask["kind"], "symlink");
    assert_eq!(mask["target"], "/dev/null");
}
#[test]
fn rejects_duplicate_members_wrong_manifest_and_escaping_or_authority_links_before_extraction() {
    let temp = tempfile::tempdir_in(PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    ))
    .unwrap();
    let declared = v!({"usr/bin/demo":json::sha256(b"example")});
    let duplicate = archive(&temp.path().join("duplicate"), true, None);
    assert!(file_overlay::review(&duplicate, &declared).is_err());
    for (index, target) in [
        "../../../outside",
        "/proc/self/fd/9",
        "/var/lib/enzimos-control/key",
    ]
    .into_iter()
    .enumerate()
    {
        let input = archive(
            &temp.path().join(format!("bad{index}")),
            false,
            Some(target),
        );
        assert!(file_overlay::review(&input, &declared).is_err());
    }
    let input = archive(&temp.path().join("good"), false, None);
    assert!(file_overlay::review(&input, &v!({"usr/bin/demo":"0".repeat(64)})).is_err());
    assert!(file_overlay::review(&input, &v!({"usr/bin/other":json::sha256(b"example")})).is_err());
}
