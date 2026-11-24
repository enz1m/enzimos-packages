// SPDX-License-Identifier: MIT
//! Shared existing-repository syntax. Outer operation codecs close their own fields.
//! Validation grants no caller, mount, credential, worker or cleanup authority.
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("existing repository text field required".into()))
}
fn document(v: &Value, path: &str) -> Result<()> {
    json::fields(v, "path inode mount sha256")?;
    require(
        v["path"] == path && v["mount"].as_u64().is_some_and(|n| n > 0),
        "closed transfer document role",
    )?;
    crate::backup_worker_request::file(&v["inode"])?;
    let m = &v["inode"];
    require(
        m[7].as_u64()
            .is_some_and(|n| n as u32 & libc::S_IFMT == libc::S_IFREG && n & 0o022 == 0)
            && m[8] == 0
            && m[9] == 0
            && m[10] == 1,
        "protected transfer public document",
    )?;
    crate::identity::sha(text(v, "sha256")?).map(|_| ())
}
/// The native backend caller of a transfer or copy context.
pub(crate) fn caller(v: &Value) -> Result<()> {
    let caller = &v["caller"];
    json::fields(
        caller,
        "pid start_ticks uid executable executable_sha256 image_epoch",
    )?;
    require(
        caller["pid"]
            .as_u64()
            .is_some_and(|n| (1..=i32::MAX as u64).contains(&n))
            && caller["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && caller["uid"] == 0
            && caller["executable"] == "/usr/lib/enzimos-backend/enzimos-system-backend",
        "original native backend transfer caller",
    )?;
    crate::identity::sha(text(caller, "executable_sha256")?)?;
    crate::backup_worker_request::file(&caller["image_epoch"])?;
    let image = &caller["image_epoch"];
    require(
        image[7] == (libc::S_IFREG | 0o755) && image[8] == 0 && image[9] == 0 && image[10] == 1,
        "protected native transfer caller image",
    )
}
/// The held operation lock of a transfer or copy context.
pub(crate) fn operation_lock(v: &Value) -> Result<()> {
    json::fields(v, "inode mount")?;
    crate::backup_worker_request::file(&v["inode"])?;
    let lock = &v["inode"];
    require(
        lock[2] == 0
            && lock[7] == (libc::S_IFREG | 0o600)
            && lock[8] == 0
            && lock[9] == 0
            && lock[10] == 1
            && v["mount"].as_u64().is_some_and(|n| n > 0),
        "original private operation lock",
    )
}
/// The fixed Restic image of a transfer or copy context.
pub(crate) fn restic(v: &Value) -> Result<()> {
    crate::settings_command::validate(v)?;
    require(
        v["path"] == "/usr/bin/restic",
        "fixed native transfer consumer",
    )
}
pub(crate) fn validate(v: &Value) -> Result<()> {
    caller(v)?;
    crate::backup_secret_persistence::root_binding(&v["source"])?;
    require(
        v["source"]["boot_id"] == v["boot_id"],
        "transfer source boot changed",
    )?;
    crate::backup_worker_request::directory(&v["root_directory"])?;
    crate::backup_worker_request::directory(&v["repository_directory"])?;
    require(
        v["root_directory"]["device"] == v["repository_directory"]["device"]
            && v["root_directory"]["mount"] == v["repository_directory"]["mount"]
            && v["root_directory"]["inode"] == 256
            && v["repository_directory"]["inode"] != 256,
        "transfer repository must be original child of top-level directory",
    )?;
    document(&v["configuration"], crate::backup_configuration::PATH)?;
    document(
        &v["pin"],
        "/var/lib/enzimos-control/backup-destination.json",
    )?;
    let destination = &v["destination"];
    json::fields(
        destination,
        "root repository repository_configuration unique_mount filesystem topology mount pin",
    )?;
    let filesystem = &destination["filesystem"];
    json::fields(filesystem, "filesystem_uuid members maximum_id")?;
    crate::identity::uuid(text(filesystem, "filesystem_uuid")?)?;
    require(
        filesystem["members"] == 1
            && filesystem["maximum_id"].as_u64().is_some_and(|n| n > 0)
            && filesystem["filesystem_uuid"] != v["source"]["configuration"]["filesystem_uuid"],
        "independent single-member transfer destination",
    )?;
    for (shape, directory) in [
        ("root", "root_directory"),
        ("repository", "repository_directory"),
    ] {
        let d = &v[directory];
        require(
            destination[shape]
                == serde_json::json!([d["device"], d["inode"], d["uid"], d["gid"], d["mode"]])
                && destination["unique_mount"] == d["mount"],
            "transfer directory differs from original destination",
        )?;
    }
    let mount = &destination["mount"];
    json::fields(
        mount,
        "id parent major minor root target filesystem options filesystem_options optional",
    )?;
    require(
        mount["id"].as_u64().is_some_and(|n| n > 0)
            && mount["target"] == "/backup-repository"
            && mount["root"] == "/"
            && mount["filesystem"] == "btrfs"
            && mount["optional"] == serde_json::json!([]),
        "closed private transfer repository mount",
    )?;
    let flags = text(mount, "options")?.split(',').collect::<BTreeSet<_>>();
    require(
        ["rw", "nodev", "nosuid", "noexec"]
            .iter()
            .all(|f| flags.contains(f))
            && !flags.contains("ro"),
        "protected writable transfer mount",
    )?;
    let pin = &destination["pin"];
    json::fields(
        pin,
        "schema filesystem_uuid fsroot repository repository_sha256",
    )?;
    require(
        pin["schema"] == 1
            && pin["filesystem_uuid"] == filesystem["filesystem_uuid"]
            && pin["fsroot"] == "/"
            && pin["repository"] == crate::backup_configuration::REPOSITORY,
        "original transfer repository pin",
    )?;
    crate::identity::sha(text(pin, "repository_sha256")?)?;
    require(
        destination["topology"].is_object(),
        "transfer topology object",
    )?;
    operation_lock(&v["operation_lock"])?;
    crate::backup_repository_header::validate(&v["header"])?;
    require(
        v["header"]["identity"] == destination["repository_configuration"]
            && v["header"]["identity"][0] == v["repository_directory"]["device"]
            && v["header"]["sha256"] == pin["repository_sha256"],
        "original encrypted transfer header/pin",
    )?;
    restic(&v["restic"])
}

pub(crate) fn intent(intent: &Value, limit: usize) -> Result<()> {
    json::fields(intent, "file mount parent bytes_sha256")?;
    crate::backup_worker_request::file(&intent["file"])?;
    let m = &intent["file"];
    require(
        m[7] == (libc::S_IFREG | 0o600)
            && m[8] == 0
            && m[9] == 0
            && m[10] == 1
            && m[2]
                .as_u64()
                .is_some_and(|n| (1..=limit as u64).contains(&n))
            && intent["mount"].as_u64().is_some_and(|n| n > 0),
        "original private transfer intent",
    )?;
    crate::identity::sha(text(intent, "bytes_sha256")?)?;
    let parent = intent["parent"]
        .as_array()
        .ok_or_else(|| Error("transfer intent parent shape".into()))?;
    require(
        parent.len() == 5
            && parent.iter().all(Value::is_u64)
            && parent[0].as_u64().is_some_and(|n| n > 0)
            && parent[1].as_u64().is_some_and(|n| n > 0)
            && parent[2] == (libc::S_IFDIR | 0o700)
            && parent[3] == 0
            && parent[4] == 0,
        "protected original transfer intent parent",
    )?;
    Ok(())
}
