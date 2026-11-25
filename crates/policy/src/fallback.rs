// SPDX-License-Identifier: MIT
//! New fallback creation: durable origin first; interrupted bytes are never adopted.
use crate::{
    birth_runtime::{self, Store},
    catalog, identity, operation, storage_runtime, subvolume,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("fallback configuration text".into()))
}
fn absent(path: &Path) -> Result<()> {
    require(
        matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "fallback destination or package lock already exists",
    )
}
fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error("fallback metadata encoding".into()))
}
fn inventory(root: Option<&Path>) -> Result<String> {
    let mut args = Vec::new();
    if let Some(root) = root {
        args.extend([
            "--root",
            root.to_str()
                .ok_or_else(|| Error("fallback path encoding".into()))?,
        ]);
    }
    args.push("-Q");
    let bytes = operation::query(
        "/usr/bin/pacman",
        &args,
        Duration::from_secs(30),
        catalog::MAX_CATALOG,
        &[0],
    )?;
    // Existing bounded_query strips surrounding whitespace before hashing.
    let body = utf8(&bytes)?.trim();
    require(
        !body.is_empty() && body.lines().count() <= 16384,
        "fallback inventory empty or excessive",
    )?;
    Ok(json::sha256(body.as_bytes()))
}
fn source(config: &Value) -> Result<(File, Value)> {
    absent(Path::new("/var/lib/pacman/db.lck"))?;
    let file = files::directory(Path::new("/"), Some(0))?;
    let normal = mount_identity::id(file.as_fd(), false)?;
    let expected = format!("/{}", text(config, "root_subvol")?);
    storage_runtime::mount_row(&storage_runtime::rows()?, "/", Some(&expected), normal)?;
    let body = files::read(Path::new("/etc/snapper/configs/root"), 65536, Some(0), true)?;
    let body = utf8(&body)?;
    for (key, expected) in [("SUBVOLUME", "/"), ("FSTYPE", "btrfs")] {
        let prefix = format!("{key}=");
        let fields = body
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix).map(str::trim))
            .collect::<Vec<_>>();
        require(
            fields == [format!("\"{expected}\"")],
            "unqualified root Snapper configuration",
        )?;
    }
    let (_, observed, readonly) = birth_runtime::observe(
        Path::new("/"),
        text(config, "root_subvol")?,
        text(config, "filesystem_uuid")?,
    )?;
    require(!readonly, "live source root is read-only")?;
    Ok((
        file,
        value!({"path":observed["path"],"id":observed["id"],"uuid":observed["uuid"],"ownership":"not-established"}),
    ))
}
fn no_pending_rebind(store: &Store) -> Result<()> {
    store.recheck()?;
    let directory = Path::new(operation::CONTROL).join("root-rebind-journal");
    let Some(held) = files::optional_directory_relative(
        store.control(),
        Path::new("root-rebind-journal"),
        Some(0),
    )?
    else {
        store.recheck()?;
        return Ok(());
    };
    let original = files::identity(&held.metadata()?);
    require(
        held.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(held.as_fd(), true)? == store.control_mount_id(),
        "unsafe root rebind registry",
    )?;
    for name in files::directory_names(&held, 32)? {
        let entry = enzimos_platform::directory_entry::Entry::observe(&held, Path::new(&name))?;
        let name = name
            .into_string()
            .map_err(|_| Error("root rebind filename encoding".into()))?;
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| Error("interrupted root rebind publication".into()))?;
        identity::safe_id(id)?;
        let retained = crate::control_record::Retained::open(
            &held,
            Path::new(&name),
            catalog::MAX_CATALOG,
            store.control_mount_id(),
        )?;
        retained.matches_entry(&entry)?;
        let mut record = retained.value()?.clone();
        crate::root_rebind_record::validate(&record, id)?;
        require(
            entry.metadata()?.mode() & 0o077 == 0,
            "unsafe root rebind record",
        )?;
        json::fields(
            &record,
            "schema id phase filesystem_uuid source target snapshot inventory_sha256 kernels kernel_hashes authority before_files replacements before_catalog after_catalog affected journal_sha256",
        )?;
        require(
            record["schema"].as_u64() == Some(1)
                && record["id"] == id
                && record["phase"] == "complete",
            "root rebinding incomplete; explicit review required",
        )?;
        let digest = enzimos_platform::json::object_mut(&mut record)?
            .remove("journal_sha256")
            .ok_or_else(|| {
                enzimos_platform::Error("root rebinding journal digest missing".into())
            })?;
        require(
            digest == json::fingerprint(&record)?,
            "root rebind journal digest mismatch",
        )?;
        retained.matches_entry(&entry)?;
        entry.recheck()?;
    }
    let current = files::directory(&directory, Some(0))?;
    let before = held.metadata()?;
    let after = current.metadata()?;
    require(
        files::identity(&before) == original
            && files::identity(&after) == original
            && mount_identity::id(current.as_fd(), true)? == store.control_mount_id(),
        "root rebind registry changed",
    )?;
    store.recheck()
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, unlinkat).")]
pub(crate) fn normalize(target: &Path, name: &str, config: &Value, root: &File) -> Result<()> {
    let mount = mount_identity::id(root.as_fd(), true)?;
    for path in [
        target.to_path_buf(),
        target.join("etc"),
        target.join("etc/enzimos"),
    ] {
        let directory = files::directory(&path, Some(0))?;
        require(
            directory.metadata()?.mode() & 0o022 == 0
                && mount_identity::id(directory.as_fd(), true)? == mount,
            "unsafe fallback configuration directory",
        )?;
    }
    let storage = target.join("etc/enzimos/storage.json");
    require(
        json::decode(
            &files::read(&storage, catalog::MAX_CATALOG, Some(0), true)?,
            catalog::MAX_CATALOG,
        )? == *config,
        "fallback storage configuration changed",
    )?;
    let history_path = target.join(".snapshots");
    let history = files::directory(&history_path, Some(0))?;
    require(
        history.metadata()?.mode() & 0o022 == 0
            && mount_identity::id(history.as_fd(), true)? == mount
            && std::fs::read_dir(&history_path)?.next().is_none()
            && !storage_runtime::rows()?
                .iter()
                .any(|r| history_path.to_str() == Some(r.target.as_str())),
        "fallback history placeholder is occupied or mounted",
    )?;
    absent(&target.join("etc/fstab.partial"))?;
    absent(&storage.with_file_name("storage.json.new"))?;
    let fstab_path = target.join("etc/fstab");
    let old = files::read(&fstab_path, catalog::MAX_CATALOG, Some(0), true)?;
    let new = birth_runtime::normalize_fstab(utf8(&old)?, text(config, "filesystem_uuid")?, name)?;
    let mut updated = config.clone();
    updated["root_subvol"] = value!(name);
    // No mutation precedes the root-recorded checkpoint. All later failures retain it.
    files::atomic(&fstab_path, new.as_bytes(), 0o644, Some(0), true)?;
    let mut body = json::canonical(&updated)?;
    body.push(b'\n');
    files::atomic(&storage, &body, 0o644, Some(0), true)?;
    let current = files::directory(&history_path, Some(0))?;
    let a = history.metadata()?;
    let b = current.metadata()?;
    require(
        (a.dev(), a.ino()) == (b.dev(), b.ino())
            && std::fs::read_dir(&history_path)?.next().is_none()
            && mount_identity::id(current.as_fd(), true)? == mount,
        "fallback history placeholder changed",
    )?;
    drop(current);
    drop(history);
    require(
        // SAFETY: The name is a NUL-terminated literal and `root` keeps the descriptor open.
        unsafe { libc::unlinkat(root.as_raw_fd(), c".snapshots".as_ptr(), libc::AT_REMOVEDIR) }
            == 0,
        "fallback placeholder removal refused",
    )?;
    subvolume::new(root.as_fd(), ".snapshots")?;
    let directory = files::directory(&history_path, Some(0))?;
    require(
        // SAFETY: fchmod takes no pointers and `directory` keeps the descriptor open.
        unsafe { libc::fchmod(directory.as_raw_fd(), 0o750) } == 0,
        "fallback history permissions refused",
    )?;
    directory.sync_all().map_err(Into::into)
}
/// Internal updater call. Retain the global operation lock throughout this call.
/// The callback observes committed records; it cannot authorize replay or adoption.
///
/// # Errors
///
/// Fails when the configuration is invalid, the destination exists, or creation fails.
pub fn create_locked<F: FnMut(&str, &Value) -> Result<()>>(
    identifier: &str,
    _operation: &files::Lock,
    mut observer: F,
) -> Result<Value> {
    operation::root_only()?;
    identity::safe_id(identifier)?;
    let mut store = Store::open(true)?;
    no_pending_rebind(&store)?;
    store.assert_no_pending()?;
    let config = store_configuration(&store)?;
    let (source_fd, observed) = source(&config)?;
    let name = format!("enzimos-old-{identifier}");
    identity::safe_id(&name)?;
    require(
        [
            "root_subvol",
            "home_subvol",
            "authority_subvol",
            "control_subvol",
        ]
        .iter()
        .all(|k| config[*k] != name),
        "fallback destination conflicts with persistent storage",
    )?;
    let mut record = value!({"schema":1,"transaction":identifier,"phase":"intent","filesystem_uuid":config["filesystem_uuid"],"created_boot":operation::boot_id()?,"source":observed,"target_name":name,"inventory_sha256":inventory(None)?,"snapshot":null,"root":null,"history":null});
    let mut top = birth_runtime::top(&store)?;
    let target = top.path().join(&name);
    absent(&target)?;
    store.save(identifier, record.clone(), true)?;
    observer("intent", &record)?;
    store.recheck()?;
    top.recheck()?;
    require(
        source(&config)?.1 == record["source"],
        "live source changed before snapshot",
    )?;
    let description = format!("enzimOS required update fallback {identifier}");
    let number = operation::query(
        "/usr/bin/snapper",
        &[
            "--no-dbus",
            "-c",
            "root",
            "create",
            "--type",
            "single",
            "--description",
            &description,
            "--cleanup-algorithm",
            "",
            "--print-number",
        ],
        Duration::from_secs(120),
        65536,
        &[0],
    )?;
    let number = utf8(&number)?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && *n <= i64::MAX as u64)
        .ok_or_else(|| Error("invalid created snapshot number; retain intent for review".into()))?;
    let snapshot_path = Path::new("/.snapshots")
        .join(number.to_string())
        .join("snapshot");
    let relative = format!(
        "{}/.snapshots/{number}/snapshot",
        text(&config, "root_subvol")?
    );
    let (snapshot, snapshot_object, readonly) =
        birth_runtime::observe(&snapshot_path, &relative, text(&config, "filesystem_uuid")?)?;
    require(readonly, "birth source snapshot must be read-only")?;
    record["snapshot"] = value!({"number":number,"object":snapshot_object});
    record["phase"] = value!("snapshot-recorded");
    store.save(identifier, record.clone(), false)?;
    observer("snapshot-recorded", &record)?;
    store.recheck()?;
    top.recheck()?;
    subvolume::snapshot(top.directory()?.as_fd(), snapshot.as_fd(), &name, false)?;
    let (root, object, readonly) =
        birth_runtime::observe(&target, &name, text(&config, "filesystem_uuid")?)?;
    require(!readonly, "new fallback root must be writable")?;
    record["root"] = object;
    record["phase"] = value!("root-recorded");
    store.save(identifier, record.clone(), false)?;
    observer("root-recorded", &record)?;
    normalize(&target, &name, &config, &root)?;
    record["history"] = birth_runtime::observe(
        &target.join(".snapshots"),
        &format!("{name}/.snapshots"),
        text(&config, "filesystem_uuid")?,
    )?
    .1;
    require(
        inventory(None)? == record["inventory_sha256"]
            && source(&config)?.1 == record["source"]
            && inventory(Some(&target))? == record["inventory_sha256"],
        "live or fallback source inventory changed",
    )?;
    store.recheck()?;
    top.recheck()?;
    record["phase"] = value!("ready");
    subvolume::sync(top.directory()?.as_fd())?;
    store.save(identifier, record.clone(), false)?;
    observer("ready", &record)?;
    drop(root);
    drop(snapshot);
    drop(source_fd);
    top.close()?;
    Ok(value!({"snapshot":number,"subvolume":name}))
}
fn store_configuration(store: &Store) -> Result<Value> {
    store.recheck()?;
    Ok(store.configuration().clone())
}
