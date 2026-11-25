// SPDX-License-Identifier: MIT
//! Fresh original replacement-repository copy. Uncertain prepared attempts never replay.
use crate::{
    backup_admission,
    backup_configuration::Configuration,
    backup_destination::Destination,
    backup_restic_runtime::Runtime,
    backup_rotation_context::Quiet,
    backup_rotation_layout::Layout,
    backup_rotation_mount::Mount,
    backup_rotation_objects::{Credential, CredentialName, Repository, RepositoryName},
    backup_rotation_record as codec, control_registry,
    storage_runtime::Guard,
};
use enzimos_platform::{
    Error, Result, files, json,
    local_restic::{RotationPrepare, RotationTask},
    mount_identity,
    receipt_registry::Registry,
    require,
};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
fn copies(
    old: &BTreeMap<String, Value>,
    new: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, String>> {
    require(
        !old.is_empty() && old.len() == new.len() && old.len() <= codec::MAX_POINTS,
        "copied rotation point count mismatch",
    )?;
    let mut lineage = BTreeMap::new();
    for (id, row) in old {
        crate::identity::sha(id)?;
        let original = if row["original"].is_null() {
            id.as_str()
        } else {
            row["original"]
                .as_str()
                .ok_or_else(|| Error("rotation point lineage text required".into()))?
        };
        crate::identity::sha(original)?;
        require(
            lineage.insert(original.to_owned(), id.clone()).is_none(),
            "ambiguous source point lineage",
        )?;
    }
    let mut map = BTreeMap::new();
    for (id, row) in new {
        crate::identity::sha(id)?;
        let original = row["original"]
            .as_str()
            .ok_or_else(|| Error("copied point must name original lineage".into()))?;
        crate::identity::sha(original)?;
        let source = lineage
            .get(original)
            .ok_or_else(|| Error("copied point names unknown source".into()))?;
        require(
            map.insert(source.clone(), id.clone()).is_none(),
            "duplicate copied source point",
        )?;
        for field in ["tree", "paths", "hostname", "tags", "time", "username"] {
            require(
                row[field] == old[source][field],
                "copied point content or metadata differs",
            )?;
        }
    }
    require(
        map.keys().eq(old.keys()),
        "rotation copied mapping incomplete",
    )?;
    Ok(map)
}
fn query(
    runtime: &Runtime,
    task: RotationTask,
    repository: &File,
    password: &File,
    source: &Layout,
    target: Option<&Layout>,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<enzimos_platform::process::Output> {
    source.recheck()?;
    if let Some(target) = target {
        target.recheck()?;
    }
    let output = runtime.rotation_query(task, repository, password, boundary)?;
    source.recheck()?;
    if let Some(target) = target {
        target.recheck()?;
    }
    Ok(output)
}
fn mutate(
    runtime: &Runtime,
    task: RotationPrepare,
    target: &File,
    next: &File,
    current: &File,
    password: &File,
    source: &Layout,
    frozen_target: Option<&Layout>,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<enzimos_platform::process::Output> {
    source.recheck()?;
    if let Some(target) = frozen_target {
        target.recheck()?;
    }
    let output = runtime.rotation_prepare(task, target, next, current, password, boundary)?;
    source.recheck()?;
    if let Some(target) = frozen_target {
        target.recheck()?;
    }
    Ok(output)
}
fn stage_shape(f: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = f.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original private replacement repository required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn absent(mount: &Mount<'_>, guard: &Guard) -> Result<()> {
    require(
        Repository::observe(mount, RepositoryName::Retired)?.is_none()
            && Credential::observe(guard, CredentialName::Retired)?.is_none(),
        "retired rotation objects require review",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub fn prepare_locked(
    guard: &Guard,
    lock: &files::Lock,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    crate::identity::safe_id(id)?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    let rows = control_registry::read_bounded(
        guard,
        "backup-rotation",
        codec::MAXIMUM,
        codec::LIMIT,
        codec::validate,
    )?;
    require(
        !rows.contains_key(id) && rows.len() < codec::MAXIMUM,
        "rotation exists or capacity reached; no replay",
    )?;
    require(
        rows.values()
            .all(|r| matches!(r["phase"].as_str(), Some("complete" | "abandoned"))),
        "unfinished rotation requires review",
    )?;
    let config = Configuration::open()?;
    let destination = Destination::open(&config, guard)?;
    destination.require_writable()?;
    let pin = backup_admission::Repository::open(&destination)?;
    let mount = Mount::observe(guard, &config)?;
    let current = Repository::observe(&mount, RepositoryName::Current)?
        .ok_or_else(|| Error("current rotation repository required".into()))?;
    require(
        Repository::observe(&mount, RepositoryName::Stage)?.is_none(),
        "existing rotation stage requires review",
    )?;
    absent(&mount, guard)?;
    let password = Credential::observe(guard, CredentialName::Current)?
        .ok_or_else(|| Error("current rotation credential required".into()))?;
    let next = Credential::observe(guard, CredentialName::Input)?
        .ok_or_else(|| Error("protected rotation input required".into()))?;
    let old_identity = password.evidence(guard)?["identity"].clone();
    let next_identity = next.evidence(guard)?["identity"].clone();
    require(
        old_identity["inode"] != next_identity["inode"],
        "rotation passwords alias",
    )?;
    let repository = current.identity(&mount)?;
    require(
        repository[0] == destination.expected_pin()?["repository_sha256"],
        "original rotation repository differs from pin",
    )?;
    let frozen = Layout::capture(current.descriptor(&mount)?, 0, false)?;
    let need = frozen
        .storage_bytes()?
        .checked_add(128 * 1024 * 1024)
        .ok_or_else(|| Error("rotation space overflow".into()))?;
    // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut fs: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatvfs(mount.descriptor()?.as_raw_fd(), &mut fs) } == 0
            && u128::from(fs.f_bavail) * u128::from(fs.f_frsize) >= u128::from(need),
        "insufficient space for complete re-encrypted repository",
    )?;
    let folder =
        files::ensure_directory_relative(guard.control(), Path::new("backup-rotation"), 0o700, 0)?;
    require(
        mount_identity::id(folder.as_fd(), true)? == guard.control_mount_id(),
        "rotation receipts crossed control mount",
    )?;
    let path = Path::new(crate::operation::CONTROL).join("backup-rotation");
    let mut registry = Registry::observe(&path, &folder, &format!("{id}.json"), 0)?;
    require(
        control_registry::read_bounded(
            guard,
            "backup-rotation",
            codec::MAXIMUM,
            codec::LIMIT,
            codec::validate,
        )? == rows,
        "rotation family changed before admission",
    )?;
    let quiet = Quiet::observe(guard)?;
    let idle = crate::transition_idle::Snapshot::online()?;
    let mut source = || {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        config.recheck()?;
        destination.require_writable()?;
        pin.recheck()?;
        mount.recheck()?;
        current.recheck(&mount)?;
        password.recheck(guard)?;
        next.recheck(guard)?;
        quiet.recheck(guard)?;
        idle.recheck()?;
        absent(&mount, guard)?;
        Ok(())
    };
    let runtime = Runtime::create(&files::random_hex(16)?, &mut source)?;
    progress("validating")?;
    let current_file = current.descriptor(&mount)?;
    let password_file = password.descriptor(guard)?;
    let next_file = next.descriptor(guard)?;
    let authentication = query(
        &runtime,
        RotationTask::Keys,
        current_file,
        password_file,
        &frozen,
        None,
        &mut source,
    )?;
    crate::backup_restic_result::keys(authentication.status.code(), &authentication.stdout)?;
    let refusal = query(
        &runtime,
        RotationTask::Keys,
        current_file,
        next_file,
        &frozen,
        None,
        &mut source,
    )?;
    require(
        refusal.status.code() == Some(12),
        "rotation input already opens current repository or authentication was uncertain",
    )?;
    let inventory = query(
        &runtime,
        RotationTask::Points,
        current_file,
        password_file,
        &frozen,
        None,
        &mut source,
    )?;
    let old = codec::points(inventory.status.code(), &inventory.stdout)?;
    require(!old.is_empty(), "rotation requires existing snapshots")?;
    let mut record = value!({"schema":1,"id":id,"phase":"prepared","created_boot":crate::operation::boot_id()?,
        "repository_binding":{"filesystem_uuid":config.value()["destination_uuid"],"repository_sha256":repository[0]},
        "old_points":old.keys().collect::<Vec<_>>(),"input_identity":next_identity,"password_identity":old_identity,
        "repository_inode":repository[1],"new_repository_sha256":null,"new_repository_inode":null,"copies":null});
    codec::validate(&record, id)?;
    source()?;
    require(
        Repository::observe(&mount, RepositoryName::Stage)?.is_none(),
        "rotation stage appeared before preparation",
    )?;
    registry.publish(&json::canonical(&record)?, &mut source)?;
    // Prepared is durable BEFORE creating the one replacement repository or
    // invoking any mutation. Failure leaves this exact uncertain attempt intact.
    let stage = files::create_directory_relative(
        mount.descriptor()?,
        Path::new("restic-rotation"),
        0o700,
        0,
    )?;
    let stage_shape = stage_shape(&stage)?;
    let stage_mount = mount_identity::id(stage.as_fd(), true)?;
    require(
        stage_mount == mount.mount_id(),
        "original new rotation directory crossed backup mount",
    )?;
    let mut checkpoint = || {
        source()?;
        registry.recheck()?;
        let named =
            files::directory_relative(mount.descriptor()?, Path::new("restic-rotation"), Some(0))?;
        require(
            stage_shape_fn(&stage)? == stage_shape
                && stage_shape_fn(&named)? == stage_shape
                && mount_identity::id(stage.as_fd(), true)? == stage_mount
                && mount_identity::id(named.as_fd(), true)? == stage_mount,
            "original rotation stage replaced or covered",
        )?;
        Ok(())
    };
    progress("initializing")?;
    let initialized = mutate(
        &runtime,
        RotationPrepare::Initialize,
        &stage,
        next_file,
        current_file,
        password_file,
        &frozen,
        None,
        &mut checkpoint,
    )?;
    require(
        initialized.status.code() == Some(0),
        "rotation initialization failed; no replay",
    )?;
    let header = crate::backup_repository_header::Header::observe(&stage)?;
    let header_sha = header.evidence(&stage)?["sha256"].clone();
    require(
        header_sha != repository[0],
        "rotation repository identity is not new",
    )?;
    progress("copying")?;
    let copied = mutate(
        &runtime,
        RotationPrepare::Copy,
        &stage,
        next_file,
        current_file,
        password_file,
        &frozen,
        None,
        &mut || {
            checkpoint()?;
            header.recheck(&stage)
        },
    )?;
    require(
        copied.status.code() == Some(0),
        "rotation copy failed; no replay",
    )?;
    let target_frozen = Layout::capture(&stage, 0, false)?;
    let mut verify = || {
        checkpoint()?;
        header.recheck(&stage)?;
        Ok(())
    };
    progress("verifying")?;
    let keys = query(
        &runtime,
        RotationTask::Keys,
        &stage,
        next_file,
        &frozen,
        Some(&target_frozen),
        &mut verify,
    )?;
    let keys = crate::backup_restic_result::keys(keys.status.code(), &keys.stdout)?;
    require(
        keys.len() == 1 && keys.values().all(|v| *v),
        "replacement repository must hold exactly one current key",
    )?;
    let refused = query(
        &runtime,
        RotationTask::Keys,
        &stage,
        password_file,
        &frozen,
        Some(&target_frozen),
        &mut verify,
    )?;
    require(
        refused.status.code() == Some(12),
        "old password opens replacement or refusal was uncertain",
    )?;
    let inventory = query(
        &runtime,
        RotationTask::Points,
        current_file,
        password_file,
        &frozen,
        Some(&target_frozen),
        &mut verify,
    )?;
    require(
        codec::points(inventory.status.code(), &inventory.stdout)? == old,
        "original snapshot inventory changed during rotation",
    )?;
    let inventory = query(
        &runtime,
        RotationTask::Points,
        &stage,
        next_file,
        &frozen,
        Some(&target_frozen),
        &mut verify,
    )?;
    let new = codec::points(inventory.status.code(), &inventory.stdout)?;
    let mapping = copies(&old, &new)?;
    let checked = mutate(
        &runtime,
        RotationPrepare::ReadData,
        &stage,
        next_file,
        current_file,
        password_file,
        &frozen,
        Some(&target_frozen),
        &mut verify,
    )?;
    require(
        checked.status.code() == Some(0),
        "replacement full-data check failed; no replay",
    )?;
    verify()?;
    record["phase"] = value!("copied");
    record["new_repository_sha256"] = header_sha;
    record["new_repository_inode"] = value!(stage_shape.1);
    record["copies"] = serde_json::to_value(&mapping)?;
    codec::validate(&record, id)?;
    registry.publish(&json::canonical(&record)?, &mut || {
        source()?;
        header.recheck(&stage)?;
        target_frozen.recheck()
    })?;
    registry.recheck()?;
    source()?;
    frozen.recheck()?;
    target_frozen.recheck()?;
    Ok(
        value!({"status":"rotation-copied-verified","rotation":id,"points":mapping.len(),"old_password_refused_by_new":true,
        "switched":false,"old_access_revoked":false,"credential_exported":false}),
    )
}
fn stage_shape_fn(f: &File) -> Result<(u64, u64, u32, u32, u32)> {
    stage_shape(f)
}
