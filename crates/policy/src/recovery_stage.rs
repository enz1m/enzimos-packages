// SPDX-License-Identifier: MIT
//! Offline restoration checkpoints precede creation and never authorize replay.
use crate::{
    birth_runtime, catalog, control_record, fallback, identity, namespaces, operation,
    recovery_context::{self, Context},
    recovery_journal::{Journal, Kind},
    recovery_records,
    storage_runtime::IndependentGuard,
    subvolume,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

/// Read-only original journal and complete subvolume census under the global lock.
pub fn status_locked(lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    namespaces::initial()?;
    lock.recheck()?;
    let journal = Journal::open(Kind::Jobs, false)?;
    let inventory = birth_runtime::inventory(false)?;
    let result = crate::boot_inventory_families::staged(&journal.records, &inventory);
    journal.unchanged()?;
    require(
        birth_runtime::inventory(false)? == inventory,
        "recovery status subvolume census changed",
    )?;
    journal.unchanged()?;
    lock.recheck()?;
    Ok(result)
}

/// Read only the fixed Root journal. This untrusted bootstrap grants no authority:
/// IndependentGuard subsequently binds every planned filesystem and boot identity.
pub(crate) fn load_job(id: &str) -> Result<Value> {
    recovery_records::job_id(id)?;
    namespaces::initial()?;
    let control = files::directory(Path::new(operation::CONTROL), Some(0))?;
    require(
        control.metadata()?.mode() & 0o7777 == 0o700,
        "unsafe recovery control bootstrap",
    )?;
    let directory = files::directory(
        &Path::new(operation::CONTROL).join("recovery-jobs"),
        Some(0),
    )?;
    let mount = mount_identity::id(control.as_fd(), true)?;
    require(
        directory.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(directory.as_fd(), true)? == mount,
        "unsafe recovery job bootstrap",
    )?;
    let job = control_record::read(
        &directory,
        Path::new(&format!("{id}.json")),
        catalog::MAX_CATALOG,
        mount,
    )?;
    recovery_records::job(&job, id)?;
    IndependentGuard::observe(&job["plan"])?;
    Ok(job)
}
pub(crate) fn load_plan(id: &str, digest: &str) -> Result<Value> {
    identity::sha(digest)?;
    let job = load_job(id)?;
    require(
        job["plan"]["plan_sha256"] == digest,
        "stale recovery preview",
    )?;
    Ok(job["plan"].clone())
}
fn target_object(context: &Context, object: &Value, writable: bool) -> Result<std::fs::File> {
    let relative = recovery_records::text(object, "path")?;
    let path = Path::new(IndependentGuard::TOP).join(relative);
    let (fd, current, readonly) = birth_runtime::observe(
        &path,
        relative,
        recovery_records::text(&context.plan, "filesystem_uuid")?,
    )?;
    require(
        current == *object && (!writable || !readonly),
        "recorded restored subvolume changed",
    )?;
    Ok(fd)
}
pub(crate) fn verify_staged(context: &Context, job: &Value) -> Result<Value> {
    recovery_records::job(job, recovery_records::text(&context.plan, "id")?)?;
    require(
        job["phase"] == "staged" && job["plan"] == context.plan,
        "completed exact recovery job required",
    )?;
    context.recheck()?;
    let target = recovery_records::text(&context.plan, "target_name")?;
    let path = Path::new(IndependentGuard::TOP).join(target);
    let root = target_object(context, &job["root"], true)?;
    let history = target_object(context, &job["history"], true)?;
    let inventory = recovery_context::subvolumes(Path::new(IndependentGuard::TOP))?;
    let prefix = format!("{target}/");
    require(
        inventory
            .iter()
            .filter(|(p, _)| p.starts_with(&prefix))
            .all(|(p, v)| {
                Some(p.as_str()) == job["history"]["path"].as_str() && *v == job["history"]
            })
            && inventory.get(recovery_records::text(&job["root"], "path")?) == Some(&job["root"])
            && inventory.get(recovery_records::text(&job["history"], "path")?)
                == Some(&job["history"]),
        "unrecorded nested restored subvolume",
    )?;
    require(
        std::fs::read_dir(path.join(".snapshots"))?.next().is_none(),
        "restored history is occupied",
    )?;
    recovery_context::contents(&context.plan, &path, &context.volume)?;
    let storage = files::read(
        &path.join("etc/enzimos/storage.json"),
        catalog::MAX_CATALOG,
        Some(0),
        true,
    )?;
    let mut expected_storage = context.plan["storage"].clone();
    expected_storage["root_subvol"] = value!(target);
    require(
        json::decode(&storage, catalog::MAX_CATALOG)? == expected_storage,
        "restored storage configuration changed",
    )?;
    let source_fstab = files::read(
        &context.source_path.join("etc/fstab"),
        catalog::MAX_CATALOG,
        Some(0),
        true,
    )?;
    let expected = birth_runtime::normalize_fstab(
        std::str::from_utf8(&source_fstab).map_err(|_| Error("source fstab encoding".into()))?,
        recovery_records::text(&context.plan, "filesystem_uuid")?,
        target,
    )?;
    let fstab = files::read(&path.join("etc/fstab"), catalog::MAX_CATALOG, Some(0), true)?;
    require(
        fstab == expected.as_bytes(),
        "restored fstab differs from normalized source",
    )?;
    for relative in ["etc/fstab.partial", "etc/enzimos/storage.json.new"] {
        require(
            matches!(std::fs::symlink_metadata(path.join(relative)), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "interrupted restored configuration",
        )?;
    }
    require(
        subvolume::observe(root.as_fd(), target)? == (job["root"].clone(), false)
            && subvolume::observe(
                history.as_fd(),
                recovery_records::text(&job["history"], "path")?,
            )? == (job["history"].clone(), false),
        "retained restored objects changed",
    )?;
    target_object(context, &job["root"], true)?;
    target_object(context, &job["history"], true)?;
    context.recheck()?;
    Ok(
        value!({"root":job["root"],"history":job["history"],"package_inventory_sha256":context.plan["material"]["inventory_sha256"],"storage_sha256":json::sha256(&storage),"fstab_sha256":json::sha256(&fstab)}),
    )
}
pub fn review_locked(id: &str, digest: &str, _lock: &files::Lock) -> Result<Value> {
    let plan = load_plan(id, digest)?;
    let jobs = Journal::open_independent(Kind::Jobs, false, &plan)?;
    require(
        jobs.records.values().all(|v| v["phase"] == "staged"),
        "unfinished staging prevents review",
    )?;
    let job = jobs
        .records
        .get(id)
        .ok_or_else(|| Error("recovery job disappeared".into()))?;
    let context = Context::observe(&plan)?;
    let material = verify_staged(&context, job)?;
    jobs.unchanged()?;
    context.recheck()?;
    Ok(
        value!({"status":"OBSERVED-staged-root-not-activated","id":id,"plan_sha256":digest,"job_sha256":json::fingerprint(job)?,"material":material,"boot_activation_available":false,"retirement_enabled":false,"assurance":"software-local-staged-data-not-boot-or-application-health"}),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub fn stage_locked<F: FnMut(&str, &Value) -> Result<()>>(
    id: &str,
    digest: &str,
    lock: &files::Lock,
    mut observer: F,
) -> Result<Value> {
    let plan = load_plan(id, digest)?;
    let mut jobs = Journal::open_independent(Kind::Jobs, false, &plan)?;
    let mut job = jobs
        .records
        .get(id)
        .cloned()
        .ok_or_else(|| Error("recovery job disappeared".into()))?;
    require(
        job["phase"] == "planned"
            && jobs
                .records
                .iter()
                .all(|(name, v)| name == id || v["phase"] == "staged"),
        "staging already started; no replay or adoption",
    )?;
    let context = Context::observe(&plan)?;
    let activations = Journal::open_independent(Kind::Activations, false, &plan)?;
    require(
        activations.records.values().all(|v| {
            matches!(
                v["phase"].as_str(),
                Some("published" | "selected" | "adopted")
            )
        }),
        "unfinished activation prevents restoration",
    )?;
    let name = recovery_records::text(&plan, "target_name")?;
    let path = Path::new(IndependentGuard::TOP).join(name);
    require(
        matches!(std::fs::symlink_metadata(&path),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "existing recovery destination cannot be adopted",
    )?;
    // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `space` is a writable `libc::statvfs` and the guarded top stays open.
        unsafe { libc::fstatvfs(context.guard.top().as_raw_fd(), &mut space) } == 0
            && space
                .f_bavail
                .checked_mul(space.f_frsize)
                .is_some_and(|bytes| bytes >= 2 * 1024 * 1024 * 1024),
        "restoration free-space admission failed",
    )?;
    jobs.unchanged()?;
    activations.unchanged()?;
    context.recheck()?;
    let previous = job.clone();
    job["stage_boot"] = value!(operation::boot_id()?);
    job["phase"] = value!("creating");
    jobs.save(id, job.clone(), Some(&previous), lock)?;
    observer("creating", &job)?;
    context.recheck()?;
    jobs.unchanged()?;
    activations.unchanged()?;
    subvolume::snapshot(
        context.guard.top().as_fd(),
        context.source.as_fd(),
        name,
        false,
    )?;
    let (root, object, readonly) = birth_runtime::observe(
        &path,
        name,
        recovery_records::text(&plan, "filesystem_uuid")?,
    )?;
    require(!readonly, "created restoration root is read-only")?;
    let previous = job.clone();
    job["root"] = object;
    job["phase"] = value!("root-recorded");
    jobs.save(id, job.clone(), Some(&previous), lock)?;
    observer("root-recorded", &job)?;
    context.recheck()?;
    jobs.unchanged()?;
    activations.unchanged()?;
    target_object(&context, &job["root"], true)?;
    fallback::normalize(&path, name, &plan["storage"], &root)?;
    let previous = job.clone();
    job["history"] = birth_runtime::observe(
        &path.join(".snapshots"),
        &format!("{name}/.snapshots"),
        recovery_records::text(&plan, "filesystem_uuid")?,
    )?
    .1;
    job["phase"] = value!("staged");
    verify_staged(&context, &job)?;
    jobs.unchanged()?;
    activations.unchanged()?;
    subvolume::sync(context.guard.top().as_fd())?;
    jobs.save(id, job.clone(), Some(&previous), lock)?;
    observer("staged", &job)?;
    Ok(
        value!({"status":"snapshot-restored-staged-not-activated","id":id,"plan_sha256":digest,"root":job["root"],"history":job["history"],"boot_activation_available":false,"home_overwritten":false,"authority_overwritten":false,"retirement_enabled":false}),
    )
}
