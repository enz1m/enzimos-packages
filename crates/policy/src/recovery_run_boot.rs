// SPDX-License-Identifier: MIT
//! Direct independent execution: detach first, validate, checkpoint, then run once.
use crate::{
    native_policy_files, operation, recovery_bootstrap as bootstrap, recovery_detachment_runtime,
    recovery_devices::Block,
    recovery_image,
    recovery_journal::{Journal, Kind},
    recovery_mounts::Mounts,
    recovery_records as records,
    recovery_run_parameters::Parameters,
    recovery_stage, recovery_unlock, recovery_workflow,
    storage_runtime::IndependentGuard,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{os::fd::AsFd, path::Path};
fn phase<T>(name: &str, result: Result<T>) -> Result<T> {
    result.map_err(|error| Error(format!("recovery {name}: {error}")))
}
fn execute(p: &Parameters, image: &str, secret: &[u8], lock: &files::Lock) -> Result<Value> {
    let job = phase("job bootstrap", recovery_stage::load_job(&p.id))?;
    let plan = &job["plan"];
    let guard = phase("independent storage", IndependentGuard::observe(plan))?;
    let authority = phase(
        "authority mount",
        files::directory(Path::new("/etc/pacman.d/gnupg"), Some(0)),
    )?;
    require(
        crate::subvolume::observe(authority.as_fd(), &p.authority)?.0
            == plan["protected"]["authority"],
        "actual mounted recovery authority differs from protected plan",
    )?;
    let rows = crate::storage_runtime::rows()?;
    require(
        rows.iter()
            .filter(|r| r.target == "/etc/pacman.d/gnupg")
            .count()
            == 1
            && rows.iter().any(|r| {
                r.target == "/etc/pacman.d/gnupg"
                    && r.filesystem == "btrfs"
                    && r.root == format!("/{}", p.authority)
            }),
        "recovery authority mount missing or shadowed",
    )?;
    let jobs = Journal::open_independent(Kind::Jobs, false, plan)?;
    require(
        jobs.records.get(&p.id) == Some(&job) && job["phase"] == "planned",
        "exact unstarted recovery job required; no replay",
    )?;
    let mut runs = Journal::open_independent(Kind::Runs, false, plan)?;
    let mut record = runs
        .records
        .get(&p.id)
        .cloned()
        .ok_or_else(|| Error("staged run missing".into()))?;
    p.matches_record(&record, &job)?;
    require(
        record["phase"] == "staged"
            && record["image"] == image
            && record["created_boot"] != operation::boot_id()?,
        "run attempt already started or same boot; no replay",
    )?;
    let images = Journal::open_independent(Kind::Images, false, plan)?;
    let published = images
        .records
        .get(image)
        .ok_or_else(|| Error("recorded run image missing".into()))?;
    phase(
        "published image verification",
        recovery_image::verify_published(published),
    )?;
    let descriptor = json::decode(
        &files::read(
            Path::new("/usr/lib/enzimos-native/recovery-image.json"),
            2 * 1024 * 1024,
            Some(0),
            true,
        )?,
        2 * 1024 * 1024,
    )?;
    recovery_image::descriptor(&descriptor)?;
    let release = files::read_kernel(Path::new("/proc/sys/kernel/osrelease"), 4096)?;
    require(
        descriptor["schema"] == 2
            && descriptor == published["inputs"]["identity"]
            && recovery_image::image_id(&descriptor)? == image
            && native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
                == descriptor["policy_files"]
            && std::str::from_utf8(&release).ok().map(str::trim)
                == descriptor["kernel_release"].as_str(),
        "running native recovery image differs from published attempt",
    )?;
    guard.recheck()?;
    jobs.unchanged()?;
    images.unchanged()?;
    runs.unchanged()?;
    bootstrap::quiet()?;
    let staged = record.clone();
    record["phase"] = value!("running");
    runs.save(&p.id, record.clone(), Some(&staged), lock)?;
    let output = match recovery_workflow::execute_locked(
        &p.id,
        records::text(&record, "plan_sha256")?,
        records::text(&record, "flavor")?,
        lock,
        |_, _| Ok(()),
    ) {
        Ok(output) => output,
        Err(error) => {
            let running = record.clone();
            record["phase"] = value!("failed");
            record["result"] =
                value!({"error":"native recovery workflow failed; explicit review required"});
            // If the checkpoint itself fails, preserve the running record rather
            // than fabricating a receipt or retrying the storage operation.
            runs.save(&p.id, record, Some(&running), lock)?;
            return Err(error);
        }
    };
    let running = record.clone();
    record["phase"] = value!("executed");
    record["result"] = value!({"status":output["status"],"flavor":output["flavor"],"home_overwritten":false,"authority_overwritten":false});
    let mut handoff = false;
    if p.automatic {
        let activations = Journal::open_independent(Kind::Activations, false, plan)?;
        let activation = activations
            .records
            .get(&p.id)
            .ok_or_else(|| Error("completed workflow activation missing".into()))?;
        activations.unchanged()?;
        match crate::recovery_handoff::load(&p.id, activation, &p.luks, secret) {
            Ok(receipt) => {
                record["result"]["handoff"] = receipt;
                handoff = true;
            }
            Err(_) => eprintln!(
                "ENZIMOS_RECOVERY_HANDOFF_FALLBACK native RAM handoff declined; completed restore remains selected"
            ),
        }
        activations.unchanged()?;
    }
    runs.unchanged()?;
    runs.save(&p.id, record, Some(&running), lock)?;
    Ok(
        value!({"status":"recovery-run-executed","id":p.id,"workflow":output["status"],"loader_started":true,
        "namespace_origin_proven":true,"home_overwritten":false,"authority_overwritten":false,"old_roots_retired":false,"ram_handoff":handoff}),
    )
}
/// Run the recovery described by `p` as PID 1 on the RAM root.
///
/// # Errors
///
/// Fails when a step (detachment, unlock, mount or restore) fails.
#[allow(unsafe_code, reason = "Linux syscall ABI (sync).")]
pub fn run(p: &Parameters) -> Result<Value> {
    bootstrap::quiet()?;
    crate::recovery_devices::coldplug()?;
    let esp = Block::by_uuid(&p.esp, true)?;
    let mut mounts = Mounts::default();
    esp.recheck()?;
    mounts.esp(esp.file.as_fd())?;
    esp.recheck()?;
    let image = phase("ESP detachment", recovery_detachment_runtime::detach(p))?;
    let encrypted = phase("encrypted device", Block::by_uuid(&p.luks, false))?;
    let (mapper, secret) = phase(
        "LUKS unlock",
        recovery_unlock::open(&encrypted, &p.filesystem),
    )?;
    // Scope all borrowed filesystem/journal descriptors before normal unmount.
    let outcome = phase(
        "mounted control and authority",
        (|| {
            mapper.recheck()?;
            files::ensure_directory(Path::new("/run/enzimos"), 0o700, 0)?;
            mounts.filesystem(
                mapper.file.as_fd(),
                Path::new(IndependentGuard::TOP),
                "btrfs",
                "subvolid=5,nodiscard",
            )?;
            mapper.recheck()?;
            let top = files::directory(Path::new(IndependentGuard::TOP), Some(0))?;
            let control =
                files::directory(&Path::new(IndependentGuard::TOP).join(&p.control), Some(0))?;
            let authority = files::directory(
                &Path::new(IndependentGuard::TOP).join(&p.authority),
                Some(0),
            )?;
            files::ensure_directory(Path::new("/var"), 0o755, 0)?;
            files::ensure_directory(Path::new("/var/lib"), 0o755, 0)?;
            mounts.bind(&control, Path::new(operation::CONTROL))?;
            files::ensure_directory(Path::new("/etc/pacman.d"), 0o755, 0)?;
            mounts.bind(&authority, Path::new("/etc/pacman.d/gnupg"))?;
            drop((top, control, authority));
            mounts.recheck()?;
            mapper.recheck()?;
            encrypted.recheck()?;
            esp.recheck()?;
            let job = phase(
                "independent lock job bootstrap",
                recovery_stage::load_job(&p.id),
            )?;
            let lock = phase(
                "independent pending-entry lock",
                operation::independent_lock(&job["plan"]),
            )?;
            phase("workflow execution", execute(p, &image, &secret, &lock))
        })(),
    );
    drop(secret);
    // SAFETY: sync takes no arguments and cannot fail.
    unsafe { libc::sync() };
    // Cleanup errors retain uncertain mounts/mapping. Never weaken them to claim
    // success; PID1 reports failure and exits through the guarded kernel reboot.
    mounts.close()?;
    recovery_unlock::close(&encrypted, mapper)?;
    outcome
}
