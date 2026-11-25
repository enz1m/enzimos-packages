// SPDX-License-Identifier: MIT
//! Confirm actual restored boot material before completing an independent run.
use crate::{
    birth_runtime, boot_entries, boot_options,
    boot_volume::Volume,
    catalog, namespaces, native_policy_files, operation, recovery_activation as activation,
    recovery_activation_runtime as runtime, recovery_boot, recovery_context,
    recovery_journal::{Journal, Kind},
    recovery_records as records,
    storage_runtime::Guard,
    subvolume,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{os::fd::AsFd, path::Path};
fn observed_object(
    path: &Path,
    object: &Value,
    filesystem: &str,
    mounted: bool,
) -> Result<std::fs::File> {
    let relative = records::text(object, "path")?;
    let (file, current, readonly) = birth_runtime::observe(path, relative, filesystem)?;
    require(
        current == *object && !readonly,
        "activated recorded subvolume differs",
    )?;
    if mounted {
        let mount = mount_identity::id(file.as_fd(), false)?;
        let rows = crate::storage_runtime::rows()?;
        persistent_mount(
            &rows,
            path.to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
            relative,
            mount,
        )?;
    }
    Ok(file)
}
/// Validate the mount carrying an already independently verified subvolume.
/// Nested history shares Root's mount; protected roles require their own mount.
fn persistent_mount(
    rows: &[enzimos_platform::mountinfo::Row],
    path: &str,
    relative: &str,
    mount: u64,
) -> Result<()> {
    if path == "/.snapshots" {
        let root = relative
            .strip_suffix("/.snapshots")
            .ok_or_else(|| Error("restored history path differs".into()))?;
        crate::identity::safe_id(root)?;
        crate::storage_runtime::mount_row(rows, "/", Some(&format!("/{root}")), mount)?;
        require(
            !rows
                .iter()
                .any(|row| row.target == "/.snapshots" || row.target.starts_with("/.snapshots/")),
            "restored history is independently mounted or shadowed",
        )
    } else {
        crate::storage_runtime::mount_row(rows, path, Some(&format!("/{relative}")), mount)?;
        Ok(())
    }
}
/// Confirm the restored boot material of the running recovery while `lock` is held.
///
/// # Errors
///
/// Fails when the restored material differs or the record cannot be written.
pub fn confirm_locked(lock: &files::Lock) -> Result<Value> {
    inspect_current(Some(lock))
}
/// Measure the full restored boot contract without advancing any receipt.
pub(crate) fn observe_current() -> Result<Value> {
    inspect_current(None)
}
fn inspect_current(lock: Option<&files::Lock>) -> Result<Value> {
    let guard = Guard::observe()?;
    let command_line = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
    let command_line = std::str::from_utf8(&command_line)
        .map_err(|_| Error("actual boot command line encoding".into()))?;
    let handoff = command_line
        .split_whitespace()
        .any(|s| s.starts_with("enzimos.handoff="));
    let id = boot_options::marker(command_line, "enzimos.staged")?;
    let mut journal = Journal::open(Kind::Activations, false)?;
    let mut record = journal
        .records
        .get(&id)
        .cloned()
        .ok_or_else(|| Error("selected activation missing".into()))?;
    require(
        matches!(record["phase"].as_str(), Some("selected" | "adopted")),
        "selected activation required",
    )?;
    require(
        record["intent"]["schema"] == 2,
        "native runtime cannot inherit legacy policy confirmation",
    )?;
    let job = &record["intent"]["job"];
    let plan = &job["plan"];
    let filesystem = records::text(plan, "filesystem_uuid")?;
    let target = records::text(&job["root"], "path")?;
    let mut config = plan["storage"].clone();
    config["root_subvol"] = value!(target);
    require(
        guard.configuration == config
            && boot_options::subvolume_from_options(command_line)? == target,
        "running and configured restored root differs",
    )?;
    let root = observed_object(Path::new("/"), &job["root"], filesystem, true)?;
    let history = observed_object(Path::new("/.snapshots"), &job["history"], filesystem, true)?;
    let mut protected = Vec::new();
    for (role, path) in [
        ("home", "/home"),
        ("authority", "/etc/pacman.d/gnupg"),
        ("control", operation::CONTROL),
    ] {
        protected.push((
            path,
            plan["protected"][role].clone(),
            observed_object(Path::new(path), &plan["protected"][role], filesystem, true)?,
        ));
    }
    let flavor = records::text(&record["selection"], "flavor")?;
    let kernel = namespaces::kernel_release()?;
    require(
        plan["material"]["kernels"][flavor] == kernel,
        "actual activated kernel differs",
    )?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
            == record["intent"]["policy_files"],
        "activated native policy differs",
    )?;
    let jobs = Journal::open(Kind::Jobs, false)?;
    require(
        jobs.records.get(&id) == Some(job),
        "activated staging journal differs",
    )?;
    let volume = Volume::observe()?;
    require(
        volume.uuid == plan["boot_uuid"],
        "activated boot volume differs",
    )?;
    recovery_context::contents(plan, Path::new("/"), &volume)?;
    let storage = files::read(
        Path::new("/etc/enzimos/storage.json"),
        catalog::MAX_CATALOG,
        Some(0),
        true,
    )?;
    let fstab = files::read(Path::new("/etc/fstab"), catalog::MAX_CATALOG, Some(0), true)?;
    require(
        json::sha256(&storage) == record["intent"]["material"]["storage_sha256"]
            && json::sha256(&fstab) == record["intent"]["material"]["fstab_sha256"],
        "activated configuration differs",
    )?;
    let entries = runtime::existing_entries(job)?;
    let expected =
        recovery_boot::expected(&record["intent"], &entries, Some(&record["selection"]))?;
    require(
        runtime::metadata(&volume, &entries)? == expected,
        "activated loader metadata differs",
    )?;
    let uefi = runtime::efi_guard()?;
    let selected = if uefi {
        Some(boot_entries::efi_string(&files::read_kernel(
            &Path::new(runtime::EFI).join(format!("LoaderEntrySelected-{}", runtime::GUID)),
            8192,
        )?)?)
    } else {
        None
    };
    let runs = if handoff {
        let runs = Journal::open(Kind::Runs, false)?;
        let run = runs
            .records
            .get(&id)
            .ok_or_else(|| Error("executed RAM handoff run missing".into()))?;
        let parameters = crate::recovery_run_parameters::Parameters::parse(records::text(
            &run["entry"],
            "options",
        )?)?;
        parameters.matches_record(run, job)?;
        require(
            parameters.luks == crate::recovery_run_stage::luks_uuid(&guard)?,
            "actual handoff encrypted ancestry differs",
        )?;
        crate::recovery_handoff::validate(&id, &record, run, command_line, selected.as_deref())?;
        Some(runs)
    } else {
        if let Some(selected) = &selected {
            require(
                *selected == activation::entry_names(&id, flavor)?.0,
                "actual UEFI selected entry differs",
            )?;
        }
        None
    };
    let boot = operation::boot_id()?;
    require(
        record["selection"]["created_boot"] != boot,
        "selection boot cannot confirm itself",
    )?;
    let observation = value!({"boot_id":boot,"kernel":kernel,"root_uuid":job["root"]["uuid"],"intent_sha256":record["intent"]["intent_sha256"],"assurance":activation::ASSURANCE});
    guard.recheck()?;
    volume.recheck()?;
    jobs.unchanged()?;
    journal.unchanged()?;
    if let Some(runs) = &runs {
        runs.unchanged()?;
    }
    require(
        subvolume::observe(root.as_fd(), target)? == (job["root"].clone(), false)
            && subvolume::observe(history.as_fd(), records::text(&job["history"], "path")?)?
                == (job["history"].clone(), false),
        "retained activated identity changed",
    )?;
    for (path, object, held) in protected {
        require(
            subvolume::observe(held.as_fd(), records::text(&object, "path")?)?
                == (object.clone(), false),
            "retained protected identity changed",
        )?;
        observed_object(Path::new(path), &object, filesystem, true)?;
    }
    let mode = if uefi { "uefi" } else { "bios" };
    if let Some(lock) = lock.filter(|_| record["observations"][mode] != observation) {
        let previous = record.clone();
        record["observations"][mode] = observation.clone();
        journal.save(&id, record, Some(&previous), lock)?;
    }
    Ok(value!({"id":id,"observation":observation,"uefi":uefi,"retirement_enabled":false}))
}
/// Finish recovery run `id` while `lock` is held.
///
/// # Errors
///
/// Fails when the run is missing or not executed.
pub fn finish_locked(id: &str, lock: &files::Lock) -> Result<Value> {
    records::job_id(id)?;
    let confirmation = confirm_locked(lock)?;
    require(
        confirmation["id"] == id,
        "finish identifier differs from actual restored boot",
    )?;
    let guard = Guard::observe()?;
    let mut runs = Journal::open(Kind::Runs, false)?;
    let mut run = runs
        .records
        .get(id)
        .cloned()
        .ok_or_else(|| Error("recovery run missing".into()))?;
    require(
        run["phase"] == "executed",
        "executed recovery run required; failed run cannot finish",
    )?;
    let workflows = Journal::open(Kind::Workflows, false)?;
    require(
        workflows
            .records
            .get(id)
            .is_some_and(|v| v["state"] == "complete" && v["plan_sha256"] == run["plan_sha256"]),
        "exact recovery workflow did not complete",
    )?;
    let volume = Volume::observe()?;
    let path = volume.path(Path::new(&format!(
        "loader/entries/{}",
        records::text(&run["entry"], "uefi_entry")?
    )))?;
    require(
        matches!(std::fs::symlink_metadata(path),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "recovery one-shot entry remains",
    )?;
    let bios = volume.artifact(
        Path::new("limine/limine.conf"),
        boot_entries::MAX_TEXT as u64,
    )?;
    let bytes = files::read_file(&bios.file, boot_entries::MAX_TEXT, Some(0), true)?;
    let menu = boot_entries::menu(
        std::str::from_utf8(&bytes).map_err(|_| Error("finish BIOS encoding".into()))?,
    )?;
    require(
        menu.entries
            .iter()
            .all(|entry| entry.title != run["entry"]["bios_title"]),
        "recovery one-shot BIOS entry remains",
    )?;
    bios.recheck()?;
    volume.recheck()?;
    guard.recheck()?;
    workflows.unchanged()?;
    runs.unchanged()?;
    let previous = run.clone();
    run["phase"] = value!("complete");
    runs.save(id, run, Some(&previous), lock)?;
    Ok(
        value!({"status":"recovery-run-complete","id":id,"restored_root_selected":true,"old_roots_retired":false}),
    )
}
