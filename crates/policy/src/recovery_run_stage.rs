// SPDX-License-Identifier: MIT
//! A durable one-shot run is recorded before publishing its loader entries/defaults.
use crate::{
    boot_entries,
    boot_volume::Volume,
    identity, native_policy_files, operation, recovery_activation_runtime as activation,
    recovery_boot, recovery_image,
    recovery_journal::{Journal, Kind},
    recovery_records as records, signed_entry,
    storage_runtime::Guard,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json as value};
use std::{path::Path, time::Duration};
pub(crate) const INIT: &str = "/usr/lib/enzimos-native/enzimos-recovery-run-init";
pub(crate) fn luks_uuid(guard: &Guard) -> Result<String> {
    guard.recheck()?;
    let source = operation::query(
        "/usr/bin/findmnt",
        &["-n", "-o", "SOURCE", "--mountpoint", "/"],
        Duration::from_secs(30),
        4096,
        &[0],
    )?;
    let source = std::str::from_utf8(&source)
        .map_err(|_| Error("encrypted source encoding".into()))?
        .trim()
        .split('[')
        .next()
        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
    require(
        source.starts_with("/dev/")
            && source.len() <= 1024
            && !source.chars().any(|c| c.is_whitespace() || c.is_control()),
        "qualified live root device required",
    )?;
    let rows = operation::query(
        "/usr/bin/lsblk",
        &["-nrso", "FSTYPE,UUID", source],
        Duration::from_secs(30),
        65536,
        &[0],
    )?;
    let rows =
        std::str::from_utf8(&rows).map_err(|_| Error("encrypted ancestry encoding".into()))?;
    let mut found = Vec::new();
    for line in rows.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() == Some(&"crypto_LUKS") {
            require(fields.len() == 2, "encrypted ancestry UUID unavailable")?;
            found.push(identity::uuid(fields[1])?.to_owned());
        }
    }
    require(
        found.len() == 1,
        "unique LUKS container of live root required",
    )?;
    guard.recheck()?;
    Ok(found.remove(0))
}
fn text(volume: &Volume, path: &str) -> Result<String> {
    let file = volume.artifact(Path::new(path), boot_entries::MAX_TEXT as u64)?;
    let body = files::read_file(&file.file, boot_entries::MAX_TEXT, Some(0), true)?;
    file.recheck()?;
    String::from_utf8(body).map_err(|_| Error("recovery run loader text encoding".into()))
}
/// Stage recovery run `id` reviewed as `digest` while `lock` is held.
///
/// # Errors
///
/// Fails when the review changed or staging fails.
pub fn stage_locked(
    id: &str,
    digest: &str,
    flavor: &str,
    image: &str,
    exit: &str,
    automatic: bool,
    lock: &files::Lock,
) -> Result<Value> {
    stage_authorized(id, digest, flavor, image, exit, automatic, lock, || {
        lock.recheck()
    })
}
#[expect(
    clippy::too_many_arguments,
    reason = "Each argument is a distinct retained input of this step."
)]
pub(crate) fn stage_authorized<F: FnMut() -> Result<()>>(
    id: &str,
    digest: &str,
    flavor: &str,
    image: &str,
    exit: &str,
    automatic: bool,
    lock: &files::Lock,
    mut authorize: F,
) -> Result<Value> {
    records::job_id(id)?;
    identity::sha(digest)?;
    records::flavor(flavor)?;
    recovery_image::identifier(image)?;
    require(
        matches!(exit, "reboot" | "poweroff"),
        "invalid recovery run exit mode",
    )?;
    let mut idle = Snapshot::planned_run(id)?;
    let job = &idle.records["jobs"][id];
    require(
        job["phase"] == "planned"
            && job["plan"]["plan_sha256"] == digest
            && job["plan"]["storage"] == idle.guard.configuration,
        "exact current recovery plan required",
    )?;
    require(
        matches!(std::fs::symlink_metadata("/var/lib/pacman/db.lck"),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "package transaction prevents recovery run staging",
    )?;
    let images = Journal::open(Kind::Images, false)?;
    let record = images
        .records
        .get(image)
        .ok_or_else(|| Error("published recovery image missing".into()))?;
    require(
        record["phase"] == "ready"
            && record["inputs"]["identity"]["schema"] == 2
            && record["filesystem_uuid"] == idle.guard.configuration["filesystem_uuid"],
        "ready native recovery image required",
    )?;
    recovery_image::verify_published(record)?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
            == record["inputs"]["identity"]["policy_files"],
        "recovery image native policy differs from installed policy",
    )?;
    authorize()?;
    lock.recheck()?;
    let mut runs = Journal::open(Kind::Runs, true)?;
    require(
        !runs.records.contains_key(id),
        "recovery run already recorded; no replay",
    )?;
    let volume = Volume::observe()?;
    require(
        volume.uuid == job["plan"]["boot_uuid"] && record["boot_uuid"] == volume.uuid,
        "recovery boot volume differs",
    )?;
    let loader = text(&volume, "loader/loader.conf")?;
    let bios = text(&volume, "limine/limine.conf")?;
    let menu = boot_entries::menu(&bios)?;
    let (entry, title) = records::run_entry_names(id)?;
    let default = boot_entries::fields(&loader, false)?
        .get("default")
        .cloned()
        .ok_or_else(|| Error("recovery UEFI default missing".into()))?;
    records::literal_entry(&default)?;
    recovery_boot::replace_default(&loader, "default ", &default)?;
    volume
        .artifact(
            Path::new(&format!("loader/entries/{default}")),
            boot_entries::MAX_TEXT as u64,
        )?
        .recheck()?;
    require(
        menu.entries.iter().all(|v| v.title != title)
            && matches!(std::fs::symlink_metadata(volume.path(Path::new(&format!("loader/entries/{entry}")))?),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "existing recovery entry cannot be adopted",
    )?;
    let one_shot = activation::efi_guard()?;
    let luks = luks_uuid(&idle.guard)?;
    let console = records::text(record, "options")?
        .split_whitespace()
        .filter(|s| s.starts_with("console="))
        .collect::<Vec<_>>()
        .join(" ");
    let config = &idle.guard.configuration;
    let mut options = format!("{console} rdinit={INIT} enzimos.recovery-run={id} enzimos.luks={luks} enzimos.fs={} enzimos.control={} enzimos.authority={} enzimos.esp={} enzimos.uefi-restore={default} enzimos.bios-restore={}:{} enzimos.run-exit={exit}",records::text(config,"filesystem_uuid")?,records::text(config,"control_subvol")?,records::text(config,"authority_subvol")?,volume.uuid,menu.selected,menu.entries.len()+1).trim().to_owned();
    if automatic {
        options.push_str(
            " quiet splash plymouth.ignore-serial-consoles loglevel=0 enzimos.restore-ui=1",
        );
    }
    records::command_line(&options)?;
    let prefix = format!("/enzimos/recovery-images/{image}");
    let unsigned_uefi = format!(
        "title {title}\nlinux {prefix}/kernel\ninitrd {prefix}/initrd.img\noptions {options}\n"
    );
    let addition = format!(
        "/{title}\n    protocol: linux\n    path: boot():{prefix}/kernel\n    module_path: boot():{prefix}/initrd.img\n    cmdline: {options}\n"
    );
    let next_bios = recovery_boot::replace_default(
        &format!("{}\n{addition}", bios.trim_end()),
        "default_entry: ",
        &(menu.entries.len() + 1).to_string(),
    )?;
    boot_entries::menu(&next_bios)?;
    let next_loader = recovery_boot::replace_default(&loader, "default ", &entry)?;
    let run = value!({"schema":1,"id":id,"phase":"staged","plan_sha256":digest,"flavor":flavor,"image":image,"created_boot":operation::boot_id()?,"entry":{"uefi_entry":entry,"uefi_previous":default,"uefi_mode":if one_shot {"one-shot"} else {"default"},"bios_title":title,"bios_previous":menu.selected,"bios_own":menu.entries.len()+1,"options":options},"result":null});
    records::run(&run, id)?;
    idle.recheck()?;
    images.unchanged()?;
    runs.unchanged()?;
    volume.writable()?;
    require(
        text(&volume, "loader/loader.conf")? == loader
            && text(&volume, "limine/limine.conf")? == bios,
        "recovery defaults changed before staging",
    )?;
    // An interrupted record never restages entries or guesses whether firmware accepted it.
    authorize()?;
    lock.recheck()?;
    runs.save(id, run.clone(), None, lock)?;
    idle.recorded_run(id, &run)?;
    // Signing may publish an immutable UKI. Its owning run intent must already
    // be durable, including when interruption precedes any loader entry write.
    authorize()?;
    lock.recheck()?;
    let uefi = signed_entry::wrap_locked(&unsigned_uefi, lock)?;
    authorize()?;
    lock.recheck()?;
    idle.recheck()?;
    images.unchanged()?;
    runs.unchanged()?;
    volume.writable()?;
    files::atomic(
        &volume.path(Path::new(&format!("loader/entries/{entry}")))?,
        uefi.as_bytes(),
        files::public_file_mode(&volume.directory)?,
        Some(0),
        false,
    )?;
    require(
        text(&volume, &format!("loader/entries/{entry}"))? == uefi,
        "recovery run UEFI entry readback differs",
    )?;
    require(
        text(&volume, "limine/limine.conf")? == bios,
        "BIOS defaults changed during run publication",
    )?;
    idle.recheck()?;
    volume.writable()?;
    authorize()?;
    lock.recheck()?;
    files::atomic(
        &volume.path(Path::new("limine/limine.conf"))?,
        next_bios.as_bytes(),
        files::public_file_mode(&volume.directory)?,
        Some(0),
        true,
    )?;
    require(
        text(&volume, "limine/limine.conf")? == next_bios,
        "recovery run BIOS readback differs",
    )?;
    require(
        text(&volume, "loader/loader.conf")? == loader,
        "UEFI defaults changed during run publication",
    )?;
    idle.recheck()?;
    volume.writable()?;
    authorize()?;
    lock.recheck()?;
    if one_shot {
        operation::query(
            "/usr/bin/bootctl",
            &["--quiet", "set-oneshot", &entry],
            Duration::from_secs(30),
            65536,
            &[0],
        )?;
        let path =
            Path::new(activation::EFI).join(format!("LoaderEntryOneShot-{}", activation::GUID));
        require(
            boot_entries::efi_string(&files::read_kernel(&path, 8192)?)? == entry,
            "recovery one-shot firmware readback differs",
        )?;
    } else {
        files::atomic(
            &volume.path(Path::new("loader/loader.conf"))?,
            next_loader.as_bytes(),
            files::public_file_mode(&volume.directory)?,
            Some(0),
            true,
        )?;
        require(
            text(&volume, "loader/loader.conf")? == next_loader,
            "recovery run UEFI default readback differs",
        )?;
    }
    volume.directory.sync_all()?;
    volume.recheck()?;
    idle.recheck()?;
    runs.unchanged()?;
    authorize()?;
    lock.recheck()?;
    Ok(
        value!({"status":"recovery-run-staged","id":id,"uefi_mode":if one_shot {"one-shot"} else {"default"},"reboot_required":true,"replay":false}),
    )
}
