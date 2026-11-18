// SPDX-License-Identifier: MIT
//! Publish one reviewed legacy ring under both policy and package-manager locks.
use crate::{
    authority, authority_build, authority_mount, authority_record, control_record, operation,
    pacman_lock::PacmanLock, subvolume, transition_idle,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{os::fd::AsFd, path::Path};
pub fn refresh_locked(_lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    let mut package_lock = PacmanLock::acquire()?;
    let id = format!("authority-{}", files::random_hex(16)?);
    let mut snapshot = transition_idle::Snapshot::authority_refresh(&id)?;
    let mounted = authority_mount::Authority::observe(&snapshot.guard)?;
    let current = mounted.files()?;
    let before = mounted.hashes()?;
    let workspace = Path::new("/run/enzimos/authority-builds");
    files::ensure_directory(workspace, 0o700, 0)?;
    let prepared = authority_build::build(
        Path::new(authority_mount::PATH),
        Path::new("/usr/share/pacman/keyrings"),
        &workspace.join(&id),
        0,
    )?;
    mounted.recheck(&snapshot.guard)?;
    snapshot.recheck()?;
    package_lock.recheck()?;
    prepared.recheck()?;
    require(
        mounted.hashes()? == before,
        "authority changed during publication review",
    )?;
    let final_files = prepared.files();
    let after = prepared.hashes();
    let mut record = value!({"schema":1,"id":id,"phase":"intent","boot":operation::boot_id()?,"filesystem_uuid":snapshot.guard.configuration["filesystem_uuid"],"authority":mounted.identity(),"before":before,"after":after,"approved":prepared.approved,"local":prepared.local,"summary":prepared.summary});
    authority_record::validate(&record, &id)?;
    let directory = Path::new(operation::CONTROL).join("authority-refresh");
    let journals = files::ensure_directory(&directory, 0o700, 0)?;
    require(
        mount_identity::id(journals.as_fd(), true)? == snapshot.guard.control_mount_id(),
        "authority journal left retained control storage",
    )?;
    let name = format!("{id}.json");
    let journal = directory.join(&name);
    files::atomic(&journal, &json::canonical(&record)?, 0o600, Some(0), false)?;
    snapshot.authority_checkpoint(&id, &record)?;
    // Keep original bytes; never reuse an earlier diagnostic directory.
    let backup = Path::new(authority_mount::PATH).join(format!(".native-previous-{id}"));
    files::create_directory(&backup, 0o700, 0)?;
    for name in authority::FILES {
        mounted.recheck(&snapshot.guard)?;
        snapshot.recheck()?;
        package_lock.recheck()?;
        prepared.recheck()?;
        files::atomic_bounded(
            &backup.join(name),
            &current[name],
            if name == "gpg.conf" { 0o644 } else { 0o600 },
            Some(0),
            false,
            8 * 1024 * 1024,
        )?;
    }
    require(
        mounted.hashes()? == before,
        "authority drift before publication",
    )?;
    package_lock.retain_on_failure()?;
    record["phase"] = value!("publishing");
    files::atomic(&journal, &json::canonical(&record)?, 0o600, Some(0), true)?;
    snapshot.authority_checkpoint(&id, &record)?;
    let attempted: Result<()> = (|| {
        for (index, name) in authority::FILES.iter().enumerate() {
            mounted.recheck(&snapshot.guard)?;
            snapshot.recheck()?;
            package_lock.recheck()?;
            prepared.recheck_material()?;
            require(
                control_record::read(
                    &journals,
                    Path::new(&format!("{id}.json")),
                    2 * 1024 * 1024,
                    snapshot.guard.control_mount_id(),
                )? == record,
                "authority publication journal changed",
            )?;
            require(
                mounted.hashes()? == authority_record::prefix(&before, &after, index)?,
                "authority publication prefix changed; retained for review",
            )?;
            files::atomic_bounded(
                &Path::new(authority_mount::PATH).join(name),
                &final_files[*name],
                if *name == "gpg.conf" { 0o644 } else { 0o600 },
                Some(0),
                true,
                8 * 1024 * 1024,
            )?;
            require(
                mounted.hashes()? == authority_record::prefix(&before, &after, index + 1)?,
                "authority publication readback changed",
            )?;
        }
        mounted.recheck(&snapshot.guard)?;
        prepared.recheck_material()?;
        snapshot.recheck()?;
        package_lock.recheck()?;
        require(
            mounted.hashes()? == after,
            "published authority differs from review",
        )?;
        subvolume::sync(snapshot.guard.control().as_fd())?;
        Ok(())
    })();
    // A failed native attempt stays blocking and is never silently rolled forward.
    record["phase"] = value!(if attempted.is_ok() {
        "complete"
    } else {
        "uncertain"
    });
    files::atomic(&journal, &json::canonical(&record)?, 0o600, Some(0), true)?;
    snapshot.authority_checkpoint(&id, &record)?;
    attempted?;
    package_lock.close()?;
    let mut summary = prepared.summary;
    summary["status"] = value!("authority-refreshed");
    Ok(summary)
}
