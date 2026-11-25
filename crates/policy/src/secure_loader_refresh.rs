// SPDX-License-Identifier: MIT
//! Update only the four installed owner loaders, verifying even unchanged bytes.
use crate::{
    boot_volume::Volume, operation, recovery_build_source::Source, secure_artifacts, secure_boot,
};
use enzimos_platform::{
    Result, files, json, memfile, mount_identity, process, publication, require,
};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, os::fd::AsFd, path::Path, time::Duration};
pub const LOADERS: [(&str, &str); 4] = [
    (
        "EFI/systemd/systemd-bootx64.efi",
        "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
    ),
    (
        "EFI/BOOT/BOOTX64.EFI",
        "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
    ),
    (
        "EFI/enzimos/refind_x64.efi",
        "/usr/share/refind/refind_x64.efi",
    ),
    (
        "EFI/enzimos/select-entry.efi",
        "/usr/share/enzimos-boot/select-entry.efi",
    ),
];
pub fn validate(record: &Value) -> Result<()> {
    let rows = record
        .as_object()
        .ok_or_else(|| enzimos_platform::Error("loader receipt object".into()))?;
    require(
        rows.len() == LOADERS.len() && LOADERS.iter().all(|(name, _)| rows.contains_key(*name)),
        "owner loader receipt exact destinations",
    )?;
    for row in rows.values() {
        json::fields(row, "source signed")?;
        for name in ["source", "signed"] {
            crate::identity::sha(
                row[name]
                    .as_str()
                    .ok_or_else(|| enzimos_platform::Error("loader receipt digest type".into()))?,
            )?;
        }
    }
    Ok(())
}
pub fn refresh_locked(volume: &Volume, lock: &files::Lock) -> Result<()> {
    refresh_authorized(volume, lock, &mut || lock.recheck())
}
pub fn refresh_authorized(
    volume: &Volume,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    authorize()?;
    lock.recheck()?;
    operation::root_only()?;
    volume.writable()?;
    let owner = crate::secure_owner_source::Owner::observe()?;
    let Some(material) = owner.material() else {
        return Ok(());
    };
    let mask = Path::new("/etc/systemd/system/systemd-boot-update.service");
    require(
        std::fs::symlink_metadata(mask)?.file_type().is_symlink()
            && std::fs::read_link(mask)? == Path::new("/dev/null"),
        "owner loaders require the installed automatic updater mask before publication",
    )?;
    let certificate = memfile::sealed("enzimos-loader-certificate", &material.pem)?;
    let receipt = Path::new(secure_boot::DIRECTORY).join("loaders.json");
    let receipt_parent = files::directory(
        receipt
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(0),
    )?;
    let previous_file = files::optional_relative(
        &receipt_parent,
        Path::new(
            receipt
                .file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        ),
    )?;
    let previous_epoch = previous_file
        .as_ref()
        .map(|f| f.metadata().map(|m| files::identity(&m)))
        .transpose()?;
    let previous = previous_file
        .as_ref()
        .map(|f| -> Result<Value> {
            json::decode(&files::read_file(f, 16384, Some(0), true)?, 16384)
        })
        .transpose()?;
    if let Some(previous) = &previous {
        validate(previous)?;
    }
    let root = files::directory(Path::new("/"), Some(0))?;
    let root_mount = mount_identity::id(root.as_fd(), true)?;
    let mut result = BTreeMap::new();
    for (name, path) in LOADERS {
        authorize()?;
        lock.recheck()?;
        volume.writable()?;
        owner.recheck()?;
        let source = Source::observe(Path::new(path), 16 * 1024 * 1024)?;
        require(
            mount_identity::id(source.file.as_fd(), true)? == root_mount,
            "loader source crosses another mount",
        )?;
        let source_hash = json::sha256(&source.body);
        let before = volume.artifact(Path::new(name), 16 * 1024 * 1024)?;
        let previous_signature = process::run_with_fds(
            "/usr/bin/sbverify",
            &["--cert", "@fd:0", "@fd:1"],
            &[],
            Duration::from_secs(600),
            16384,
            &[certificate.as_fd(), before.file.as_fd()],
        )?;
        require(
            previous_signature.status.success(),
            "existing installed loader is not owned by the original certificate",
        )?;
        before.recheck()?;
        owner.recheck()?;
        let unchanged = previous
            .as_ref()
            .is_some_and(|p| p[name]["source"] == source_hash && p[name]["signed"] == before.sha);
        let mut owned_signed = None;
        if !unchanged {
            before.recheck()?;
            source.recheck()?;
            authorize()?;
            lock.recheck()?;
            owned_signed = Some(secure_artifacts::sign_retained_authorized(
                Path::new(path),
                Some(&volume.path(Path::new(name))?),
                lock,
                authorize,
            )?);
        }
        authorize()?;
        lock.recheck()?;
        let signed = volume.artifact(Path::new(name), 16 * 1024 * 1024)?;
        if let Some(owned) = &owned_signed {
            owned.recheck(authorize)?;
            require(
                files::identity(&signed.file.metadata()?)
                    == files::identity(&owned.file(authorize)?.metadata()?),
                "installed owner loader differs from original signed output",
            )?;
        }
        let verification = process::run_with_fds(
            "/usr/bin/sbverify",
            &["--cert", "@fd:0", "@fd:1"],
            &[],
            Duration::from_secs(600),
            16384,
            &[certificate.as_fd(), signed.file.as_fd()],
        )?;
        require(
            verification.status.success(),
            "actual installed owner loader signature refused",
        )?;
        signed.recheck()?;
        if let Some(owned) = &owned_signed {
            owned.recheck(authorize)?;
        }
        source.recheck()?;
        owner.recheck()?;
        volume.recheck()?;
        result.insert(
            name.to_owned(),
            value!({"source":source_hash,"signed":signed.sha}),
        );
    }
    owner.recheck()?;
    let record = value!(result);
    validate(&record)?;
    authorize()?;
    lock.recheck()?;
    if let Some(original) = &previous_file {
        require(
            Some(files::identity(&original.metadata()?)) == previous_epoch,
            "original owner loader receipt changed during signing",
        )?;
    }
    let prepared = publication::Prepared::write_authorized(
        &receipt,
        &json::canonical(&record)?,
        0,
        authorize,
    )?;
    if let Some(original) = &previous_file {
        prepared.require_original(original)?;
    }
    let published = prepared.commit_retained_authorized(previous.is_some(), authorize)?;
    published.recheck()?;
    require(
        files::read(&receipt, 16384, Some(0), true)? == json::canonical(&record)?,
        "owner loader receipt readback differs",
    )?;
    require(
        std::fs::symlink_metadata(mask)?.file_type().is_symlink()
            && std::fs::read_link(mask)? == Path::new("/dev/null"),
        "owner loaders require the installed automatic updater mask",
    )?;
    authorize()?;
    lock.recheck()?;
    volume.recheck()
}
