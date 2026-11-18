// SPDX-License-Identifier: MIT
//! Confirm a later, actually running managed boot without changing selection.
use crate::{
    boot_entries, boot_options, boot_volume::Volume, catalog, generation_stage, namespaces,
    operation, recovery_activation_runtime as activation, root_rebind_boot, subvolume,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, os::fd::AsFd, path::Path};

/// Pure binding check; every supplied observation is measured by confirm_locked.
pub fn observation(
    record: &Value,
    filesystem: &str,
    boot: &str,
    command_line: &str,
    root: &Value,
    kernel: &str,
    inventory: &str,
    fingerprints: &Value,
    uefi: bool,
    selected: Option<&str>,
) -> Result<Value> {
    let generation = record["generation"]
        .as_str()
        .ok_or_else(|| Error("registered generation identity missing".into()))?;
    catalog::material(&record["material"], generation)?;
    crate::identity::uuid(filesystem)?;
    crate::identity::uuid(boot)?;
    require(
        record["state"] == "ready" && record["created_boot"] != boot,
        "only a later boot can confirm a ready publication",
    )?;
    require(
        boot_options::marker(command_line, "enzimos.generation")? == generation,
        "actual generation marker differs",
    )?;
    require(
        !command_line.split_whitespace().any(|word| {
            [
                "init=",
                "rdinit=",
                "enzimos.staged=",
                "enzimos.run=",
                "enzimos.recovery=",
                "enzimos.handoff=",
            ]
            .iter()
            .any(|prefix| word.starts_with(prefix))
        }),
        "regular managed boot required for generation confirmation",
    )?;
    let material = &record["material"];
    require(
        root == &material["root_identity"]
            && boot_options::subvolume_from_options(command_line)? == root["path"]
            && json::sha256(inventory.as_bytes()) == material["inventory_sha256"]
            && fingerprints == &record["entry_fingerprints"],
        "running root, inventory or loader binding differs",
    )?;
    let matches = ["linux", "linux-lts"]
        .into_iter()
        .filter(|flavor| material["kernels"][*flavor] == kernel)
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        "actual running kernel differs from publication",
    )?;
    require(
        if uefi {
            selected == Some(format!("enzimos-{generation}-{}.conf", matches[0]).as_str())
        } else {
            selected.is_none()
        },
        "actual firmware selected entry differs",
    )?;
    Ok(
        value!({"boot_id":boot,"kernel":kernel,"uefi":uefi,"filesystem_uuid":filesystem,
        "root_uuid":root["uuid"],"material_sha256":json::fingerprint(material)?,
        "assurance":"software-local-observed-boot-not-firmware-authentication"}),
    )
}

pub fn confirm_locked(_lock: &files::Lock) -> Result<Value> {
    namespaces::initial()?;
    let snapshot = Snapshot::online()?;
    let pacman = files::directory(Path::new("/var/lib/pacman"), Some(0))?;
    require(
        files::optional_relative(&pacman, Path::new("db.lck"))?.is_none(),
        "package transaction active",
    )?;
    let bytes = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
    let command_line =
        std::str::from_utf8(&bytes).map_err(|_| Error("actual boot options encoding".into()))?;
    let generation = boot_options::marker(command_line, "enzimos.generation")?;
    let mut transaction = catalog::Transaction::begin()?;
    let record = transaction.data["generations"]
        .get(&generation)
        .cloned()
        .ok_or_else(|| Error("actual generation is not publisher registered".into()))?;
    let volume = Volume::observe()?;
    let owner = crate::secure_owner_source::Owner::observe()?;
    root_rebind_boot::generations(&volume, &transaction.data)?;
    let texts = root_rebind_boot::texts(&volume)?;
    let entries = texts
        .iter()
        .filter_map(|(name, body)| {
            name.strip_prefix("loader/entries/")
                .map(|key| (key.to_owned(), body.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let fingerprints =
        boot_entries::fingerprint_entries(&record, &entries, &texts["limine/limine.conf"])?;
    let mut signatures = Vec::new();
    for flavor in ["linux", "linux-lts"] {
        if let Some(verified) = crate::signed_entry::retain(&boot_entries::fields(
            &entries[&format!("enzimos-{generation}-{flavor}.conf")],
            false,
        )?)? {
            signatures.push(verified);
        }
    }
    let mut held = Vec::new();
    for (name, body) in &texts {
        let artifact = volume.artifact(Path::new(name), boot_entries::MAX_TEXT as u64)?;
        require(
            files::read_file(&artifact.file, boot_entries::MAX_TEXT, Some(0), true)?
                == body.as_bytes(),
            "boot metadata changed during observation",
        )?;
        held.push(artifact);
    }
    let ready = volume.artifact(
        Path::new(&format!("enzimos/generations/{generation}/READY.json")),
        catalog::MAX_CATALOG as u64,
    )?;
    require(
        json::decode(
            &files::read_file(&ready.file, catalog::MAX_CATALOG, Some(0), true)?,
            catalog::MAX_CATALOG,
        )? == value!({"generation":generation,"kernels":record["material"]["kernels"],"files":record["material"]["files"]}),
        "retained ready manifest differs",
    )?;
    held.push(ready);
    for row in record["material"]["files"]
        .as_array()
        .ok_or_else(|| Error("publication artifacts missing".into()))?
    {
        let artifact = volume.artifact(
            Path::new(&format!(
                "enzimos/generations/{generation}/{}",
                row["name"].as_str().unwrap()
            )),
            128 * 1024 * 1024,
        )?;
        require(
            artifact.sha == row["sha256"] && Some(artifact.bytes) == row["bytes"].as_u64(),
            "retained boot artifact differs",
        )?;
        held.push(artifact);
    }
    let root = files::directory(Path::new("/"), Some(0))?;
    let name = snapshot.guard.configuration["root_subvol"]
        .as_str()
        .unwrap();
    let (object, readonly) = subvolume::observe(root.as_fd(), name)?;
    require(!readonly, "running generation root must be writable")?;
    let root_identity =
        value!({"path":name,"id":object["id"],"uuid":object["uuid"],"ownership":"not-established"});
    let root_mount = mount_identity::id(root.as_fd(), true)?;
    let rows = crate::storage_runtime::rows()?;
    require(
        rows.iter()
            .filter(|row| {
                row.target == "/"
                    && row.id == root_mount
                    && row.filesystem == "btrfs"
                    && row.root == format!("/{name}")
                    && row.options.split(',').any(|word| word == "rw")
            })
            .count()
            == 1,
        "actual root mount differs from publication",
    )?;
    let inventory = generation_stage::inventory(&root)?;
    let kernel = namespaces::kernel_release()?;
    // Both installed kernel bytes must agree, not merely uname's version string.
    let mut kernels = Vec::new();
    for flavor in ["linux", "linux-lts"] {
        let release = record["material"]["kernels"][flavor].as_str().unwrap();
        let path = format!("usr/lib/modules/{release}/vmlinuz");
        let file = files::open_relative(&root, Path::new(&path))?;
        let before = files::identity(&file.metadata()?);
        require(
            mount_identity::id(file.as_fd(), true)? == root_mount,
            "kernel crosses root mount",
        )?;
        let expected = record["material"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == format!("vmlinuz-{flavor}"))
            .unwrap();
        let (bytes, digest) = stream_copy::hash_borrowed(&file, 128 * 1024 * 1024, Some(0))?;
        require(
            digest == expected["sha256"] && Some(bytes) == expected["bytes"].as_u64(),
            "installed kernel bytes differ from boot artifact",
        )?;
        kernels.push((path, file, before));
    }
    let uefi = activation::efi_guard()?;
    let selected = if uefi {
        Some(boot_entries::efi_string(&files::read_kernel(
            &Path::new(activation::EFI).join(format!("LoaderEntrySelected-{}", activation::GUID)),
            8192,
        )?)?)
    } else {
        None
    };
    let boot = operation::boot_id()?;
    let confirmation = observation(
        &record,
        transaction.config["filesystem_uuid"].as_str().unwrap(),
        &boot,
        command_line,
        &root_identity,
        &kernel,
        &inventory,
        &fingerprints,
        uefi,
        selected.as_deref(),
    )?;
    let next = catalog::confirm_document(&transaction.data, &generation, &confirmation)?;
    snapshot.recheck()?;
    transaction.recheck()?;
    owner.recheck()?;
    for verified in &signatures {
        verified.recheck()?;
    }
    volume.recheck()?;
    for artifact in &held {
        artifact.recheck()?;
    }
    for (path, file, before) in &kernels {
        require(
            files::identity(&file.metadata()?) == *before
                && files::identity(&files::open_relative(&root, Path::new(path))?.metadata()?)
                    == *before,
            "original installed kernel replaced",
        )?;
    }
    require(
        subvolume::observe(root.as_fd(), name)? == (object, false)
            && generation_stage::inventory(&root)? == inventory
            && files::read_kernel(Path::new("/proc/cmdline"), 65536)? == bytes
            && operation::boot_id()? == boot
            && activation::efi_guard()? == uefi
            && files::optional_relative(&pacman, Path::new("db.lck"))?.is_none()
            && root_rebind_boot::texts(&volume)? == texts,
        "actual boot inputs changed before confirmation",
    )?;
    if let Some(selected) = &selected {
        require(
            boot_entries::efi_string(&files::read_kernel(
                &Path::new(activation::EFI)
                    .join(format!("LoaderEntrySelected-{}", activation::GUID)),
                8192,
            )?)? == *selected,
            "selected entry changed before confirmation",
        )?;
    }
    snapshot.recheck()?;
    transaction.data = next;
    transaction.commit()?;
    Ok(value!({"generation":generation,"confirmation":confirmation,"retirement_enabled":false}))
}
