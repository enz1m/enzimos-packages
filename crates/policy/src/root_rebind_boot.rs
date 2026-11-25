// SPDX-License-Identifier: MIT
//! The complete boot directory and immutable publisher artifacts are measured together.
use crate::{
    boot_entries, boot_volume::Volume, identity, recovery_activation, recovery_boot,
    recovery_image, root_rebind_plan::Texts, signed_entry,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, path::Path};
pub(crate) fn body(volume: &Volume, name: &str, limit: usize) -> Result<Vec<u8>> {
    let artifact = volume.artifact(Path::new(name), limit as u64)?;
    let bytes = files::read_file(&artifact.file, limit, Some(0), true)?;
    artifact.recheck()?;
    volume.recheck()?;
    Ok(bytes)
}
pub(crate) fn texts(volume: &Volume) -> Result<Texts> {
    let directory = volume.directory(Path::new("loader/entries"))?;
    let names = files::directory_names(&directory, 126)?;
    require(names.len() <= 126, "rebind boot entry count bound")?;
    let mut ordered = vec![
        "loader/loader.conf".to_owned(),
        "limine/limine.conf".to_owned(),
    ];
    let mut original_members = Vec::new();
    for entry in names {
        let name = entry
            .into_string()
            .map_err(|_| Error("rebind boot entry name encoding".into()))?;
        identity::safe_id(&name)?;
        let entry =
            enzimos_platform::directory_entry::Entry::observe(&directory, Path::new(&name))?;
        require(
            name.ends_with(".conf") && entry.metadata()?.is_file(),
            "unknown rebind boot metadata member",
        )?;
        ordered.push(format!("loader/entries/{name}"));
        original_members.push(entry);
    }
    let mut result = Texts::new();
    for name in ordered {
        result.insert(
            name.clone(),
            String::from_utf8(body(volume, &name, boot_entries::MAX_TEXT)?)
                .map_err(|_| Error("rebind boot text encoding".into()))?,
        );
    }
    for original in original_members {
        original.recheck()?;
    }
    volume.recheck()?;
    Ok(result)
}
pub(crate) fn generations(volume: &Volume, catalog: &Value) -> Result<()> {
    let records = enzimos_platform::json::object(&catalog["generations"])?;
    let path = volume.path(Path::new("enzimos/generations"))?;
    let mut original_members = Vec::new();
    let names = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
        Err(e) => return Err(e.into()),
        Ok(_) => {
            let held = volume.directory(Path::new("enzimos/generations"))?;
            let entries = files::directory_names(&held, 64)?;
            require(entries.len() <= 64, "rebind generation directory bound")?;
            let mut names = BTreeSet::new();
            for entry in entries {
                let name = entry
                    .into_string()
                    .map_err(|_| Error("rebind generation name encoding".into()))?;
                identity::safe_id(&name)?;
                let entry =
                    enzimos_platform::directory_entry::Entry::observe(&held, Path::new(&name))?;
                require(
                    entry.metadata()?.is_dir(),
                    "unrecognized generation directory object",
                )?;
                let child = volume.directory(Path::new(&format!("enzimos/generations/{name}")))?;
                entry.matches(&child)?;
                original_members.push(entry);
                names.insert(name);
            }
            names
        }
    };
    require(
        names == records.keys().cloned().collect(),
        "unregistered or missing generation prevents rebind",
    )?;
    for (id, record) in records {
        require(
            record["state"] == "ready",
            "unfinished generation prevents rebind",
        )?;
        let ready = json::decode(
            &body(
                volume,
                &format!("enzimos/generations/{id}/READY.json"),
                crate::catalog::MAX_CATALOG,
            )?,
            crate::catalog::MAX_CATALOG,
        )?;
        require(
            ready
                == value!({"generation":id,"kernels":record["material"]["kernels"],"files":record["material"]["files"]}),
            "immutable generation manifest changed",
        )?;
        for row in enzimos_platform::json::array(&record["material"]["files"])? {
            let name = enzimos_platform::json::string(&row["name"])?;
            let artifact = volume.artifact(
                Path::new(&format!("enzimos/generations/{id}/{name}")),
                128 * 1024 * 1024,
            )?;
            require(
                artifact.bytes == enzimos_platform::json::unsigned(&row["bytes"])?
                    && artifact.sha == row["sha256"],
                "immutable generation bytes changed",
            )?;
            artifact.recheck()?;
        }
    }
    for original in original_members {
        original.recheck()?;
    }
    volume.recheck()
}
pub(crate) fn auxiliary(volume: &Volume, images: &Value, activations: &Value) -> Result<()> {
    let actual = texts(volume)?;
    let menu = boot_entries::menu(&actual["limine/limine.conf"])?;
    for image in enzimos_platform::json::object(images)?.values() {
        recovery_image::verify_published(image)?;
    }
    for (id, activation) in enzimos_platform::json::object(activations)? {
        recovery_activation::validate(activation, id)?;
        let entries = recovery_boot::entries(&activation["intent"]["job"])?;
        for (name, expected) in entries.uefi {
            let actual = boot_entries::fields(
                actual
                    .get(&format!("loader/entries/{name}"))
                    .ok_or_else(|| Error("staged UEFI owner missing".into()))?,
                false,
            )?;
            let expected = boot_entries::fields(&expected, false)?;
            require(
                ["title", "linux", "initrd", "options"]
                    .iter()
                    .all(|key| actual.get(*key) == expected.get(*key))
                    && actual
                        .keys()
                        .all(|key| expected.contains_key(key) || key == "uki"),
                "staged UEFI owner changed",
            )?;
            signed_entry::verify(&actual)?;
        }
        // Staged entry fragments have no default. Give the parser its explicit
        // single header without altering any published menu or selection.
        let expected = boot_entries::menu(&format!("default_entry: 1\n{}", entries.bios))?;
        for entry in expected.entries {
            let found = menu
                .entries
                .iter()
                .find(|row| row.title == entry.title)
                .ok_or_else(|| Error("staged BIOS owner missing".into()))?;
            require(
                boot_entries::fields(&found.text, true)?
                    == boot_entries::fields(&entry.text, true)?,
                "staged BIOS owner changed",
            )?;
        }
    }
    volume.recheck()
}
