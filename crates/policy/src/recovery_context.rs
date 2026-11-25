// SPDX-License-Identifier: MIT
//! Retained offline source, protected roots, boot material and conflict journals.
use crate::{
    birth, birth_runtime, boot_entries,
    boot_volume::Volume,
    catalog, control_record, identity, namespaces, operation,
    recovery_journal::{Journal, Kind, Records},
    recovery_publication, recovery_records, root_rebind_record, signed_entry,
    storage_runtime::IndependentGuard,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
pub(crate) const QUERY_CONFIG: &str = "/usr/lib/enzimos-native/recovery-pacman.conf";
pub(crate) struct Context {
    pub guard: IndependentGuard,
    pub source: File,
    pub source_path: PathBuf,
    pub plan: Value,
    pub conflicts: Value,
    pub volume: Volume,
}
pub(crate) fn subvolumes(path: &Path) -> Result<Records> {
    let body = operation::query(
        "/usr/bin/btrfs",
        &[
            "subvolume",
            "list",
            "-a",
            "-u",
            "-q",
            path.to_str()
                .ok_or_else(|| Error("subvolume inventory path encoding".into()))?,
        ],
        Duration::from_secs(30),
        catalog::MAX_CATALOG,
        &[0],
    )?;
    birth_runtime::parse_inventory(
        std::str::from_utf8(&body).map_err(|_| Error("subvolume inventory encoding".into()))?,
    )
}
pub(crate) fn private_records<F>(
    guard: &IndependentGuard,
    folder: &str,
    maximum: usize,
    mut validate: F,
) -> Result<Records>
where
    F: FnMut(&Value, &str) -> Result<()>,
{
    identity::safe_id(folder)?;
    guard.recheck()?;
    let path = Path::new(operation::CONTROL).join(folder);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Records::new()),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    let directory = files::directory(&path, Some(0))?;
    require(
        directory.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
        "unsafe independent recovery registry",
    )?;
    let entries = std::fs::read_dir(&path)?
        .take(maximum + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    require(
        entries.len() <= maximum,
        "independent recovery registry count bound",
    )?;
    let mut records = Records::new();
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error("independent registry filename encoding".into()))?;
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| Error("unknown or interrupted independent registry write".into()))?;
        identity::safe_id(id)?;
        let record = control_record::read(
            &directory,
            Path::new(&name),
            catalog::MAX_CATALOG,
            guard.control_mount_id(),
        )?;
        validate(&record, id)?;
        records.insert(id.into(), record);
    }
    let current = files::directory(&path, Some(0))?;
    let a = directory.metadata()?;
    let b = current.metadata()?;
    require(
        (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
            && mount_identity::id(current.as_fd(), true)? == guard.control_mount_id(),
        "independent registry replaced",
    )?;
    guard.recheck()?;
    Ok(records)
}
fn catalog_data(guard: &IndependentGuard) -> Result<Value> {
    let directory = Path::new(operation::CONTROL).join("generation-registry");
    let held = files::directory(&directory, Some(0))?;
    require(
        held.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(held.as_fd(), true)? == guard.control_mount_id(),
        "unsafe independent generation registry",
    )?;
    for entry in std::fs::read_dir(&directory)?.take(3) {
        let entry = entry?;
        require(
            matches!(entry.file_name().to_str(), Some("lock" | "catalog.json")),
            "unknown or interrupted independent generation registry write",
        )?;
    }
    let data = control_record::read(
        &held,
        Path::new("catalog.json"),
        catalog::MAX_CATALOG,
        guard.control_mount_id(),
    )?;
    catalog::validate(
        &data,
        recovery_records::text(guard.plan(), "filesystem_uuid")?,
    )?;
    let current = files::directory(&directory, Some(0))?;
    let a = held.metadata()?;
    let b = current.metadata()?;
    require(
        (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
            && mount_identity::id(current.as_fd(), true)? == guard.control_mount_id(),
        "independent generation registry replaced",
    )?;
    Ok(data)
}
pub(crate) fn fingerprint_entries(volume: &Volume, record: &Value) -> Result<Value> {
    let mut uefi = std::collections::BTreeMap::new();
    let generation = recovery_records::text(record, "generation")?;
    for flavor in ["linux", "linux-lts"] {
        let name = format!("enzimos-{generation}-{flavor}.conf");
        let file = volume.artifact(
            Path::new(&format!("loader/entries/{name}")),
            boot_entries::MAX_TEXT as u64,
        )?;
        let bytes = files::read_file(&file.file, boot_entries::MAX_TEXT, Some(0), true)?;
        let body =
            std::str::from_utf8(&bytes).map_err(|_| Error("publisher entry encoding".into()))?;
        signed_entry::verify(&boot_entries::fields(body, false)?)?;
        file.recheck()?;
        uefi.insert(name, body.to_owned());
    }
    let bios = volume.artifact(
        Path::new("limine/limine.conf"),
        boot_entries::MAX_TEXT as u64,
    )?;
    let bytes = files::read_file(&bios.file, boot_entries::MAX_TEXT, Some(0), true)?;
    let result = boot_entries::fingerprint_entries(
        record,
        &uefi,
        std::str::from_utf8(&bytes).map_err(|_| Error("publisher BIOS encoding".into()))?,
    )?;
    bios.recheck()?;
    volume.recheck()?;
    Ok(result)
}
fn conflicts(guard: &IndependentGuard, volume: &Volume) -> Result<Value> {
    let plan = guard.plan();
    let filesystem = recovery_records::text(plan, "filesystem_uuid")?;
    let update_applies = private_records(
        guard,
        "update-applies",
        crate::update_apply_record::MAXIMUM,
        crate::update_apply_record::validate,
    )?;
    require(
        update_applies.values().all(|row| {
            crate::update_apply_record::finished(row) && row["filesystem_uuid"] == filesystem
        }),
        "incomplete or foreign native update apply prevents recovery",
    )?;
    let boot_publications = private_records(
        guard,
        "boot-publications",
        128,
        crate::generation_publication::validate,
    )?;
    require(
        boot_publications
            .values()
            .all(|row| row["phase"] == "complete" && row["filesystem_uuid"] == filesystem),
        "incomplete or foreign boot generation publication prevents recovery",
    )?;
    let update_workers = private_records(
        guard,
        "update-workers",
        crate::update_worker_record::MAXIMUM,
        crate::update_worker_record::validate,
    )?;
    require(
        update_workers.values().all(|record| {
            record["phase"] == "complete" && record["request"]["filesystem_uuid"] == filesystem
        }),
        "incomplete or foreign update worker prevents recovery",
    )?;
    let module_views = private_records(
        guard,
        "module-views",
        crate::module_view_record::MAXIMUM,
        crate::module_view_record::validate,
    )?;
    require(
        module_views
            .values()
            .all(|record| record["phase"] == "complete" && record["filesystem_uuid"] == filesystem),
        "incomplete or foreign module view prevents recovery",
    )?;
    let authority_refresh = private_records(
        guard,
        "authority-refresh",
        crate::authority_record::MAXIMUM,
        crate::authority_record::validate,
    )?;
    require(
        authority_refresh
            .values()
            .all(|record| record["phase"] == "complete" && record["filesystem_uuid"] == filesystem),
        "incomplete or foreign authority publication prevents recovery",
    )?;
    let births = private_records(guard, "root-births", birth_runtime::MAX_RECORDS, |v, id| {
        birth::validate(v, id, filesystem)
    })?;
    require(
        births
            .values()
            .all(|r| matches!(r["phase"].as_str(), Some("ready" | "retired")))
            && births.get(recovery_records::text(
                &plan["source_birth"],
                "transaction",
            )?) == Some(&plan["source_birth"]),
        "incomplete or changed recovery source birth",
    )?;
    let rebinds = private_records(
        guard,
        "root-rebind-journal",
        32,
        root_rebind_record::validate,
    )?;
    require(
        rebinds
            .values()
            .all(|r| r["phase"] == "complete" && r["filesystem_uuid"] == filesystem),
        "incomplete or foreign root rebind prevents recovery",
    )?;
    let catalog = catalog_data(guard)?;
    require(
        catalog["generations"]
            .as_object()
            .unwrap()
            .values()
            .all(|r| r["state"] == "ready"),
        "incomplete generation prevents recovery",
    )?;
    let generation = recovery_records::text(plan, "generation")?;
    let record = &catalog["generations"][generation];
    require(
        record["material"] == plan["material"]
            && fingerprint_entries(volume, record)? == record["entry_fingerprints"],
        "recovery generation material or loader binding changed",
    )?;
    let images = Journal::open_independent(Kind::Images, false, plan)?;
    require(
        images
            .records
            .values()
            .all(|r| r["phase"] == "ready" && r["filesystem_uuid"] == filesystem),
        "incomplete or foreign image prevents recovery",
    )?;
    let publications = Journal::open_independent(Kind::Publications, false, plan)?;
    for (id, journal) in &publications.records {
        let current = images
            .records
            .get(id)
            .ok_or_else(|| Error("orphan recovery publication".into()))?;
        recovery_publication::expected_record(journal, current)?;
    }
    images.recheck()?;
    publications.recheck()?;
    Ok(
        value!({"update_applies":update_applies,"boot_publications":boot_publications,"update_workers":update_workers,"module_views":module_views,"authority_refresh":authority_refresh,"births":births,"rebinds":rebinds,"catalog":catalog,"images":images.records,"publications":publications.records}),
    )
}
pub(crate) fn contents(plan: &Value, source: &Path, volume: &Volume) -> Result<()> {
    let lock = source.join("var/lib/pacman/db.lck");
    require(
        matches!(std::fs::symlink_metadata(lock), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "snapshot contains package lock",
    )?;
    for relative in [
        "usr",
        "usr/lib",
        "usr/lib/modules",
        "var",
        "var/lib",
        "var/lib/pacman",
        "var/lib/pacman/local",
    ] {
        files::directory(&source.join(relative), Some(0))?;
    }
    require(
        files::read(Path::new(QUERY_CONFIG), 4096, Some(0), true)?
            == b"[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\n",
        "recovery query configuration changed",
    )?;
    let inventory = operation::query(
        "/usr/bin/pacman",
        &[
            "--root",
            source.to_str().unwrap(),
            "--config",
            QUERY_CONFIG,
            "-Q",
        ],
        Duration::from_secs(30),
        catalog::MAX_CATALOG,
        &[0],
    )?;
    let inventory = std::str::from_utf8(&inventory)
        .map_err(|_| Error("snapshot package inventory encoding".into()))?
        .trim();
    require(
        json::sha256(inventory.as_bytes()) == plan["material"]["inventory_sha256"],
        "snapshot package inventory differs from recovery plan",
    )?;
    let generation = recovery_records::text(plan, "generation")?;
    let prefix = format!("enzimos/generations/{generation}");
    let ready = volume.artifact(
        Path::new(&format!("{prefix}/READY.json")),
        catalog::MAX_CATALOG as u64,
    )?;
    require(
        json::decode(
            &files::read_file(&ready.file, catalog::MAX_CATALOG, Some(0), true)?,
            catalog::MAX_CATALOG,
        )? == value!({"generation":generation,"kernels":plan["material"]["kernels"],"files":plan["material"]["files"]}),
        "recovery boot manifest changed",
    )?;
    ready.recheck()?;
    for row in plan["material"]["files"].as_array().unwrap() {
        let artifact = volume.artifact(
            Path::new(&format!(
                "{prefix}/{}",
                recovery_records::text(row, "name")?
            )),
            128 * 1024 * 1024,
        )?;
        require(
            artifact.bytes == row["bytes"].as_u64().unwrap() && artifact.sha == row["sha256"],
            "recovery boot artifact changed",
        )?;
        artifact.recheck()?;
    }
    for flavor in ["linux", "linux-lts"] {
        let release = recovery_records::text(&plan["material"]["kernels"], flavor)?;
        let root = files::directory(&source.join(format!("usr/lib/modules/{release}")), Some(0))?;
        let mut file = files::open_relative(&root, Path::new("vmlinuz"))?;
        let before = files::identity(&file.metadata()?);
        let (_, sha) = stream_copy::hash(&mut file, 128 * 1024 * 1024, Some(0))?;
        let name = format!("vmlinuz-{flavor}");
        let expected = plan["material"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap();
        require(
            sha == expected["sha256"]
                && files::identity(&files::open_relative(&root, Path::new("vmlinuz"))?.metadata()?)
                    == before,
            "snapshot kernel differs from recovery artifact",
        )?;
    }
    volume.recheck()
}
impl Context {
    pub(crate) fn observe(plan: &Value) -> Result<Self> {
        let guard = IndependentGuard::observe(plan)?;
        let inventory = subvolumes(Path::new(IndependentGuard::TOP))?;
        let source_root = recovery_records::text(&plan["source_birth"]["source"], "path")?;
        let prefix = format!("{source_root}/");
        let snapshots = format!("{source_root}/.snapshots");
        require(
            inventory.keys().all(|path| {
                !path.starts_with(&prefix)
                    || path == &snapshots
                    || path.starts_with(&format!("{snapshots}/"))
            }),
            "unqualified nested source data prevents snapshot recovery",
        )?;
        for role in ["home", "authority", "control"] {
            let expected = &plan["protected"][role];
            let relative = recovery_records::text(expected, "path")?;
            require(
                inventory.get(relative) == Some(expected)
                    && birth_runtime::observe(
                        &Path::new(IndependentGuard::TOP).join(relative),
                        relative,
                        recovery_records::text(plan, "filesystem_uuid")?,
                    )?
                    .1 == *expected,
                "protected recovery identity changed",
            )?;
        }
        let expected = &plan["source_birth"]["snapshot"]["object"];
        let relative = recovery_records::text(expected, "path")?;
        require(
            inventory.get(relative) == Some(expected),
            "recovery snapshot inventory changed",
        )?;
        let source_path = Path::new(IndependentGuard::TOP).join(relative);
        let (source, observed, readonly) = birth_runtime::observe(
            &source_path,
            relative,
            recovery_records::text(plan, "filesystem_uuid")?,
        )?;
        require(
            observed == *expected && readonly,
            "recovery source snapshot changed or writable",
        )?;
        let target =
            Path::new(IndependentGuard::TOP).join(recovery_records::text(plan, "target_name")?);
        namespaces::observe()?.refuse_subtrees(
            source_path.to_str().unwrap(),
            target.to_str().unwrap(),
            &format!("/{}", recovery_records::text(plan, "target_name")?),
        )?;
        require(
            json::decode(
                &files::read(
                    &source_path.join("etc/enzimos/storage.json"),
                    catalog::MAX_CATALOG,
                    Some(0),
                    true,
                )?,
                catalog::MAX_CATALOG,
            )? == plan["storage"],
            "snapshot storage configuration differs from plan",
        )?;
        let volume = Volume::observe()?;
        require(
            volume.uuid == plan["boot_uuid"],
            "recovery boot filesystem differs from plan",
        )?;
        contents(plan, &source_path, &volume)?;
        let conflicts = conflicts(&guard, &volume)?;
        let context = Self {
            guard,
            source,
            source_path,
            plan: plan.clone(),
            conflicts,
            volume,
        };
        context.recheck()?;
        Ok(context)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.volume.recheck()?;
        let target_name = recovery_records::text(&self.plan, "target_name")?;
        let target = Path::new(IndependentGuard::TOP).join(target_name);
        namespaces::observe()?.refuse_subtrees(
            self.source_path.to_str().unwrap(),
            target.to_str().unwrap(),
            &format!("/{target_name}"),
        )?;
        let expected = &self.plan["source_birth"]["snapshot"]["object"];
        let relative = recovery_records::text(expected, "path")?;
        require(
            crate::subvolume::observe(self.source.as_fd(), relative)? == (expected.clone(), true)
                && birth_runtime::observe(
                    &self.source_path,
                    relative,
                    recovery_records::text(&self.plan, "filesystem_uuid")?,
                )?
                .1 == *expected,
            "retained recovery source changed",
        )?;
        require(
            conflicts(&self.guard, &self.volume)? == self.conflicts,
            "recovery conflict records changed",
        )
    }
}
