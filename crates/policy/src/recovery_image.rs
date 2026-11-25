// SPDX-License-Identifier: MIT
//! Recovery image identities include the exact native runtime bytes.
use crate::{
    birth, boot_entries, boot_volume::Volume, identity, recovery_activation,
    recovery_records as records, signed_entry,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;
use std::{fs::File, os::fd::AsFd, path::Path};
pub(crate) const MAX_IMAGE: u64 = 192 * 1024 * 1024;
pub(crate) const MAX_IMAGES: usize = 8;
pub const ASSURANCE: &str = "software-local-recovery-boot-not-firmware-or-application-health";
pub fn identifier(id: &str) -> Result<&str> {
    let hash = id
        .strip_prefix("ri-")
        .ok_or_else(|| Error("invalid recovery image ID".into()))?;
    identity::sha(hash)?;
    Ok(id)
}
pub fn descriptor(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema kernel_release kernel_sha256 base_initrd_sha256 policy_files",
    )?;
    let native = match v["schema"].as_u64() {
        Some(1) => false,
        Some(2) => true,
        _ => return Err(Error("invalid recovery descriptor schema".into())),
    };
    identity::safe_id(records::text(v, "kernel_release")?)?;
    identity::sha(records::text(v, "kernel_sha256")?)?;
    identity::sha(records::text(v, "base_initrd_sha256")?)?;
    recovery_activation::policy_files(&v["policy_files"], native, true)
}
pub fn image_id(v: &Value) -> Result<String> {
    descriptor(v)?;
    Ok(format!("ri-{}", json::fingerprint(v)?))
}
pub fn manifest(v: &Value) -> Result<()> {
    json::fields(v, "schema identity files")?;
    require(
        v["schema"].as_u64() == Some(1),
        "invalid recovery image inputs schema",
    )?;
    descriptor(&v["identity"])?;
    json::fields(&v["files"], "kernel initrd.img")?;
    for row in enzimos_platform::json::object(&v["files"])?.values() {
        json::fields(row, "bytes sha256")?;
        require(
            row["bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= MAX_IMAGE),
            "recovery artifact byte bound",
        )?;
        identity::sha(records::text(row, "sha256")?)?;
    }
    require(
        v["files"]["kernel"]["sha256"] == v["identity"]["kernel_sha256"],
        "recovery kernel descriptor mismatch",
    )
}
pub(crate) fn entry_names(id: &str) -> Result<(String, String)> {
    identifier(id)?;
    Ok((format!("{id}.conf"), format!("enzimOS recovery {id}")))
}
pub(crate) fn entry_texts(id: &str, options: &str) -> Result<(String, String)> {
    let (_, title) = entry_names(id)?;
    records::command_line(options)?;
    let prefix = format!("/enzimos/recovery-images/{id}");
    Ok((
        format!(
            "title {title}\nlinux {prefix}/kernel\ninitrd {prefix}/initrd.img\noptions {options}\n"
        ),
        format!(
            "/{title}\n protocol: linux\n path: boot():{prefix}/kernel\n module_path: boot():{prefix}/initrd.img\n cmdline: {options}\n"
        ),
    ))
}
pub fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(
        v,
        "schema id phase created_boot filesystem_uuid control boot_uuid inputs options observations",
    )?;
    manifest(&v["inputs"])?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["id"] == id
            && image_id(&v["inputs"]["identity"])? == id,
        "recovery image record ID mismatch",
    )?;
    identity::uuid(records::text(v, "created_boot")?)?;
    identity::uuid(records::text(v, "filesystem_uuid")?)?;
    require(
        matches!(v["phase"].as_str(), Some("intent" | "artifacts" | "ready")),
        "invalid recovery image phase",
    )?;
    let control = &v["control"];
    identity::safe_id(records::text(control, "path")?)?;
    birth::object(
        control,
        records::text(control, "path")?,
        control["parent_uuid"].as_str(),
    )?;
    records::fat_uuid(records::text(v, "boot_uuid")?)?;
    let options = records::text(v, "options")?;
    records::command_line(options)?;
    let marker = format!("enzimos.recovery={id}");
    let words = options.split_whitespace().collect::<Vec<_>>();
    require(
        words
            .iter()
            .filter(|w| w.starts_with("enzimos.recovery="))
            .copied()
            .collect::<Vec<_>>()
            == [marker]
            && words.iter().all(|w| {
                ![
                    "root=",
                    "rootflags=",
                    "init=",
                    "rdinit=",
                    "initrd=",
                    "BOOT_IMAGE=",
                    "enzimos.generation=",
                ]
                .iter()
                .any(|p| w.starts_with(p))
            }),
        "recovery command line is not independent",
    )?;
    let observations = v["observations"]
        .as_object()
        .ok_or_else(|| Error("recovery image observations".into()))?;
    require(
        observations
            .keys()
            .all(|s| matches!(s.as_str(), "uefi" | "bios"))
            && (v["phase"] == "ready" || observations.is_empty()),
        "unfinished recovery image cannot be confirmed",
    )?;
    for (mode, pair) in observations {
        json::fields(pair, "first latest")?;
        for observation in enzimos_platform::json::object(pair)?.values() {
            json::fields(
                observation,
                "boot_id kernel identity_sha256 assurance selected_entry",
            )?;
            identity::uuid(records::text(observation, "boot_id")?)?;
            require(
                observation["boot_id"] != v["created_boot"]
                    && observation["kernel"] == v["inputs"]["identity"]["kernel_release"]
                    && observation["identity_sha256"]
                        == json::fingerprint(&v["inputs"]["identity"])?
                    && observation["assurance"] == ASSURANCE,
                "recovery image boot observation mismatch",
            )?;
            require(
                if mode == "uefi" {
                    observation["selected_entry"] == format!("{id}.conf")
                } else {
                    observation["selected_entry"].is_null()
                },
                "recovery image selected entry mismatch",
            )?;
        }
    }
    Ok(())
}
pub(crate) struct Artifacts {
    volume: Volume,
    folder: File,
    original: files::FileIdentity,
    relative: String,
    artifacts: Vec<crate::boot_volume::Artifact>,
}
impl Artifacts {
    pub(crate) fn recheck(&self) -> Result<()> {
        self.volume.recheck()?;
        let named = self.volume.directory(Path::new(&self.relative))?;
        require(
            files::identity(&self.folder.metadata()?) == self.original
                && files::identity(&named.metadata()?) == self.original
                && enzimos_platform::mount_identity::id(self.folder.as_fd(), true)?
                    == self.volume.unique
                && enzimos_platform::mount_identity::id(named.as_fd(), true)? == self.volume.unique,
            "original recovery image directory changed",
        )?;
        for artifact in &self.artifacts {
            artifact.recheck()?;
        }
        self.volume.recheck()
    }
}
pub(crate) fn retain_artifacts(v: &Value) -> Result<Artifacts> {
    let id = records::text(v, "id")?;
    validate(v, id)?;
    let volume = Volume::observe()?;
    require(
        volume.uuid == records::text(v, "boot_uuid")?,
        "recovery boot volume changed",
    )?;
    let relative = format!("enzimos/recovery-images/{id}");
    let folder = volume.directory(Path::new(&relative))?;
    let original = files::identity(&folder.metadata()?);
    let members = files::directory_names(&folder, 3)?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    require(
        members
            == ["kernel", "initrd.img", "identity.json"]
                .map(std::ffi::OsString::from)
                .into_iter()
                .collect(),
        "unexpected recovery image members",
    )?;
    let mut artifacts = Vec::new();
    for (name, expected) in enzimos_platform::json::object(&v["inputs"]["files"])? {
        let artifact = volume.artifact(Path::new(&format!("{relative}/{name}")), MAX_IMAGE)?;
        require(
            artifact.bytes == enzimos_platform::json::unsigned(&expected["bytes"])?
                && artifact.sha == records::text(expected, "sha256")?,
            "recovery image artifact drift",
        )?;
        artifact.recheck()?;
        artifacts.push(artifact);
    }
    let identity_file = volume.artifact(
        Path::new(&format!("{relative}/identity.json")),
        2 * 1024 * 1024,
    )?;
    require(
        json::decode(
            &files::read_file(&identity_file.file, 2 * 1024 * 1024, Some(0), true)?,
            2 * 1024 * 1024,
        )? == v["inputs"]["identity"],
        "published recovery identity changed",
    )?;
    identity_file.recheck()?;
    let named = volume.directory(Path::new(&relative))?;
    require(
        files::identity(&folder.metadata()?) == original
            && files::identity(&named.metadata()?) == original,
        "original recovery image directory changed during artifact verification",
    )?;
    artifacts.push(identity_file);
    let retained = Artifacts {
        volume,
        folder,
        original,
        relative,
        artifacts,
    };
    retained.recheck()?;
    Ok(retained)
}
pub(crate) fn verify_artifacts(v: &Value) -> Result<Volume> {
    let retained = retain_artifacts(v)?;
    retained.recheck()?;
    Ok(retained.volume)
}
pub(crate) struct Published {
    artifacts: Artifacts,
    loaders: Vec<crate::boot_volume::Artifact>,
    signed: Option<signed_entry::Verification>,
}
impl Published {
    pub(crate) fn measurements(&self) -> Result<std::collections::BTreeMap<String, Value>> {
        self.recheck()?;
        let mut rows = std::collections::BTreeMap::new();
        for artifact in self.artifacts.artifacts.iter().chain(self.loaders.iter()) {
            let path = artifact
                .path
                .strip_prefix("/boot")
                .map_err(|_| Error("original ESP artifact root differs".into()))?;
            let path = path
                .to_str()
                .ok_or_else(|| Error("original ESP artifact path encoding".into()))?;
            rows.insert(
                path.into(),
                serde_json::json!({"bytes":artifact.bytes,"sha256":artifact.sha}),
            );
        }
        self.recheck()?;
        Ok(rows)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.artifacts.recheck()?;
        for loader in &self.loaders {
            loader.recheck()?;
        }
        if let Some(signed) = &self.signed {
            signed.recheck()?;
        }
        self.artifacts.recheck()
    }
    pub(crate) fn observe(v: &Value) -> Result<Self> {
        let artifacts = retain_artifacts(v)?;
        let volume = &artifacts.volume;
        let id = records::text(v, "id")?;
        let (filename, title) = entry_names(id)?;
        let (expected, expected_bios) = entry_texts(id, records::text(v, "options")?)?;
        let entry = volume.artifact(
            Path::new(&format!("loader/entries/{filename}")),
            boot_entries::MAX_TEXT as u64,
        )?;
        let body = files::read_file(&entry.file, boot_entries::MAX_TEXT, Some(0), true)?;
        let body =
            std::str::from_utf8(&body).map_err(|_| Error("recovery entry encoding".into()))?;
        let actual = boot_entries::fields(body, false)?;
        let expected = boot_entries::fields(&expected, false)?;
        for key in ["title", "linux", "initrd", "options"] {
            require(
                actual.get(key) == expected.get(key),
                "recovery UEFI entry drift",
            )?;
        }
        require(
            actual
                .keys()
                .all(|k| expected.contains_key(k) || k == "uki"),
            "unrecognized recovery entry field",
        )?;
        let signed = signed_entry::retain(&actual)?;
        let menu_file = volume.artifact(
            Path::new("limine/limine.conf"),
            boot_entries::MAX_TEXT as u64,
        )?;
        let menu_bytes = files::read_file(&menu_file.file, boot_entries::MAX_TEXT, Some(0), true)?;
        let menu = boot_entries::menu(
            std::str::from_utf8(&menu_bytes)
                .map_err(|_| Error("recovery BIOS menu encoding".into()))?,
        )?;
        let matches = menu
            .entries
            .iter()
            .filter(|row| row.title == title)
            .collect::<Vec<_>>();
        require(
            matches.len() == 1
                && boot_entries::fields(&matches[0].text, true)?
                    == boot_entries::fields(&expected_bios, true)?,
            "recovery BIOS entry drift",
        )?;
        entry.recheck()?;
        menu_file.recheck()?;
        artifacts.recheck()?;
        let retained = Self {
            artifacts,
            loaders: vec![entry, menu_file],
            signed,
        };
        retained.recheck()?;
        Ok(retained)
    }
}
pub fn verify_published(v: &Value) -> Result<()> {
    Published::observe(v)?.recheck()
}

/// Publisher-owned image status; original artifacts remain held through final checks.
pub fn status_locked(lock: &enzimos_platform::files::Lock) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    use crate::recovery_journal::{Journal, Kind};
    let journal = Journal::open(Kind::Images, false)?;
    let publications = Journal::open(Kind::Publications, false)?;
    let mut blockers = std::collections::BTreeSet::new();
    let mut images = std::collections::BTreeMap::new();
    let mut retained = Vec::new();
    for (id, publication) in &publications.records {
        if !journal.records.get(id).is_some_and(|image| {
            image["phase"] == "ready"
                && crate::recovery_publication::expected_record(publication, image).is_ok()
        }) {
            blockers.insert(format!("pending-recovery-publication-journal:{id}"));
        }
    }
    for (id, record) in &journal.records {
        let valid = if record["phase"] == "ready" {
            match Published::observe(record) {
                Ok(original) => {
                    original.recheck()?;
                    retained.push(original);
                    true
                }
                Err(_) => {
                    blockers.insert(format!("recovery-image-binding-drift:{id}"));
                    false
                }
            }
        } else {
            blockers.insert(format!("pending-recovery-publication:{id}"));
            false
        };
        let modes: Vec<_> = enzimos_platform::json::object(&record["observations"])?
            .keys()
            .collect();
        images.insert(id.clone(), serde_json::json!({"phase":record["phase"],"live_bindings_match":valid,"software_observed_modes":modes,"deletion_authorized":false}));
    }
    if images.is_empty() {
        blockers.insert("no-publisher-owned-recovery-image".to_owned());
    }
    for original in &retained {
        original.recheck()?;
    }
    journal.unchanged()?;
    publications.unchanged()?;
    lock.recheck()?;
    Ok(
        serde_json::json!({"images":images,"blockers":blockers,"retirement_enabled":false,"scope":"new image origin and software-local observations; not firmware/app health or complete references"}),
    )
}
