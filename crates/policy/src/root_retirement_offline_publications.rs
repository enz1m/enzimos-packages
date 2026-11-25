// SPDX-License-Identifier: MIT
//! Original ready publication closure, with conservative before-state references.
//! Historical rows do not create deletion permission or adopt missing live files.
use crate::{
    boot_entries, boot_volume::Artifact, recovery_journal::Kind,
    root_retirement_boot_artifacts::Restored, root_retirement_offline_control::Control,
    root_retirement_offline_ledgers::Ledgers, root_retirement_offline_loaders::Loaders,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original publication read-only descriptor required",
    )?;
    Ok(value)
}
fn members(file: &File) -> Result<()> {
    require(
        files::directory_names(file, 3)?
            .into_iter()
            .collect::<BTreeSet<_>>()
            == ["kernel", "initrd.img", "identity.json"]
                .map(std::ffi::OsString::from)
                .into_iter()
                .collect(),
        "ready publication image has interrupted or unknown members",
    )
}
pub(crate) fn historical_roots(journal: &Value) -> Result<BTreeSet<String>> {
    let menu = boot_entries::menu(crate::recovery_records::text(journal, "bios_before")?)?;
    let mut roots = BTreeSet::new();
    for row in menu.entries {
        let fields = boot_entries::fields(&row.text, true)?;
        require(
            fields
                .keys()
                .all(|key| ["protocol", "path", "module_path", "cmdline"].contains(&key.as_str()))
                && fields.get("protocol").is_some_and(|value| value == "linux"),
            "unsupported historical BIOS entry cannot be forgotten",
        )?;
        let options = fields
            .get("cmdline")
            .ok_or_else(|| Error("historical BIOS options missing".into()))?;
        require(
            options.len() <= 8192 && !options.chars().any(char::is_control),
            "historical BIOS options bound",
        )?;
        if options
            .split_whitespace()
            .any(|word| word.starts_with("root=") || word.starts_with("rootflags="))
        {
            roots.insert(crate::boot_options::subvolume_from_options(options)?);
        }
    }
    // Previous UEFI configuration is retained by the original journal. Its
    // selector can be unresolved after completion; it is never replayed here.
    boot_entries::fields(
        crate::recovery_records::text(journal, "default_before")?,
        false,
    )?;
    Ok(roots)
}
fn ready_pair(journal: &Value, image: &Value) -> Result<()> {
    crate::recovery_publication::expected_record(journal, image)?;
    require(
        image["phase"] == "ready",
        "pending publication remains a protection blocker",
    )
}
struct Material {
    folder: File,
    epoch: files::FileIdentity,
    flags: i32,
    mount: u64,
    artifacts: BTreeMap<String, (Artifact, i32)>,
}
pub struct Publications<'a, 's> {
    control: &'a Control<'a, 's>,
    ledgers: &'a Ledgers<'a, 's>,
    loaders: &'a Loaders<'a, 's>,
    boot: &'a Restored<'a, 's>,
    materials: BTreeMap<String, Material>,
    historical_roots: BTreeSet<String>,
}
impl<'a, 's> Publications<'a, 's> {
    pub(crate) fn require_original_actors(
        &self,
        ledgers: &Ledgers<'a, 's>,
        loaders: &Loaders<'a, 's>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.ledgers, ledgers) && std::ptr::eq(self.loaders, loaders),
            "original publication closure belongs to another ledger or loader actor",
        )?;
        self.recheck()
    }
    pub(crate) fn observe(
        control: &'a Control<'a, 's>,
        ledgers: &'a Ledgers<'a, 's>,
        loaders: &'a Loaders<'a, 's>,
        boot: &'a Restored<'a, 's>,
    ) -> Result<Self> {
        ledgers.require_original_control(control)?;
        loaders.require_original_ledgers(ledgers)?;
        loaders.require_original_boot(boot)?;
        boot.require_original_control(control)?;
        let publications = ledgers.recovery_rows(Kind::Publications)?;
        let images = ledgers.recovery_rows(Kind::Images)?;
        let volume = boot.original_volume()?;
        let identity = control.evidence()?["identity"].clone();
        let filesystem =
            crate::filesystem::observe(control.descriptor()?.as_fd())?["filesystem_uuid"].clone();
        let mut materials = BTreeMap::new();
        let mut historical = BTreeSet::new();
        for (id, publication) in &publications {
            let image = images
                .get(id)
                .ok_or_else(|| Error("original publication image receipt missing".into()))?;
            ready_pair(publication, image)?;
            historical.extend(historical_roots(publication)?);
        }
        for (id, image) in images {
            require(
                image["phase"] == "ready"
                    && image["control"] == identity
                    && image["filesystem_uuid"] == filesystem
                    && image["boot_uuid"] == volume.uuid,
                "unfinished or foreign original recovery image protects retirement",
            )?;
            loaders.published_image(image)?;
            let prefix = format!("enzimos/recovery-images/{id}");
            let folder = volume.directory(Path::new(&prefix))?;
            let metadata = folder.metadata()?;
            require(
                metadata.is_dir()
                    && metadata.uid() == 0
                    && metadata.gid() == 0
                    && metadata.mode() & 0o022 == 0,
                "protected original ready image directory required",
            )?;
            members(&folder)?;
            let mut artifacts = BTreeMap::new();
            for (name, expected) in enzimos_platform::json::object(&image["inputs"]["files"])? {
                let artifact = volume.artifact(
                    Path::new(&format!("{prefix}/{name}")),
                    crate::recovery_image::MAX_IMAGE,
                )?;
                require(
                    artifact.bytes == enzimos_platform::json::unsigned(&expected["bytes"])?
                        && artifact.sha == enzimos_platform::json::string(&expected["sha256"])?,
                    "original ready image artifact differs from retained receipt",
                )?;
                artifacts.insert(name.clone(), (artifact, 0));
            }
            let descriptor = volume.artifact(
                Path::new(&format!("{prefix}/identity.json")),
                2 * 1024 * 1024,
            )?;
            require(
                json::decode(
                    &files::read_file(&descriptor.file, 2 * 1024 * 1024, Some(0), true)?,
                    2 * 1024 * 1024,
                )? == image["inputs"]["identity"],
                "original ready image descriptor differs from retained receipt",
            )?;
            artifacts.insert("identity.json".into(), (descriptor, 0));
            for (artifact, original_flags) in artifacts.values_mut() {
                *original_flags = flags(&artifact.file)?;
            }
            materials.insert(
                id.into(),
                Material {
                    epoch: files::identity(&metadata),
                    flags: flags(&folder)?,
                    mount: mount_identity::id(folder.as_fd(), true)?,
                    folder,
                    artifacts,
                },
            );
        }
        let result = Self {
            control,
            ledgers,
            loaders,
            boot,
            materials,
            historical_roots: historical,
        };
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.ledgers.require_original_control(self.control)?;
        self.loaders.require_original_boot(self.boot)?;
        self.loaders.require_original_ledgers(self.ledgers)?;
        self.boot.require_original_control(self.control)?;
        let publications = self.ledgers.recovery_rows(Kind::Publications)?;
        let images = self.ledgers.recovery_rows(Kind::Images)?;
        let mut roots = BTreeSet::new();
        for (id, publication) in publications {
            ready_pair(
                publication,
                images
                    .get(id)
                    .ok_or_else(|| Error("original ready publication receipt missing".into()))?,
            )?;
            roots.extend(historical_roots(publication)?);
        }
        require(
            roots == self.historical_roots
                && images.keys().copied().collect::<BTreeSet<_>>()
                    == self
                        .materials
                        .keys()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>(),
            "original ready publication closure changed",
        )?;
        let volume = self.boot.original_volume()?;
        for (id, material) in &self.materials {
            let named = volume.directory(Path::new(&format!("enzimos/recovery-images/{id}")))?;
            require(
                files::identity(&material.folder.metadata()?) == material.epoch
                    && files::identity(&named.metadata()?) == material.epoch
                    && flags(&material.folder)? == material.flags
                    && mount_identity::id(material.folder.as_fd(), true)? == material.mount
                    && mount_identity::id(named.as_fd(), true)? == material.mount,
                "original ready image folder changed, replaced or covered",
            )?;
            members(&material.folder)?;
            members(&named)?;
            for (artifact, original_flags) in material.artifacts.values() {
                artifact.recheck()?;
                require(
                    flags(&artifact.file)? == *original_flags,
                    "original ready image descriptor flags changed",
                )?;
            }
            self.loaders.published_image(images[id.as_str()])?;
        }
        self.ledgers.require_original_control(self.control)
    }
    pub(crate) fn require_unmentioned(
        &self,
        targets: &crate::root_retirement_offline_targets::Targets<'a, 's>,
    ) -> Result<()> {
        self.recheck()?;
        targets.require_original_ledgers(self.ledgers)?;
        let rows = targets.rows()?;
        let rows = rows
            .as_array()
            .filter(|rows| (1..=64).contains(&rows.len()))
            .ok_or_else(|| Error("original publication target list bound".into()))?;
        let root = rows
            .last()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["path"]
            .as_str()
            .ok_or_else(|| Error("original publication target root".into()))?;
        require(
            targets.superseded_owner()?.is_some()
                || self
                    .historical_roots
                    .iter()
                    .all(|path| path != root && !path.starts_with(&format!("{root}/"))),
            "historical publication before-state root protects publisher-born target",
        )?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"ready_images":self.materials.len(),"publication_before_root_references":self.historical_roots,
            "original_live_material_and_loader_closure_verified":true,"historical_exemptions_authorized":false,"execution_authorized":false}),
        )
    }
}
