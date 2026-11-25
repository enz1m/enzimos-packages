// SPDX-License-Identifier: MIT
//! Ready native image and current installed runtime retain actual original bytes.
use crate::{
    boot_volume::{Artifact, Volume},
    native_policy_files,
    root_retirement_online_journal::Journal,
    root_retirement_references::Observation,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub struct Image<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    references: &'a Observation<'a>,
    receipt: crate::control_record::Observation,
    volume: Volume,
    folder: File,
    epoch: files::FileIdentity,
    folder_flags: i32,
    member_flags: BTreeMap<String, i32>,
    members: BTreeMap<String, Artifact>,
    runtime: native_policy_files::Original,
    record: Value,
}
impl<'a> Image<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        references: &'a Observation<'a>,
        journal: &Journal<'_>,
        id: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        references.require_original_source(guard, lock, authorize)?;
        journal.require_original_source(guard, lock)?;
        let receipt = journal.duplicate_observation()?;
        crate::recovery_image::identifier(id)?;
        let original = references.original(authorize)?;
        let record = original["records"]["images"]
            .get(id)
            .cloned()
            .ok_or_else(|| {
                enzimos_platform::Error("original ready native image receipt missing".into())
            })?;
        crate::recovery_image::validate(&record, id)?;
        require(
            record["phase"] == "ready"
                && record["inputs"]["identity"]["schema"] == 2
                && record["filesystem_uuid"] == guard.configuration["filesystem_uuid"]
                && crate::subvolume::observe(
                    guard.control().as_fd(),
                    guard.configuration["control_subvol"].as_str().unwrap(),
                )?
                .0 == record["control"],
            "original ready native image filesystem/control mismatch",
        )?;
        crate::recovery_image::verify_published(&record)?;
        let runtime = native_policy_files::Original::retain()?;
        require(
            *runtime.hashes()? == record["inputs"]["identity"]["policy_files"],
            "ready image must carry exact current installed native runtime bytes",
        )?;
        let volume = Volume::observe()?;
        volume.writable()?;
        require(
            record["boot_uuid"] == volume.uuid,
            "native image belongs to another actual ESP",
        )?;
        let folder = volume.directory(Path::new(&format!("enzimos/recovery-images/{id}")))?;
        let epoch = files::identity(&folder.metadata()?);
        let folder_flags = readonly_flags(&folder)?;
        require(
            folder.metadata()?.gid() == 0 && folder.metadata()?.mode() & 0o022 == 0,
            "original native image directory protection",
        )?;
        let mut members = BTreeMap::new();
        let mut member_flags = BTreeMap::new();
        for name in ["kernel", "initrd.img", "identity.json"] {
            let artifact = volume.artifact(
                Path::new(&format!("enzimos/recovery-images/{id}/{name}")),
                if name == "identity.json" {
                    2 * 1024 * 1024
                } else {
                    crate::recovery_image::MAX_IMAGE
                },
            )?;
            if name == "identity.json" {
                require(
                    json::decode(
                        &files::read_file(&artifact.file, 2 * 1024 * 1024, Some(0), true)?,
                        2 * 1024 * 1024,
                    )? == record["inputs"]["identity"],
                    "original native image descriptor changed",
                )?;
            } else {
                require(
                    record["inputs"]["files"][name]["sha256"] == artifact.sha
                        && record["inputs"]["files"][name]["bytes"] == artifact.bytes,
                    "original native image payload differs from ready receipt",
                )?;
            }
            member_flags.insert(name.into(), readonly_flags(&artifact.file)?);
            members.insert(name.into(), artifact);
        }
        let this = Self {
            guard,
            lock,
            references,
            receipt,
            volume,
            folder,
            epoch,
            folder_flags,
            member_flags,
            members,
            runtime,
            record,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub(crate) fn require_original_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "ready image belongs to another original guard/lock",
        )?;
        self.recheck(authorize)
    }
    pub(crate) fn require_staged_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        published: &crate::root_retirement_online_journal::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "staged image belongs to another original guard/lock",
        )?;
        published.require_source(guard, lock)?;
        self.recheck_staged(published, authorize)
    }
    pub fn staged_record(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<&Value> {
        self.recheck_staged(published, authorize)?;
        Ok(&self.record)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_inner(None, authorize)
    }
    pub fn recheck_staged(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck_inner(Some(published), authorize)
    }
    fn recheck_inner(
        &self,
        published: Option<&crate::root_retirement_online_journal::Published<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        if let Some(published) = published {
            self.references
                .verify_staged_root_receipt(published, authorize)?;
            published.require_original_observation(&self.receipt)?;
        } else {
            self.references
                .require_original_source(self.guard, self.lock, authorize)?;
            self.receipt.recheck()?;
        }
        let id = self.record["id"].as_str().unwrap();
        require(
            self.references.original_image_receipt(id)? == &self.record,
            "original native image receipt changed",
        )?;
        self.volume.writable()?;
        let named = self
            .volume
            .directory(Path::new(&format!("enzimos/recovery-images/{id}")))?;
        let expected =
            BTreeSet::from(["kernel", "initrd.img", "identity.json"].map(std::ffi::OsString::from));
        require(
            readonly_flags(&self.folder)? == self.folder_flags,
            "original image directory description flags changed",
        )?;
        for folder in [&self.folder, &named] {
            require(
                files::identity(&folder.metadata()?) == self.epoch
                    && mount_identity::id(folder.as_fd(), true)? == self.volume.unique
                    && files::directory_names(folder, 3)?
                        .into_iter()
                        .collect::<BTreeSet<_>>()
                        == expected,
                "original native image directory changed/replaced/covered",
            )?;
        }
        for (name, original) in &self.members {
            require(
                readonly_flags(&original.file)? == self.member_flags[name],
                "original image member description flags changed",
            )?;
            original.recheck()?;
            authorize()?;
        }
        self.runtime.recheck()?;
        require(
            *self.runtime.hashes()? == self.record["inputs"]["identity"]["policy_files"],
            "original image/current runtime binding changed",
        )?;
        crate::recovery_image::verify_published(&self.record)?;
        if let Some(published) = published {
            published.require_original_observation(&self.receipt)?;
            self.references
                .verify_staged_root_receipt(published, authorize)
        } else {
            self.receipt.recheck()?;
            self.references.recheck(authorize)
        }
    }
    pub fn record(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.record)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            value!({"record":self.record,"directory_epoch":self.epoch,"directory_flags":self.folder_flags,"member_flags":self.member_flags,"boot_uuid":self.volume.uuid,"mount":self.volume.unique,
            "runtime":self.runtime.evidence()?,"members":self.members.iter().map(|(name,artifact)|
                Ok((name.clone(),value!({"epoch":files::identity(&artifact.file.metadata()?),"sha256":artifact.sha,"bytes":artifact.bytes}))))
                .collect::<Result<BTreeMap<_,_>>>()?,"execution_authorized":false}),
        )
    }
}

fn readonly_flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original image read-only description required",
    )?;
    Ok(flags)
}
