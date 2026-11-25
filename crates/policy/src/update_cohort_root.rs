// SPDX-License-Identifier: MIT
//! Root admission binds the original configuration, receipt and public authority.
use crate::{
    authority_mount::Authority,
    operation,
    storage_runtime::Guard,
    update_admission,
    update_cohort::{self, Cohort},
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
/// The admitted update cohort with its configuration, receipt and authority.
pub struct Admitted {
    guard: Guard,
    authority: Authority,
    authority_hashes: Value,
    config: File,
    config_identity: files::FileIdentity,
    config_mount: u64,
    receipt: File,
    receipt_identity: files::FileIdentity,
    control: File,
    document: Value,
    source: Cohort,
    authority_files: Vec<(String, File, files::FileIdentity)>,
}
impl Admitted {
    /// Admit the offline update cohort under the fixed configuration and authority.
    ///
    /// # Errors
    ///
    /// Fails when the configuration, receipt or authority is unsafe, changed or invalid.
    pub fn observe() -> Result<Self> {
        operation::root_only()?;
        let guard = Guard::observe()?;
        let authority = Authority::observe(&guard)?;
        let authority_hashes = authority.hashes()?;
        let authority_directory =
            files::directory(Path::new(crate::authority_mount::PATH), Some(0))?;
        let mut authority_files = Vec::new();
        for name in crate::authority::FILES {
            let file = files::open_relative(&authority_directory, Path::new(name))?;
            require(
                mount_identity::id(file.as_fd(), true)?
                    == enzimos_platform::json::unsigned(&authority.identity()["mount"])?
                    && json::sha256(&files::read_file(&file, 8 * 1024 * 1024, Some(0), true)?)
                        == authority_hashes[name],
                "original update authority file changed",
            )?;
            authority_files.push((
                name.to_owned(),
                file.try_clone()?,
                files::identity(&file.metadata()?),
            ));
        }
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let config = files::open_relative(&parent, Path::new("update-pacman.conf"))?;
        let config_identity = files::identity(&config.metadata()?);
        let config_mount = mount_identity::id(config.as_fd(), true)?;
        require(
            files::read_file(&config, 65536, Some(0), true)?
                == update_cohort::configuration().as_bytes(),
            "fixed admitted update configuration changed",
        )?;
        let control = files::directory(Path::new(operation::CONTROL), Some(0))?;
        require(
            mount_identity::id(control.as_fd(), true)? == guard.control_mount_id(),
            "update control directory independently mounted",
        )?;
        let receipt = files::open_relative(&control, Path::new("update-admission.json"))?;
        let receipt_identity = files::identity(&receipt.metadata()?);
        require(
            receipt.metadata()?.mode() & 0o7777 == 0o600
                && mount_identity::id(receipt.as_fd(), true)? == guard.control_mount_id(),
            "unsafe or independently mounted update receipt",
        )?;
        let document = json::decode(&files::read_file(&receipt, 65536, Some(0), true)?, 65536)?;
        update_admission::validate(&document)?;
        let source = Cohort::observe()?;
        require(
            document["phase"] == "complete"
                && document["admission_sha256"] == json::fingerprint(source.document())?,
            "update requires the exact completed admission",
        )?;
        let admitted = Self {
            guard,
            authority,
            authority_hashes,
            config,
            config_identity,
            config_mount,
            receipt,
            receipt_identity,
            control,
            document,
            source,
            authority_files,
        };
        admitted.recheck()?;
        admitted
            .source
            .verify_signatures(Path::new(crate::authority_mount::PATH))?;
        admitted.recheck()?;
        Ok(admitted)
    }
    /// The admitted cohort.
    pub fn source(&self) -> &Cohort {
        &self.source
    }
    /// The admission receipt.
    pub fn receipt(&self) -> &Value {
        &self.document
    }
    /// The storage guard the cohort was admitted on.
    pub fn guard(&self) -> &Guard {
        &self.guard
    }
    /// Verify the configuration, receipt and authority are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when any of them changed.
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.authority.recheck(&self.guard)?;
        let directory = files::directory(Path::new(crate::authority_mount::PATH), Some(0))?;
        for (name, held, identity) in &self.authority_files {
            let named = files::open_relative(&directory, Path::new(name))?;
            for file in [held, &named] {
                require(
                    files::identity(&file.metadata()?) == *identity
                        && mount_identity::id(file.as_fd(), true)?
                            == enzimos_platform::json::unsigned(
                                &self.authority.identity()["mount"],
                            )?,
                    "original update authority file replaced or changed",
                )?;
            }
        }
        require(
            self.authority.hashes()? == self.authority_hashes,
            "original update authority changed",
        )?;
        self.source.recheck()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let config = files::open_relative(&parent, Path::new("update-pacman.conf"))?;
        require(
            files::identity(&config.metadata()?) == self.config_identity
                && files::identity(&self.config.metadata()?) == self.config_identity
                && mount_identity::id(config.as_fd(), true)? == self.config_mount
                && mount_identity::id(self.config.as_fd(), true)? == self.config_mount
                && files::read_file(&self.config, 65536, Some(0), true)?
                    == update_cohort::configuration().as_bytes(),
            "original update configuration replaced or changed",
        )?;
        let named_control = files::directory(Path::new(operation::CONTROL), Some(0))?;
        let a = self.control.metadata()?;
        let b = named_control.metadata()?;
        require(
            (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
                == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode())
                && mount_identity::id(self.control.as_fd(), true)? == self.guard.control_mount_id()
                && mount_identity::id(named_control.as_fd(), true)?
                    == self.guard.control_mount_id(),
            "original update control directory replaced",
        )?;
        let receipt = files::open_relative(&self.control, Path::new("update-admission.json"))?;
        for file in [&receipt, &self.receipt] {
            require(
                files::identity(&file.metadata()?) == self.receipt_identity
                    && mount_identity::id(file.as_fd(), true)? == self.guard.control_mount_id(),
                "original update admission receipt changed",
            )?;
        }
        Ok(())
    }
}
