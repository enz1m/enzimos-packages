// SPDX-License-Identifier: MIT
//! Fixed archive inputs retained from original capture and staging actors.
//! Descriptors here are data; this actor grants no mount, process or cleanup role.
use crate::{
    backup_capture_scope, backup_inventory_stage::Staged, backup_source_capture::Released,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs::File, os::fd::AsFd};
struct Directory<'a> {
    file: &'a File,
    epoch: files::FileIdentity,
    mount: u64,
}
impl<'a> Directory<'a> {
    fn retain(file: &'a File) -> Result<Self> {
        let metadata = file.metadata()?;
        let epoch = files::identity(&metadata);
        require(
            metadata.is_dir()
                && epoch.8 == 0
                && epoch.9 == 0
                && epoch.7 & 0o7022 == 0
                && enzimos_platform::files::status_flags(&file) & libc::O_ACCMODE == libc::O_RDONLY,
            "original protected readonly archive descriptor required",
        )?;
        let this = Self {
            file,
            epoch,
            mount: mount_identity::id(file.as_fd(), true)?,
        };
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "original archive input changed or remounted",
        )
    }
}
pub struct Inputs<'a, 'c, 's, 'cfg, 'g> {
    capture: &'a Released<'s, 'cfg, 'g>,
    stage: &'a Staged<'c, 's, 'cfg, 'g>,
    directories: BTreeMap<String, Directory<'a>>,
    scope: Value,
}
impl<'a, 'c, 's, 'cfg, 'g> Inputs<'a, 'c, 's, 'cfg, 'g> {
    pub fn observe(
        capture: &'a Released<'s, 'cfg, 'g>,
        stage: &'a Staged<'c, 's, 'cfg, 'g>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        stage.require_original(capture)?;
        let scope = backup_capture_scope::review(capture)?;
        let mut directories = BTreeMap::new();
        for snapshot in capture.snapshots()? {
            let dataset = snapshot.dataset()?;
            let target = format!("/backup-source/{}", dataset.archive);
            require(
                directories
                    .insert(
                        target,
                        Directory::retain(snapshot.snapshot()?.original_directory()?)?,
                    )
                    .is_none(),
                "duplicate original archive input",
            )?;
        }
        for (target, file) in [
            ("/backup-source/boot", stage.boot_directory()?),
            ("/backup-source/inventory", stage.original_directory()?),
        ] {
            require(
                directories
                    .insert(target.into(), Directory::retain(file)?)
                    .is_none(),
                "duplicate fixed staged archive input",
            )?;
        }
        let this = Self {
            capture,
            stage,
            directories,
            scope,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn require_original_lock(&self, lock: &files::Lock) -> Result<()> {
        self.recheck()?;
        self.capture.require_original(lock)
    }
    pub(crate) fn guard(&self) -> &'g crate::storage_runtime::Guard {
        self.capture.guard()
    }
    pub fn recheck(&self) -> Result<()> {
        enzimos_platform::recheck_scope::evaluation(|| {
            self.stage.require_original(self.capture)?;
            require(
                backup_capture_scope::review(self.capture)? == self.scope,
                "original archive scope changed",
            )?;
            let sources = self.scope["sources"]
                .as_array()
                .ok_or_else(|| Error("original archive scope shape".into()))?;
            require(
                (4..=34).contains(&sources.len()) && sources.len() == self.directories.len(),
                "complete original archive input set required",
            )?;
            for source in sources {
                let target = source
                    .as_str()
                    .ok_or_else(|| Error("original archive path shape".into()))?;
                self.directories
                    .get(target)
                    .ok_or_else(|| Error("original archive input missing".into()))?
                    .recheck()?;
            }
            Ok(())
        })
    }
    /// Fixed archive targets and their actual original descriptors, never caller paths.
    pub fn directories(&self) -> Result<BTreeMap<&str, &File>> {
        enzimos_platform::recheck_scope::evaluation(|| {
            self.recheck()?;
            Ok(self
                .directories
                .iter()
                .map(|(target, original)| (target.as_str(), original.file))
                .collect())
        })
    }
    /// Fixed backup command tail from the actual captured scope. Repository,
    /// credential, scratch and readonly source bindings are separate consumer roles.
    pub fn arguments(&self) -> Result<Vec<String>> {
        enzimos_platform::recheck_scope::evaluation(|| {
            self.recheck()?;
            let mut args = [
                "backup",
                "--json",
                "--tag",
                "enzimos-whole-linux",
                "--host",
                "enzimos",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
            let exclusions = self.scope["excludes"]
                .as_array()
                .ok_or_else(|| Error("original archive exclusions shape".into()))?;
            require(exclusions.len() <= 128, "original archive exclusion count")?;
            for pattern in exclusions {
                args.push("--exclude".into());
                args.push(
                    pattern
                        .as_str()
                        .ok_or_else(|| Error("original archive exclusion shape".into()))?
                        .to_owned(),
                );
            }
            args.extend(enzimos_platform::backup_command::skipped_arguments());
            for source in enzimos_platform::json::array(&self.scope["sources"])? {
                args.push(enzimos_platform::json::string(source)?.to_owned());
            }
            self.recheck()?;
            Ok(args)
        })
    }
    /// Review data only; an isolated consumer must admit readonly bindings separately.
    pub fn evidence(&self) -> Result<Value> {
        enzimos_platform::recheck_scope::evaluation(|| {
            self.recheck()?;
            Ok(
                json!({"schema":1,"role":"backup-archive-inputs","scope":self.scope,
            "inventory":self.stage.evidence()?,"directories":self.directories.iter().map(|(target, d)|
                (target, json!({"inode":d.epoch,"mount":d.mount}))).collect::<BTreeMap<_,_>>(),
            "boot_inventory_staged":true,"source_mounts_admitted":false,
            "transfer_entered":false,"backup_complete":false}),
            )
        })
    }
}
