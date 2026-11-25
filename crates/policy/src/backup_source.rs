// SPDX-License-Identifier: MIT
//! Dataset and readonly snapshot lineage retained independently of Snapper numbers.
use crate::{
    backup_source_layout::{Dataset, validate_dataset},
    filesystem,
    storage_runtime::Guard,
    subvolume,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(f: &File) -> Result<Shape> {
    let m = f.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected backup source directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn same(f: &File, named: &File, expected: Shape, mount: u64) -> Result<()> {
    require(
        shape(f)? == expected
            && shape(named)? == expected
            && mount_identity::id(f.as_fd(), true)? == mount
            && mount_identity::id(named.as_fd(), true)? == mount,
        "original backup source directory changed or replaced",
    )
}
/// Dataset binding does not authorize capture: callers must additionally qualify
/// all nested subvolumes/mounts and retain their complete source inventory.
pub struct Source<'a> {
    guard: &'a Guard,
    dataset: Dataset,
    file: File,
    shape: Shape,
    mount: u64,
    mount_row: enzimos_platform::mountinfo::Row,
    object: Value,
    config_path: PathBuf,
    config_parent: File,
    config_parent_shape: Shape,
    config_parent_mount: u64,
    config: File,
    config_identity: files::FileIdentity,
    config_mount: u64,
    config_body: Vec<u8>,
}
impl<'a> Source<'a> {
    pub fn open(dataset: Dataset, guard: &'a Guard) -> Result<Self> {
        validate_dataset(&dataset)?;
        guard.recheck()?;
        let file = files::directory(Path::new(&dataset.path), Some(0))?;
        require(
            file.metadata()?.ino() == 256,
            "backup dataset must be an actual Btrfs subvolume root",
        )?;
        let normal = mount_identity::id(file.as_fd(), false)?;
        let mount_row = crate::storage_runtime::rows()?
            .into_iter()
            .find(|r| r.id == normal)
            .ok_or_else(|| {
                enzimos_platform::Error("backup source kernel mount unavailable".into())
            })?;
        require(
            mount_row.filesystem == "btrfs"
                && (dataset.path == mount_row.target
                    || mount_row.target == "/"
                    || dataset.path.starts_with(&format!("{}/", mount_row.target))),
            "backup source mount path mismatch",
        )?;
        if dataset.path == "/" || dataset.path == "/home" {
            let key = if dataset.path == "/" {
                "root_subvol"
            } else {
                "home_subvol"
            };
            require(
                mount_row.target == dataset.path
                    && mount_row.root
                        == format!(
                            "/{}",
                            enzimos_platform::json::string(&guard.configuration[key])?
                        ),
                "configured backup source mount differs",
            )?;
        }
        require(
            filesystem::observe(file.as_fd())?["filesystem_uuid"]
                == guard.configuration["filesystem_uuid"],
            "backup source outside protected filesystem",
        )?;
        let (object, readonly) = subvolume::observe(file.as_fd(), &dataset.path)?;
        require(
            !readonly,
            "backup source must be the writable configured dataset",
        )?;
        let config_path = Path::new("/etc/snapper/configs").join(&dataset.name);
        let config_parent = files::directory(
            config_path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        let config = files::open_relative(&config_parent, Path::new(&dataset.name))?;
        let m = config.metadata()?;
        require(
            m.gid() == 0,
            "Root backup Snapper configuration group required",
        )?;
        let config_body = files::read_file(&config, 65536, Some(0), true)?;
        crate::home_history_source::configuration_for(&config_body, &dataset.path)?;
        let this = Self {
            guard,
            dataset,
            shape: shape(&file)?,
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            mount_row,
            object,
            config_path,
            config_parent_shape: shape(&config_parent)?,
            config_parent_mount: mount_identity::id(config_parent.as_fd(), true)?,
            config_parent,
            config_identity: files::identity(&m),
            config_mount: mount_identity::id(config.as_fd(), true)?,
            config,
            config_body,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        enzimos_platform::recheck_scope::once(self, "backup-source", || self.recheck_fresh())
    }
    fn recheck_fresh(&self) -> Result<()> {
        self.guard.recheck()?;
        let named = files::directory(Path::new(&self.dataset.path), Some(0))?;
        same(&self.file, &named, self.shape, self.mount)?;
        require(
            mount_identity::id(self.file.as_fd(), false)? == self.mount_row.id
                && crate::storage_runtime::rows()?
                    .iter()
                    .find(|r| r.id == self.mount_row.id)
                    == Some(&self.mount_row),
            "original backup source kernel mount changed",
        )?;
        let (object, readonly) = subvolume::observe(self.file.as_fd(), &self.dataset.path)?;
        require(
            !readonly
                && object == self.object
                && filesystem::observe(self.file.as_fd())?["filesystem_uuid"]
                    == self.guard.configuration["filesystem_uuid"],
            "original backup source subvolume changed",
        )?;
        let parent = files::directory(
            self.config_path
                .parent()
                .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
            Some(0),
        )?;
        same(
            &self.config_parent,
            &parent,
            self.config_parent_shape,
            self.config_parent_mount,
        )?;
        let config = files::open_relative(&self.config_parent, Path::new(&self.dataset.name))?;
        require(
            files::identity(&config.metadata()?) == self.config_identity
                && files::identity(&self.config.metadata()?) == self.config_identity
                && mount_identity::id(config.as_fd(), true)? == self.config_mount
                && mount_identity::id(self.config.as_fd(), true)? == self.config_mount
                && files::read_file(&self.config, 65536, Some(0), true)? == self.config_body,
            "original backup Snapper configuration changed or replaced",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"filesystem_uuid":self.guard.configuration["filesystem_uuid"],"object":self.object,
            "configuration_sha256":json::sha256(&self.config_body),"configuration_inode":self.config_identity,
            "configuration_mount":self.config_mount,"configuration_parent":self.config_parent_shape,
            "source_shape":self.shape,"source_mount":self.mount,"name":self.dataset.name,"archive":self.dataset.archive}),
        )
    }
    pub fn dataset(&self) -> &Dataset {
        &self.dataset
    }
    pub(crate) fn guard(&self) -> &'a Guard {
        self.guard
    }
    pub(crate) fn original_directory(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub(crate) fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.file.as_fd())
    }
    pub(crate) fn filesystem_path(&self) -> String {
        let relative = self
            .dataset
            .path
            .strip_prefix(&self.mount_row.target)
            .expect("the dataset path lies below its mount target, checked at observation")
            .trim_start_matches('/');
        let root = self.mount_row.root.trim_matches('/');
        if relative.is_empty() {
            root.into()
        } else if root.is_empty() {
            relative.into()
        } else {
            format!("{root}/{relative}")
        }
    }
}
fn lineage(source: &Value, snapshot: &Value, readonly: bool) -> Result<()> {
    require(
        readonly
            && snapshot["id"].as_u64().is_some_and(|n| n >= 256)
            && snapshot["id"] != source["id"]
            && snapshot["uuid"] != source["uuid"]
            && snapshot["parent_uuid"] == source["uuid"],
        "backup snapshot identity/readonly lineage mismatch",
    )
}
pub struct Snapshot<'a, 'g> {
    source: &'a Source<'g>,
    number: u64,
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    number_parent: File,
    number_shape: Shape,
    number_mount: u64,
    file: File,
    shape: Shape,
    mount: u64,
    object: Value,
    information: File,
    information_epoch: files::FileIdentity,
    information_mount: u64,
    information_sha256: String,
}
impl<'a, 'g> Snapshot<'a, 'g> {
    /// Duplicate only descriptors and epochs of this actual checked actor.
    /// This does not reopen a snapshot number or import decoded evidence.
    pub(crate) fn duplicate_original(&self) -> Result<Self> {
        self.recheck()?;
        let copy = Self {
            source: self.source,
            number: self.number,
            parent: self.parent.try_clone()?,
            parent_shape: self.parent_shape,
            parent_mount: self.parent_mount,
            number_parent: self.number_parent.try_clone()?,
            number_shape: self.number_shape,
            number_mount: self.number_mount,
            file: self.file.try_clone()?,
            shape: self.shape,
            mount: self.mount,
            object: self.object.clone(),
            information: self.information.try_clone()?,
            information_epoch: self.information_epoch,
            information_mount: self.information_mount,
            information_sha256: self.information_sha256.clone(),
        };
        copy.recheck()?;
        self.recheck()?;
        Ok(copy)
    }
    pub(crate) fn guard(&self) -> &'g Guard {
        self.source.guard()
    }
    pub(crate) fn dataset(&self) -> &Dataset {
        self.source.dataset()
    }

    pub(crate) fn original_parent(&self, parent: &File) -> Result<()> {
        self.recheck()?;
        require(
            shape(parent)? == self.parent_shape
                && mount_identity::id(parent.as_fd(), true)? == self.parent_mount,
            "created backup snapshot left original snapshot directory",
        )
    }
    pub fn open(source: &'a Source<'g>, number: u64) -> Result<Self> {
        require(
            (1..(1u64 << 63)).contains(&number),
            "invalid backup snapshot number",
        )?;
        source.recheck()?;
        let parent = files::directory_relative(&source.file, Path::new(".snapshots"), Some(0))?;
        let path = format!("{number}/snapshot");
        let number_parent =
            files::directory_relative(&parent, Path::new(&number.to_string()), Some(0))?;
        let file = files::directory_relative(&number_parent, Path::new("snapshot"), Some(0))?;
        require(
            file.metadata()?.ino() == 256,
            "backup snapshot must be an actual Btrfs subvolume root",
        )?;
        require(
            filesystem::observe(file.as_fd())?["filesystem_uuid"]
                == source.guard.configuration["filesystem_uuid"],
            "backup snapshot filesystem mismatch",
        )?;
        let (object, readonly) = subvolume::observe(
            file.as_fd(),
            &format!(
                "{}/.snapshots/{path}",
                source.dataset.path.trim_end_matches('/')
            ),
        )?;
        lineage(&source.object, &object, readonly)?;
        let information = files::open_relative(&number_parent, Path::new("info.xml"))?;
        let im = information.metadata()?;
        require(
            im.is_file()
                && im.uid() == 0
                && im.gid() == 0
                && im.mode() & 0o022 == 0
                && im.nlink() == 1,
            "original Snapper metadata authority",
        )?;
        let information_sha256 =
            json::sha256(&files::read_file(&information, 65536, Some(0), true)?);
        let information_epoch = files::identity(&im);
        let information_mount = mount_identity::id(information.as_fd(), true)?;
        let this = Self {
            source,
            number,
            information,
            information_epoch,
            information_mount,
            information_sha256,
            parent_shape: shape(&parent)?,
            parent_mount: mount_identity::id(parent.as_fd(), true)?,
            parent,
            number_shape: shape(&number_parent)?,
            number_mount: mount_identity::id(number_parent.as_fd(), true)?,
            number_parent,
            shape: shape(&file)?,
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            object,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.source.recheck()?;
        let parent =
            files::directory_relative(&self.source.file, Path::new(".snapshots"), Some(0))?;
        same(&self.parent, &parent, self.parent_shape, self.parent_mount)?;
        let number_parent =
            files::directory_relative(&self.parent, Path::new(&self.number.to_string()), Some(0))?;
        same(
            &self.number_parent,
            &number_parent,
            self.number_shape,
            self.number_mount,
        )?;
        self.information_recheck()?;
        require(
            files::directory_names(&self.number_parent, 3)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                == std::collections::BTreeSet::from([
                    std::ffi::OsString::from("info.xml"),
                    std::ffi::OsString::from("snapshot"),
                ]),
            "original snapshot number has unknown members",
        )?;
        let file = files::directory_relative(&self.number_parent, Path::new("snapshot"), Some(0))?;
        same(&self.file, &file, self.shape, self.mount)?;
        let (object, readonly) = subvolume::observe(
            self.file.as_fd(),
            enzimos_platform::json::string(&self.object["path"])?,
        )?;
        lineage(&self.source.object, &object, readonly)?;
        require(
            object == self.object
                && filesystem::observe(self.file.as_fd())?["filesystem_uuid"]
                    == self.source.guard.configuration["filesystem_uuid"],
            "original backup snapshot changed",
        )
    }
    fn information_recheck(&self) -> Result<()> {
        let named = files::open_relative(&self.number_parent, Path::new("info.xml"))?;
        require(
            files::identity(&self.information.metadata()?) == self.information_epoch
                && files::identity(&named.metadata()?) == self.information_epoch
                && mount_identity::id(self.information.as_fd(), true)? == self.information_mount
                && mount_identity::id(named.as_fd(), true)? == self.information_mount
                && self.information_mount == self.number_mount
                && json::sha256(&files::read_file(&self.information, 65536, Some(0), true)?)
                    == self.information_sha256,
            "original Snapper metadata changed or covered",
        )
    }
    /// Called only after the capture owner durably enters one-use retirement.
    pub(crate) fn destroy_original(self) -> Result<RemovedSnapshot<'a, 'g>> {
        self.recheck()?;
        subvolume::destroy_readonly_original(
            self.number_parent.as_fd(),
            self.file.as_fd(),
            &self.object,
        )?;
        let retired = RemovedSnapshot { original: self };
        retired.recheck()?;
        Ok(retired)
    }
    pub(crate) fn original_directory(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.file.as_fd())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"number":self.number,"object":self.object,"shape":self.shape,"mount":self.mount,"source":self.source.evidence()?}),
        )
    }
}

/// Original subvolume directory entry retired. Snapper metadata and parent
/// directory cleanup remain separate; this is never a completed-backup actor.
pub struct RemovedSnapshot<'a, 'g> {
    original: Snapshot<'a, 'g>,
}
impl<'a, 'g> RemovedSnapshot<'a, 'g> {
    pub fn recheck(&self) -> Result<()> {
        let original = &self.original;
        original.source.recheck()?;
        let parent =
            files::directory_relative(&original.source.file, Path::new(".snapshots"), Some(0))?;
        same(
            &original.parent,
            &parent,
            original.parent_shape,
            original.parent_mount,
        )?;
        let number = files::directory_relative(
            &original.parent,
            Path::new(&original.number.to_string()),
            Some(0),
        )?;
        same(
            &original.number_parent,
            &number,
            original.number_shape,
            original.number_mount,
        )?;
        original.information_recheck()?;
        require(
            files::directory_names(&original.number_parent, 2)?
                == vec![std::ffi::OsString::from("info.xml")],
            "retired snapshot metadata parent has unknown members",
        )?;
        require(
            files::optional_directory_relative(
                &original.number_parent,
                Path::new("snapshot"),
                Some(0),
            )?
            .is_none(),
            "retired snapshot entry reappeared; no cleanup adoption",
        )
    }
    pub(crate) fn retire_metadata(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<RemovedMetadata<'a, 'g>> {
        authorize()?;
        self.recheck()?;
        let original = &self.original;
        let metadata = enzimos_platform::named_retirement::Quarantined::enter(
            &original.number_parent,
            &original.information,
            Path::new("info.xml"),
            0,
            authorize,
        )?
        .unlink(authorize)?;
        authorize()?;
        original.source.recheck()?;
        require(
            files::directory_is_empty(&original.number_parent)?,
            "original snapshot number directory is not empty",
        )?;
        let directory = enzimos_platform::named_retirement::Quarantined::enter(
            &original.parent,
            &original.number_parent,
            Path::new(&original.number.to_string()),
            0,
            authorize,
        )?
        .unlink(authorize)?;
        let retired = RemovedMetadata {
            original: self.original,
            metadata,
            directory,
        };
        retired.recheck()?;
        Ok(retired)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"snapshot":self.original.object,"subvolume_removed":true,
            "snapshot_metadata_removed":false,"source_cleanup_complete":false,"backup_complete":false}),
        )
    }
}

/// Actual original Snapper metadata and empty number directory retired.
pub struct RemovedMetadata<'a, 'g> {
    original: Snapshot<'a, 'g>,
    metadata: enzimos_platform::named_retirement::Removed,
    directory: enzimos_platform::named_retirement::Removed,
}
impl RemovedMetadata<'_, '_> {
    pub fn recheck(&self) -> Result<()> {
        self.original.source.recheck()?;
        let parent = files::directory_relative(
            &self.original.source.file,
            Path::new(".snapshots"),
            Some(0),
        )?;
        same(
            &self.original.parent,
            &parent,
            self.original.parent_shape,
            self.original.parent_mount,
        )?;
        self.metadata.recheck()?;
        self.directory.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"snapshot":self.original.object,"subvolume_removed":true,
            "snapshot_metadata_removed":true,"snapshot_number_directory_removed":true,
            "source_cleanup_complete":false,"backup_complete":false}),
        )
    }
}
