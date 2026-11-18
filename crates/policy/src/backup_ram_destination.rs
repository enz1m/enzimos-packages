// SPDX-License-Identifier: MIT
//! Independent RAM restore repository; cannot supply a live-system Guard.
use super::{Configuration, MOUNT, Shape, independent, mount, shape};
use crate::{filesystem, storage_runtime, topology};
use enzimos_platform::{Result, files, json, mount_identity, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) struct Destination<'a> {
    config: &'a Configuration,
    source: &'a crate::backup_ram_source::Source,
    root: File,
    root_shape: Shape,
    unique: u64,
    normal: u64,
    filesystem: Value,
    mount: mountinfo::Row,
    topology: topology::Graph,
    repository: File,
    repository_shape: Shape,
    repository_config: File,
    config_identity: files::FileIdentity,
    config_body: Vec<u8>,
}
impl<'a> Destination<'a> {
    pub(crate) fn open(
        config: &'a Configuration,
        source: &'a crate::backup_ram_source::Source,
    ) -> Result<Self> {
        config.recheck()?;
        source.recheck()?;
        let uuid = config.value()["destination_uuid"].as_str().unwrap();
        require(
            source.configuration()["filesystem_uuid"] != uuid,
            "backup destination must be independent of source/control filesystem",
        )?;
        let root = files::directory(Path::new(MOUNT), Some(0))?;
        let unique = mount_identity::id(root.as_fd(), true)?;
        let normal = mount_identity::id(root.as_fd(), false)?;
        let filesystem = filesystem::observe(root.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == uuid,
            "backup destination filesystem mismatch",
        )?;
        let mount = mount(&storage_runtime::rows()?, normal)?;
        let topology = topology::mounted_btrfs(uuid)?;
        independent(
            &topology.json(),
            &topology::mounted_btrfs(source.configuration()["filesystem_uuid"].as_str().unwrap())?
                .json(),
        )?;
        let repository = files::directory_relative(&root, Path::new("restic"), Some(0))?;
        require(
            mount_identity::id(repository.as_fd(), true)? == unique,
            "backup repository crosses a mount boundary",
        )?;
        let repository_config = files::open_relative(&repository, Path::new("config"))?;
        let m = repository_config.metadata()?;
        require(
            m.uid() == 0
                && m.mode() & 0o022 == 0
                && m.nlink() == 1
                && mount_identity::id(repository_config.as_fd(), true)? == unique,
            "protected backup repository configuration required",
        )?;
        let this = Self {
            config,
            source,
            root_shape: shape(&root)?,
            root,
            unique,
            normal,
            filesystem,
            mount,
            topology,
            repository_shape: shape(&repository)?,
            repository,
            config_identity: files::identity(&m),
            config_body: files::read_file(&repository_config, 1024 * 1024, Some(0), true)?,
            repository_config,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.config.recheck()?;
        self.source.recheck()?;
        let named = files::directory(Path::new(MOUNT), Some(0))?;
        let repo = files::directory_relative(&self.root, Path::new("restic"), Some(0))?;
        let config = files::open_relative(&self.repository, Path::new("config"))?;
        require(
            shape(&named)? == self.root_shape
                && shape(&self.root)? == self.root_shape
                && mount_identity::id(named.as_fd(), true)? == self.unique
                && mount_identity::id(self.root.as_fd(), true)? == self.unique
                && mount_identity::id(self.root.as_fd(), false)? == self.normal
                && filesystem::observe(self.root.as_fd())? == self.filesystem
                && mount(&storage_runtime::rows()?, self.normal)? == self.mount
                && topology::mounted_btrfs(
                    self.config.value()["destination_uuid"].as_str().unwrap(),
                )? == self.topology
                && shape(&repo)? == self.repository_shape
                && shape(&self.repository)? == self.repository_shape
                && mount_identity::id(repo.as_fd(), true)? == self.unique
                && mount_identity::id(self.repository.as_fd(), true)? == self.unique
                && files::identity(&config.metadata()?) == self.config_identity
                && files::identity(&self.repository_config.metadata()?) == self.config_identity
                && mount_identity::id(config.as_fd(), true)? == self.unique
                && mount_identity::id(self.repository_config.as_fd(), true)? == self.unique
                && files::read_file(&self.repository_config, 1024 * 1024, Some(0), true)?
                    == self.config_body,
            "original backup destination epoch changed or replaced",
        )
    }
    pub(crate) fn expected_pin(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"schema":1,"filesystem_uuid":self.filesystem["filesystem_uuid"],"fsroot":"/","repository":crate::backup_configuration::REPOSITORY,"repository_sha256":json::sha256(&self.config_body)}),
        )
    }
    pub(crate) fn repository_descriptor(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.repository.as_fd())
    }
    pub(crate) fn source(&self) -> &crate::backup_ram_source::Source {
        self.source
    }
}
