// SPDX-License-Identifier: MIT
//! Original destination mount without requiring a repository at its current name.
//! A switch boundary may deliberately leave that name absent; mount identity never does.
use crate::{
    backup_configuration::Configuration,
    backup_destination, filesystem,
    storage_runtime::{self, Guard},
    topology,
};
use enzimos_platform::{Result, files, mount_identity, mountinfo, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected rotation destination parent required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub(crate) struct Mount<'a> {
    guard: &'a Guard,
    configuration: &'a Configuration,
    root: File,
    shape: Shape,
    unique: u64,
    normal: u64,
    filesystem: Value,
    row: mountinfo::Row,
    topology: topology::Graph,
}
impl<'a> Mount<'a> {
    pub(crate) fn observe(guard: &'a Guard, configuration: &'a Configuration) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        configuration.recheck()?;
        let uuid = configuration.value()["destination_uuid"].as_str().unwrap();
        require(
            guard.configuration["filesystem_uuid"] != uuid,
            "rotation destination overlaps system filesystem",
        )?;
        let root = files::directory(Path::new("/backup-repository"), Some(0))?;
        let unique = mount_identity::id(root.as_fd(), true)?;
        let normal = mount_identity::id(root.as_fd(), false)?;
        let filesystem = filesystem::observe(root.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == uuid,
            "rotation destination filesystem differs",
        )?;
        let row = backup_destination::mount(&storage_runtime::rows()?, normal)?;
        backup_destination::writable(&row)?;
        let topology = topology::mounted_btrfs(uuid)?;
        backup_destination::independent(
            &topology.json(),
            &topology::mounted_btrfs(guard.configuration["filesystem_uuid"].as_str().unwrap())?
                .json(),
        )?;
        let original = Self {
            guard,
            configuration,
            shape: shape(&root)?,
            root,
            unique,
            normal,
            filesystem,
            row,
            topology,
        };
        original.recheck()?;
        Ok(original)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.configuration.recheck()?;
        let named = files::directory(Path::new("/backup-repository"), Some(0))?;
        let row = backup_destination::mount(&storage_runtime::rows()?, self.normal)?;
        backup_destination::writable(&row)?;
        require(
            shape(&self.root)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.root.as_fd(), true)? == self.unique
                && mount_identity::id(named.as_fd(), true)? == self.unique
                && mount_identity::id(self.root.as_fd(), false)? == self.normal
                && filesystem::observe(self.root.as_fd())? == self.filesystem
                && row == self.row
                && topology::mounted_btrfs(
                    self.configuration.value()["destination_uuid"]
                        .as_str()
                        .unwrap(),
                )? == self.topology,
            "original rotation mount replaced or drifted",
        )
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.root)
    }
    pub(crate) fn mount_id(&self) -> u64 {
        self.unique
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"shape":self.shape,"unique_mount":self.unique,"filesystem":self.filesystem,"topology":self.topology.json()}),
        )
    }
}
