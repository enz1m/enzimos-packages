// SPDX-License-Identifier: MIT
//! Storage transactions retain the original configuration file, not just equal JSON.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const LIMIT: usize = 2 * 1024 * 1024;
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o022 == 0,
        "protected storage configuration parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(crate) struct Configuration {
    path: PathBuf,
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    bytes: Vec<u8>,
    value: Value,
    owner: u32,
}
impl Configuration {
    pub(crate) fn open() -> Result<Self> {
        Self::retained(Path::new("/etc/enzimos/storage.json"), 0)
    }
    fn retained(path: &Path, owner: u32) -> Result<Self> {
        let parent = files::directory(path.parent().unwrap(), Some(owner))?;
        let file = files::open_relative(&parent, Path::new(path.file_name().unwrap()))?;
        let m = file.metadata()?;
        require(
            m.uid() == owner && m.gid() == owner && m.nlink() == 1 && m.mode() & 0o022 == 0,
            "protected storage configuration inode required",
        )?;
        let bytes = files::read_file(&file, LIMIT, Some(owner), true)?;
        let value = json::decode(&bytes, LIMIT)?;
        crate::storage::validate(&value)?;
        let this = Self {
            path: path.into(),
            parent_shape: shape(&parent, owner)?,
            parent_mount: mount_identity::id(parent.as_fd(), true)?,
            parent,
            identity: files::identity(&m),
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            bytes,
            value,
            owner,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn value(&self) -> &Value {
        &self.value
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let parent = files::directory(self.path.parent().unwrap(), Some(self.owner))?;
        let named = files::open_relative(&self.parent, Path::new(self.path.file_name().unwrap()))?;
        require(
            shape(&self.parent, self.owner)? == self.parent_shape
                && shape(&parent, self.owner)? == self.parent_shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && mount_identity::id(parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && files::read_file(&self.file, LIMIT, Some(self.owner), true)? == self.bytes,
            "original storage configuration changed or replaced",
        )
    }
}
