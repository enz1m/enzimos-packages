// SPDX-License-Identifier: MIT
//! Original exclusive directory creation witness. Existing directories never
//! construct this actor, and dropping it never removes or repairs a pathname.
use crate::{Error, Result, files, mount_identity, receipt_registry, require};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o022 == 0,
        "original exclusive directory authority",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub struct Created {
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    name: PathBuf,
    file: File,
    epoch: files::FileIdentity,
    owner: u32,
}
impl Created {
    pub fn create(
        parent: &File,
        name: &Path,
        owner: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        require(
            name.components().count() == 1
                && matches!(name.components().next(), Some(Component::Normal(_))),
            "exclusive directory single leaf",
        )?;
        let parent_shape = shape(parent, owner)?;
        let parent_mount = mount_identity::id(parent.as_fd(), true)?;
        let file = files::create_directory_relative(parent, name, 0o700, owner)?;
        let this = Self {
            parent: parent.try_clone()?,
            parent_shape,
            parent_mount,
            name: name.into(),
            epoch: files::identity(&file.metadata()?),
            file,
            owner,
        };
        this.recheck()?;
        authorize()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        let named = files::directory_relative(&self.parent, &self.name, Some(self.owner))?;
        require(
            shape(&self.parent, self.owner)? == self.parent_shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == self.parent_mount
                && mount_identity::id(named.as_fd(), true)? == self.parent_mount
                && self.file.metadata()?.mode() & 0o7777 == 0o700
                && files::directory_is_empty(&self.file)?,
            "original newly created directory changed/covered/nonempty",
        )
    }
    pub fn require_parent(&self, parent: &File, name: &Path) -> Result<()> {
        self.recheck()?;
        require(
            shape(parent, self.owner)? == self.parent_shape
                && name == self.name
                && mount_identity::id(parent.as_fd(), true)? == self.parent_mount,
            "exclusive directory requires independently held original parent/leaf",
        )?;
        self.recheck()
    }
    /// Consume the empty exclusive creation witness into a new-row registry
    /// before any receipt publication. The registry retains this actual inode.
    pub fn into_receipt_registry(
        self,
        path: &Path,
        own_leaf: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<receipt_registry::Registry> {
        authorize()?;
        self.recheck()?;
        let named_parent = files::directory(
            path.parent()
                .ok_or_else(|| Error("new registry parent path".into()))?,
            Some(self.owner),
        )?;
        self.require_parent(
            &named_parent,
            Path::new(
                path.file_name()
                    .ok_or_else(|| Error("new registry leaf path".into()))?,
            ),
        )?;
        let registry = receipt_registry::Registry::observe(path, &self.file, own_leaf, self.owner)?;
        registry.require_original_members(&Default::default())?;
        self.recheck()?;
        authorize()?;
        registry.recheck()?;
        Ok(registry)
    }
}
