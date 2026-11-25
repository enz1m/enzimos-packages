// SPDX-License-Identifier: MIT
//! Original offline control subvolume over an actual owned unlock/mount pair.
//! The recorded identity is a comparison; it cannot construct an execution actor.
use crate::{recovery_unlock::CreatedMapping, root_retirement_offline_scope::Mounts};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub struct Control<'a, 's> {
    mapping: &'a CreatedMapping<'s>,
    mounts: &'a Mounts<'s>,
    file: File,
    name: String,
    epoch: files::FileIdentity,
    mount: u64,
    flags: i32,
    identity: Value,
}
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline control observation flags",
    )?;
    Ok(flags)
}
fn private(file: &File) -> Result<()> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.ino() == 256 && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "actual private Root control subvolume required",
    )
}
impl<'a, 's> Control<'a, 's> {
    pub(crate) fn original_scope(&self) -> Result<&'s crate::root_retirement_offline_scope::Scope> {
        self.recheck()?;
        self.mapping.original_scope()
    }
    pub(crate) fn require_original_kernel_boot(
        &self,
        kernel: &crate::root_retirement_kernel_boot::Original<'_>,
    ) -> Result<()> {
        self.recheck()?;
        kernel.require_original_scope(self.mapping.original_scope()?)?;
        let parameters = kernel.parameters()?;
        require(
            parameters.control == self.name
                && parameters.filesystem == self.mapping.filesystem_uuid()?,
            "actual kernel boot differs from original control/mapping identity",
        )
    }
    pub(crate) fn require_original_mounts(&self, mounts: &Mounts<'s>) -> Result<()> {
        require(
            std::ptr::eq(self.mounts, mounts),
            "original offline control/mount actor differs",
        )?;
        self.recheck()
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub(crate) fn mount_id(&self) -> Result<u64> {
        self.recheck()?;
        Ok(self.mount)
    }
    pub fn observe(
        mapping: &'a CreatedMapping<'s>,
        mounts: &'a Mounts<'s>,
        name: &str,
        expected: &Value,
    ) -> Result<Self> {
        mapping.require_original_mount(mounts)?;
        crate::identity::safe_id(name)?;
        json::fields(expected, "path id uuid parent_uuid")?;
        crate::identity::uuid(expected["uuid"].as_str().unwrap_or(""))?;
        require(
            expected["path"] == name && expected["id"].as_u64().is_some_and(|id| id >= 256),
            "closed offline control identity comparison required",
        )?;
        let top = mounts.original_top()?;
        let file = files::directory_relative(top, Path::new(name), Some(0))?;
        private(&file)?;
        let mount = mount_identity::id(top.as_fd(), true)?;
        require(
            mount_identity::id(file.as_fd(), true)? == mount
                && crate::subvolume::observe(file.as_fd(), name)? == (expected.clone(), false),
            "actual original offline control differs from recorded comparison",
        )?;
        let this = Self {
            mapping,
            mounts,
            name: name.into(),
            epoch: files::identity(&file.metadata()?),
            flags: flags(&file)?,
            file,
            mount,
            identity: expected.clone(),
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.mapping.require_original_mount(self.mounts)?;
        let named =
            files::directory_relative(self.mounts.original_top()?, Path::new(&self.name), Some(0))?;
        for file in [&self.file, &named] {
            private(file)?;
            require(
                files::identity(&file.metadata()?) == self.epoch
                    && mount_identity::id(file.as_fd(), true)? == self.mount
                    && crate::subvolume::observe(file.as_fd(), &self.name)?
                        == (self.identity.clone(), false),
                "original offline control epoch/mount/subvolume changed or replaced",
            )?;
        }
        require(
            flags(&self.file)? == self.flags,
            "original offline control descriptor flags changed",
        )?;
        self.mapping.require_original_mount(self.mounts)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let result = value!({"identity":self.identity,"mount":self.mount,
            "original_epoch":self.epoch,"execution_authorized":false});
        self.recheck()?;
        Ok(result)
    }
}
