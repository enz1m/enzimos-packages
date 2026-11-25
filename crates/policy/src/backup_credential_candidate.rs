// SPDX-License-Identifier: MIT
//! Retain both fixed protected credential descriptions without reading their bytes.
use crate::{backup_credential::Credential, storage_runtime::Guard};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json as value};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;

/// No Debug, serialization, secret bytes or digest accessor. Metadata evidence
/// cannot construct this actor or authorize any repository operation.
pub struct Candidate<'g> {
    guard: &'g Guard,
    current: Credential,
    next: Credential,
    original: Value,
}
impl<'g> Candidate<'g> {
    pub fn observe(guard: &'g Guard) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let current = Credential::open()?;
        let next = Credential::open_next()?;
        let mut this = Self {
            guard,
            current,
            next,
            original: Value::Null,
        };
        this.original = this.metadata()?;
        this.recheck()?;
        Ok(this)
    }
    fn metadata(&self) -> Result<Value> {
        self.guard.recheck()?;
        let current = self.current.binding(self.guard)?;
        let next = self.next.binding(self.guard)?;
        require(
            (current["dev"].as_u64(), current["ino"].as_u64())
                != (next["dev"].as_u64(), next["ino"].as_u64()),
            "candidate recovery credential aliases current password",
        )?;
        let file = std::fs::File::from(self.next.descriptor()?.try_clone_to_owned()?);
        require(
            file.metadata()?.gid() == 0,
            "candidate recovery credential group authority",
        )?;
        let root = self.guard.backup_root_binding()?;
        let persistent = value!({"filesystem_uuid":root["configuration"]["filesystem_uuid"],
            "root_uuid":root["root"]["uuid"],"root_id":root["root"]["id"],"root_path":root["root"]["path"],
            "inode":next["ino"],"size":next["size"],"mtime_ns":next["mtime_ns"],"ctime_ns":next["ctime_ns"]});
        // Schema2 enrollment persists subvolume identity, not boot-local st_dev.
        Ok(value!({"input_identity":persistent,"root":root,
            "current_file":files::identity(&std::fs::File::from(self.current.descriptor()?.try_clone_to_owned()?).metadata()?),
            "next_file":files::identity(&file.metadata()?),
            "next_mount":enzimos_platform::mount_identity::id(file.as_fd(),true)?}))
    }
    pub fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        require(
            self.metadata()? == self.original,
            "original candidate/current credential or persistent source changed",
        )
    }
    pub(crate) fn persistent_identity(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.original["input_identity"])
    }
    pub fn evidence(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.original)
    }
    pub(crate) fn require_guard(&self, guard: &Guard) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard),
            "candidate requires original storage actor",
        )?;
        self.recheck()
    }
    pub(crate) fn descriptors(
        &self,
        guard: &Guard,
    ) -> Result<(std::os::fd::BorrowedFd<'_>, std::os::fd::BorrowedFd<'_>)> {
        self.require_guard(guard)?;
        Ok((self.current.descriptor()?, self.next.descriptor()?))
    }
}
