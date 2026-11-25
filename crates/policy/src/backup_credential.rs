// SPDX-License-Identifier: MIT
//! Metadata-only credential retention. No password bytes or digest enter policy evidence.
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o022 == 0,
        "protected backup credential parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
/// Deliberately has no Debug, serialization, bytes, or hash accessor. A worker
/// may borrow the original descriptor only after a fresh metadata check.
/// Holding this descriptor does not itself seal its content against writers.
pub struct Credential {
    path: PathBuf,
    parent: File,
    parent_shape: Shape,
    parent_mount: u64,
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    owner: u32,
    flags: i32,
    parent_flags: i32,
}
impl Credential {
    pub fn open() -> Result<Self> {
        crate::namespaces::initial()?;
        Self::retained(Path::new(crate::backup_configuration::PASSWORD), 0)
    }
    pub(crate) fn open_next() -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        Self::retained(Path::new("/etc/enzimos/backup.next-password"), 0)
    }
    fn retained(path: &Path, owner: u32) -> Result<Self> {
        let parent = files::directory(
            path.parent().ok_or_else(|| {
                enzimos_platform::Error("backup credential parent required".into())
            })?,
            Some(owner),
        )?;
        let file = files::open_relative(
            &parent,
            Path::new(path.file_name().ok_or_else(|| {
                enzimos_platform::Error("backup credential name required".into())
            })?),
        )?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == owner
                && m.mode() & 0o077 == 0
                && m.nlink() == 1
                && (1..=4096).contains(&m.len()),
            "private single-link backup credential required",
        )?;
        let flags = enzimos_platform::files::status_flags(&file);
        let parent_flags = enzimos_platform::files::status_flags(&parent);
        require(
            flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY
                && flags & libc::O_PATH == 0
                && parent_flags >= 0,
            "original credential read-only description required",
        )?;
        let this = Self {
            path: path.into(),
            parent_shape: shape(&parent, owner)?,
            parent_mount: mount_identity::id(parent.as_fd(), true)?,
            identity: files::identity(&m),
            mount: mount_identity::id(file.as_fd(), true)?,
            parent,
            file,
            owner,
            flags,
            parent_flags,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        let parent = files::directory(self.path.parent().unwrap(), Some(self.owner))?;
        let named = files::open_relative(&self.parent, Path::new(self.path.file_name().unwrap()))?;
        require(
            shape(&parent, self.owner)? == self.parent_shape
                && shape(&self.parent, self.owner)? == self.parent_shape
                && enzimos_platform::files::status_flags(&self.parent) == self.parent_flags
                && enzimos_platform::files::status_flags(&self.file) == self.flags
                && mount_identity::id(parent.as_fd(), true)? == self.parent_mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original backup credential epoch changed or replaced",
        )
    }
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.file.as_fd())
    }
    pub(crate) fn binding(
        &self,
        guard: &crate::storage_runtime::Guard,
    ) -> Result<serde_json::Value> {
        self.recheck()?;
        guard.recheck()?;
        require(
            self.mount == guard.root_mount_id() && self.identity.0 == guard.root_device(),
            "backup credential must belong to the configured live root",
        )?;
        let m = self.file.metadata()?;
        let nanos = |seconds: i64, ns: i64| {
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|v| v.checked_add(ns))
                .ok_or_else(|| {
                    enzimos_platform::Error("backup credential metadata time bound".into())
                })
        };
        Ok(
            serde_json::json!({"dev":m.dev(),"ino":m.ino(),"size":m.len(),"mtime_ns":nanos(m.mtime(),m.mtime_nsec())?,"ctime_ns":nanos(m.ctime(),m.ctime_nsec())?}),
        )
    }
}
