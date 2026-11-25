// SPDX-License-Identifier: MIT
//! Exclusive package-manager admission. Cleanup can unlink only our held inode.
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
pub(crate) struct PacmanLock {
    parent: File,
    file: Option<File>,
    mount: u64,
    owner: u32,
    retain_on_drop: bool,
}
impl PacmanLock {
    pub(crate) fn acquire() -> Result<Self> {
        crate::storage_runtime::initial_namespace()?;
        Self::under(Path::new("/var/lib/pacman"), 0)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, openat).")]
    fn under(path: &Path, owner: u32) -> Result<Self> {
        require(
            enzimos_platform::process_identity::effective_uid() == owner,
            "package lock owner mismatch",
        )?;
        let parent = files::directory(path, Some(owner))?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c"db.lck".as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(
            raw >= 0,
            "pacman already running or its lock cannot be created",
        )?;
        let file = unsafe { File::from_raw_fd(raw) };
        require(
            unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0,
            "package lock mode uncertain",
        )?;
        file.sync_all()?;
        parent.sync_all()?;
        let this = Self {
            mount: mount_identity::id(file.as_fd(), true)?,
            parent,
            file: Some(file),
            owner,
            retain_on_drop: false,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("package lock already released".into()))?;
        let m = file.metadata()?;
        let named = files::open_relative(&self.parent, Path::new("db.lck"))?;
        require(
            m.is_file()
                && m.uid() == self.owner
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && m.len() == 0
                && files::identity(&named.metadata()?) == files::identity(&m)
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "package lock identity changed",
        )
    }
    /// Once trust publication can mutate, an interrupted caller leaves the
    /// package-manager lock present until the retained receipt is reviewed.
    pub(crate) fn retain_on_failure(&mut self) -> Result<()> {
        self.recheck()?;
        self.retain_on_drop = true;
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub(crate) fn close(&mut self) -> Result<()> {
        if self.file.is_none() {
            return Ok(());
        }
        self.recheck()?;
        require(
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), c"db.lck".as_ptr(), 0) } == 0,
            "owned package lock removal failed",
        )?;
        self.parent.sync_all()?;
        self.file.take();
        Ok(())
    }
}
impl Drop for PacmanLock {
    fn drop(&mut self) {
        if !self.retain_on_drop {
            let _ = self.close();
        }
    }
}
