// SPDX-License-Identifier: MIT
//! Metadata-only sealed input. No plaintext, digest, Debug or serialization API.
use crate::{Error, Result, files, require};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
};
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
pub struct Retained {
    file: File,
    identity: files::FileIdentity,
    owner: u32,
    length: usize,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn qualified(file: &File, owner: u32) -> Result<files::FileIdentity> {
    let m = file.metadata()?;
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    require(
        m.is_file()
            && m.uid() == owner
            && m.nlink() == 0
            && m.mode() & 0o7077 == 0
            && (1..=4096).contains(&m.len())
            && seals >= 0
            && seals & SEALS == SEALS
            && flags >= 0
            && flags & libc::O_ACCMODE != libc::O_WRONLY,
        "secret-input-refused",
    )?;
    Ok(files::identity(&m))
}
pub fn retain(fd: BorrowedFd<'_>, uid: u32) -> Result<Retained> {
    require(
        (1000..i32::MAX as u32).contains(&uid),
        "secret-input-refused",
    )?;
    let file = File::from(fd.try_clone_to_owned()?);
    let identity = qualified(&file, uid)?;
    let this = Retained {
        length: file.metadata()?.len() as usize,
        file,
        identity,
        owner: uid,
    };
    this.recheck()?;
    Ok(this)
}
impl Retained {
    pub fn recheck(&self) -> Result<()> {
        require(
            qualified(&self.file, self.owner)? == self.identity,
            "original sealed input metadata changed",
        )
    }
    pub fn length(&self) -> Result<usize> {
        self.recheck()?;
        Ok(self.length)
    }
    pub fn fd(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.file.as_fd())
    }
    /// Caller supplies a newly created original private inode after persisting its
    /// intent. There is no path, plaintext read/write fallback, overwrite or hash.
    /// Partial output remains owned by the caller for explicit review on failure.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (fcntl, fsync, geteuid, lseek and others)."
    )]
    pub fn copy_into_new(&self, output: &File) -> Result<()> {
        self.recheck()?;
        let before = output.metadata()?;
        let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
        require(
            before.is_file()
                && before.uid() == unsafe { libc::geteuid() }
                && before.nlink() == 1
                && before.mode() & 0o7777 == 0o600
                && before.len() == 0
                && flags >= 0
                && flags & libc::O_ACCMODE != libc::O_RDONLY
                && flags & libc::O_APPEND == 0
                && unsafe { libc::lseek(output.as_raw_fd(), 0, libc::SEEK_CUR) } == 0,
            "new private credential output required",
        )?;
        let position = unsafe { libc::lseek(self.file.as_raw_fd(), 0, libc::SEEK_CUR) };
        require(position >= 0, "sealed input position unavailable")?;
        let mut offset: libc::off_t = 0;
        let mut interrupted = 0;
        while (offset as usize) < self.length {
            self.recheck()?;
            let count = unsafe {
                libc::sendfile(
                    output.as_raw_fd(),
                    self.file.as_raw_fd(),
                    &mut offset,
                    self.length - offset as usize,
                )
            };
            if count < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    && interrupted < 16
                {
                    interrupted += 1;
                    continue;
                }
                return Err(Error(
                    "kernel credential copy refused; partial output retained".into(),
                ));
            }
            require(
                count > 0 && offset >= 0 && offset as usize <= self.length,
                "kernel credential copy incomplete; partial output retained",
            )?;
        }
        require(
            unsafe { libc::fsync(output.as_raw_fd()) } == 0,
            "credential copy durability unknown",
        )?;
        let after = output.metadata()?;
        require(
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode(),
                before.nlink(),
            ) == (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode(),
                after.nlink(),
            ) && after.len() == self.length as u64
                && unsafe { libc::lseek(self.file.as_raw_fd(), 0, libc::SEEK_CUR) } == position,
            "credential output or original sender position changed",
        )?;
        self.recheck()
    }
}
