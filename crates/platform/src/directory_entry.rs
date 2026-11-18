// SPDX-License-Identifier: MIT
//! A retained member observes metadata without opening its contents or following links.
use crate::{Error, Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::{File, Metadata},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

pub struct Entry {
    parent: File,
    parent_identity: files::FileIdentity,
    parent_mount: u64,
    name: PathBuf,
    file: File,
    identity: files::FileIdentity,
    mount: u64,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn open(parent: &File, name: &Path) -> Result<File> {
    require(
        name.components().count() == 1
            && matches!(name.components().next(), Some(Component::Normal(_))),
        "single directory member name required",
    )?;
    let name = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| Error("directory member encoding".into()))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
impl Entry {
    /// No owner, file type, executable, or write authority follows from this observation.
    pub fn observe(parent: &File, name: &Path) -> Result<Self> {
        require(
            parent.metadata()?.is_dir(),
            "original member parent must be a directory",
        )?;
        let parent_identity = files::identity(&parent.metadata()?);
        let parent_mount = mount_identity::id(parent.as_fd(), true)?;
        let file = open(parent, name)?;
        let this = Self {
            identity: files::identity(&file.metadata()?),
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            parent: parent.try_clone()?,
            parent_identity,
            parent_mount,
            name: name.into(),
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        let named = open(&self.parent, &self.name)?;
        require(
            files::identity(&self.parent.metadata()?) == self.parent_identity
                && mount_identity::id(self.parent.as_fd(), true)? == self.parent_mount
                && files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original directory member changed, replaced or remounted",
        )
    }
    pub fn metadata(&self) -> Result<Metadata> {
        self.recheck()?;
        let metadata = self.file.metadata()?;
        require(
            files::identity(&metadata) == self.identity,
            "original member metadata epoch changed",
        )?;
        Ok(metadata)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (readlinkat).")]
    pub fn read_link(&self, maximum: usize) -> Result<PathBuf> {
        require((1..=65536).contains(&maximum), "original link length bound")?;
        require(
            self.metadata()?.file_type().is_symlink(),
            "original symlink descriptor required",
        )?;
        let mut bytes = vec![0u8; maximum + 1];
        // Linux readlinkat supports an empty pathname for O_PATH|O_NOFOLLOW links.
        let length = unsafe {
            libc::readlinkat(
                self.file.as_raw_fd(),
                c"".as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        require(
            length > 0 && length as usize <= maximum,
            "original symlink exceeds bound",
        )?;
        bytes.truncate(length as usize);
        self.recheck()?;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
    }
    pub fn matches(&self, file: &File) -> Result<()> {
        self.recheck()?;
        require(
            files::identity(&file.metadata()?) == self.identity
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "opened member differs from original metadata descriptor",
        )
    }
}
