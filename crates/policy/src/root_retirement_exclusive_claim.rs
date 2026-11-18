// SPDX-License-Identifier: MIT
//! Actual mapper O_EXCL open/held descriptor and consuming explicit release.
//! A released observation is not a persistent mounted-device ownership claim.
use crate::recovery_unlock::CreatedMapping;
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::MetadataExt,
    },
};
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn flags(file: &File) -> Result<i32> {
    let value = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "actual exclusive mapper description must be read-only",
    )?;
    Ok(value)
}
pub struct Held<'a, 's> {
    mapping: &'a CreatedMapping<'s>,
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    mount: u64,
    identity: Value,
}
pub struct Released<'a, 's> {
    mapping: &'a CreatedMapping<'s>,
    epoch: files::FileIdentity,
    identity: Value,
}
impl<'a, 's> Held<'a, 's> {
    #[allow(unsafe_code, reason = "Linux syscall ABI (open).")]
    pub fn acquire(mapping: &'a CreatedMapping<'s>) -> Result<Self> {
        mapping.recheck()?;
        let (original, path) = mapping.original_mapper_node()?;
        let path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| enzimos_platform::Error("original mapper node encoding".into()))?;
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY
                    | libc::O_EXCL
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK,
            )
        };
        require(
            descriptor >= 0,
            "actual mapper kernel exclusive claim unavailable; no retry or fallback",
        )?;
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata()?;
        require(
            metadata.mode() & libc::S_IFMT == libc::S_IFBLK
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0
                && files::identity(&metadata) == files::identity(&original.metadata()?),
            "kernel claim opened another original mapper node",
        )?;
        let identity = crate::block::observe(file.as_fd())?;
        require(
            identity == crate::block::observe(original.as_fd())?,
            "actual exclusive mapper identity differs",
        )?;
        let result = Self {
            mapping,
            epoch: files::identity(&metadata),
            flags: flags(&file)?,
            mount: mount_identity::id(file.as_fd(), true)?,
            file,
            identity,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.mapping.recheck()?;
        let (original, _) = self.mapping.original_mapper_node()?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&original.metadata()?) == self.epoch
                && flags(&self.file)? == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(original.as_fd(), true)? == self.mount
                && crate::block::observe(self.file.as_fd())? == self.identity,
            "original held kernel mapper claim changed",
        )?;
        self.mapping.recheck()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (close, fcntl).")]
    pub fn release(self) -> Result<Released<'a, 's>> {
        self.recheck()?;
        let Self {
            mapping,
            file,
            epoch,
            identity,
            ..
        } = self;
        let descriptor = file.into_raw_fd();
        require(
            unsafe { libc::close(descriptor) } == 0,
            "kernel mapper claim release uncertain; no mount or retry",
        )?;
        require(
            unsafe { libc::fcntl(descriptor, libc::F_GETFD) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
            "original claim description still open after release",
        )?;
        let result = Released {
            mapping,
            epoch,
            identity,
        };
        result.recheck()?;
        Ok(result)
    }
}
impl Released<'_, '_> {
    pub(crate) fn require_original_mapping(&self, mapping: &CreatedMapping<'_>) -> Result<()> {
        require(
            std::ptr::eq(self.mapping, mapping),
            "actual released mapper claim belongs to another original unlock",
        )?;
        self.recheck()
    }
    pub fn recheck(&self) -> Result<()> {
        self.mapping.recheck()?;
        let (original, _) = self.mapping.original_mapper_node()?;
        require(
            files::identity(&original.metadata()?) == self.epoch
                && crate::block::observe(original.as_fd())? == self.identity,
            "original mapper changed after actual claim release",
        )?;
        self.mapping.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"actual_kernel_exclusive_open_succeeded":true,"original_claim_description_released":true,"persistent_exclusive_claim_held":false,"execution_authorized":false}),
        )
    }
}
