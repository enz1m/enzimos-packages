// SPDX-License-Identifier: MIT
//! Private original-inode checks shared by newly published setup artifacts.
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};

pub(crate) fn recheck(
    parent: &File,
    name: &str,
    file: &File,
    original: files::FileIdentity,
    mount: u64,
    owner: u32,
) -> Result<()> {
    let named = files::open_relative(parent, Path::new(name))?;
    let held = file.metadata()?;
    require(
        files::identity(&held) == original
            && files::identity(&named.metadata()?) == original
            && held.uid() == owner
            && held.gid() == owner
            && held.mode() & 0o7777 == 0o600
            && held.nlink() == 1
            && mount_identity::id(file.as_fd(), true)? == mount
            && mount_identity::id(named.as_fd(), true)? == mount,
        "original private setup publication changed or replaced",
    )
}

/// Remove one of this run's own publications by name in its retained parent,
/// after the caller rechecked the exact inode, and make the removal durable.
#[allow(unsafe_code, reason = "Linux syscall ABI (fsync, unlinkat).")]
pub(crate) fn retract(parent: &File, name: &std::ffi::CStr) -> Result<()> {
    use std::os::fd::AsRawFd;
    require(
        // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
        unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "setup publication retraction refused",
    )?;
    require(
        // SAFETY: fsync takes no pointers and `parent` keeps the descriptor open.
        unsafe { libc::fsync(parent.as_raw_fd()) } == 0,
        "setup publication retraction durability unknown",
    )
}

/// link/unlink changes ctime and link count, but cannot authorize any other
/// change to the inode the publisher created. Capture the resulting epoch only
/// after checking this known transition.
pub(crate) fn after_unlink(
    original: files::FileIdentity,
    file: &File,
) -> Result<files::FileIdentity> {
    let current = files::identity(&file.metadata()?);
    require(
        current.0 == original.0
            && current.1 == original.1
            && current.2 == original.2
            && current.3 == original.3
            && current.4 == original.4
            && current.7 == original.7
            && current.8 == original.8
            && current.9 == original.9
            && current.10 == 1,
        "publication changed beyond its owned link transition",
    )?;
    Ok(current)
}
