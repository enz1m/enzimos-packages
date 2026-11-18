// SPDX-License-Identifier: MIT
//! Fixed kernel member opens for the private boot copy implementation.
use enzimos_platform::{Result, directory_entry::Entry, require};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
pub(crate) fn open(parent: &File, name: &str, owner: u32) -> Result<File> {
    require(
        !name.is_empty() && !name.contains('/') && !matches!(name, "." | ".."),
        "boot member component",
    )?;
    let entry = Entry::observe(parent, Path::new(name))?;
    let original = entry.metadata()?;
    require(
        (original.is_file() || original.is_dir())
            && original.uid() == owner
            && original.mode() & 0o7022 == 0,
        "unsafe boot member type or ownership",
    )?;
    let c = std::ffi::CString::new(name)
        .map_err(|_| enzimos_platform::Error("boot member NUL".into()))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    require(raw >= 0, "original boot member open failed")?;
    let file = unsafe { File::from_raw_fd(raw) };
    let m = file.metadata()?;
    require(
        (m.is_file() || m.is_dir()) && m.uid() == owner && m.mode() & 0o7022 == 0,
        "unsafe boot member type or ownership",
    )?;
    entry.matches(&file)?;
    Ok(file)
}
