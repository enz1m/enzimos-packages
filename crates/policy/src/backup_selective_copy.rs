// SPDX-License-Identifier: MIT
//! Exclusive original output write; refusal retains the partial entry and never retries.
use enzimos_platform::{Result, files, mount_identity, require, stream_copy};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};
fn shape(parent: &File) -> Result<(u64, u64, u32, u32, u32, u64)> {
    let m = parent.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(parent.as_fd(), true)?,
    ))
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, fremovexattr, geteuid, openat)."
)]
pub(crate) fn write(
    parent: &File,
    data: &[u8],
    digest: &str,
    owner: u32,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<File> {
    require(
        unsafe { libc::geteuid() } == owner
            && data.len() <= crate::backup_selective_result::MAX_FILE as usize
            && enzimos_platform::json::sha256(data) == digest,
        "original export writer identity/bytes",
    )?;
    let original = shape(parent)?;
    require(
        parent.metadata()?.is_dir() && original.3 == owner && original.2 & 0o7777 == 0o700,
        "original private export directory",
    )?;
    authorize()?;
    require(
        shape(parent)? == original,
        "original export parent changed before create",
    )?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c"content.bin".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(
        fd >= 0,
        "exclusive export content creation failed; no adoption",
    )?;
    let output = unsafe { File::from_raw_fd(fd) };
    // Remove inherited ACLs before publishing Root-private bytes. Never restore
    // historical permissions, attributes or ownership.
    if unsafe { libc::fremovexattr(fd, c"system.posix_acl_access".as_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        require(
            matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)),
            "export ACL removal failed; retain entry",
        )?;
    }
    require(
        unsafe { libc::fchmod(fd, 0o600) } == 0,
        "export content mode publication failed",
    )?;
    let mut epoch = files::identity(&output.metadata()?);
    let check = |epoch: files::FileIdentity| -> Result<()> {
        let named = files::open_relative(parent, Path::new("content.bin"))?;
        require(
            shape(parent)? == original
                && files::identity(&output.metadata()?) == epoch
                && files::identity(&named.metadata()?) == epoch
                && epoch.8 == owner
                && epoch.9 == original.4
                && epoch.7 & 0o7777 == 0o600
                && epoch.10 == 1
                && mount_identity::id(output.as_fd(), true)? == original.5
                && mount_identity::id(named.as_fd(), true)? == original.5,
            "original export content replaced/changed/covered",
        )
    };
    check(epoch)?;
    let mut offset = 0;
    for chunk in data.chunks(65536) {
        authorize()?;
        check(epoch)?;
        output.write_all_at(chunk, offset)?;
        offset += chunk.len() as u64;
        let after = files::identity(&output.metadata()?);
        require(
            (after.0, after.1, after.7, after.8, after.9, after.10)
                == (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9, epoch.10)
                && after.2 == offset
                && (after.3, after.4) >= (epoch.3, epoch.4)
                && (after.5, after.6) >= (epoch.5, epoch.6),
            "export changed outside original bounded write",
        )?;
        epoch = after;
        check(epoch)?;
        authorize()?;
        check(epoch)?;
    }
    authorize()?;
    check(epoch)?;
    output.sync_all()?;
    parent.sync_all()?;
    let (length, sha) = stream_copy::hash_borrowed(
        &output,
        crate::backup_selective_result::MAX_FILE,
        Some(owner),
    )?;
    require(
        length == data.len() as u64 && sha == digest,
        "actual original export readback differs",
    )?;
    authorize()?;
    check(epoch)?;
    Ok(output)
}
