// SPDX-License-Identifier: MIT
//! FAT-aware owned publication. Mount permissions are retained rather than
//! pretending FAT implements arbitrary Unix644 modes on a private0077 mount.
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fstatfs, openat, renameat2)."
)]
pub(super) fn write(
    parent: &File,
    name: &str,
    bytes: &[u8],
    original: Option<&File>,
) -> Result<File> {
    require(
        bytes.len() <= 32 * 1024 * 1024
            && !name.is_empty()
            && !name.contains('/')
            && !matches!(name, "." | ".."),
        "bounded single FAT publication member required",
    )?;
    let p = parent.metadata()?;
    require(
        p.is_dir()
            && p.uid() == 0
            && p.gid() == 0
            && p.mode() & 0o022 == 0
            && enzimos_platform::process_identity::effective_uid() == 0,
        "original protected FAT publication parent required",
    )?;
    let mount = mount_identity::id(parent.as_fd(), true)?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(parent.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x4d44,
        "actual FAT publication filesystem required",
    )?;
    let destination = CString::new(name).unwrap();
    let epoch = original
        .map(|f| f.metadata().map(|m| files::identity(&m)))
        .transpose()?;
    if let Some(original) = original {
        let named = files::open_relative(parent, Path::new(name))?;
        require(
            files::identity(&named.metadata()?) == epoch.unwrap()
                && mount_identity::id(original.as_fd(), true)? == mount,
            "original FAT destination differs",
        )?;
    } else {
        require(
            files::optional_relative(parent, Path::new(name))?.is_none(),
            "FAT destination collision; no overwrite",
        )?;
    }
    let temporary = format!(".enzimos-boot-{}", files::random_hex(16)?);
    let tmp = CString::new(temporary.as_str()).unwrap();
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(raw >= 0, "exclusive FAT publication writer required")?;
    let mut writer = unsafe { File::from_raw_fd(raw) };
    writer.write_all(bytes)?;
    writer.sync_all()?;
    let written = files::identity(&writer.metadata()?);
    let temp_file = files::open_relative(parent, Path::new(&temporary))?;
    require(
        files::identity(&temp_file.metadata()?) == written
            && mount_identity::id(writer.as_fd(), true)? == mount
            && files::read_file(&temp_file, bytes.len().max(1), Some(0), true)? == bytes,
        "owned FAT writer readback differs",
    )?;
    let now = parent.metadata()?;
    require(
        (now.dev(), now.ino(), now.mode(), now.uid(), now.gid())
            == (p.dev(), p.ino(), p.mode(), p.uid(), p.gid())
            && mount_identity::id(parent.as_fd(), true)? == mount,
        "original FAT parent changed",
    )?;
    if let Some(original) = original {
        let named = files::open_relative(parent, Path::new(name))?;
        require(
            files::identity(&original.metadata()?) == epoch.unwrap()
                && files::identity(&named.metadata()?) == epoch.unwrap(),
            "original FAT replacement changed",
        )?;
    }
    require(
        unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                tmp.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
                if original.is_some() {
                    0
                } else {
                    libc::RENAME_NOREPLACE
                },
            )
        } == 0,
        "owned FAT publication rename failed; temporary retained for review",
    )?;
    parent.sync_all()?;
    let result = files::open_relative(parent, Path::new(name))?;
    let after = result.metadata()?;
    require(
        after.dev() == writer.metadata()?.dev()
            && after.ino() == writer.metadata()?.ino()
            && after.uid() == 0
            && after.gid() == 0
            && after.mode() & 0o022 == 0
            && mount_identity::id(result.as_fd(), true)? == mount
            && files::read_file(&result, bytes.len().max(1), Some(0), true)? == bytes,
        "owned FAT publication inode/readback changed",
    )?;
    Ok(result)
}
