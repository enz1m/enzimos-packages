// SPDX-License-Identifier: MIT
//! Unprivileged descriptor-only copy core; a grant coordinator must supply the actual files.
use crate::{delivery_export::MAX_FILE, identity};
use enzimos_platform::{Result, files, mount_identity, require, stream_copy};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
/// The returned actual output file is retained for the supervisor's independent verification.
/// No path, historical owner or JSON value grants permission to create output.
pub fn copy_owned(
    home: &File,
    source: &File,
    id: &str,
    bytes: u64,
    digest: &str,
    uid: u32,
) -> Result<File> {
    identity::safe_id(id)?;
    copy_named(
        home,
        source,
        &format!("enzimos-restored-{id}.bin"),
        bytes,
        digest,
        uid,
    )
}
/// Only an ordinary owner can create an exclusive safe leaf through its actual directory.
/// This primitive does not authorize a grant or historical path.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, fremovexattr, getresuid, openat)."
)]
pub fn copy_named(
    home: &File,
    source: &File,
    name: &str,
    bytes: u64,
    digest: &str,
    uid: u32,
) -> Result<File> {
    require(
        crate::delivery_cancel::filename(name),
        "safe delivery filename required",
    )?;
    identity::sha(digest)?;
    let mut real = 0;
    let mut effective = 0;
    let mut saved = 0;
    require(
        // SAFETY: The three outputs are writable uid_t values.
        unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } == 0
            && real == uid
            && effective == uid
            && saved == uid
            && (1000..i32::MAX as u32).contains(&uid),
        "ordinary dropped delivery identity required",
    )?;
    require(bytes <= MAX_FILE, "delivery byte bound")?;
    let parent = shape(home)?;
    require(
        home.metadata()?.is_dir() && parent.2 == uid && parent.4 & 0o022 == 0,
        "original recipient-owned directory required",
    )?;
    let mount = mount_identity::id(home.as_fd(), true)?;
    let original = files::identity(&source.metadata()?);
    let source_mount = mount_identity::id(source.as_fd(), true)?;
    let (length, sha) = stream_copy::hash_borrowed(source, MAX_FILE, None)?;
    require(
        length == bytes && sha == digest,
        "delivery source differs before creation",
    )?;
    let c = CString::new(name.as_bytes())
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    require(
        shape(home)? == parent
            && mount_identity::id(home.as_fd(), true)? == mount
            && files::identity(&source.metadata()?) == original,
        "original delivery inputs changed",
    )?;
    // SAFETY: `c` is a NUL-terminated C string and `home` keeps the descriptor open.
    let fd = unsafe {
        libc::openat(
            home.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    let output = unsafe { File::from_raw_fd(fd) };
    // The final name remains on every failure. Never unlink a partial or replay.
    let acl = CString::new("system.posix_acl_access")
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    // SAFETY: `acl` is a NUL-terminated CString and `output` keeps the descriptor open.
    if unsafe { libc::fremovexattr(output.as_raw_fd(), acl.as_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        require(
            matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)),
            "delivery ACL removal refused; output retained",
        )?;
    }
    require(
        // SAFETY: fchmod takes no pointers and `output` keeps the descriptor open.
        unsafe { libc::fchmod(output.as_raw_fd(), 0o600) } == 0,
        "delivery protection refused; output retained",
    )?;
    let mut offset = 0;
    let mut buffer = vec![0u8; 65536];
    while offset < bytes {
        let count = source.read_at(
            &mut buffer[..((bytes - offset) as usize).min(65536)],
            offset,
        )?;
        require(count > 0, "delivery source shortened; output retained")?;
        output.write_all_at(&buffer[..count], offset)?;
        offset += count as u64;
    }
    require(
        files::identity(&source.metadata()?) == original
            && mount_identity::id(source.as_fd(), true)? == source_mount,
        "original delivery source changed; output retained",
    )?;
    let output_epoch = files::identity(&output.metadata()?);
    let (length, sha) = stream_copy::hash_borrowed(&output, MAX_FILE, Some(uid))?;
    let m = output.metadata()?;
    require(
        length == bytes
            && sha == digest
            && files::identity(&m) == output_epoch
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && mount_identity::id(output.as_fd(), true)? == mount,
        "delivery output readback differs; output retained",
    )?;
    output.sync_all()?;
    home.sync_all()?;
    let named = files::open_relative(home, Path::new(name))?;
    require(
        files::identity(&named.metadata()?) == output_epoch
            && files::identity(&output.metadata()?) == output_epoch
            && files::identity(&source.metadata()?) == original
            && mount_identity::id(source.as_fd(), true)? == source_mount
            && shape(home)? == parent
            && mount_identity::id(home.as_fd(), true)? == mount,
        "original delivered output or directory changed",
    )?;
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> tempfile::TempDir {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap()
    }
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (lseek).")]
    fn actual_owned_descriptor_copy_never_overwrites_or_moves_shared_source_cursor() {
        let temp = fixture();
        let uid = enzimos_platform::process_identity::effective_uid();
        assert!(
            (1000..i32::MAX as u32).contains(&uid),
            "owned-file fixture requires ordinary test user"
        );
        let parent = files::directory(temp.path(), Some(uid)).unwrap();
        let source = files::atomic_relative_retained(
            &parent,
            Path::new("source"),
            b"private recovered bytes",
            0o600,
            Some(uid),
            false,
            4096,
        )
        .unwrap();
        assert_eq!(
            // SAFETY: lseek takes no pointers and `source` keeps the descriptor open.
            unsafe { libc::lseek(source.as_raw_fd(), 7, libc::SEEK_SET) },
            7
        );
        let sha = enzimos_platform::json::sha256(b"private recovered bytes");
        let copied = copy_owned(&parent, &source, "receipt1", 23, &sha, uid).unwrap();
        assert_eq!(
            files::read_file(&copied, 4096, Some(uid), true).unwrap(),
            b"private recovered bytes"
        );
        assert_eq!(
            // SAFETY: lseek takes no pointers and `source` keeps the descriptor open.
            unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
            7
        );
        assert!(copy_owned(&parent, &source, "receipt1", 23, &sha, uid).is_err());
        assert_eq!(
            files::read_file(&copied, 4096, Some(uid), true).unwrap(),
            b"private recovered bytes"
        );
        assert!(copy_owned(&parent, &source, "wrong", 23, &"b".repeat(64), uid).is_err());
        assert!(
            files::optional_relative(&parent, Path::new("enzimos-restored-wrong.bin"))
                .unwrap()
                .is_none()
        );
    }
}
