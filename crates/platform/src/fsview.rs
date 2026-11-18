// SPDX-License-Identifier: MIT
//! Descriptor-relative views for walking snapshots and homes as root.
//!
//! Every lookup stays beneath a retained directory: no symlinks, no `..`, no
//! magic links and no crossing into another mount, so a path chosen by an
//! unprivileged caller can never name anything outside the tree it belongs to.
use crate::{Error, Result, require};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, FileType, Metadata};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Validate a relative path made of plain names only.
///
/// # Errors
/// Refuses empty, absolute, overlong or noncanonical paths and `.`/`..`.
pub fn relative(path: &Path) -> Result<()> {
    require(
        !path.as_os_str().is_empty()
            && !path.is_absolute()
            && path.as_os_str().len() <= 4096
            && !path.as_os_str().as_bytes().contains(&0)
            && path.components().count() <= 128
            && path
                .components()
                .all(|c| matches!(c, Component::Normal(n) if !n.is_empty())),
        "plain relative path required",
    )
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Open `path` beneath `root` without following symlinks or leaving the mount.
///
/// `flags` are ordinary open flags (`O_RDONLY`, `O_DIRECTORY`, `O_PATH`, ...);
/// `O_CLOEXEC` and `O_NOFOLLOW` are always added.
///
/// # Errors
/// Fails when the path is not plain, escapes, crosses a mount or a symlink, or
/// does not exist. `NotFound` keeps the `not-found` text so callers can tell.
#[allow(unsafe_code, reason = "Linux syscall ABI (openat2).")]
pub fn open_beneath(root: &File, path: &Path, flags: i32) -> Result<File> {
    relative(path)?;
    let name =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| Error("invalid path".into()))?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: libc::RESOLVE_BENEATH
            | libc::RESOLVE_NO_SYMLINKS
            | libc::RESOLVE_NO_MAGICLINKS
            | libc::RESOLVE_NO_XDEV,
    };
    // SAFETY: `name` is a live NUL-terminated string and `how` a fully
    // initialized open_how of the size passed; the kernel only reads both.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(Error(match error.raw_os_error() {
            Some(libc::ENOENT) => "not-found".into(),
            Some(libc::ENOTDIR) => "not-found".into(),
            Some(libc::ELOOP | libc::EXDEV) => "path-not-allowed".into(),
            _ => format!("open failed: {error}"),
        }));
    }
    let fd = i32::try_from(fd).map_err(|_| Error("descriptor range".into()))?;
    // SAFETY: openat2 returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open an absolute directory path component by component, refusing symlinks
/// (mount points along the way are allowed, unlike [`open_beneath`]).
///
/// # Errors
/// Fails for relative paths, symlinks or missing directories.
pub fn open_directory(path: &Path) -> Result<File> {
    crate::files::directory(path, None)
}

/// A directory entry with the type the kernel reported (no extra stat).
pub struct Entry {
    /// Plain name inside the directory.
    pub name: OsString,
    /// Kind as reported by the directory listing.
    pub kind: FileType,
}

fn proc_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

/// List up to `maximum` entries of an open directory.
///
/// # Errors
/// Fails when the directory cannot be read or holds more than `maximum` entries.
pub fn entries(directory: &File, maximum: usize) -> Result<Vec<Entry>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(proc_path(directory))? {
        let entry = entry?;
        require(result.len() < maximum, "directory-too-large")?;
        result.push(Entry {
            name: entry.file_name(),
            kind: entry.file_type()?,
        });
    }
    Ok(result)
}

/// Metadata of `name` inside an open directory, without following a symlink.
///
/// # Errors
/// Fails when the entry is gone or the name is not a plain name.
pub fn stat_at(directory: &File, name: &OsStr) -> Result<Metadata> {
    require(
        !name.is_empty() && name != "." && name != ".." && !name.as_bytes().contains(&b'/'),
        "plain name required",
    )?;
    Ok(std::fs::symlink_metadata(proc_path(directory).join(name))?)
}

/// Open a child directory of an open directory; `None` when it is not one.
///
/// # Errors
/// Fails on unexpected open errors (not on "not a directory" or symlinks).
pub fn child_directory(directory: &File, name: &OsStr) -> Result<Option<File>> {
    match open_beneath(
        directory,
        Path::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
    ) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.0 == "not-found" || e.0 == "path-not-allowed" => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether a small regular file `name` exists directly in `directory`.
#[must_use]
pub fn has_file(directory: &File, name: &str) -> bool {
    stat_at(directory, OsStr::new(name)).is_ok_and(|m| m.is_file())
}

/// Read at most `limit` bytes from the start of `name` in `directory`.
///
/// # Errors
/// Fails for non-regular files and read errors.
pub fn read_head(directory: &File, name: &str, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = open_beneath(directory, Path::new(name), libc::O_RDONLY)?;
    require(file.metadata()?.is_file(), "regular file required")?;
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

const FS_IOC_FIEMAP: libc::c_ulong = 0xC020_660B;
const FIEMAP_EXTENT_LAST: u32 = 0x1;
const FIEMAP_EXTENT_UNKNOWN: u32 = 0x2;
const FIEMAP_EXTENT_DELALLOC: u32 = 0x4;
const FIEMAP_EXTENT_INLINE: u32 = 0x200;
const BATCH: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FiemapExtent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved: [u32; 3],
}
#[repr(C)]
struct Fiemap {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    count: u32,
    reserved: u32,
    extents: [FiemapExtent; BATCH],
}

/// Physical extents `(physical, length)` of a regular file, up to `limit`.
///
/// Inline, delayed and unknown extents have no shareable physical location and
/// are reported with physical 0 (counted, never matched).
///
/// # Errors
/// Fails when the filesystem does not support FIEMAP or `limit` is exceeded.
#[allow(unsafe_code, reason = "Linux ioctl ABI (FS_IOC_FIEMAP).")]
pub fn extents(file: &File, limit: usize) -> Result<Vec<(u64, u64)>> {
    let mut result = Vec::new();
    let mut start = 0u64;
    loop {
        let mut map = Fiemap {
            start,
            length: u64::MAX - start,
            flags: 0,
            mapped: 0,
            count: BATCH as u32,
            reserved: 0,
            extents: [FiemapExtent::default(); BATCH],
        };
        // SAFETY: `map` is a writable fiemap header followed by `count`
        // extent slots, exactly the layout FS_IOC_FIEMAP fills.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_FIEMAP, &mut map as *mut Fiemap) };
        require(rc == 0, "extent map unavailable")?;
        let mapped = (map.mapped as usize).min(BATCH);
        if mapped == 0 {
            return Ok(result);
        }
        for extent in &map.extents[..mapped] {
            require(result.len() < limit, "extent-limit")?;
            let unshareable = extent.flags
                & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_INLINE)
                != 0;
            result.push((if unshareable { 0 } else { extent.physical }, extent.length));
            if extent.flags & FIEMAP_EXTENT_LAST != 0 {
                return Ok(result);
            }
        }
        let last = map.extents[mapped - 1];
        start = last
            .logical
            .checked_add(last.length)
            .ok_or_else(|| Error("extent range".into()))?;
    }
}

const BTRFS_IOC_SUBVOL_GETFLAGS: libc::c_ulong = 0x8008_9419;
const BTRFS_IOC_SUBVOL_SETFLAGS: libc::c_ulong = 0x4008_941A;
const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;

/// Whether an open Btrfs subvolume root is read-only.
///
/// # Errors
/// Fails when `subvolume` is not a Btrfs subvolume root.
#[allow(unsafe_code, reason = "Linux ioctl ABI (BTRFS_IOC_SUBVOL_GETFLAGS).")]
pub fn subvolume_readonly(subvolume: &File) -> Result<bool> {
    let mut flags = 0u64;
    // SAFETY: the ioctl writes one u64 into `flags`.
    let rc = unsafe {
        libc::ioctl(
            subvolume.as_raw_fd(),
            BTRFS_IOC_SUBVOL_GETFLAGS,
            &mut flags as *mut u64,
        )
    };
    require(rc == 0, "not a btrfs subvolume")?;
    Ok(flags & BTRFS_SUBVOL_RDONLY != 0)
}

/// Set or clear the read-only flag of an open Btrfs subvolume root (root only).
///
/// # Errors
/// Fails when `subvolume` is not a subvolume root or the caller lacks rights.
#[allow(unsafe_code, reason = "Linux ioctl ABI (BTRFS_IOC_SUBVOL_*FLAGS).")]
pub fn set_subvolume_readonly(subvolume: &File, readonly: bool) -> Result<()> {
    let mut flags = 0u64;
    // SAFETY: the ioctl writes one u64 into `flags`.
    let rc = unsafe {
        libc::ioctl(
            subvolume.as_raw_fd(),
            BTRFS_IOC_SUBVOL_GETFLAGS,
            &mut flags as *mut u64,
        )
    };
    require(rc == 0, "not a btrfs subvolume")?;
    let wanted = if readonly {
        flags | BTRFS_SUBVOL_RDONLY
    } else {
        flags & !BTRFS_SUBVOL_RDONLY
    };
    if wanted == flags {
        return Ok(());
    }
    // SAFETY: the ioctl reads one u64 from `wanted`.
    let rc = unsafe {
        libc::ioctl(
            subvolume.as_raw_fd(),
            BTRFS_IOC_SUBVOL_SETFLAGS,
            &wanted as *const u64,
        )
    };
    require(rc == 0, "subvolume flag change refused")
}

/// Remove `name` (a file, symlink or whole tree) inside `directory`.
///
/// Never follows symlinks and never leaves the directory's mount. Entries whose
/// owner is not `owner` are kept (and reported), so a tree is only partly
/// removed when it holds other accounts' files. Returns `(removed, kept)`.
///
/// # Errors
/// Fails on unexpected I/O errors.
pub fn remove_tree(directory: &File, name: &OsStr, owner: u32, depth: usize) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    require(depth < 256, "tree too deep")?;
    let meta = stat_at(directory, name)?;
    if meta.uid() != owner {
        return Ok((0, 1));
    }
    let mut kept = 0;
    let mut removed = 0;
    if meta.is_dir() {
        let Some(child) = child_directory(directory, name)? else {
            return Ok((0, 1));
        };
        require(child.metadata()?.dev() == meta.dev(), "mount boundary")?;
        for entry in entries(&child, 1 << 20)? {
            let (r, k) = remove_tree(&child, &entry.name, owner, depth + 1)?;
            removed += r;
            kept += k;
        }
        if kept == 0 {
            unlink_at(directory, name, true)?;
            removed += 1;
        }
    } else {
        unlink_at(directory, name, false)?;
        removed += 1;
    }
    Ok((removed, kept))
}

#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn unlink_at(directory: &File, name: &OsStr, dir: bool) -> Result<()> {
    let c = CString::new(name.as_bytes()).map_err(|_| Error("invalid name".into()))?;
    // SAFETY: `c` is a live NUL-terminated plain name; the fd is open.
    let rc = unsafe {
        libc::unlinkat(
            directory.as_raw_fd(),
            c.as_ptr(),
            if dir { libc::AT_REMOVEDIR } else { 0 },
        )
    };
    require(rc == 0, "remove failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn remove_tree_keeps_foreign_entries_and_symlink_targets() {
        let dir = tempfile::tempdir().expect("temp dir");
        let me = std::fs::metadata(dir.path()).expect("meta").uid();
        std::fs::create_dir_all(dir.path().join("t/sub")).expect("mkdir");
        std::fs::write(dir.path().join("t/sub/f"), b"x").expect("write");
        std::fs::write(dir.path().join("outside"), b"keep").expect("write");
        std::os::unix::fs::symlink(dir.path().join("outside"), dir.path().join("t/l"))
            .expect("symlink");
        let root = File::open(dir.path()).expect("open");
        let (removed, kept) = remove_tree(&root, OsStr::new("t"), me, 0).expect("remove");
        assert_eq!((removed, kept), (4, 0), "file, symlink, sub and t removed");
        assert!(
            dir.path().join("outside").exists(),
            "symlink target untouched"
        );
        std::fs::create_dir(dir.path().join("u")).expect("mkdir");
        assert_eq!(
            remove_tree(&root, OsStr::new("u"), me + 1, 0).expect("foreign"),
            (0, 1),
            "foreign owner kept"
        );
    }
}
