// SPDX-License-Identifier: MIT
//! Descriptor-relative file access that never follows symlinks and checks owners and modes.
use crate::{Error, Result, require};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

/// File status flags (`F_GETFL`) of an open descriptor, or `-1` when the query fails.
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
pub fn status_flags<F: std::os::fd::AsFd + ?Sized>(fd: &F) -> libc::c_int {
    // SAFETY: F_GETFL only reads flags of a descriptor kept open by the borrow.
    unsafe { libc::fcntl(fd.as_fd().as_raw_fd(), libc::F_GETFL) }
}

#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn openat(parent: i32, name: &std::ffi::OsStr, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| Error("invalid file name".into()))?;
    // SAFETY: `name` is a NUL-terminated CString that outlives the call.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(Error(format!(
            "descriptor open failed: {name:?} kind={:?} errno={:?}",
            error.kind(),
            error.raw_os_error()
        )));
    }
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn directory_ok(f: &File, owner: Option<u32>) -> Result<()> {
    let m = f.metadata()?;
    require(m.is_dir(), "not a directory")?;
    if let Some(owner) = owner {
        require(
            (m.uid() == 0 || m.uid() == owner) && m.mode() & 0o022 == 0,
            "unsafe directory authority",
        )?;
    }
    Ok(())
}

/// Observe emptiness through the original directory description, including when
/// its pathname is renamed or covered. This observation grants no ownership.
///
/// # Errors
///
/// Fails when the directory cannot be enumerated or leaves its original filesystem.
pub fn directory_is_empty(file: &File) -> Result<bool> {
    Ok(directory_scan(file, 1, true)?.is_empty())
}
/// Bounded names from an original directory. Returned names do not authorize
/// opening members; callers must still retain and recheck each original file.
///
/// # Errors
///
/// Fails when enumeration fails or the directory holds more than `maximum` members.
pub fn directory_names(file: &File, maximum: usize) -> Result<Vec<std::ffi::OsString>> {
    require((1..=131072).contains(&maximum), "directory inventory bound")?;
    directory_scan(file, maximum, false)
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (__errno_location, close, closedir, fdopendir and others)."
)]
fn directory_scan(
    file: &File,
    maximum: usize,
    stop_at_first: bool,
) -> Result<Vec<std::ffi::OsString>> {
    use std::os::fd::{AsFd, IntoRawFd};
    let before = identity(&file.metadata()?);
    require(file.metadata()?.is_dir(), "original directory required")?;
    let mount = crate::mount_identity::id(file.as_fd(), true)?;
    // A fresh openat description has its own directory cursor. dup would share
    // the caller's cursor and could falsely observe EOF on a nonempty directory.
    let stream = openat(
        file.as_raw_fd(),
        std::ffi::OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    require(
        identity(&stream.metadata()?) == before
            && crate::mount_identity::id(stream.as_fd(), true)? == mount,
        "directory enumeration left original filesystem",
    )?;
    let raw = stream.into_raw_fd();
    // SAFETY: `raw` came from `into_raw_fd`, so ownership passes to the DIR stream on success.
    let pointer = unsafe { libc::fdopendir(raw) };
    if pointer.is_null() {
        // SAFETY: fdopendir failed, so `raw` is still owned here and closed exactly once.
        unsafe { libc::close(raw) };
        return Err(std::io::Error::last_os_error().into());
    }
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        #[allow(unsafe_code, reason = "Linux syscall ABI (closedir).")]
        fn drop(&mut self) {
            // SAFETY: The pointer came from a successful fdopendir and is closed only by this drop.
            unsafe { libc::closedir(self.0) };
        }
    }
    let directory = Directory(pointer);
    let mut result = Vec::new();
    let mut finished = false;
    // Include dot, dot-dot and EOF within a fixed syscall bound.
    for _ in 0..maximum + 3 {
        // SAFETY: errno is thread-local and always writable.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `directory.0` is a live DIR stream owned by `directory`.
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            require(
                // SAFETY: errno is thread-local and always readable.
                unsafe { *libc::__errno_location() } == 0,
                "original directory enumeration failed",
            )?;
            finished = true;
            break;
        }
        // SAFETY: readdir returned a non-null entry whose `d_name` is NUL-terminated and valid
        // until the next readdir.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if !matches!(name, b"." | b"..") {
            require(result.len() < maximum, "original directory member bound")?;
            result.push(std::ffi::OsString::from(std::ffi::OsStr::from_bytes(name)));
            if stop_at_first {
                finished = true;
                break;
            }
        }
    }
    require(
        identity(&file.metadata()?) == before
            && crate::mount_identity::id(file.as_fd(), true)? == mount,
        "original directory changed during enumeration",
    )?;
    require(finished, "original directory enumeration bound")?;
    Ok(result)
}

/// Read kernel-generated regular pseudo-files without trusting their stat size.
/// The path is still walked without symlinks and the owner/type remain checked.
///
/// # Errors
///
/// Fails on the same path, ownership and size checks as [`read_kernel_owned`].
pub fn read_kernel(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read_kernel_owned(path, limit, 0)
}
/// Read a kernel pseudo-file below `/proc` or `/sys`, whose parent directories must be owned by
/// Root or `owner`.
///
/// # Errors
///
/// Fails for other paths, a `limit` above 4 MiB, an unsafe parent or file, or content larger than
/// `limit`.
pub fn read_kernel_owned(path: &Path, limit: usize, owner: u32) -> Result<Vec<u8>> {
    require(
        path.starts_with("/proc") || path.starts_with("/sys"),
        "kernel file path required",
    )?;
    require(limit <= 4 * 1024 * 1024, "kernel read bound")?;
    let parent = directory(
        path.parent()
            .ok_or_else(|| Error("missing kernel parent".into()))?,
        Some(owner),
    )
    .map_err(|error| Error(format!("kernel parent admission: {error}")))?;
    let mut file = open_relative(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| Error("missing kernel filename".into()))?,
        ),
    )
    .map_err(|error| Error(format!("kernel original file open: {error}")))?;
    let before = file
        .metadata()
        .map_err(|error| Error(format!("kernel original file metadata: {error}")))?;
    require(
        (before.uid() == 0 || before.uid() == owner) && before.mode() & 0o022 == 0,
        "unsafe kernel file",
    )?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error(format!("kernel original file read: {error}")))?;
    require(bytes.len() <= limit, "kernel file read bound")?;
    let after = file
        .metadata()
        .map_err(|error| Error(format!("kernel final file metadata: {error}")))?;
    require(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "kernel file identity changed",
    )?;
    Ok(bytes)
}

// Walking from an opened root and retaining each directory descriptor prevents
// ancestor rename/symlink substitution from redirecting later opens or writes.
/// Name the full requested path in a failed walk (the open error names only
/// the failing component).
fn at_path<T>(result: Result<T>, path: &Path) -> Result<T> {
    result.map_err(|error| Error(format!("{} (in {})", error.0, path.display())))
}
/// Open an absolute directory by walking each component without following symlinks.
///
/// # Errors
///
/// Fails on a relative or noncanonical path, a symlink or non-directory component, or, when `owner`
/// is set, a directory not owned by Root or `owner` or writable by group or others.
pub fn directory(path: &Path, owner: Option<u32>) -> Result<File> {
    at_path(directory_walk(path, owner), path)
}
fn directory_walk(path: &Path, owner: Option<u32>) -> Result<File> {
    require(path.is_absolute(), "absolute path required")?;
    let mut current = openat(
        libc::AT_FDCWD,
        std::ffi::OsStr::new("/"),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    directory_ok(&current, owner)?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = openat(
                    current.as_raw_fd(),
                    name,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                directory_ok(&current, owner)?;
            }
            _ => return Err(Error("noncanonical path".into())),
        }
    }
    Ok(current)
}
/// Walk below an already retained directory; ancestor symlinks are refused.
///
/// # Errors
///
/// Fails on the same component checks as [`directory`].
pub fn directory_relative(root: &File, path: &Path, owner: Option<u32>) -> Result<File> {
    at_path(directory_relative_walk(root, path, owner), path)
}
fn directory_relative_walk(root: &File, path: &Path, owner: Option<u32>) -> Result<File> {
    require(
        !path.is_absolute()
            && !path.as_os_str().is_empty()
            && path.as_os_str().as_bytes().len() <= 4096,
        "bounded relative directory path required",
    )?;
    directory_ok(root, owner)?;
    let mut current = root.try_clone()?;
    for (index, part) in path.components().enumerate() {
        require(index < 128, "relative directory depth bound")?;
        let Component::Normal(name) = part else {
            return Err(Error("noncanonical relative directory".into()));
        };
        current = openat(
            current.as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        directory_ok(&current, owner)?;
    }
    Ok(current)
}

/// Create any missing directories of an absolute path with `mode` (0o700 or 0o755), keeping
/// existing ones.
///
/// # Errors
///
/// Fails unless the caller's effective UID is `owner`, or when an existing component is not a
/// directory owned by `owner` with exactly `mode`.
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, mkdirat).")]
pub fn ensure_directory(path: &Path, mode: u32, owner: u32) -> Result<File> {
    require(
        path.is_absolute()
            && matches!(mode, 0o700 | 0o755)
            && crate::process_identity::effective_uid() == owner,
        "directory writer authority or mode",
    )?;
    let mut current = directory(Path::new("/"), Some(owner))?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                let c = CString::new(name.as_bytes())
                    .map_err(|_| Error("invalid directory name".into()))?;
                // SAFETY: `c` is a NUL-terminated CString and `current` keeps the descriptor open
                // for the call.
                let rc = unsafe { libc::mkdirat(current.as_raw_fd(), c.as_ptr(), mode) };
                if rc < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                let next = openat(
                    current.as_raw_fd(),
                    name,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                if rc == 0 {
                    require(
                        // SAFETY: fchmod takes no pointers and `next` keeps the descriptor open for
                        // the call.
                        unsafe { libc::fchmod(next.as_raw_fd(), mode) } == 0,
                        "directory mode publication failed",
                    )?;
                    next.sync_all()?;
                    current.sync_all()?;
                }
                directory_ok(&next, Some(owner))?;
                current = next;
            }
            _ => return Err(Error("noncanonical directory path".into())),
        }
    }
    let m = current.metadata()?;
    require(
        m.uid() == owner && m.mode() & 0o777 == mode,
        "directory owner or mode mismatch",
    )?;
    Ok(current)
}

/// Create exactly one new directory with `mode` (0o700 or 0o755) below an existing parent.
///
/// # Errors
///
/// Fails unless the caller's effective UID is `owner`, when the name already exists, or when the
/// parent is unsafe.
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, mkdirat).")]
pub fn create_directory(path: &Path, mode: u32, owner: u32) -> Result<File> {
    require(
        matches!(mode, 0o700 | 0o755) && crate::process_identity::effective_uid() == owner,
        "directory writer authority or mode",
    )?;
    let parent = directory(
        path.parent()
            .ok_or_else(|| Error("missing directory parent".into()))?,
        Some(owner),
    )?;
    let name = path
        .file_name()
        .ok_or_else(|| Error("missing directory filename".into()))?;
    let c = CString::new(name.as_bytes()).map_err(|_| Error("invalid directory name".into()))?;
    require(
        // SAFETY: `c` is a NUL-terminated CString and `parent` keeps the descriptor open for the
        // call.
        unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), mode) } == 0,
        "new directory required",
    )?;
    let created = openat(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    require(
        // SAFETY: fchmod takes no pointers and `created` keeps the descriptor open for the call.
        unsafe { libc::fchmod(created.as_raw_fd(), mode) } == 0,
        "directory mode publication failed",
    )?;
    created.sync_all()?;
    parent.sync_all()?;
    require(
        created.metadata()?.uid() == owner,
        "directory owner mismatch",
    )?;
    Ok(created)
}

/// Create exactly one new member through the held original parent. Existing
/// names, including dangling symlinks, are never adopted or removed on failure.
///
/// # Errors
///
/// Fails unless the caller's effective UID is `owner`, when `name` is not a single component or
/// already exists, or when the created directory's identity or mount differs.
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, mkdirat).")]
pub fn create_directory_relative(
    parent: &File,
    name: &Path,
    mode: u32,
    owner: u32,
) -> Result<File> {
    require(
        matches!(mode, 0o700 | 0o755)
            && crate::process_identity::effective_uid() == owner
            && name.components().count() == 1
            && matches!(name.components().next(), Some(Component::Normal(_))),
        "exclusive relative directory writer",
    )?;
    directory_ok(parent, Some(owner))?;
    let before = parent.metadata()?;
    let shape = (
        before.dev(),
        before.ino(),
        before.mode(),
        before.uid(),
        before.gid(),
    );
    let mount = crate::mount_identity::id(std::os::fd::AsFd::as_fd(parent), true)?;
    let c = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| Error("directory leaf encoding".into()))?;
    require(
        // SAFETY: `c` is a NUL-terminated CString and `parent` keeps the descriptor open for the
        // call.
        unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), mode) } == 0,
        "new relative directory required; no adoption",
    )?;
    let created = openat(
        parent.as_raw_fd(),
        name.as_os_str(),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    require(
        // SAFETY: fchmod takes no pointers and `created` keeps the descriptor open for the call.
        unsafe { libc::fchmod(created.as_raw_fd(), mode) } == 0,
        "new directory mode publication",
    )?;
    created.sync_all()?;
    parent.sync_all()?;
    let m = created.metadata()?;
    let now = parent.metadata()?;
    let named = directory_relative(parent, name, Some(owner))?;
    require(
        (now.dev(), now.ino(), now.mode(), now.uid(), now.gid()) == shape
            && m.uid() == owner
            && m.gid() == before.gid()
            && m.mode() & 0o7777 == mode
            && identity(&named.metadata()?) == identity(&m)
            && crate::mount_identity::id(std::os::fd::AsFd::as_fd(parent), true)? == mount
            && crate::mount_identity::id(std::os::fd::AsFd::as_fd(&created), true)? == mount,
        "original relative directory identity or mount differs",
    )?;
    Ok(created)
}
/// Like [`read`], but returns `None` when the file is absent and its parent directory is safe.
///
/// # Errors
///
/// Fails on the same checks as [`read`].
pub fn read_optional(
    path: &Path,
    limit: usize,
    owner: Option<u32>,
    single_link: bool,
) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => read(path, limit, owner, single_link).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            directory(
                path.parent()
                    .ok_or_else(|| Error("missing parent".into()))?,
                owner,
            )?;
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Open a regular file below `root` by walking a relative path without following symlinks.
///
/// # Errors
///
/// Fails on an absolute or noncanonical path, a symlink component, or a final member that is not a
/// regular file.
pub fn open_relative(root: &File, path: &Path) -> Result<File> {
    at_path(open_relative_walk(root, path), path)
}
fn open_relative_walk(root: &File, path: &Path) -> Result<File> {
    require(!path.is_absolute(), "relative path required")?;
    let mut dir = root.try_clone()?;
    let parts: Vec<_> = path.components().collect();
    require(!parts.is_empty(), "empty path")?;
    for (i, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(Error("noncanonical path".into()));
        };
        let last = i + 1 == parts.len();
        dir = openat(
            dir.as_raw_fd(),
            name,
            libc::O_RDONLY
                | if last {
                    libc::O_NONBLOCK
                } else {
                    libc::O_DIRECTORY
                },
            0,
        )?;
        if last {
            require(dir.metadata()?.is_file(), "regular file required")?;
        }
    }
    Ok(dir)
}

/// Only kernel ENOENT is absence; unsafe types and other open failures remain errors.
/// A relative multi-component path is walked one held directory at a time.
///
/// # Errors
///
/// Fails on an absolute or noncanonical path, a member that is not a safe directory, or any open
/// error other than absence.
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
pub fn optional_directory_relative(
    parent: &File,
    name: &Path,
    owner: Option<u32>,
) -> Result<Option<File>> {
    require(
        name.components().count() >= 1
            && name.components().all(|c| matches!(c, Component::Normal(_))),
        "relative optional directory path required",
    )?;
    if name.components().count() > 1 {
        let mut current = parent.try_clone()?;
        for part in name.components() {
            match optional_directory_relative(&current, Path::new(part.as_os_str()), owner)? {
                Some(next) => current = next,
                None => return Ok(None),
            }
        }
        return Ok(Some(current));
    }
    directory_ok(parent, owner)?;
    let name = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| Error("invalid optional directory name".into()))?;
    // SAFETY: `name` is a NUL-terminated CString and `parent` keeps the descriptor open for the
    // call.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error.into())
        };
    }
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    let file = unsafe { File::from_raw_fd(raw) };
    directory_ok(&file, owner)?;
    Ok(Some(file))
}
/// Only kernel ENOENT is absence; unsafe types and other open failures remain errors.
///
/// # Errors
///
/// Fails when `name` is not one component, the member is not a regular file, or the open fails
/// other than with absence.
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
pub fn optional_relative(parent: &File, name: &Path) -> Result<Option<File>> {
    require(
        name.components().count() == 1
            && matches!(name.components().next(), Some(Component::Normal(_))),
        "single optional file name required",
    )?;
    let name = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| Error("invalid optional file name".into()))?;
    // SAFETY: `name` is a NUL-terminated CString and `parent` keeps the descriptor open for the
    // call.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error.into())
        };
    }
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    let file = unsafe { File::from_raw_fd(raw) };
    require(file.metadata()?.is_file(), "optional regular file required")?;
    Ok(Some(file))
}

/// Public-data aliases may resolve only beneath a retained directory. Linux
/// openat2 refuses absolute links, '..' escapes and magic /proc descriptor links.
///
/// # Errors
///
/// Fails when `path` is not a bounded relative path, resolves outside `root`, or is not a regular
/// file.
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
pub fn open_beneath(root: &File, path: &Path) -> Result<File> {
    require(
        !path.is_absolute()
            && !path.as_os_str().is_empty()
            && path.as_os_str().as_bytes().len() <= 4096
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "bounded relative public-data alias required",
    )?;
    require(
        root.metadata()?.is_dir(),
        "public-data alias root directory required",
    )?;
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error("invalid public-data alias".into()))?;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: 0x8 | 0x2,
    };
    // SAFETY: The path is NUL-terminated, `how` outlives the call and its size is passed, and
    // `root` stays open.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    require(
        raw >= 0,
        "public-data alias escaped its retained root or could not be opened",
    )?;
    // SAFETY: `raw` was just returned by openat2 and is owned by nothing else.
    let file = unsafe { File::from_raw_fd(raw as i32) };
    require(
        file.metadata()?.is_file(),
        "public-data alias must resolve to a regular file",
    )?;
    Ok(file)
}

/// Read a regular file by absolute path, walking its parent with [`directory`] and the file with
/// [`read_file`].
///
/// # Errors
///
/// Fails on the checks of [`directory`] and [`read_file`].
pub fn read(path: &Path, limit: usize, owner: Option<u32>, single_link: bool) -> Result<Vec<u8>> {
    let parent = directory(
        path.parent()
            .ok_or_else(|| Error("missing parent".into()))?,
        owner,
    )?;
    let file = openat(
        parent.as_raw_fd(),
        path.file_name()
            .ok_or_else(|| Error("missing filename".into()))?,
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?;
    read_file(&file, limit, owner, single_link)
}
/// Stable bounded pread preserves the borrowed descriptor's shared offset.
///
/// # Errors
///
/// Fails when the file is not regular, exceeds `limit` (at most 512 MiB), has more than one link
/// while `single_link` is set, is unsafe for `owner`, or changes during the read.
pub fn read_file(
    file: &File,
    limit: usize,
    owner: Option<u32>,
    single_link: bool,
) -> Result<Vec<u8>> {
    require(limit <= 512 * 1024 * 1024, "file read byte bound")?;
    let before = file.metadata()?;
    require(
        before.is_file() && before.len() <= limit as u64 && (!single_link || before.nlink() == 1),
        "unsafe file type, size or links",
    )?;
    if let Some(owner) = owner {
        require(
            before.uid() == owner && before.mode() & 0o022 == 0,
            "unsafe file authority",
        )?;
    }
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; 65536];
    loop {
        let remaining = (limit + 1 - bytes.len()).min(chunk.len());
        let count = file.read_at(&mut chunk[..remaining], bytes.len() as u64)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        require(bytes.len() <= limit, "file grew beyond read bound")?;
    }
    let after = file.metadata()?;
    require(
        bytes.len() <= limit
            && bytes.len() as u64 == before.len()
            && identity(&before) == identity(&after),
        "file changed during read",
    )?;
    Ok(bytes)
}

/// Inode identity and content-change fields of [`identity`], in its field order.
pub type FileIdentity = (u64, u64, u64, i64, i64, i64, i64, u32, u32, u32, u64);
/// Device, inode, size, mtime, ctime, mode, owner, group and link count of `m`.
pub fn identity(m: &std::fs::Metadata) -> FileIdentity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
    )
}

/// Hex-encode `bytes` random bytes from the kernel.
///
/// # Errors
///
/// Fails when `bytes` is zero or above 256, or the kernel random source fails.
#[allow(unsafe_code, reason = "Linux syscall ABI (getrandom).")]
pub fn random_hex(bytes: usize) -> Result<String> {
    require(bytes > 0 && bytes <= 256, "random size bound")?;
    let mut data = vec![0u8; bytes];
    let mut pos = 0;
    while pos < data.len() {
        // SAFETY: The pointer and length describe the unfilled tail of `data`.
        let n = unsafe { libc::getrandom(data[pos..].as_mut_ptr().cast(), data.len() - pos, 0) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(std::io::Error::last_os_error().into());
        }
        require(n > 0, "random source unavailable")?;
        pos += n as usize;
    }
    Ok(data.iter().map(|v| format!("{v:02x}")).collect())
}

/// Create a protected directory tree below an already retained filesystem root.
///
/// # Errors
///
/// Fails unless the caller's effective UID is `owner`, or when the path is noncanonical, deeper
/// than its bound, or crosses a directory with another owner or mode.
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, mkdirat).")]
pub fn ensure_directory_relative(root: &File, path: &Path, mode: u32, owner: u32) -> Result<File> {
    require(
        !path.is_absolute()
            && !path.as_os_str().is_empty()
            && path.as_os_str().as_bytes().len() <= 4096
            && matches!(mode, 0o700 | 0o755)
            && crate::process_identity::effective_uid() == owner,
        "relative directory writer authority",
    )?;
    directory_ok(root, Some(owner))?;
    let mut current = root.try_clone()?;
    for (index, part) in path.components().enumerate() {
        require(index < 128, "relative directory depth bound")?;
        let Component::Normal(name) = part else {
            return Err(Error("noncanonical relative directory".into()));
        };
        let name_c =
            CString::new(name.as_bytes()).map_err(|_| Error("invalid directory name".into()))?;
        // SAFETY: `name_c` is a NUL-terminated CString and `current` keeps the descriptor open for
        // the call.
        let rc = unsafe { libc::mkdirat(current.as_raw_fd(), name_c.as_ptr(), mode) };
        if rc < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(std::io::Error::last_os_error().into());
        }
        let next = openat(
            current.as_raw_fd(),
            name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        if rc == 0 {
            require(
                // SAFETY: fchmod takes no pointers and `next` keeps the descriptor open for the
                // call.
                unsafe { libc::fchmod(next.as_raw_fd(), mode) } == 0,
                "relative directory mode publication",
            )?;
            next.sync_all()?;
            current.sync_all()?;
        }
        directory_ok(&next, Some(owner))?;
        require(
            next.metadata()?.uid() == owner,
            "relative directory owner differs",
        )?;
        current = next;
    }
    Ok(current)
}

/// Exclusive flock on an owned lock file, rechecked against its original path, parent and mount.
pub struct Lock {
    file: File,
    identity: FileIdentity,
    mount: u64,
    path: std::path::PathBuf,
    parent: File,
    parent_shape: (u64, u64, u32, u32, u32),
}

/// Replace only an owned regular file or symlink, never following its destination.
///
/// # Errors
///
/// Fails on the checks of [`symlink_member`] or when `target` is not absolute.
pub fn symlink_relative(parent: &File, name: &Path, target: &str, owner: u32) -> Result<()> {
    require(
        target.starts_with('/'),
        "absolute configured symlink target required",
    )?;
    symlink_member(parent, name, target, owner)
}
/// Publish an archive's already reviewed link without following its destination.
/// The archive caller must additionally validate its target-root containment.
///
/// # Errors
///
/// Fails unless the caller's effective UID is `owner`, when `name` is not one component, when an
/// existing member is not an owned file or symlink, or when the member changes during publication.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fstatat, renameat2, symlinkat and others)."
)]
pub fn symlink_member(parent: &File, name: &Path, target: &str, owner: u32) -> Result<()> {
    directory_ok(parent, Some(owner))?;
    require(
        crate::process_identity::effective_uid() == owner
            && name.components().count() == 1
            && matches!(name.components().next(), Some(Component::Normal(_)))
            && !target.is_empty()
            && target.len() <= 4096
            && !target.contains('\0'),
        "symlink publication shape or authority",
    )?;
    let name = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| Error("invalid symlink name".into()))?;
    let target = CString::new(target).map_err(|_| Error("invalid symlink target".into()))?;
    // Device, inode, mode, owner, link count and ctime of the member, if present.
    type Observation = Option<(u64, u64, u32, u32, u64, i64, i64)>;
    let observe = || -> Result<Observation> {
        // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid value.
        let mut s: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `name` is NUL-terminated, `s` is a writable `libc::stat`, and `parent` stays
        // open.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                &mut s,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error.into())
            };
        }
        require(
            s.st_uid == owner
                && s.st_nlink == 1
                && (s.st_mode & libc::S_IFMT == libc::S_IFLNK
                    || (s.st_mode & libc::S_IFMT == libc::S_IFREG && s.st_mode & 0o022 == 0)),
            "unsafe previous symlink publication member",
        )?;
        Ok(Some((
            s.st_dev,
            s.st_ino,
            s.st_mode,
            s.st_uid,
            s.st_nlink,
            s.st_ctime,
            s.st_ctime_nsec,
        )))
    };
    let before = observe()?;
    let temp = CString::new(format!(".enzimos-link-{}", random_hex(16)?))
        .map_err(|_| Error("invalid generated native name".into()))?;
    require(
        // SAFETY: Both paths are NUL-terminated CStrings and `parent` keeps the descriptor open for
        // the call.
        unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), temp.as_ptr()) } == 0,
        "private symlink creation failed",
    )?;
    let result = (|| {
        require(observe()? == before, "symlink publication member changed")?;
        require(
            // SAFETY: Both names are NUL-terminated CStrings and `parent` keeps the descriptor open
            // for the call.
            unsafe {
                libc::renameat2(
                    parent.as_raw_fd(),
                    temp.as_ptr(),
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    if before.is_some() {
                        0
                    } else {
                        libc::RENAME_NOREPLACE
                    },
                )
            } == 0,
            "symlink publication refused",
        )?;
        parent.sync_all()?;
        Ok(())
    })();
    // SAFETY: `temp` is a NUL-terminated CString and `parent` keeps the descriptor open for the
    // call.
    unsafe { libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0) };
    result
}
impl Lock {
    /// Acquire the lock at `path`, failing when another holder owns it.
    ///
    /// # Errors
    ///
    /// Fails when another process holds the lock, or on the checks of [`Lock::try_acquire`].
    pub fn acquire(path: &Path, owner: u32) -> Result<Self> {
        Self::try_acquire(path, owner)?
            .ok_or_else(|| Error("another operation owns the lock".into()))
    }
    /// Only a kernel-reported competing flock is retryable. Path, permissions,
    /// descriptor and filesystem errors remain errors, never apparent busyness.
    ///
    /// # Errors
    ///
    /// Fails unless the caller's effective UID is `owner`, or when the lock file is unsafe,
    /// replaced, or cannot be opened.
    #[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
    pub fn try_acquire(path: &Path, owner: u32) -> Result<Option<Self>> {
        require(
            crate::process_identity::effective_uid() == owner,
            "lock owner mismatch",
        )?;
        let parent = directory(
            path.parent()
                .ok_or_else(|| Error("missing parent".into()))?,
            Some(owner),
        )?;
        let file = openat(
            parent.as_raw_fd(),
            path.file_name()
                .ok_or_else(|| Error("missing filename".into()))?,
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        let m = file.metadata()?;
        require(
            m.is_file() && m.uid() == owner && m.mode() & 0o077 == 0 && m.nlink() == 1,
            "unsafe lock file",
        )?;
        // SAFETY: flock takes no pointers and `file` keeps the descriptor open for the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(error.into());
        }
        let named = open_relative(
            &parent,
            Path::new(
                path.file_name()
                    .ok_or_else(|| Error("missing retained filename".into()))?,
            ),
        )?;
        require(
            identity(&file.metadata()?) == identity(&m)
                && identity(&named.metadata()?) == identity(&m),
            "lock file replaced before acquisition",
        )?;
        let pm = parent.metadata()?;
        Ok(Some(Self {
            identity: identity(&m),
            mount: crate::mount_identity::id(std::os::fd::AsFd::as_fd(&file), true)?,
            path: path.into(),
            parent_shape: (pm.dev(), pm.ino(), pm.mode(), pm.uid(), pm.gid()),
            parent,
            file,
        }))
    }
    /// The locked file.
    pub fn as_file(&self) -> &File {
        &self.file
    }
    /// Duplicate the actual original open description; never reacquire by name.
    /// Closing one lease keeps flock exclusion until the last duplicate closes.
    ///
    /// # Errors
    ///
    /// Fails when the lock no longer passes [`Lock::recheck`] or duplication fails.
    pub fn duplicate(&self) -> Result<Self> {
        self.recheck()?;
        let other = Self {
            identity: self.identity,
            mount: self.mount,
            path: self.path.clone(),
            parent_shape: self.parent_shape,
            parent: self.parent.try_clone()?,
            file: self.file.try_clone()?,
        };
        self.recheck()?;
        other.recheck()?;
        Ok(other)
    }
    /// Verify the original named inode, parent, mount and actual exclusion. An
    /// identical replacement cannot turn a stale descriptor into authorization.
    ///
    /// # Errors
    ///
    /// Fails when the named lock file, its parent or mount changed, or the description lost
    /// exclusion.
    #[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
    pub fn recheck(&self) -> Result<()> {
        use std::os::fd::AsFd;
        let owner = self.identity.8;
        let parent = directory(
            self.path
                .parent()
                .ok_or_else(|| Error("missing retained parent directory".into()))?,
            Some(owner),
        )?;
        let shape = |f: &File| -> Result<(u64, u64, u32, u32, u32)> {
            let m = f.metadata()?;
            Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
        };
        require(
            shape(&parent)? == self.parent_shape && shape(&self.parent)? == self.parent_shape,
            "original lock parent changed",
        )?;
        let named = open_relative(
            &self.parent,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| Error("missing retained filename".into()))?,
            ),
        )?;
        require(
            identity(&self.file.metadata()?) == self.identity
                && identity(&named.metadata()?) == self.identity
                && crate::mount_identity::id(self.file.as_fd(), true)? == self.mount
                && crate::mount_identity::id(named.as_fd(), true)? == self.mount
                && crate::mount_identity::id(parent.as_fd(), true)?
                    == crate::mount_identity::id(self.parent.as_fd(), true)?,
            "original lock inode replaced, changed or remounted",
        )?;
        crate::flock_identity::exclusive(&self.file)?;
        // SAFETY: flock takes no pointers and `named` keeps the descriptor open for the call.
        let rc = unsafe { libc::flock(named.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        let error = std::io::Error::last_os_error();
        require(
            rc == -1 && error.raw_os_error() == Some(libc::EWOULDBLOCK),
            "original lock description lost exclusion",
        )?;
        crate::flock_identity::exclusive(&self.file)
    }
}

mod publication;
pub use publication::atomic;
pub use publication::atomic_bounded;
pub use publication::atomic_relative;
pub use publication::atomic_relative_retained;
pub use publication::atomic_replace_original;
pub use publication::public_directory_mode;
pub use publication::public_file_mode;
