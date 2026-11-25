use super::*;

/// [`atomic_bounded`] with a 2 MiB limit.
///
/// # Errors
///
/// As [`atomic_bounded`].
pub fn atomic(
    path: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<u32>,
    replace: bool,
) -> Result<()> {
    atomic_bounded(path, body, mode, owner, replace, 2 * 1024 * 1024)
}
/// Write `body` to a temporary sibling and rename it over `path` with `mode`.
///
/// # Errors
///
/// Fails when `mode` is not 0o600, 0o640 or 0o644, `body` exceeds the limit (at most 32 MiB),
/// `name` is not one component, the parent or an existing member is unsafe for `owner`, the caller
/// is not `owner`, or the member changes before the rename. With `replace` unset, an existing
/// member also fails.
pub fn atomic_bounded(
    path: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<u32>,
    replace: bool,
    limit: usize,
) -> Result<()> {
    let parent = directory(
        path.parent()
            .ok_or_else(|| Error("missing parent".into()))?,
        owner,
    )?;
    atomic_relative(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| Error("missing filename".into()))?,
        ),
        body,
        mode,
        owner,
        replace,
        limit,
    )
}
/// Public files on a protected FAT ESP have a kernel-synthesized private mode.
/// Keep the writer's exact mode check; do not make private publications permissive.
///
/// # Errors
///
/// Fails when the parent filesystem cannot be queried.
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub fn public_file_mode(parent: &File) -> Result<u32> {
    directory_ok(parent, None)?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `filesystem` is a writable `libc::statfs` and `parent` keeps the descriptor open.
        unsafe { libc::fstatfs(parent.as_raw_fd(), &mut filesystem) } == 0,
        "public publication filesystem unavailable",
    )?;
    Ok(if filesystem.f_type == 0x4d44 {
        0o600
    } else {
        0o644
    })
}

/// Directory mode synthesized by the same retained public publication volume.
///
/// # Errors
///
/// As [`public_file_mode`].
pub fn public_directory_mode(parent: &File) -> Result<u32> {
    Ok(if public_file_mode(parent)? == 0o600 {
        0o700
    } else {
        0o755
    })
}

/// Publish beneath a retained parent, without reopening any ancestor by name.
///
/// # Errors
///
/// Fails when `mode` is not 0o600, 0o640 or 0o644, `body` exceeds the limit (at most 32 MiB),
/// `name` is not one component, the parent or an existing member is unsafe for `owner`, the caller
/// is not `owner`, or the member changes before the rename. With `replace` unset, an existing
/// member also fails.
pub fn atomic_relative(
    parent: &File,
    name: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<u32>,
    replace: bool,
    limit: usize,
) -> Result<()> {
    atomic_relative_retained(parent, name, body, mode, owner, replace, limit).map(|_| ())
}
/// Return the actual published read-only inode, retaining it across the caller's
/// next boundary. Named and writer descriptors must identify that same inode.
///
/// # Errors
///
/// Fails when `mode` is not 0o600, 0o640 or 0o644, `body` exceeds the limit (at most 32 MiB),
/// `name` is not one component, the parent or an existing member is unsafe for `owner`, the caller
/// is not `owner`, or the member changes before the rename. With `replace` unset, an existing
/// member also fails.
pub fn atomic_relative_retained(
    parent: &File,
    name: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<u32>,
    replace: bool,
    limit: usize,
) -> Result<File> {
    atomic_original(parent, name, body, mode, owner, replace, limit, None)
}
/// Replace only the caller's retained original member, never an adopted name.
///
/// # Errors
///
/// Fails when `mode` is not 0o600, 0o640 or 0o644, `body` exceeds the limit (at most 32 MiB),
/// `name` is not one component, the parent or an existing member is unsafe for `owner`, the caller
/// is not `owner`, or the member changes before the rename. With `replace` unset, an existing
/// member also fails. Fails also when the current member is not `original`.
pub fn atomic_replace_original(
    parent: &File,
    name: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<u32>,
    limit: usize,
    original: &File,
) -> Result<File> {
    atomic_original(parent, name, body, mode, owner, true, limit, Some(original))
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, renameat2, unlinkat)."
)]
#[expect(
    clippy::too_many_arguments,
    reason = "Private core shared by the public atomic publication entry points."
)]
fn atomic_original(
    parent: &File,
    name: &Path,
    body: &[u8],
    mode: u32,
    owner: Option<u32>,
    replace: bool,
    limit: usize,
    original: Option<&File>,
) -> Result<File> {
    require(
        matches!(mode, 0o600 | 0o640 | 0o644) && limit <= 32 * 1024 * 1024 && body.len() <= limit,
        "write bound or mode",
    )?;
    directory_ok(parent, owner)?;
    if let Some(owner) = owner {
        require(
            crate::process_identity::effective_uid() == owner,
            "writer owner mismatch",
        )?;
    }
    require(
        name.components().count() == 1
            && matches!(name.components().next(), Some(Component::Normal(_))),
        "single relative publication name required",
    )?;
    let name =
        CString::new(name.as_os_str().as_bytes()).map_err(|_| Error("invalid filename".into()))?;
    let previous = optional_relative(
        parent,
        Path::new(std::ffi::OsStr::from_bytes(name.as_bytes())),
    )?;
    let before = previous
        .as_ref()
        .map(|file| -> Result<FileIdentity> {
            let m = file.metadata()?;
            require(
                m.nlink() > 0 && m.mode() & 0o022 == 0 && owner.is_none_or(|o| m.uid() == o),
                "unsafe previous atomic publication member",
            )?;
            Ok(identity(&m))
        })
        .transpose()?;
    if let Some(original) = original {
        require(
            before == Some(identity(&original.metadata()?)),
            "atomic replacement original member differs",
        )?;
    }
    let temp = CString::new(format!(".enzimos-write-{}", random_hex(16)?))
        .map_err(|_| Error("invalid generated native name".into()))?;
    let mut file = openat(
        parent.as_raw_fd(),
        std::ffi::OsStr::from_bytes(temp.as_bytes()),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        mode,
    )?;
    let result = (|| {
        require(
            // SAFETY: fchmod takes no pointers and `file` keeps the descriptor open.
            unsafe { libc::fchmod(file.as_raw_fd(), mode) } == 0,
            "set private file mode failed",
        )?;
        file.write_all(body)?;
        file.sync_all()?;
        let current = optional_relative(
            parent,
            Path::new(std::ffi::OsStr::from_bytes(name.as_bytes())),
        )?;
        require(
            current
                .as_ref()
                .map(|f| f.metadata().map(|m| identity(&m)))
                .transpose()?
                == before,
            "atomic publication member changed before rename",
        )?;
        if let Some(original) = original {
            require(
                before == Some(identity(&original.metadata()?)),
                "atomic replacement original inode changed before rename",
            )?;
        }
        // SAFETY: Both names are NUL-terminated CStrings and `parent` keeps the descriptor open.
        let rc = unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                temp.as_ptr(),
                parent.as_raw_fd(),
                name.as_ptr(),
                if replace { 0 } else { libc::RENAME_NOREPLACE },
            )
        };
        require(rc == 0, "atomic publication refused")?;
        parent.sync_all()?;
        let published = openat(
            parent.as_raw_fd(),
            std::ffi::OsStr::from_bytes(name.as_bytes()),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        let written = identity(&file.metadata()?);
        let published_identity = identity(&published.metadata()?);
        require(
            published_identity == written
                && written.2 == body.len() as u64
                && written.7 & 0o7777 == mode
                && written.10 == 1,
            &format!(
                "atomic publication changed after rename: same_identity={} bytes={} expected_bytes={} mode={:o} expected_mode={:o} links={}",
                published_identity == written,
                written.2,
                body.len(),
                written.7 & 0o7777,
                mode,
                written.10
            ),
        )?;
        require(
            crate::mount_identity::id(std::os::fd::AsFd::as_fd(&published), true)?
                == crate::mount_identity::id(std::os::fd::AsFd::as_fd(parent), true)?,
            "atomic publication crosses its retained parent mount",
        )?;
        Ok(published)
    })();
    // A failed write may retire only its own still-named temporary inode.
    if let Ok(Some(named)) = optional_relative(
        parent,
        Path::new(std::ffi::OsStr::from_bytes(temp.as_bytes())),
    ) && matches!((named.metadata(),file.metadata()),(Ok(a),Ok(b)) if identity(&a) == identity(&b))
    {
        // SAFETY: `temp` is a NUL-terminated CString and `parent` keeps the descriptor open.
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), temp.as_ptr(), 0);
        }
    }
    result
}
