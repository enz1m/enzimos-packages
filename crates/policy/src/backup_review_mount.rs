// SPDX-License-Identifier: MIT
//! A private, detached, exclusively created read-only filesystem instance.
//! No mount path, descriptor export, adoption, remount or lazy unmount fallback.
use crate::{backup_candidates::Selection, filesystem, topology};
use enzimos_platform::{Error, Result, files, mount_identity, require, stream_copy};
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::{Duration, Instant},
};
const ATTRIBUTES: u32 = 1 | 2 | 4 | 8; // mount.h READONLY|NOSUID|NODEV|NOEXEC
const GET_SUBVOL_INFO: libc::c_ulong = 0x81f8943c; // Btrfs UAPI, 504 bytes
#[allow(
    unsafe_code,
    reason = "Transfers an acquired native descriptor into Rust ownership."
)]
fn descriptor(raw: libc::c_long) -> Result<File> {
    if raw < 0 {
        return Err(Error(
            "exclusive read-only filesystem operation refused".into(),
        ));
    }
    // SAFETY: Callers pass a descriptor-returning syscall result; nonnegative values are fresh and
    // owned by nothing else.
    Ok(unsafe { File::from_raw_fd(raw as i32) })
}
#[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
fn configure(file: &File, command: u32, key: Option<&CStr>, value: Option<&CStr>) -> Result<()> {
    let null = std::ptr::null::<libc::c_char>();
    require(
        // SAFETY: The key and value are NUL-terminated or null as fsconfig allows, and `file` stays
        // open.
        unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                file.as_raw_fd(),
                command,
                key.map_or(null, CStr::as_ptr),
                value.map_or(null, CStr::as_ptr),
                0i32,
            )
        } == 0,
        "exclusive read-only filesystem configuration refused",
    )
}
fn absent(uuid: &str) -> Result<bool> {
    crate::identity::uuid(uuid)?;
    // An absent leaf is the only accepted absence. Missing/unsafe kernel parent fails.
    let _parent = files::directory(Path::new("/sys/fs/btrfs"), Some(0))?;
    match std::fs::symlink_metadata(Path::new("/sys/fs/btrfs").join(uuid)) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
pub(crate) fn wait_closed(uuid: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if absent(uuid)? {
            return Ok(());
        }
        require(
            Instant::now() < deadline,
            "owned filesystem remains referenced; intent requires inspection",
        )?;
        std::thread::sleep(Duration::from_millis(20));
    }
}
pub(crate) fn repository_metadata(root: &File, unique: u64, owner: u32) -> Result<Value> {
    require(
        root.metadata()?.uid() == owner
            && root.metadata()?.mode() & 0o022 == 0
            && mount_identity::id(root.as_fd(), true)? == unique,
        "original protected repository root required",
    )?;
    let Some(repository) =
        files::optional_directory_relative(root, Path::new("restic"), Some(owner))?
    else {
        return Ok(json!({"state":"absent","configuration_sha256":null}));
    };
    require(
        repository.metadata()?.uid() == owner
            && mount_identity::id(repository.as_fd(), true)? == unique,
        "protected original review repository required",
    )?;
    if files::directory_is_empty(&repository)? {
        return Ok(json!({"state":"empty","configuration_sha256":null}));
    }
    let config = files::open_relative(&repository, Path::new("config"))?;
    let before = files::identity(&config.metadata()?);
    require(
        config.metadata()?.uid() == owner
            && config.metadata()?.mode() & 0o022 == 0
            && config.metadata()?.nlink() == 1
            && mount_identity::id(config.as_fd(), true)? == unique,
        "protected encrypted repository configuration required",
    )?;
    let (length, digest) = stream_copy::hash_borrowed(&config, 1024 * 1024, Some(owner))?;
    require(
        length > 0 && files::identity(&config.metadata()?) == before,
        "repository configuration empty or changed",
    )?;
    let named = files::open_relative(&repository, Path::new("config"))?;
    let current = files::directory_relative(root, Path::new("restic"), Some(owner))?;
    require(
        files::identity(&named.metadata()?) == before
            && (current.metadata()?.dev(), current.metadata()?.ino())
                == (repository.metadata()?.dev(), repository.metadata()?.ino())
            && mount_identity::id(current.as_fd(), true)? == unique,
        "repository metadata original inode changed",
    )?;
    Ok(json!({"state":"existing","configuration_sha256":digest}))
}
fn protection(flags: libc::c_ulong, tree: u64, inode: u64) -> Result<()> {
    let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    require(
        flags & required == required && tree == 5 && inode == 256,
        "whole read-only protected Btrfs top level required",
    )
}
pub(crate) struct Mount {
    root: Option<File>,
    mount: Option<File>,
    unique: u64,
    uuid: String,
    filesystem: Value,
}
impl Mount {
    /// The caller must durably persist its prepared intent and recheck authorization
    /// immediately before invoking this private constructor.
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat, syscall).")]
    pub(crate) fn create(
        selection: &Selection<'_>,
        preflight: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        crate::storage_runtime::initial_namespace()?;
        selection.recheck()?;
        let device = selection.descriptor()?;
        require(
            absent(selection.uuid_hint())?,
            "existing filesystem instance requires review",
        )?;
        let context =
            // SAFETY: The filesystem name is a NUL-terminated literal.
            descriptor(unsafe { libc::syscall(libc::SYS_fsopen, c"btrfs".as_ptr(), 1u32) })?;
        let source = CString::new(format!("/proc/self/fd/{}", device.as_raw_fd())).unwrap();
        configure(&context, 1, Some(c"source"), Some(&source))?;
        configure(&context, 0, Some(c"ro"), None)?;
        configure(&context, 1, Some(c"rescue"), Some(c"nologreplay"))?;
        configure(&context, 1, Some(c"subvolid"), Some(c"5"))?;
        // CREATE_EXCL, Linux >=6.6: never reuse an extant superblock whose options
        // could silently ignore our nologreplay request. No older-kernel fallback.
        preflight()?;
        configure(&context, 8, None, None)?;
        preflight()?;
        // SAFETY: fsmount takes no pointers and `context` keeps the descriptor open.
        let mount = descriptor(unsafe {
            libc::syscall(libc::SYS_fsmount, context.as_raw_fd(), 1u32, ATTRIBUTES)
        })?;
        // fsmount leaves a reconfiguration context referencing the instance.
        // Retaining it would prevent proven closure and expose remount authority.
        drop(context);
        // SAFETY: The name is a NUL-terminated literal and `mount` keeps the descriptor open.
        let root = descriptor(libc::c_long::from(unsafe {
            libc::openat(
                mount.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        }))?;
        let unique = mount_identity::id(root.as_fd(), true)?;
        let filesystem = filesystem::observe(root.as_fd())?;
        let this = Self {
            root: Some(root),
            mount: Some(mount),
            unique,
            uuid: selection.uuid_hint().into(),
            filesystem,
        };
        this.recheck(selection)?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs, ioctl).")]
    pub(crate) fn recheck(&self, selection: &Selection<'_>) -> Result<()> {
        selection.recheck()?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| Error("closed review scope".into()))?;
        let mount = self
            .mount
            .as_ref()
            .ok_or_else(|| Error("closed review mount".into()))?;
        // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
        let mut info = [0u64; 63];
        require(
            // SAFETY: `status` is a writable `libc::statvfs` and `root` keeps the descriptor open.
            unsafe { libc::fstatvfs(root.as_raw_fd(), &mut status) } == 0
                // SAFETY: `info` is 504 bytes, the size encoded in GET_SUBVOL_INFO, and `root`
                // stays open.
                && unsafe { libc::ioctl(root.as_raw_fd(), GET_SUBVOL_INFO, info.as_mut_ptr()) }
                    == 0,
            "review filesystem protection unavailable",
        )?;
        protection(status.f_flag, info[0], root.metadata()?.ino())?;
        let evidence = selection.evidence()?;
        let major = evidence["device"]["major"]
            .as_u64()
            .ok_or_else(|| Error("selected device major required".into()))?;
        let minor = evidence["device"]["minor"]
            .as_u64()
            .ok_or_else(|| Error("selected device minor required".into()))?;
        let member = (
            u32::try_from(major).map_err(|_| Error("selected major overflow".into()))?,
            u32::try_from(minor).map_err(|_| Error("selected minor overflow".into()))?,
        );
        require(
            mount_identity::id(root.as_fd(), true)? == self.unique
                && mount_identity::id(mount.as_fd(), true)? == self.unique
                && filesystem::observe(root.as_fd())? == self.filesystem
                && self.filesystem["filesystem_uuid"] == self.uuid
                && self.filesystem["members"] == 1
                && topology::btrfs_roots(&self.uuid)? == vec![member]
                && topology::mounted_btrfs(&self.uuid)?.json() == evidence["topology"],
            "review filesystem membership or original mount changed",
        )?;
        selection.recheck()
    }
    pub(crate) fn repository(&self) -> Result<Value> {
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| Error("closed review root".into()))?;
        repository_metadata(root, self.unique, 0)
    }
    /// Dropping an O_PATH mount FD alone is not evidence of kernel scope closure.
    /// Consume every owned directory/mount reference, then require the exclusively
    /// created filesystem's kernel registration to disappear within a fixed bound.
    pub(crate) fn close(mut self) -> Result<()> {
        drop(self.root.take());
        drop(self.mount.take());
        wait_closed(&self.uuid)
    }
}
