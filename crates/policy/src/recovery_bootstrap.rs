// SPDX-License-Identifier: MIT
//! Direct native PID1 bootstrap for a new, initially empty independent RAM root.
use crate::{namespaces, operation};
use enzimos_platform::{Error, Result, files, require};
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};
#[allow(unsafe_code, reason = "Linux syscall ABI (fstat, fstatfs, open).")]
pub(crate) fn direct_ram_pid1() -> Result<()> {
    require(
        std::process::id() == 1 && enzimos_platform::process_identity::effective_uid() == 0,
        "independent recovery requires direct Root PID1",
    )?;
    // SAFETY: The path is a NUL-terminated literal.
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    require(root >= 0, "RAM root unavailable")?;
    // SAFETY: `root` was just returned by open and is owned by nothing else.
    let root = unsafe { std::fs::File::from_raw_fd(root) };
    // SAFETY: `libc::stat` is a plain C struct, for which all-zero bytes are a valid value.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `metadata` is a writable `libc::stat` and `root` keeps the descriptor open.
        unsafe { libc::fstat(root.as_raw_fd(), &mut metadata) } == 0
            && metadata.st_uid == 0
            && metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
            // SAFETY: `filesystem` is a writable `libc::statfs` and `root` keeps the descriptor
            // open.
            && unsafe { libc::fstatfs(root.as_raw_fd(), &mut filesystem) } == 0
            && matches!(filesystem.f_type as u64, 0x01021994 | 0x858458f6),
        "independent RAM root required",
    )?;
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (mount).")]
fn mount(
    source: &str,
    target: &str,
    kind: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    // Existing archive and sysfs mountpoints may be private or read-only. A
    // mount does not require their mode to be 0755. Retain safe Root-owned
    // directories without changing them or following ancestor links.
    direct_ram_pid1()?;
    let path = Path::new(target);
    let directory = match std::fs::symlink_metadata(path) {
        Ok(_) => files::directory(path, Some(0))
            .map_err(|error| Error(format!("independent {kind} mountpoint: {error}")))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            files::ensure_directory(path, 0o755, 0)?
        }
        Err(error) => return Err(error.into()),
    };
    use std::os::unix::fs::MetadataExt;
    require(
        directory.metadata()?.uid() == 0,
        "independent mountpoint owner refused",
    )?;
    let source =
        CString::new(source).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    let target =
        CString::new(target).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    let kind_c =
        CString::new(kind).map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    require(
        // SAFETY: All non-null pointers are NUL-terminated CStrings that outlive the call.
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                kind_c.as_ptr(),
                flags,
                data.as_ref()
                    .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
            )
        } == 0,
        &format!("independent {kind} filesystem mount failed"),
    )
}
/// Set up the independent RAM root as PID 1: mounts, console and limits.
///
/// # Errors
///
/// Fails when the RAM root is missing or unsafe, or a mount or setup step fails.
#[allow(unsafe_code, reason = "Linux syscall ABI (dup2, fchmod, open).")]
pub fn initialize() -> Result<()> {
    direct_ram_pid1()?;
    // Kernel-created rootfs can initially be writable by everyone. Normalize
    // only the proven direct Root PID1 RAM root before guarded path traversal.
    // SAFETY: The path is a NUL-terminated literal.
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    require(root >= 0, "independent RAM root unavailable")?;
    // SAFETY: `root` was just returned by open and is owned by nothing else.
    let root = unsafe { std::fs::File::from_raw_fd(root) };
    require(
        // SAFETY: fchmod takes no pointers and `root` keeps the descriptor open.
        unsafe { libc::fchmod(root.as_raw_fd(), 0o755) } == 0,
        "independent RAM root permissions refused",
    )?;
    if Path::new("/proc/self/stat").exists() {
        namespaces::initial()?;
    }
    let restricted = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    mount("proc", "/proc", "proc", restricted, None)?;
    mount("sysfs", "/sys", "sysfs", restricted, None)?;
    mount("cgroup2", "/sys/fs/cgroup", "cgroup2", restricted, None)?;
    mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        libc::MS_NOSUID,
        Some("mode=0755"),
    )?;
    mount(
        "tmpfs",
        "/run",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("mode=0755"),
    )?;
    namespaces::initial()?;
    require(
        std::fs::read_dir("/proc/self/task")?.count() == 1,
        "single-task independent PID1 required",
    )?;
    // SAFETY: The path is a NUL-terminated literal.
    let console = unsafe { libc::open(c"/dev/console".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    require(console >= 0, "recovery console unavailable")?;
    // SAFETY: `console` was just returned by open and is owned by nothing else.
    let console = unsafe { std::fs::File::from_raw_fd(console) };
    for fd in [0, 1, 2] {
        require(
            // SAFETY: dup2 takes no pointers and `console` keeps the source open.
            unsafe { libc::dup2(console.as_raw_fd(), fd) } == fd,
            "recovery console setup failed",
        )?;
    }
    if Path::new("/sys/firmware/efi").is_dir() {
        mount(
            "efivarfs",
            "/sys/firmware/efi/efivars",
            "efivarfs",
            restricted | libc::MS_RDONLY,
            None,
        )?;
    }
    let machine = std::env::consts::ARCH;
    require(
        machine == "x86_64",
        "qualified recovery architecture required",
    )?;
    operation::boot_id()?;
    Ok(())
}
/// Sync and power off.
///
/// # Errors
///
/// As [`reboot`].
pub fn power_off() -> Result<()> {
    reboot(true)
}
/// Sync and boot the loaded recovery kernel.
///
/// # Errors
///
/// Fails when the kernel declines the handoff.
#[allow(unsafe_code, reason = "Linux syscall ABI (reboot, sync).")]
pub fn handoff_reboot() -> Result<()> {
    quiet()?;
    // SAFETY: sync takes no arguments and cannot fail.
    unsafe { libc::sync() };
    require(
        // SAFETY: reboot with RB_KEXEC takes no pointers.
        unsafe { libc::reboot(libc::RB_KEXEC) } == 0,
        "kernel declined loaded recovery handoff",
    )
}
/// Sync and reboot, or power off when `poweroff` is set.
///
/// # Errors
///
/// Fails when the kernel refuses.
#[allow(unsafe_code, reason = "Linux syscall ABI (reboot, sync).")]
pub fn reboot(poweroff: bool) -> Result<()> {
    direct_ram_pid1()?;
    namespaces::initial()?;
    // SAFETY: sync takes no arguments and cannot fail.
    unsafe { libc::sync() };
    // SAFETY: reboot takes no pointers.
    let result = unsafe {
        libc::reboot(if poweroff {
            libc::RB_POWER_OFF
        } else {
            libc::RB_AUTOBOOT
        })
    };
    if result != 0 {
        return Err(Error("kernel refused independent recovery poweroff".into()));
    }
    Ok(())
}
/// Before storage exposure, no other userspace task may own devices or mounts.
pub(crate) fn quiet() -> Result<()> {
    direct_ram_pid1()?;
    namespaces::initial()?;
    require(
        std::fs::read_dir("/proc/self/task")?.count() == 1,
        "single-task recovery PID1 required",
    )?;
    let mut count = 0;
    for row in std::fs::read_dir("/proc")? {
        let row = row?;
        let name = row.file_name();
        let name = name.to_string_lossy();
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        count += 1;
        require(count <= 16384, "recovery process count bound")?;
        let body = files::read_kernel(&row.path().join("stat"), 8192)?;
        let body =
            std::str::from_utf8(&body).map_err(|_| Error("kernel process stat encoding".into()))?;
        let tail = body
            .rsplit_once(") ")
            .ok_or_else(|| Error("kernel process stat".into()))?
            .1;
        let flags = tail
            .split_whitespace()
            .nth(6)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| Error("kernel process flags".into()))?;
        require(
            flags & 0x00200000 != 0 || name == "1",
            "other userspace prevents independent recovery",
        )?;
    }
    namespaces::initial()?;
    Ok(())
}
