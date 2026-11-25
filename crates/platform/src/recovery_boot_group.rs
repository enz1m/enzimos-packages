// SPDX-License-Identifier: MIT
//! Original kernel cgroup for one complete recovery tool and all descendants.
use crate::{Error, Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const PARENT: &str = "/sys/fs/cgroup/enzimos-complete-boot";
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original complete boot cgroup required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn epoch(file: &File) -> Result<(u64, u64, u32, u32, u32, u64)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid(), m.nlink()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, mkdirat, openat).")]
fn directory(parent: &File, name: &str, exclusive: bool) -> Result<File> {
    let name = CString::new(name).map_err(|_| Error("invalid cgroup member name".into()))?;
    // SAFETY: `name` is a NUL-terminated CString and `parent` keeps the descriptor open.
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    require(
        rc == 0
            || (!exclusive && std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST)),
        "complete boot cgroup directory collision/failure",
    )?;
    // SAFETY: `name` is a NUL-terminated CString and `parent` keeps the descriptor open.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(
        fd >= 0,
        "original complete boot cgroup directory unavailable",
    )?;
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    let file = unsafe { File::from_raw_fd(fd) };
    if rc == 0 {
        require(
            // SAFETY: fchmod takes no pointers and `file` keeps the descriptor open.
            unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } == 0,
            "new complete boot cgroup mode failed",
        )?;
    }
    shape(&file)?;
    require(
        mount_identity::id(file.as_fd(), true)? == mount_identity::id(parent.as_fd(), true)?,
        "cgroup directory crossed original hierarchy mount",
    )?;
    Ok(file)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn member(parent: &File, name: &str, write: bool) -> Result<File> {
    let name = CString::new(name).map_err(|_| Error("invalid cgroup member name".into()))?;
    // SAFETY: `name` is a NUL-terminated CString and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if write {
                    libc::O_WRONLY
                } else {
                    libc::O_RDONLY
                },
        )
    };
    require(raw >= 0, "original complete boot cgroup member unavailable")?;
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(raw) })
}
/// A new cgroup for complete-boot tools, with a device policy and kill control.
pub struct Group {
    path: PathBuf,
    parent: File,
    directory: File,
    parent_shape: (u64, u64, u32, u32, u32),
    directory_shape: (u64, u64, u32, u32, u32),
    mount: u64,
    procs: File,
    kill: File,
    events: File,
    epochs: [(u64, u64, u32, u32, u32, u64); 3],
    closed: bool,
    device_policy: File,
    statuses: [i32; 3],
}
impl Group {
    /// Create a uniquely named cgroup below the root of the unified hierarchy.
    ///
    /// # Errors
    ///
    /// Fails unless the caller is Root, when the hierarchy is not writable cgroup v2, the group
    /// already has members, or the device policy cannot be attached.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    pub fn create() -> Result<Self> {
        require(
            crate::process_identity::effective_uid() == 0,
            "Root complete boot cgroup required",
        )?;
        let base = files::directory(Path::new("/sys/fs/cgroup"), Some(0))?;
        // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `fs` is a writable `libc::statfs` and `base` keeps the descriptor open.
            unsafe { libc::fstatfs(base.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x63677270,
            "unified writable recovery cgroup hierarchy required; no execution fallback",
        )?;
        let parent = directory(&base, "enzimos-complete-boot", false)?;
        let parent_shape = shape(&parent)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let leaf = files::random_hex(16)?;
        let directory = directory(&parent, &leaf, true)?;
        let directory_shape = shape(&directory)?;
        let procs = member(&directory, "cgroup.procs", true)?;
        let kill = member(&directory, "cgroup.kill", true)?;
        let events = member(&directory, "cgroup.events", false)?;
        let epochs = [epoch(&procs)?, epoch(&kill)?, epoch(&events)?];
        let statuses = [&procs, &kill, &events].map(|f| crate::files::status_flags(&f));
        require(
            statuses.iter().all(|f| *f >= 0),
            "original cgroup description flags unavailable",
        )?;
        let device_policy = crate::recovery_boot_devices::attach(&directory)?;
        let this = Self {
            path: Path::new(PARENT).join(leaf),
            parent,
            directory,
            parent_shape,
            directory_shape,
            mount,
            procs,
            kill,
            events,
            epochs,
            closed: false,
            device_policy,
            statuses,
        };
        this.recheck()?;
        require(
            !this.populated()?,
            "new complete boot cgroup already populated",
        )?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, fstatfs).")]
    fn recheck_held(&self) -> Result<()> {
        require(
            !self.closed
                && shape(&self.parent)? == self.parent_shape
                && shape(&self.directory)? == self.directory_shape,
            "original held complete boot cgroup changed",
        )?;
        // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `fs` is a writable `libc::statfs` and `self.directory` keeps the descriptor
            // open.
            unsafe { libc::fstatfs(self.directory.as_raw_fd(), &mut fs) } == 0
                && fs.f_type == 0x63677270,
            "original cgroup kernel filesystem changed",
        )?;
        for (index, file) in [&self.procs, &self.kill, &self.events].iter().enumerate() {
            require(
                epoch(file)? == self.epochs[index]
                    && mount_identity::id(file.as_fd(), true)? == self.mount
                    && crate::files::status_flags(&file) == self.statuses[index],
                "original held cgroup member/flags changed",
            )?;
        }
        require(
            // SAFETY: F_GETFD takes no pointers and `self.device_policy` keeps the descriptor open.
            unsafe { libc::fcntl(self.device_policy.as_raw_fd(), libc::F_GETFD) }
                & libc::FD_CLOEXEC
                != 0,
            "original device policy description changed",
        )?;
        Ok(())
    }
    /// Verify the cgroup and its held control files are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when the group was retired, replaced or remounted, or a control file changed.
    pub fn recheck(&self) -> Result<()> {
        self.recheck_held()?;
        require(!self.closed, "complete boot cgroup already retired")?;
        let parent = files::directory(Path::new(PARENT), Some(0))?;
        let named = files::directory_relative(
            &self.parent,
            Path::new(
                self.path
                    .file_name()
                    .ok_or_else(|| Error("missing retained filename".into()))?,
            ),
            Some(0),
        )?;
        require(
            shape(&self.parent)? == self.parent_shape
                && shape(&parent)? == self.parent_shape
                && shape(&self.directory)? == self.directory_shape
                && shape(&named)? == self.directory_shape,
            "original complete boot cgroup replaced or changed",
        )?;
        for file in [
            &self.parent,
            &parent,
            &self.directory,
            &named,
            &self.procs,
            &self.kill,
            &self.events,
        ] {
            require(
                mount_identity::id(file.as_fd(), true)? == self.mount,
                "original complete boot cgroup mount changed",
            )?;
        }
        for (index, name) in ["cgroup.procs", "cgroup.kill", "cgroup.events"]
            .iter()
            .enumerate()
        {
            let current = member(&self.directory, name, index < 2)?;
            require(
                epoch(&current)? == self.epochs[index],
                "original complete boot cgroup member replaced",
            )?;
        }
        Ok(())
    }
    pub(crate) fn procs(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.procs)
    }
    fn populated(&self) -> Result<bool> {
        self.recheck_held()?;
        let mut file = self.events.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        require(bytes.len() <= 4096, "complete boot cgroup events bound")?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error("complete boot cgroup events encoding".into()))?;
        let lines = text
            .lines()
            .filter_map(|line| line.strip_prefix("populated "))
            .collect::<Vec<_>>();
        require(
            lines.len() == 1 && matches!(lines[0], "0" | "1"),
            "complete boot cgroup population unavailable",
        )?;
        Ok(lines[0] == "1")
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (write).")]
    pub(crate) fn kill_and_wait(&self) -> Result<()> {
        self.recheck_held()?;
        if self.populated()? {
            require(
                // SAFETY: The buffer is a 2-byte static literal and `self.kill` keeps the
                // descriptor open.
                unsafe { libc::write(self.kill.as_raw_fd(), b"1\n".as_ptr().cast(), 2) } == 2,
                "complete boot descendant kill failed; original cgroup retained",
            )?;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.populated()? {
            require(
                Instant::now() < deadline,
                "complete boot descendants remain; no completion",
            )?;
            std::thread::sleep(Duration::from_millis(20));
        }
        self.recheck_held()
    }
    /// Kill any remaining members and remove the empty cgroup.
    ///
    /// # Errors
    ///
    /// Fails when the group changed or cannot be emptied or removed.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub fn close(&mut self) -> Result<()> {
        self.kill_and_wait()?;
        self.recheck()?;
        let name = CString::new(
            self.path
                .file_name()
                .ok_or_else(|| Error("missing retained filename".into()))?
                .as_encoded_bytes(),
        )
        .map_err(|_| Error("invalid cgroup filename".into()))?;
        require(
            // SAFETY: `name` is a NUL-terminated CString and `self.parent` keeps the descriptor
            // open.
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                == 0,
            "original empty complete boot cgroup removal failed",
        )?;
        self.closed = true;
        Ok(())
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.kill_and_wait();
        }
    }
}
