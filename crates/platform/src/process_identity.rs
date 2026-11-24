// SPDX-License-Identifier: MIT
//! pidfds bind a sampled task; executable identity comes from an owned fixed file.
use crate::{Error, Result, files, require};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub pid: u32,
    pub parent: u32,
    pub start_ticks: u64,
    pub state: char,
}
pub fn parse_stat(body: &str, expected: u32) -> Result<Stat> {
    parse_stat_inner(body, expected, false)
}
/// Kernel tasks created at boot can legitimately have zero start ticks. Only
/// the kernel PF_KTHREAD bit permits that exception; ordinary callers keep the
/// existing stricter admission. This parses an observation, not a task actor.
pub fn parse_kernel_stat(body: &str, expected: u32) -> Result<Stat> {
    parse_stat_inner(body, expected, true)
}
fn parse_stat_inner(body: &str, expected: u32, kernel: bool) -> Result<Stat> {
    require(
        body.len() <= 8192 && !body.contains('\0'),
        "process stat bound",
    )?;
    let begin = body
        .find('(')
        .ok_or_else(|| Error("process stat shape".into()))?;
    let end = body
        .rfind(')')
        .ok_or_else(|| Error("process stat shape".into()))?;
    require(begin < end, "process stat shape")?;
    let pid = body[..begin]
        .trim()
        .parse::<u32>()
        .map_err(|_| Error("process stat PID".into()))?;
    require(
        pid == expected && pid > 0 && pid < i32::MAX as u32,
        "process stat PID mismatch",
    )?;
    let fields = body[end + 1..].split_whitespace().collect::<Vec<_>>();
    require(
        fields.len() >= 20 && fields.len() <= 64 && fields[0].len() == 1,
        "process stat fields",
    )?;
    let parent = fields[1]
        .parse()
        .map_err(|_| Error("process parent identity".into()))?;
    let start_ticks = fields[19]
        .parse()
        .map_err(|_| Error("process start identity".into()))?;
    if kernel {
        let flags = fields[6]
            .parse::<u64>()
            .map_err(|_| Error("kernel process flags".into()))?;
        require(flags & 0x0020_0000 != 0, "actual kernel task flag required")?;
    }
    require(
        start_ticks > 0 || pid == 1 || kernel,
        "process start identity",
    )?;
    let state = fields[0]
        .chars()
        .next()
        .ok_or_else(|| Error("missing process state".into()))?;
    require("RSDZTtXxKWPI".contains(state), "process stat state")?;
    Ok(Stat {
        pid,
        parent,
        start_ticks,
        state,
    })
}
pub fn parse_uids(body: &str) -> Result<[u32; 4]> {
    require(
        body.len() <= 65536 && !body.contains('\0'),
        "process status bound",
    )?;
    let rows = body
        .lines()
        .filter_map(|s| s.strip_prefix("Uid:"))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "process UID fields")?;
    let values = rows[0]
        .split_whitespace()
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| Error("process UID fields".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    values
        .try_into()
        .map_err(|_| Error("process UID fields".into()))
}
fn executable(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn image(m: &std::fs::Metadata) -> (u64, u64, u64, u32, u32, u32, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
    )
}
fn pinned_bytes(file: &File, owner: u32) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    require(
        before.is_file()
            && before.uid() == owner
            && before.mode() & 0o022 == 0
            && before.mode() & 0o111 != 0
            && before.nlink() <= 1
            && (4..=32 * 1024 * 1024).contains(&before.len()),
        "retained Root executable authority changed",
    )?;
    let mut bytes = vec![0u8; before.len() as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file.read_at(&mut bytes[offset..], offset as u64)?;
        require(count > 0, "retained Root executable truncated")?;
        offset += count;
    }
    let after = file.metadata()?;
    // Replacing an executing ELF's name changes link count and ctime, not its image.
    require(
        image(&before) == image(&after) && after.nlink() <= 1 && bytes.starts_with(b"\x7fELF"),
        "retained Root executable image changed",
    )?;
    Ok(bytes)
}
/// A pinned executable image and the digest of its bytes at pin time.
struct Pinned {
    file: File,
    sha: String,
    /// The inode identity at the last full readback that matched `sha`.
    verified: std::sync::Mutex<Option<files::FileIdentity>>,
}
impl Pinned {
    fn new(file: File, sha: String) -> Self {
        Self {
            file,
            sha,
            verified: std::sync::Mutex::new(None),
        }
    }
    /// The image still holds the pinned bytes. Bytes are read back only when
    /// the inode's identity differs from the last verified one: any change of
    /// its data advances ctime, which userspace cannot set, so an identical
    /// identity (including ctime and link count) proves the bytes unchanged.
    fn verify(&self, owner: u32) -> Result<std::fs::Metadata> {
        let metadata = self.file.metadata()?;
        require(
            metadata.uid() == owner
                && metadata.mode() & 0o022 == 0
                && metadata.mode() & 0o111 != 0
                && metadata.nlink() <= 1,
            "retained Root executable authority changed",
        )?;
        let mut verified = self
            .verified
            .lock()
            .map_err(|_| Error("retained Root executable verification poisoned".into()))?;
        if *verified != Some(files::identity(&metadata)) {
            *verified = None;
            let bytes = pinned_bytes(&self.file, owner)?;
            require(
                crate::json::sha256(&bytes) == self.sha,
                "retained Root executable bytes changed",
            )?;
            let after = self.file.metadata()?;
            require(
                files::identity(&after) == files::identity(&metadata),
                "retained Root executable changed during verification",
            )?;
            *verified = Some(files::identity(&after));
        }
        Ok(metadata)
    }
    fn duplicate(&self) -> Result<Self> {
        Ok(Self::new(self.file.try_clone()?, self.sha.clone()))
    }
}
pub struct Retained {
    pub stat: Stat,
    uid: u32,
    pidfd: File,
    fixed: Vec<PathBuf>,
    pinned: Option<Pinned>,
}
impl Retained {
    /// Root handoff must preserve the caller's actual open description, not just an inode.
    pub fn require_description(
        &self,
        file: std::os::fd::BorrowedFd<'_>,
        descriptor: u32,
    ) -> Result<()> {
        self.require_descriptions(&[(file, descriptor)])
    }
    /// Check a bounded handoff as one observation. Full executable and credential
    /// measurements bracket the batch; each KCMP retains its own original-task
    /// liveness checks. No descriptor is admitted by inode or numeric PID alone.
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, syscall).")]
    pub fn require_descriptions(
        &self,
        descriptions: &[(std::os::fd::BorrowedFd<'_>, u32)],
    ) -> Result<()> {
        require(
            unsafe { libc::geteuid() } == 0
                && self.uid == 0
                && !descriptions.is_empty()
                && descriptions.len() <= 64
                && descriptions.iter().all(|(_, number)| *number < 1_048_576),
            "Root retained descriptor authority required",
        )?;
        self.recheck()?;
        for (file, descriptor) in descriptions {
            require(!self.exited()?, "original description actor exited")?;
            require(
                unsafe {
                    libc::syscall(
                        libc::SYS_kcmp,
                        std::process::id(),
                        self.stat.pid,
                        0,
                        file.as_raw_fd() as usize,
                        *descriptor as usize,
                    )
                } == 0,
                "caller open-description identity unavailable or changed",
            )?;
            require(!self.exited()?, "original description actor exited")?;
        }
        self.recheck()
    }
    /// Borrow the retained task handle for an event-loop readiness watch only.
    pub fn pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.pidfd.as_fd()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    pub(crate) fn duplicate_root(&self) -> Result<Self> {
        require(
            unsafe { libc::geteuid() } == 0 && self.uid == 0,
            "original Root process required",
        )?;
        self.recheck()?;
        Ok(Self {
            stat: self.stat.clone(),
            uid: self.uid,
            pidfd: self.pidfd.try_clone()?,
            fixed: self.fixed.clone(),
            pinned: self.pinned.as_ref().map(Pinned::duplicate).transpose()?,
        })
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    pub(crate) fn root_image_binding(&self) -> Result<(PathBuf, String)> {
        require(
            unsafe { libc::geteuid() } == 0 && self.uid == 0 && self.fixed.len() == 1,
            "single original Root image required",
        )?;
        self.recheck()?;
        let pinned = self
            .pinned
            .as_ref()
            .ok_or_else(|| Error("original pinned Root image required".into()))?;
        Ok((self.fixed[0].clone(), pinned.sha.clone()))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    pub fn open(pid: u32, start: u64, uid: u32, executables: &[PathBuf]) -> Result<Self> {
        require(
            pid > 0
                && pid < i32::MAX as u32
                && (start > 0 || (pid == 1 && uid == 0))
                && (uid == 0 || (1000..u32::MAX).contains(&uid))
                && !executables.is_empty()
                && executables.len() <= 8,
            "process binding bounds",
        )?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        require(fd >= 0, "process disappeared or pidfd unavailable")?;
        let pidfd = unsafe { File::from_raw_fd(fd) };
        let stat = Self::observe(pid, uid, executables)?;
        require(stat.start_ticks == start, "process identity changed")?;
        let retained = Self {
            stat,
            uid,
            pidfd,
            fixed: executables.into(),
            pinned: None,
        };
        retained.recheck()?;
        Ok(retained)
    }
    fn observe(pid: u32, uid: u32, fixed: &[PathBuf]) -> Result<Stat> {
        Self::observe_with_image(pid, uid, fixed, None)
    }
    /// Pin a freshly admitted Root image before package mutation can replace its name.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, geteuid).")]
    pub fn pin_executable(mut self, file: &File) -> Result<Self> {
        require(
            unsafe { libc::geteuid() } == 0 && self.uid == 0 && self.pinned.is_none(),
            "fresh Root executable pin required",
        )?;
        self.recheck()?;
        let metadata = file.metadata()?;
        require(
            metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && metadata.mode() & 0o111 != 0
                && metadata.nlink() == 1
                && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                    == libc::O_RDONLY,
            "Root executable pin authority refused",
        )?;
        let bytes = files::read_file(file, 32 * 1024 * 1024, Some(0), true)?;
        require(
            bytes.starts_with(b"\x7fELF"),
            "native Root executable pin required",
        )?;
        self.pinned = Some(Pinned::new(file.try_clone()?, crate::json::sha256(&bytes)));
        self.recheck()?;
        Ok(self)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
    fn observe_with_image(
        pid: u32,
        uid: u32,
        fixed: &[PathBuf],
        pinned: Option<&Pinned>,
    ) -> Result<Stat> {
        let root = PathBuf::from(format!("/proc/{pid}"));
        let read = |name: &str, bound| -> Result<String> {
            String::from_utf8(files::read_kernel_owned(&root.join(name), bound, uid)?)
                .map_err(|_| Error("process observation encoding".into()))
        };
        let first = parse_stat(&read("stat", 8192)?, pid)?;
        require(!matches!(first.state, 'Z' | 'X' | 'x'), "process exited")?;
        let uids = parse_uids(&read("status", 65536)?)?;
        require(
            uids.iter().all(|u| *u == uids[0]) && (uids[0] == 0 || uids[0] == uid),
            "process UID changed",
        )?;
        let directory = files::directory(&root, Some(uid))?;
        // Only this kernel-created symlink is followed. Fixed executable paths
        // are walked without symlinks and remain Root-owned and nonwritable.
        let name = c"exe";
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "process executable unavailable")?;
        let held = unsafe { File::from_raw_fd(fd) };
        let actual = held.metadata()?;
        let mut admitted = false;
        if let Some(pinned) = pinned {
            let metadata = pinned.verify(0)?;
            admitted = image(&actual) == image(&metadata);
        }
        for path in fixed.iter().filter(|_| pinned.is_none()) {
            match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
                Ok(_) => {}
            }
            let parent = files::directory(
                path.parent()
                    .ok_or_else(|| Error("fixed executable parent".into()))?,
                Some(0),
            )?;
            let file = files::open_relative(
                &parent,
                Path::new(
                    path.file_name()
                        .ok_or_else(|| Error("fixed executable name".into()))?,
                ),
            )?;
            let m = file.metadata()?;
            require(
                m.uid() == 0 && m.mode() & 0o022 == 0,
                "unsafe fixed executable",
            )?;
            if executable(&actual) == executable(&m) {
                admitted = true;
            }
        }
        require(admitted, "process executable changed")?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "process executable unavailable")?;
        let last_exe = unsafe { File::from_raw_fd(fd) };
        require(
            (if pinned.is_some() {
                image(&last_exe.metadata()?) == image(&actual)
            } else {
                executable(&last_exe.metadata()?) == executable(&actual)
            }) && parse_uids(&read("status", 65536)?)? == uids,
            "process credentials or executable changed",
        )?;
        let last = parse_stat(&read("stat", 8192)?, pid)?;
        require(
            (first.pid, first.parent, first.start_ticks)
                == (last.pid, last.parent, last.start_ticks),
            "process changed during observation",
        )?;
        Ok(last)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    pub fn exited(&self) -> Result<bool> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        require(
            result >= 0 && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "retained process observation unavailable",
        )?;
        Ok(result > 0)
    }
    pub fn recheck(&self) -> Result<()> {
        require(!self.exited()?, "retained process exited")?;
        let current =
            Self::observe_with_image(self.stat.pid, self.uid, &self.fixed, self.pinned.as_ref())?;
        require(
            current.start_ticks == self.stat.start_ticks,
            "retained process changed",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    pub fn terminate<F: FnOnce() -> Result<()>>(&self, fresh_authority: F) -> Result<()> {
        require(
            self.stat.pid > 1,
            "initial system manager cannot be signalled through task retention",
        )?;
        fresh_authority()?;
        self.recheck()?;
        require(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGTERM,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            } == 0,
            "owned process signal outcome requires review",
        )
    }
}
pub fn parse_pidfd_mapping(body: &str) -> Result<Option<u32>> {
    require(
        body.len() <= 8192 && !body.contains('\0'),
        "pidfd information bound",
    )?;
    let values = |key: &str| -> Result<Vec<i64>> {
        let rows = body
            .lines()
            .filter_map(|line| line.strip_prefix(key))
            .collect::<Vec<_>>();
        require(rows.len() == 1, "pidfd target field missing or duplicated")?;
        let fields = rows[0].split_whitespace().collect::<Vec<_>>();
        require(
            !fields.is_empty() && fields.len() <= 33,
            "pidfd namespace hierarchy bound",
        )?;
        fields
            .into_iter()
            .map(|text| {
                require(
                    text == "-1" || text.bytes().all(|b| b.is_ascii_digit()),
                    "pidfd target encoding",
                )?;
                let pid = text
                    .parse::<i64>()
                    .map_err(|_| Error("pidfd target unavailable".into()))?;
                require(
                    pid == -1 || (pid > 0 && pid < i64::from(i32::MAX)),
                    "pidfd target exited or invalid",
                )?;
                Ok(pid)
            })
            .collect()
    };
    let pids = values("Pid:")?;
    require(pids.len() == 1, "single procfs pidfd target required")?;
    let pid = pids[0];
    let hierarchy = values("NSpid:")?;
    // Kernel fdinfo starts in the procfs namespace; later IDs name descendants.
    require(hierarchy[0] == pid, "pidfd namespace target differs")?;
    require(
        (pid == -1 && hierarchy.len() == 1)
            || (pid > 0 && hierarchy.iter().all(|&value| value > 0)),
        "pidfd namespace target exited or invalid",
    )?;
    Ok((pid != -1).then_some(pid as u32))
}
pub fn parse_pidfd_info(body: &str) -> Result<u32> {
    parse_pidfd_mapping(body)?.ok_or_else(|| Error("pidfd target exited or invalid".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn pidfd_mapping(fd: std::os::fd::BorrowedFd<'_>) -> Result<Option<u32>> {
    let path = PathBuf::from(format!(
        "/proc/{}/fdinfo/{}",
        std::process::id(),
        fd.as_raw_fd()
    ));
    let body = files::read_kernel_owned(&path, 8192, unsafe { libc::geteuid() })?;
    parse_pidfd_mapping(
        std::str::from_utf8(&body).map_err(|_| Error("pidfd target encoding".into()))?,
    )
}
pub fn pidfd_target(fd: std::os::fd::BorrowedFd<'_>) -> Result<u32> {
    pidfd_mapping(fd)?.ok_or_else(|| Error("pidfd target exited or invalid".into()))
}

#[cfg(test)]
mod pinned_tests {
    use super::*;
    use std::os::unix::fs::{FileExt, PermissionsExt};

    fn image(directory: &Path, bytes: &[u8]) -> (PathBuf, Pinned) {
        let path = directory.join("image");
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = File::open(&path).unwrap();
        (path, Pinned::new(file, crate::json::sha256(bytes)))
    }
    fn directory() -> tempfile::TempDir {
        let base =
            std::env::var_os("ENZIMOS_TEST_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        tempfile::tempdir_in(base).unwrap()
    }
    fn owner() -> u32 {
        // SAFETY: geteuid has no preconditions.
        #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
        unsafe {
            libc::geteuid()
        }
    }

    #[test]
    fn an_in_place_write_of_the_same_size_is_caught_after_a_verified_check() {
        let directory = directory();
        let (path, pinned) = image(directory.path(), b"\x7fELF original image");
        pinned.verify(owner()).unwrap();
        // ctime has at least the kernel's timestamp granularity; wait it out
        // so the write below cannot land in the same tick as the first check.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all_at(b"altered", 5).unwrap();
        drop(writer);
        assert!(pinned.verify(owner()).is_err());
        assert!(pinned.verified.lock().unwrap().is_none());
    }
}
