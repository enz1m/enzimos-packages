// SPDX-License-Identifier: MIT
//! Retain the original launcher and the exact agent in its private process group.
use enzimos_platform::{Result, files, process_identity, require};
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
pub(crate) struct Owner {
    child: Child,
    pidfd: Option<File>,
    leader: File,
    image: File,
    owner: u32,
    task: u32,
    root: Option<process_identity::Retained>,
    reaped: bool,
}
impl Owner {
    #[allow(unsafe_code, reason = "Fork-child setup must run before exec.")]
    pub(crate) fn start(home: &Path, owner: u32) -> Result<Self> {
        require(
            enzimos_platform::process_identity::effective_uid() == owner,
            "development agent owner mismatch",
        )?;
        let parent = files::directory(Path::new("/usr/bin"), Some(0))?;
        let image = files::open_relative(&parent, Path::new("gpg-agent"))?;
        require(
            image.metadata()?.mode() & 0o111 != 0
                && files::read_file(&image, 32 * 1024 * 1024, Some(0), true)?
                    .starts_with(b"\x7fELF"),
            "development agent fixed native image required",
        )?;
        // SAFETY: F_DUPFD_CLOEXEC takes no pointers and `image` keeps the descriptor open.
        let alias = unsafe { libc::fcntl(image.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        require(alias >= 0, "development agent image duplication failed")?;
        // SAFETY: `alias` is a fresh duplicate owned by nothing else.
        let alias = unsafe { OwnedFd::from_raw_fd(alias) };
        let mut command = Command::new(format!("/proc/self/fd/{}", alias.as_raw_fd()));
        command
            .arg0("/usr/bin/gpg-agent")
            .args([
                "--no-options",
                "--homedir",
                home.to_str()
                    .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
                "--daemon",
                "--no-detach",
                "--disable-scdaemon",
                "--no-allow-external-cache",
                "--default-cache-ttl",
                "1",
                "--max-cache-ttl",
                "1",
            ])
            .env_clear()
            .env("PATH", "/usr/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let caller = std::process::id() as libc::pid_t;
        // SAFETY: The pre_exec closure only calls prctl, getppid and setsid, which are
        // async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != caller
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        // SAFETY: pidfd_open takes no pointers.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) as i32 };
        if raw < 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(enzimos_platform::Error(
                "development agent pidfd unavailable".into(),
            ));
        }
        let this = Self {
            child,
            pidfd: None,
            // SAFETY: `raw` was just returned by pidfd_open and is owned by nothing else.
            leader: unsafe { File::from_raw_fd(raw) },
            image,
            owner,
            task: 0,
            root: None,
            reaped: false,
        };
        this.recheck()?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (getpgid, syscall).")]
    pub(crate) fn bind(&mut self, pid: u32) -> Result<()> {
        require(
            self.pidfd.is_none()
                && pid > 1
                // SAFETY: getpgid takes no pointers.
                && unsafe { libc::getpgid(pid as i32) } == self.child.id() as i32,
            "development daemon must belong to original launcher's private process group",
        )?;
        // SAFETY: pidfd_open takes no pointers.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
        require(raw >= 0, "development daemon pidfd unavailable")?;
        // SAFETY: `raw` was just returned by pidfd_open and is owned by nothing else.
        self.pidfd = Some(unsafe { File::from_raw_fd(raw) });
        self.task = pid;
        if self.owner == 0 {
            let stat = files::read_kernel_owned(
                &Path::new("/proc").join(pid.to_string()).join("stat"),
                8192,
                0,
            )?;
            let stat = process_identity::parse_stat(
                std::str::from_utf8(&stat).map_err(|_| {
                    enzimos_platform::Error("development agent stat encoding".into())
                })?,
                pid,
            )?;
            let actor = process_identity::Retained::open(
                stat.pid,
                stat.start_ticks,
                0,
                &[PathBuf::from("/usr/bin/gpg-agent")],
            )?
            .pin_executable(&self.image)?;
            self.root_scope(pid)?;
            self.root = Some(actor);
        }
        self.recheck()
    }
    fn root_scope(&self, pid: u32) -> Result<()> {
        let root = Path::new("/proc").join(pid.to_string());
        require(
            files::read_kernel_owned(&root.join("cgroup"), 65536, 0)?
                == files::read_kernel(
                    &Path::new("/proc")
                        .join(std::process::id().to_string())
                        .join("cgroup"),
                    65536,
                )?,
            "development agent escaped original worker cgroup",
        )?;
        for namespace in ["cgroup", "ipc", "mnt", "net", "pid", "user", "uts"] {
            let a = std::fs::metadata(root.join("ns").join(namespace))?;
            let b = std::fs::metadata(Path::new("/proc/self/ns").join(namespace))?;
            require(
                (a.dev(), a.ino()) == (b.dev(), b.ino()),
                "development agent namespaces differ",
            )?;
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    pub(crate) fn exited(&self) -> Result<bool> {
        let mut poll = libc::pollfd {
            fd: self
                .pidfd
                .as_ref()
                .ok_or_else(|| {
                    enzimos_platform::Error("development agent not yet measured".into())
                })?
                .as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` is one writable pollfd and the count is 1.
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        require(
            result >= 0 && poll.revents & (libc::POLLERR | libc::POLLNVAL) == 0,
            "development agent pidfd observation",
        )?;
        Ok(result > 0)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (getpgid).")]
    pub(crate) fn recheck(&self) -> Result<()> {
        require(
            !self.reaped && (self.pidfd.is_none() || !self.exited()?),
            "original development agent exited",
        )?;
        if self.pidfd.is_some() {
            require(
                // SAFETY: getpgid takes no pointers.
                unsafe { libc::getpgid(self.task as i32) } == self.child.id() as i32,
                "development daemon left original private process group",
            )?;
        }
        if let Some(actor) = &self.root {
            actor.recheck()?;
            self.root_scope(self.task)?;
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    pub(crate) fn terminate(&self) -> Result<()> {
        self.recheck()?;
        require(
            // SAFETY: The siginfo pointer is null and the pidfd stays open.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd
                        .as_ref()
                        .ok_or_else(|| {
                            enzimos_platform::Error("development daemon unmeasured".into())
                        })?
                        .as_raw_fd(),
                    libc::SIGTERM,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            } == 0,
            "original development agent stop outcome",
        )
    }
}
impl Drop for Owner {
    #[allow(unsafe_code, reason = "Linux syscall ABI (kill, syscall).")]
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // The child is kept unreaped; the pidfd identifies the original task.
        if let Some(fd) = &self.pidfd {
            // SAFETY: The siginfo pointer is null and `fd` keeps the pidfd open.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        // Its original launcher is kept unreaped, reserving this private group
        // identifier until all owned descendants have been stopped.
        let _keep_leader = &self.leader;
        // SAFETY: kill takes no pointers; the child called setsid, so the negative ID names only
        // its own group.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            if let Ok(Some(_)) = self.child.try_wait() {
                self.reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
