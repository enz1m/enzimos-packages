// SPDX-License-Identifier: MIT
//! Atomically create one original child and pidfd in its original private kernel group.
use crate::{delivery_worker_group::Group, namespaces, operation};
use enzimos_platform::{Result, files, mount_identity, process_identity, require};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};
const IMAGE: &str = "/usr/lib/enzimos-native/enzimos-policy";
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_INTO_CGROUP: u64 = 0x200000000;
const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}
#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Cap {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const DIRECTORY: &str = "/usr/lib/enzimos-native";
fn directory_shape(file: &File) -> Result<(u64, u64, u32, u32, u32, u64)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "Root native image directory required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
/// A Root-opened original executable, retained from review through child execution.
/// No serialized identity or digest can construct this actor.
pub(crate) struct Image {
    directory: File,
    directory_shape: (u64, u64, u32, u32, u32, u64),
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    sha: String,
}
impl Image {
    pub(crate) fn open() -> Result<Self> {
        operation::root_only()?;
        namespaces::initial()?;
        let directory = files::directory(Path::new(DIRECTORY), Some(0))?;
        let directory_shape = directory_shape(&directory)?;
        let file = files::open_relative(&directory, Path::new("enzimos-policy"))?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o755,
            "fixed Root policy child image required",
        )?;
        let identity = files::identity(&m);
        let bytes = files::read_file(&file, 32 * 1024 * 1024, Some(0), true)?;
        require(
            bytes.starts_with(b"\x7fELF"),
            "fixed native child image required",
        )?;
        let this = Self {
            directory,
            directory_shape,
            identity,
            mount: mount_identity::id(file.as_fd(), true)?,
            sha: enzimos_platform::json::sha256(&bytes),
            file,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        namespaces::initial()?;
        let named_directory = files::directory(Path::new(DIRECTORY), Some(0))?;
        require(
            directory_shape(&self.directory)? == self.directory_shape
                && directory_shape(&named_directory)? == self.directory_shape,
            "original native executable directory replaced or covered",
        )?;
        let named = files::open_relative(&named_directory, Path::new("enzimos-policy"))?;
        require(
            files::identity(&self.file.metadata()?) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original delivery executable changed, replaced or covered",
        )
    }
    pub(crate) fn evidence(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"file":self.identity,"mount":self.mount,"sha256":self.sha,
            "directory":self.directory_shape}),
        )
    }
}
pub(crate) struct Child {
    pid: u32,
    pidfd: File,
    image: File,
    identity: files::FileIdentity,
    closed: bool,
}
impl Child {
    /// Callers must persist their unused grant's entry intent before calling.
    /// There is no fork/PID/migration or alternate-image fallback.
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (_exit, dup2, fcntl and others)."
    )]
    pub(crate) fn spawn(
        approved: &Image,
        group: &Group,
        channel: &enzimos_platform::fd_packet::Packet,
        uid: u32,
        gid: u32,
    ) -> Result<Self> {
        operation::root_only()?;
        namespaces::initial()?;
        require(
            (1000..i32::MAX as u32).contains(&uid) && (1..i32::MAX as u32).contains(&gid),
            "ordinary delivery child credentials required",
        )?;
        require(group.empty()?, "original delivery group must start empty")?;
        approved.recheck()?;
        let identity = approved.identity;
        let fd = unsafe { libc::fcntl(approved.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        require(fd >= 64, "original child image alias unavailable")?;
        let image = unsafe { File::from_raw_fd(fd) };
        require(
            files::identity(&image.metadata()?) == identity,
            "original child image alias differs",
        )?;
        approved.recheck()?;
        let null = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open("/dev/null")?;
        let m = null.metadata()?;
        require(
            m.mode() & libc::S_IFMT == libc::S_IFCHR
                && libc::major(m.rdev()) == 1
                && libc::minor(m.rdev()) == 3
                && m.uid() == 0,
            "actual null character device required",
        )?;
        let socket_alias =
            unsafe { libc::fcntl(channel.as_fd().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        require(
            socket_alias >= 64,
            "original child channel alias unavailable",
        )?;
        let socket_alias = unsafe { File::from_raw_fd(socket_alias) };
        let null_alias = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        require(null_alias >= 64, "original null device alias unavailable")?;
        let null_alias = unsafe { File::from_raw_fd(null_alias) };
        let parent = enzimos_platform::process_identity::current_pid();
        let socket = socket_alias.as_raw_fd();
        let exec = image.as_raw_fd();
        let null_fd = null_alias.as_raw_fd();
        let args = [
            CString::new(IMAGE).map_err(|_| enzimos_platform::Error("invalid C string".into()))?,
            CString::new("delivery-copy-worker")
                .map_err(|_| enzimos_platform::Error("invalid C string".into()))?,
            CString::new("--fd3")
                .map_err(|_| enzimos_platform::Error("invalid C string".into()))?,
        ];
        let argv = [
            args[0].as_ptr(),
            args[1].as_ptr(),
            args[2].as_ptr(),
            std::ptr::null(),
        ];
        let env = [std::ptr::null::<libc::c_char>()];
        let mut pidfd = -1i32;
        let mut clone = CloneArgs {
            flags: CLONE_PIDFD | CLONE_INTO_CGROUP | CLONE_CLEAR_SIGHAND,
            pidfd: (&mut pidfd as *mut i32) as u64,
            exit_signal: libc::SIGCHLD as u64,
            cgroup: group.clone_target()?.as_raw_fd() as u64,
            ..Default::default()
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut clone,
                std::mem::size_of::<CloneArgs>(),
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if result == 0 {
            // Multithreaded parent: this branch uses only fixed buffers and Linux
            // syscalls, then execveat/_exit. No allocation, locks or Rust destructor.
            unsafe {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent
                {
                    libc::_exit(127);
                }
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
                    libc::_exit(127);
                }
                if libc::dup2(null_fd, 0) < 0
                    || libc::dup2(null_fd, 1) < 0
                    || libc::dup2(null_fd, 2) < 0
                    || libc::dup2(socket, 3) < 0
                    || libc::fcntl(3, libc::F_SETFD, 0) < 0
                {
                    libc::_exit(127);
                }
                let cpu = libc::rlimit {
                    rlim_cur: 30,
                    rlim_max: 30,
                };
                let size = libc::rlimit {
                    rlim_cur: crate::delivery_export::MAX_FILE,
                    rlim_max: crate::delivery_export::MAX_FILE,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0
                    || libc::setrlimit(libc::RLIMIT_FSIZE, &size) != 0
                    || libc::setsid() < 0
                    || libc::syscall(libc::SYS_setgroups, 0usize, std::ptr::null::<libc::gid_t>())
                        != 0
                    || libc::syscall(libc::SYS_setresgid, gid, gid, gid) != 0
                    || libc::syscall(libc::SYS_setresuid, uid, uid, uid) != 0
                {
                    libc::_exit(127);
                }
                let mut header = Header {
                    version: 0x20080522,
                    pid: 0,
                };
                let mut caps = [Cap {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                }; 2];
                if libc::syscall(libc::SYS_capset, &mut header, caps.as_mut_ptr()) != 0
                    || libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_CLEAR_ALL,
                        0,
                        0,
                        0,
                    ) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent
                {
                    libc::_exit(127);
                }
                libc::syscall(
                    libc::SYS_execveat,
                    exec,
                    c"".as_ptr(),
                    argv.as_ptr(),
                    env.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                libc::_exit(127);
            }
        }
        // CLONE_PIDFD publishes this descriptor atomically with child creation.
        require(
            pidfd >= 0 && result > 1 && result < i64::from(i32::MAX),
            "atomic original delivery child identity unavailable",
        )?;
        let this = Self {
            pid: result as u32,
            pidfd: unsafe { File::from_raw_fd(pidfd) },
            image,
            identity,
            closed: false,
        };
        this.live()?;
        group.contains_only(this.pid)?;
        Ok(this)
    }
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    pub(crate) fn live(&self) -> Result<()> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(
            !self.closed
                && unsafe { libc::poll(&mut poll, 1, 0) } == 0
                && process_identity::pidfd_target(self.pidfd.as_fd())? == self.pid
                && files::identity(&self.image.metadata()?) == self.identity,
            "original delivery child exited or image changed",
        )
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (waitid).")]
    pub(crate) fn success(&mut self, maximum: Duration) -> Result<()> {
        require(
            maximum > Duration::ZERO && maximum <= Duration::from_secs(5),
            "delivery exit deadline bound",
        )?;
        let until = Instant::now() + maximum;
        loop {
            // SAFETY: `libc::siginfo_t` is a plain C struct, for which all-zero bytes are a valid
            // value.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pidfd.as_raw_fd() as u32,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if unsafe { info.si_pid() } != 0 {
                self.closed = true;
                return require(
                    info.si_code == libc::CLD_EXITED
                        && unsafe { info.si_status() } == 0
                        && files::identity(&self.image.metadata()?) == self.identity,
                    "original delivery worker failed; no replay",
                );
            }
            require(
                Instant::now() < until,
                "delivery worker exit unknown; no replay",
            )?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Child {
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    fn drop(&mut self) {
        if !self.closed {
            // Only the original kernel pidfd is signalled; never a PID number.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }
            let _ = self.success(Duration::from_secs(2));
        }
    }
}
