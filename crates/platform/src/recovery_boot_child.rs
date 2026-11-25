// SPDX-License-Identifier: MIT
//! Closed child-only complete boot environment. Caller mounts remain unchanged.
//! Policy must supply original admitted root/home/ESP/control/authority descriptors.
use crate::Error;
use crate::{Result, require};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
};
/// Closed tools run inside a restored system.
#[derive(Clone, Copy)]
pub enum Tool {
    /// Rebuild the initramfs images with `mkinitcpio -P`.
    Initramfs,
    /// Install the boot loader with `bootctl install`.
    Loader,
}
impl Tool {
    pub(crate) fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Initramfs => &["/", "/usr/bin/mkinitcpio", "-P"],
            Self::Loader => &[
                "/",
                "/usr/bin/bootctl",
                "--esp-path=/boot",
                "--no-variables",
                "install",
            ],
        }
    }
}
/// Descriptors and strings prepared before fork for one complete-boot tool child.
pub struct Context {
    // All strings and descriptors are prepared before fork. enter_child allocates
    // nothing and opens only fixed component paths below its private cloned root.
    root: File,
    root_alias: CString,
    root_device: u64,
    root_inode: u64,
    sources: Vec<File>,
    aliases: Vec<CString>,
    procs: File,
}
impl Context {
    /// Prepare a child that enters the restored root and joins `group`.
    ///
    /// # Errors
    ///
    /// Fails unless the caller is Root, when the root is not the frozen replacement root, a source
    /// directory is invalid, or the cgroup procs file is unavailable.
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
    pub fn prepare(
        root: &File,
        home: &File,
        esp: &File,
        control: &File,
        authority: &File,
        group: &crate::recovery_boot_group::Group,
    ) -> Result<Self> {
        require(
            crate::process_identity::effective_uid() == 0,
            "Root complete boot child required",
        )?;
        let procs = group.procs()?;
        let metadata = root.metadata()?;
        require(
            metadata.is_dir()
                && metadata.ino() == 256
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o755,
            "original prepared replacement root required",
        )?;
        let mut info = [0u64; 63];
        require(
            // SAFETY: `info` is 504 bytes, the size encoded in the ioctl number, and `root` keeps
            // the descriptor open.
            unsafe {
                libc::ioctl(
                    root.as_raw_fd(),
                    0x81f8943c as libc::c_ulong,
                    info.as_mut_ptr(),
                )
            } == 0
                && info[36] & 1 != 0,
            "complete boot requires the original frozen replacement root",
        )?;
        let root = root.try_clone()?;
        let sources = [home, esp, control, authority]
            .into_iter()
            .map(|s| s.try_clone().map_err(crate::Error::from))
            .collect::<Result<Vec<_>>>()?;
        for source in &sources {
            let m = source.metadata()?;
            require(
                m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
                "original complete boot source directory required",
            )?;
        }
        let aliases = sources
            .iter()
            .map(|f| {
                CString::new(format!("/proc/self/fd/{}", f.as_raw_fd()))
                    .map_err(|_| Error("invalid generated native name".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        let root_alias = CString::new(format!("/proc/self/fd/{}", root.as_raw_fd()))
            .map_err(|_| Error("invalid generated native name".into()))?;
        require(
            procs.metadata()?.is_file() && procs.metadata()?.uid() == 0,
            "owned complete boot cgroup procs required",
        )?;
        // Keep the mount identities live through preparation; the policy's
        // original-source callback checks each before and throughout execution.
        for file in [
            &root,
            &sources[0],
            &sources[1],
            &sources[2],
            &sources[3],
            procs,
        ] {
            crate::mount_identity::id(file.as_fd(), true)?;
        }
        Ok(Self {
            root,
            root_alias,
            root_device: metadata.dev(),
            root_inode: metadata.ino(),
            sources,
            aliases,
            procs: procs.try_clone()?,
        })
    }
    #[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
    pub(crate) unsafe fn enter_child(&self) -> std::io::Result<()> {
        // SAFETY: The caller upholds the same pre_exec contract that `enter_inner` requires.
        unsafe { self.enter_inner() }
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (WEXITSTATUS, WIFEXITED, WTERMSIG, __errno_location and others)."
    )]
    unsafe fn enter_inner(&self) -> std::io::Result<()> {
        // SAFETY: This runs in the owned pre_exec child, on descriptors held by `self` and
        // NUL-terminated literals.
        unsafe {
            // Join the actual original cgroup before any restored tool executes.
            if libc::write(self.procs.as_raw_fd(), b"0\n".as_ptr().cast(), 2) != 2 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The grandchild is actual PID1 in the fresh PID namespace. The
            // native outer child only waits; it never executes restored code.
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let parent_fd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as i32;
            if parent_fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let child = libc::fork();
            if child < 0 {
                libc::close(parent_fd);
                return Err(std::io::Error::last_os_error());
            }
            if child > 0 {
                // Close the outer copy of Command's exec-error channel, so the
                // actual inner exec remains the spawn acknowledgement boundary.
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
                    libc::kill(child, libc::SIGKILL);
                    libc::_exit(125);
                }
                let mut status = 0;
                loop {
                    let waited = libc::waitpid(child, &mut status, 0);
                    if waited == child {
                        break;
                    }
                    if waited < 0 && *libc::__errno_location() != libc::EINTR {
                        libc::_exit(125);
                    }
                }
                libc::_exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut parent = libc::pollfd {
                fd: parent_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut parent, 1, 0) != 0 {
                libc::close(parent_fd);
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            libc::close(parent_fd);
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // A child-only root clone clears noexec only on this exact new bind.
            if libc::mount(
                self.root_alias.as_ptr(),
                c"/restore-system".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::mount(
                std::ptr::null(),
                c"/restore-system".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NODEV | libc::MS_NOSUID,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let root = libc::open(
                c"/restore-system".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            );
            if root < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut status: libc::stat = std::mem::zeroed();
            if libc::fstat(root, &mut status) != 0
                || status.st_dev != self.root_device
                || status.st_ino != self.root_inode
            {
                libc::close(root);
                return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
            }
            if libc::fchdir(root) != 0 {
                libc::close(root);
                return Err(std::io::Error::last_os_error());
            }
            libc::close(root);
            // Parent admission retains all these exact empty placeholders.
            for (index, target) in [
                c"home",
                c"boot",
                c"var/lib/enzimos-control",
                c"etc/pacman.d/gnupg",
            ]
            .iter()
            .enumerate()
            {
                if libc::mount(
                    self.aliases[index].as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::mount(
                    std::ptr::null(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND
                        | libc::MS_REMOUNT
                        | libc::MS_NODEV
                        | libc::MS_NOSUID
                        | libc::MS_NOEXEC
                        | if index == 1 { 0 } else { libc::MS_RDONLY },
                    std::ptr::null(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (target, kind) in [
                (c"proc", c"proc"),
                (c"sys", c"sysfs"),
                (c"run", c"tmpfs"),
                (c"tmp", c"tmpfs"),
                (c"var/tmp", c"tmpfs"),
            ] {
                if libc::mount(
                    kind.as_ptr(),
                    target.as_ptr(),
                    kind.as_ptr(),
                    libc::MS_NOSUID
                        | libc::MS_NODEV
                        | if kind == c"tmpfs" {
                            0
                        } else {
                            libc::MS_NOEXEC | libc::MS_RDONLY
                        },
                    std::ptr::null(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Use a fresh minimal device filesystem, never a recursive host /dev.
            if libc::mount(
                c"tmpfs".as_ptr(),
                c"dev".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NOEXEC,
                c"mode=0755,size=16m".as_ptr().cast(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            for (name, major, minor) in [
                (c"dev/null", 1, 3),
                (c"dev/zero", 1, 5),
                (c"dev/random", 1, 8),
                (c"dev/urandom", 1, 9),
            ] {
                if libc::mknod(
                    name.as_ptr(),
                    libc::S_IFCHR | 0o666,
                    libc::makedev(major, minor),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::symlink(c"/proc/self/fd".as_ptr(), c"dev/fd".as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::chroot(c".".as_ptr()) != 0 || libc::chdir(c"/".as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Metadata and ordinary build UID/GID transitions only. No mount,
            // ptrace, module loading, device creation, network or cgroup escape.
            let allowed: u64 = 0x880000db;
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            #[derive(Clone, Copy)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let mut data = [Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for capability in 0..=40 {
                if allowed & (1u64 << capability) == 0
                    && libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (index, row) in data.iter_mut().enumerate() {
                let mask = (allowed >> (index * 32)) as u32;
                row.effective &= mask;
                row.permitted &= mask;
                row.inheritable = 0;
            }
            if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0
                || libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            // Original source descriptions are kept until clone assembly above.
            let _ = (&self.root, &self.sources);
            Ok(())
        }
    }
}
