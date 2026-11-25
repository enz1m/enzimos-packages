// SPDX-License-Identifier: MIT
//! Broker retention is metadata-only; only an ordinary confined consumer reads.
use enzimos_platform::{Result, require, secret as sealed};
use std::os::fd::{AsRawFd, BorrowedFd};
use zeroize::Zeroizing;
/// A sealed secret memfd received from a user, see [`retain`].
pub struct Retained {
    original: sealed::Retained,
}
impl Retained {
    /// Secret length in bytes.
    ///
    /// # Errors
    ///
    /// Fails when the secret's metadata changed.
    pub fn length(&self) -> Result<usize> {
        self.original.length()
    }
    /// The secret's descriptor.
    ///
    /// # Errors
    ///
    /// Fails when the secret's metadata changed.
    pub fn fd(&self) -> Result<BorrowedFd<'_>> {
        self.original.fd()
    }
    /// Verify the secret's metadata is unchanged.
    ///
    /// # Errors
    ///
    /// Fails when it changed.
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()
    }
    /// The production validator additionally sets CPU/address-space/core limits,
    /// drops Root/groups and disables privilege gains/dumps before this entry.
    ///
    /// # Errors
    ///
    /// Fails when called as Root, the secret changed, or its bytes are not a valid secret.
    #[allow(unsafe_code, reason = "Linux syscall ABI (pread).")]
    pub fn validate_in_consumer(&self) -> Result<()> {
        require(
            enzimos_platform::process_identity::effective_uid() != 0,
            "Root broker cannot read credential bytes",
        )?;
        self.recheck()?;
        let fd = self.fd()?;
        let mut bytes = Zeroizing::new(vec![0; self.length()?]);
        // SAFETY: The buffer pointer and length describe `bytes`, and `fd` is borrowed open.
        let n = unsafe { libc::pread(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        require(
            n == bytes.len() as isize
                && !bytes.iter().any(|b| matches!(*b, 0 | 10 | 13))
                && std::str::from_utf8(&bytes).is_ok(),
            "secret-input-refused",
        )?;
        self.recheck()
    }
}
/// Retain `fd` as a sealed secret owned by `uid`.
///
/// # Errors
///
/// Fails unless `fd` is a sealed, private, unlinked memfd of a regular user.
pub fn retain(fd: BorrowedFd<'_>, uid: u32) -> Result<Retained> {
    Ok(Retained {
        original: sealed::retain(fd, uid)?,
    })
}
/// Confine this process to validating the secret on `input`: close other descriptors, drop
/// privileges and capabilities, and install a syscall filter.
///
/// # Errors
///
/// Fails when any confinement step cannot be applied or verified.
#[allow(unsafe_code, reason = "Linux syscall ABI (close, fcntl and others).")]
pub fn constrain_consumer(input: BorrowedFd<'_>) -> Result<()> {
    let fd = input.as_raw_fd();
    require(
        // SAFETY: F_GETFD takes no pointers; `input` keeps the descriptor open.
        fd >= 3 && unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
        "secret consumer descriptor required",
    )?;
    let pid = std::process::id();
    let mut tasks = std::fs::read_dir(format!("/proc/{pid}/task"))?;
    require(
        tasks.next().transpose()?.is_some() && tasks.next().transpose()?.is_none(),
        "single-threaded secret consumer required",
    )?;
    drop(tasks);
    let mut originals = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        require(originals.len() < 128, "secret consumer descriptor bound")?;
        let number = entry?
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or_else(|| enzimos_platform::Error("consumer descriptor encoding".into()))?;
        if number > 2 && number != fd {
            originals.push(number);
        }
    }
    let parent = enzimos_platform::process_identity::parent_pid();
    require(parent > 1, "secret consumer supervisor required")?;
    // Only stdio and this already-retained sealed input survive into the reader.
    // close_range is mandatory; no /proc fallback or inherited service authority.
    if fd > 3 {
        require(
            // SAFETY: close_range takes no pointers; it closes only descriptors below the retained
            // input.
            unsafe { libc::syscall(libc::SYS_close_range, 3u32, (fd - 1) as u32, 0u32) } == 0,
            "secret consumer descriptor isolation unavailable",
        )?;
    }
    require(
        // SAFETY: close_range takes no pointers; it closes only descriptors above the retained
        // input.
        unsafe { libc::syscall(libc::SYS_close_range, (fd + 1) as u32, u32::MAX, 0u32) } == 0,
        "secret consumer descriptor isolation unavailable",
    )?;
    require(
        originals
            .iter()
            // SAFETY: F_GETFD takes no pointers; it only probes whether a closed number is still
            // open.
            .all(|other| unsafe { libc::fcntl(*other, libc::F_GETFD) } < 0),
        "secret consumer inherited authority survived isolation",
    )?;
    for (resource, value) in [
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_CPU, 1),
        (libc::RLIMIT_AS, 64 * 1024 * 1024),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        require(
            // SAFETY: `limit` is a valid rlimit that outlives the call.
            unsafe { libc::setrlimit(resource, &limit) } == 0,
            "secret consumer confinement unavailable",
        )?;
    }
    if enzimos_platform::process_identity::effective_uid() == 0 {
        let body = enzimos_platform::files::read_kernel(
            std::path::Path::new("/proc/sys/kernel/cap_last_cap"),
            8,
        )?;
        let last = std::str::from_utf8(&body)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|n| *n <= 63)
            .ok_or_else(|| enzimos_platform::Error("consumer capability ABI unavailable".into()))?;
        for cap in 0..=last {
            require(
                // SAFETY: prctl(PR_CAPBSET_DROP) takes no pointers.
                unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } == 0,
                "secret consumer capability bounding drop unavailable",
            )?;
        }
        require(
            // SAFETY: setgroups with a zero count accepts a null list.
            unsafe { libc::setgroups(0, std::ptr::null()) } == 0
                // SAFETY: setresgid takes no pointers.
                && unsafe { libc::setresgid(65534, 65534, 65534) } == 0
                // SAFETY: setresuid takes no pointers.
                && unsafe { libc::setresuid(65534, 65534, 65534) } == 0,
            "secret consumer confinement unavailable",
        )?;
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let mut caps = [Caps {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    require(
        // SAFETY: prctl(PR_SET_KEEPCAPS) takes no pointers.
        unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } == 0
            // SAFETY: `header` and the two-element `caps` array match the kernel capability ABI
            // version.
            && unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) } == 0
            // SAFETY: `header` and the two-element `caps` array match the kernel capability ABI
            // version.
            && unsafe { libc::syscall(libc::SYS_capget, &header, caps.as_mut_ptr()) } == 0
            && caps
                .iter()
                .all(|c| c.effective == 0 && c.permitted == 0 && c.inheritable == 0),
        "secret consumer capability retirement unavailable",
    )?;
    require(
        // SAFETY: prctl(PR_SET_PDEATHSIG) takes no pointers.
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0
            && enzimos_platform::process_identity::parent_pid() == parent,
        "secret consumer supervisor disappeared",
    )?;
    require(
        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) takes no pointers.
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0
            // SAFETY: prctl(PR_SET_DUMPABLE) takes no pointers.
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "secret consumer confinement unavailable",
    )?;
    syscall_filter()?;
    // Mandatory runtime negative controls before any password read. If either
    // operation succeeds, retire its owned handle and refuse the consumer.
    // SAFETY: The path is a NUL-terminated C string literal.
    let opened = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            c"/dev/null".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    let open_denied =
        opened < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if opened >= 0 {
        // SAFETY: `opened` was returned by openat above and is closed exactly once.
        unsafe { libc::close(opened) };
    }
    // SAFETY: socket takes no pointers.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    let socket_denied =
        socket < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if socket >= 0 {
        // SAFETY: `socket` was returned by socket above and is closed exactly once.
        unsafe { libc::close(socket) };
    }
    require(
        open_denied && socket_denied,
        "actual consumer syscall isolation unavailable",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (prctl).")]
fn syscall_filter() -> Result<()> {
    require(
        cfg!(target_arch = "x86_64"),
        "exact consumer syscall ABI required",
    )?;
    fn row(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    let mut filter = vec![
        row(0x20, 0, 0, 4),
        row(0x15, 1, 0, 0xc000003e),
        row(0x06, 0, 0, 0x80000000),
        row(0x20, 0, 0, 0),
        row(0x35, 0, 1, 0x40000000), // Reject x32 ABI bypass of native syscall numbers.
        row(0x06, 0, 0, 0x80000000),
    ];
    // Once the ELF loader has completed, this reader needs neither file opens,
    // process creation/exec nor any networking operation. Unknown ordinary
    // runtime syscalls remain under the reader's dropped UID/resource limits.
    for nr in [
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_creat,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fsconfig,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
    ] {
        filter.extend([
            row(0x15, 0, 1, nr as u32),
            row(0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
        ]);
    }
    filter.push(row(0x06, 0, 0, 0x7fff0000));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    require(
        // SAFETY: `program` points at `filter`, which outlives the call, and its length matches.
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } == 0,
        "secret consumer syscall confinement unavailable",
    )
}
