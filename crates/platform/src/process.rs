// SPDX-License-Identifier: MIT
use crate::{Error, Result, require};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Bounded vendor ELF admission. Arch Restic includes its Go runtime and
/// currently exceeds 32 MiB; other fixed commands keep the smaller limit.
pub fn executable_limit(program: &str) -> u64 {
    if program == "/usr/bin/restic" {
        64 * 1024 * 1024
    } else {
        32 * 1024 * 1024
    }
}

/// Bounded journal text for a refused command: program, exit status and the
/// last stderr line. Error strings stay single-line and never carry stdout.
pub fn refusal(program: &str, output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    let last = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let tail: String = last
        .chars()
        .rev()
        .take(200)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    crate::diagnostic::bounded(&format!(
        "{program} exited {}: {}",
        output
            .status
            .code()
            .map_or_else(|| "by signal".to_owned(), |c| c.to_string()),
        tail.trim()
    ))
}
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Child-local aliases assigned to explicit inherited descriptors. These
    /// are observations of a retired command, not usable parent descriptors.
    pub descriptor_aliases: Vec<String>,
}
struct OwnedChild(Child, bool);
impl Drop for OwnedChild {
    #[allow(unsafe_code, reason = "Linux syscall ABI (kill).")]
    fn drop(&mut self) {
        // A descendant holding a pipe cannot outlive the bounded command scope.
        if !self.1 {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}
/// A command's total deadline plus an optional inactivity limit. Time is
/// passed in, so the decision is tested with a fake clock.
#[derive(Debug)]
struct Watchdog {
    deadline: Instant,
    stall: Option<Duration>,
    last_activity: Instant,
}
impl Watchdog {
    fn new(start: Instant, timeout: Duration, stall: Option<Duration>) -> Self {
        Self {
            deadline: start + timeout,
            stall,
            last_activity: start,
        }
    }
    /// Any stdout or stderr bytes count as progress.
    fn activity(&mut self, now: Instant) {
        self.last_activity = self.last_activity.max(now);
    }
    fn check(&self, now: Instant) -> Result<()> {
        require(
            now < self.deadline,
            "command deadline exceeded; outcome requires inspection",
        )?;
        if let Some(stall) = self.stall
            && now.saturating_duration_since(self.last_activity) >= stall
        {
            return Err(Error(format!(
                "command stalled: no output for {} s; outcome requires inspection",
                stall.as_secs()
            )));
        }
        Ok(())
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    require(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "pipe setup failed",
    )
}
// Called only between fork and exec, with no allocation or parent mutation.
#[allow(unsafe_code, reason = "Linux syscall ABI (prctl, syscall, unshare).")]
unsafe fn offline_namespace() -> std::io::Result<()> {
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
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
    if unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Linux CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN. Prevent exec from
    // regaining route/link mutation or setns authority in this owned child.
    for capability in [12u32, 13, 21] {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mask = !(1u32 << (capability % 32));
        let row = &mut data[(capability / 32) as usize];
        row.effective &= mask;
        row.permitted &= mask;
        row.inheritable &= mask;
    }
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
/// Diagnostics never share a caller's tight stdout bound: a command whose
/// stdout is a number may still explain a failure on stderr, and that must
/// surface as its real exit status, not as an output-bound violation.
pub const STDERR_MINIMUM: usize = 64 * 1024;
fn stderr_limit(limit: usize) -> usize {
    limit.max(STDERR_MINIMUM)
}
fn drain(
    pipe: &mut impl Read,
    data: &mut Vec<u8>,
    limit: usize,
    program: &str,
    stream: &str,
) -> Result<bool> {
    let mut buf = [0; 16384];
    for _ in 0..16 {
        match pipe.read(&mut buf) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if data.len().saturating_add(n) > limit {
                    // Name the command and stream so the journal shows which
                    // bound a real system exceeded.
                    return Err(Error(format!(
                        "command output bound exceeded: {program} {stream} over {limit} bytes"
                    )));
                }
                data.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(false)
}

pub fn run(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
) -> Result<Output> {
    run_with_fds(program, args, input, timeout, limit, &[])
}
/// Pass explicitly borrowed descriptors. An argument `@fd:N` becomes the child
/// /proc/self/fd path for descriptor N; `@fd-dir:N` selects its directory contents.
/// Duplicates stay above stdio and Rust's
/// exec-error pipe; no low descriptor is reassigned inside pre_exec.
pub fn run_with_fds(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
) -> Result<Output> {
    run_context(
        program,
        args,
        input,
        timeout,
        limit,
        descriptors,
        false,
        None,
    )
}
/// Execute reviewed native bytes from their retained read-only descriptor.
/// The logical program still passes the same fixed-path registry and sets argv0.
pub fn run_pinned(
    program: &str,
    image: &std::fs::File,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
) -> Result<Output> {
    run_pinned_observed(
        program,
        image,
        args,
        input,
        timeout,
        limit,
        descriptors,
        None,
        false,
        None,
        None,
    )
}
/// Fixed target commands with a fresh, empty child-only network namespace.
/// The caller and its watchers retain their original namespaces. Namespace
/// creation failure has no execution fallback.
pub fn run_pinned_offline(
    image: &std::fs::File,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
) -> Result<Output> {
    run_pinned_observed(
        "/usr/bin/chroot",
        image,
        args,
        input,
        timeout,
        limit,
        descriptors,
        None,
        true,
        None,
        None,
    )
}
/// Observe bounded stdout chunks while the original owned child is still alive.
/// Observer failure keeps the same owned process-group termination semantics.
pub fn run_pinned_stream(
    program: &str,
    image: &std::fs::File,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
    observer: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<Output> {
    run_pinned_observed(
        program,
        image,
        args,
        input,
        timeout,
        limit,
        descriptors,
        Some(observer),
        false,
        None,
        None,
    )
}
/// Check the original caller while a bounded pinned-image child is alive.
/// A refused checkpoint retires that owned process group and preserves caller
/// transaction evidence; it never reruns the command.
pub fn run_pinned_with_checkpoint(
    program: &str,
    image: &std::fs::File,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
    checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<Output> {
    checkpoint()?;
    let output = run_pinned_observed(
        program,
        image,
        args,
        input,
        timeout,
        limit,
        descriptors,
        None,
        false,
        None,
        Some(checkpoint),
    )?;
    checkpoint()?;
    Ok(output)
}
/// Closed restored-system tool in an original owned cgroup and child namespaces.
#[allow(unsafe_code, reason = "Linux syscall ABI (prctl).")]
pub fn recovery_boot_tool(
    image: &std::fs::File,
    tool: crate::recovery_boot_child::Tool,
    context: crate::recovery_boot_child::Context,
    group: &crate::recovery_boot_group::Group,
    checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<Output> {
    use std::os::unix::fs::MetadataExt;
    require(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "complete boot caller cannot protect its original descriptions",
    )?;
    checkpoint()?;
    group.recheck()?;
    let m = image.metadata()?;
    require(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.mode() & 0o111 != 0
            && crate::files::read_file(image, 32 * 1024 * 1024, Some(0), true)?
                .starts_with(b"\x7fELF"),
        "original restored native chroot image required",
    )?;
    let before = crate::files::identity(&m);
    let output = run_observed_context(
        "/usr/bin/chroot",
        tool.arguments(),
        &[],
        Duration::from_secs(1800),
        2 * 1024 * 1024,
        &[],
        false,
        Some(image),
        None,
        false,
        None,
        Some(&mut || {
            checkpoint()?;
            group.recheck()?;
            require(
                crate::files::identity(&image.metadata()?) == before,
                "original restored chroot image changed",
            )
        }),
        Some(context),
        None,
    );
    // Even a tool which starts a new session cannot leave a descendant behind.
    // The original kernel cgroup is independently retained outside the child.
    group.kill_and_wait()?;
    checkpoint()?;
    output
}
/// When set, pinned children's diagnostics are also written to this process's stderr as
/// they arrive (the journal, for a systemd worker), so a long job can be followed live.
static ECHO_CHILD_OUTPUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn echo_child_output(on: bool) {
    ECHO_CHILD_OUTPUT.store(on, std::sync::atomic::Ordering::Relaxed);
}
/// Only diagnostics are echoed: a child's stderr, when it is plain text. Stdout can be
/// binary (keyring exports) or huge, and gpg narrates every signature on stderr; a flood
/// would stall the journal and with it the worker writing to it.
fn echo(program: &str, bytes: &[u8]) {
    if !ECHO_CHILD_OUTPUT.load(std::sync::atomic::Ordering::Relaxed)
        || bytes.is_empty()
        || program.ends_with("/gpg")
        || program.ends_with("/gpgv")
        || program.ends_with("/pacman-key")
    {
        return;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    {
        return;
    }
    let _ = std::io::Write::write_all(&mut std::io::stderr(), bytes);
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, geteuid).")]
fn run_pinned_observed(
    program: &str,
    image: &std::fs::File,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
    observer: Option<&mut dyn FnMut(&[u8]) -> Result<()>>,
    isolated_network: bool,
    local_restic: Option<crate::local_restic::Consumer>,
    boundary: Option<&mut dyn FnMut() -> Result<()>>,
) -> Result<Output> {
    use std::os::unix::fs::MetadataExt;
    let before = crate::files::identity(&image.metadata()?);
    let m = image.metadata()?;
    require(
        m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o022 == 0
            && m.mode() & 0o111 != 0
            && unsafe { libc::fcntl(image.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                == libc::O_RDONLY,
        "pinned executable ownership, mode or open-description flags",
    )?;
    require(
        crate::files::read_file(
            image,
            executable_limit(program) as usize,
            Some(m.uid()),
            true,
        )?
        .starts_with(b"\x7fELF"),
        "pinned native executable required",
    )?;
    require(
        crate::files::identity(&image.metadata()?) == before,
        "pinned executable changed before execution",
    )?;
    let stall_limit = local_restic
        .as_ref()
        .and_then(crate::local_restic::Consumer::stall_limit);
    run_observed_context(
        program,
        args,
        input,
        timeout,
        limit,
        descriptors,
        false,
        Some(image),
        observer,
        isolated_network,
        local_restic,
        boundary,
        None,
        stall_limit,
    )
}
pub(crate) fn local_restic(
    image: &std::fs::File,
    args: &[&str],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
    task: crate::local_restic::Consumer,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<Output> {
    run_pinned_observed(
        "/usr/bin/restic",
        image,
        args,
        &[],
        timeout,
        limit,
        descriptors,
        None,
        true,
        Some(task),
        Some(boundary),
    )
}
pub(crate) fn remote_restic(
    image: &std::fs::File,
    args: &[&str],
    descriptors: &[BorrowedFd<'_>],
    task: crate::local_restic::Consumer,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<Output> {
    require(
        matches!(task, crate::local_restic::Consumer::Remote(_)),
        "closed remote Restic invocation required",
    )?;
    let timeout = match &task {
        crate::local_restic::Consumer::Remote(invocation) => invocation.timeout(),
        _ => unreachable!(),
    };
    run_pinned_observed(
        "/usr/bin/restic",
        image,
        args,
        &[],
        timeout,
        crate::remote_restic::OUTPUT_LIMIT,
        descriptors,
        None,
        // Restic reads the share through the child's kernel CIFS mount,
        // made before the child leaves the network namespace.
        true,
        Some(task),
        Some(boundary),
    )
}
/// Independent recovery has no udev rules for encrypted storage. This fixed
/// context cannot inject arbitrary environment variables into privileged tools.
pub fn recovery_cryptsetup(
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    descriptors: &[BorrowedFd<'_>],
) -> Result<Output> {
    run_context(
        "/usr/bin/cryptsetup",
        args,
        input,
        timeout,
        65536,
        descriptors,
        true,
        None,
    )
}
pub fn output(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    codes: &[i32],
) -> Result<String> {
    let result = run(program, args, input, timeout, 2 * 1024 * 1024)?;
    if !result.status.code().is_some_and(|c| codes.contains(&c)) {
        return Err(Error(format!(
            "command refused: {}",
            refusal(program, &result)
        )));
    }
    String::from_utf8(result.stdout).map_err(|_| Error("invalid command text".into()))
}

#[cfg(test)]
mod boundary_tests;

#[cfg(test)]
mod bound_tests;

mod execution;
use execution::run_context;
use execution::run_observed_context;
