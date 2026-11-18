// SPDX-License-Identifier: MIT
use std::{
    os::fd::{AsRawFd, FromRawFd},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
#[test]
fn child_runner() {
    if std::env::var_os("ENZIMOS_OWNED_PARENT_LOSS_FIXTURE").is_none() {
        return;
    }
    enzimos_platform::process::run(
        "/usr/bin/sleep",
        &["60"],
        &[],
        Duration::from_secs(65),
        4096,
    )
    .unwrap();
}
struct Reaper(libc::c_int);
impl Drop for Reaper {
    #[allow(unsafe_code, reason = "Linux syscall ABI (prctl).")]
    fn drop(&mut self) {
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.0) };
    }
}
struct Scope {
    parent: Child,
    parent_done: bool,
    child: Option<(std::fs::File, libc::pid_t)>,
}
impl Drop for Scope {
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall, waitpid).")]
    fn drop(&mut self) {
        if !self.parent_done {
            let _ = self.parent.kill();
            let _ = self.parent.wait();
        }
        if let Some((fd, pid)) = &self.child {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            unsafe { libc::waitpid(*pid, std::ptr::null_mut(), 0) };
        }
    }
}
#[test]
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (WIFSIGNALED, WTERMSIG, poll, prctl and others)."
)]
fn abrupt_owner_loss_kills_its_actual_bounded_child() {
    let mut previous = 0;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut previous) },
        0
    );
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let _reaper = Reaper(previous);
    let parent = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_runner", "--nocapture"])
        .env("ENZIMOS_OWNED_PARENT_LOSS_FIXTURE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut scope = Scope {
        parent,
        parent_done: false,
        child: None,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let expected = std::fs::canonicalize("/usr/bin/sleep").unwrap();
    loop {
        // Rust's test worker, rather than its main thread, owns the actual fork.
        let tasks = std::fs::read_dir(format!("/proc/{}/task", scope.parent.id())).unwrap();
        for task in tasks.take(64) {
            let task = task.unwrap();
            let children =
                std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
            if let Some(pid) = children
                .split_whitespace()
                .take(16)
                .find_map(|s| s.parse::<libc::pid_t>().ok())
            {
                if scope.child.is_some() {
                    break;
                }
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
                assert!(fd >= 0);
                scope.child = Some((unsafe { std::fs::File::from_raw_fd(fd) }, pid));
            }
            if scope.child.is_some() {
                break;
            }
        }
        if scope.child.as_ref().is_some_and(|(_, pid)| {
            std::fs::read_link(format!("/proc/{pid}/exe")).ok().as_ref() == Some(&expected)
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "actual owned sleep child did not exec"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    scope.parent.kill().unwrap();
    scope.parent.wait().unwrap();
    scope.parent_done = true;
    let (pidfd, pid) = scope.child.as_ref().unwrap();
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
    assert!(
        poll.revents & libc::POLLIN != 0,
        "owned descendant survived its caller"
    );
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(*pid, &mut status, 0) }, *pid);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    scope.child = None;
}
