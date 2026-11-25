use super::*;
use std::{fs::File, os::unix::fs::PermissionsExt, path::Path};
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (poll, syscall).")]
fn idle_child_observes_revocation_and_retires_original_process() {
    let work = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let directory = tempfile::tempdir_in(work).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("sleep");
    std::fs::copy("/usr/bin/sleep", &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let image = File::open(&path).unwrap();
    // SAFETY: gettid takes no arguments and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let mut original = None;
    let mut boundary = || -> Result<()> {
        let children = std::fs::read_to_string(format!("/proc/self/task/{tid}/children"))?;
        if let Some(pid) = children.split_whitespace().next() {
            let pid: u32 = pid.parse().map_err(|_| Error("fixture child PID".into()))?;
            let stat = crate::process_identity::parse_stat(
                &std::fs::read_to_string(format!("/proc/{pid}/stat"))?,
                pid,
            )?;
            // SAFETY: pidfd_open takes no pointers.
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            require(raw >= 0, "owned fixture pidfd unavailable")?;
            // SAFETY: `raw` was just returned by pidfd_open and is owned by nothing else.
            let retained = unsafe { File::from_raw_fd(raw as i32) };
            require(
                crate::process_identity::pidfd_target(std::os::fd::AsFd::as_fd(&retained))? == pid,
                "owned fixture pidfd differs",
            )?;
            let after = crate::process_identity::parse_stat(
                &std::fs::read_to_string(format!("/proc/{pid}/stat"))?,
                pid,
            )?;
            require(
                after.start_ticks == stat.start_ticks,
                "owned fixture child epoch changed",
            )?;
            original = Some(retained);
            return Err(Error("fixture caller revoked while child idle".into()));
        }
        Ok(())
    };
    let started = Instant::now();
    assert!(
        run_pinned_with_checkpoint(
            "/usr/bin/sleep",
            &image,
            &["60"],
            &[],
            Duration::from_secs(5),
            64,
            &[],
            &mut boundary
        )
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let original = original.expect("revocation must observe the actual idle child");
    let mut poll = libc::pollfd {
        fd: original.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` is one writable pollfd and the count is 1.
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
    assert!(poll.revents & libc::POLLIN != 0);
}
