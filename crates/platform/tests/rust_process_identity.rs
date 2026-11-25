// SPDX-License-Identifier: MIT
//! Process stat parsing and open-description identity checks.
use enzimos_platform::process_identity::parse_stat;
#[test]
fn retained_pidfd_detects_owned_child_exit_and_refuses_wrong_start_time() {
    let uid = enzimos_platform::process_identity::effective_uid();
    assert!(
        (1000..u32::MAX).contains(&uid),
        "run native host tests as the ordinary workspace account"
    );
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    use std::os::unix::fs::MetadataExt;
    let tuple = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    let expected = std::fs::metadata("/usr/bin/sleep").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let actual = std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
        if tuple(&actual) == tuple(&expected) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned child never reached its expected executable"
        );
        assert!(child.0.try_wait().unwrap().is_none());
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let stat = enzimos_platform::files::read_kernel_owned(
        std::path::Path::new(&format!("/proc/{pid}/stat")),
        8192,
        uid,
    )
    .unwrap();
    let stat = parse_stat(std::str::from_utf8(&stat).unwrap(), pid).unwrap();
    let fixed = vec![std::path::PathBuf::from("/usr/bin/sleep")];
    let retained =
        enzimos_platform::process_identity::Retained::open(pid, stat.start_ticks, uid, &fixed)
            .unwrap();
    assert!(
        enzimos_platform::process_identity::Retained::open(pid, stat.start_ticks + 1, uid, &fixed)
            .is_err()
    );
    retained.recheck().unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(retained.recheck().is_err());
}

#[test]
#[ignore = "requires the disposable Root preflight guest and actual KCMP authority"]
#[allow(unsafe_code, reason = "Fork-child setup must run before exec.")]
fn root_batched_handoff_requires_every_original_open_description_and_live_actor() {
    use enzimos_platform::{files, process_identity::Retained};
    use std::{
        fs::OpenOptions,
        io::Write,
        os::{
            fd::{AsFd, AsRawFd},
            unix::{fs::OpenOptionsExt, process::CommandExt},
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    assert_eq!(enzimos_platform::process_identity::effective_uid(), 0);
    assert!(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .split_whitespace()
            .any(|s| s == "enzimos.native-preflight=1")
    );
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.0.try_wait().unwrap().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let dir = std::env::temp_dir().join(format!(
        "enzimos-root-kcmp-{}",
        files::random_hex(16).unwrap()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("synthetic-description");
    let mut first = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    first
        .write_all(b"public synthetic Root descriptor fixture")
        .unwrap();
    let second = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let alias = first.try_clone().unwrap();
    let (a, b) = (first.as_raw_fd(), second.as_raw_fd());
    let mut command = Command::new("/usr/bin/sleep");
    command
        .arg("10")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: The pre_exec closure only calls dup2, which is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(a, 64) != 64 || libc::dup2(b, 65) != 65 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(2);
    let retained = loop {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.0.id())).unwrap();
        let sampled = parse_stat(&stat, child.0.id()).unwrap();
        if let Ok(actor) = Retained::open(
            child.0.id(),
            sampled.start_ticks,
            0,
            &[PathBuf::from("/usr/bin/sleep")],
        ) {
            break actor;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    };
    retained
        .require_descriptions(&[(alias.as_fd(), 64), (second.as_fd(), 65)])
        .unwrap();
    assert!(
        retained
            .require_descriptions(&[(second.as_fd(), 64)])
            .is_err()
    );
    assert!(
        retained
            .require_descriptions(&[(first.as_fd(), 64), (first.as_fd(), 65)])
            .is_err()
    );
    assert!(
        retained
            .require_descriptions(&[(first.as_fd(), 64), (first.as_fd(), 66)])
            .is_err()
    );
    assert!(retained.require_descriptions(&[]).is_err());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(
        retained
            .require_descriptions(&[(first.as_fd(), 64)])
            .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
