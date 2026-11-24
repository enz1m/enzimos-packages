use super::*;

pub(super) fn run_context(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
    offline_cryptsetup: bool,
    image: Option<&std::fs::File>,
) -> Result<Output> {
    run_observed_context(
        program,
        args,
        input,
        timeout,
        limit,
        descriptors,
        offline_cryptsetup,
        image,
        None,
        false,
        None,
        None,
        None,
        None,
    )
}
#[allow(unsafe_code, reason = "Fork-child setup must run before exec.")]
pub(super) fn run_observed_context(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
    limit: usize,
    descriptors: &[BorrowedFd<'_>],
    offline_cryptsetup: bool,
    image: Option<&std::fs::File>,
    mut observer: Option<&mut dyn FnMut(&[u8]) -> Result<()>>,
    isolated_network: bool,
    local_restic: Option<crate::local_restic::Consumer>,
    mut boundary: Option<&mut dyn FnMut() -> Result<()>>,
    complete_boot: Option<crate::recovery_boot_child::Context>,
    stall: Option<Duration>,
) -> Result<Output> {
    require(
        (program.starts_with("/usr/bin/") && !program.contains("/../"))
            || program == "/usr/lib/systemd/ukify"
            || program == "/usr/lib/enzimos-native/enzimos-policy"
            || program == "/usr/lib/enzimos-native/enzimos-media-auth"
            || program == "/usr/lib/enzimos-native/enzimos-update-worker"
            || program == "/usr/lib/enzimos-backend/enzimos-secret-validator",
        "fixed executable path required",
    )?;
    require(
        input.len() <= 2 * 1024 * 1024 && limit <= 32 * 1024 * 1024 && !timeout.is_zero(),
        "command bounds",
    )?;
    require(descriptors.len() <= 8, "inherited descriptor bound")?;
    let mut inherited = Vec::<OwnedFd>::new();
    for file in descriptors {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        require(fd >= 0, "inherited descriptor duplication failed")?;
        inherited.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let mapping = inherited.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
    let descriptor_aliases = mapping
        .iter()
        .map(|fd| format!("/proc/self/fd/{fd}"))
        .collect();
    let arguments = args
        .iter()
        .map(|arg| {
            if let Some(index) = arg
                .strip_prefix("@fd:")
                .or_else(|| arg.strip_prefix("@fd-dir:"))
                .or_else(|| arg.strip_prefix("@fd-number:"))
            {
                let index = index
                    .parse::<usize>()
                    .map_err(|_| Error("descriptor argument index".into()))?;
                let fd = mapping
                    .get(index)
                    .ok_or_else(|| Error("descriptor argument unavailable".into()))?;
                if arg.starts_with("@fd-number:") {
                    return Ok(fd.to_string());
                }
                if arg.starts_with("@fd-dir:") {
                    require(
                        std::fs::File::from(inherited[index].try_clone()?)
                            .metadata()?
                            .is_dir(),
                        "directory descriptor argument required",
                    )?;
                }
                Ok(format!(
                    "/proc/self/fd/{fd}{}",
                    if arg.starts_with("@fd-dir:") {
                        "/."
                    } else {
                        ""
                    }
                ))
            } else {
                Ok((*arg).to_owned())
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let image_alias = if let Some(file) = image {
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
        require(fd >= 0, "pinned executable descriptor duplication failed")?;
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        None
    };
    let image_path = image_alias
        .as_ref()
        .map(|file| format!("/proc/self/fd/{}", file.as_raw_fd()));
    let mut command = Command::new(image_path.as_deref().unwrap_or(program));
    command.arg0(program);
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if program == "/usr/bin/blkid" {
        command
            .env("BLKID_CONF", "/dev/null")
            .env("BLKID_FILE", "/dev/null");
    }
    if offline_cryptsetup {
        require(
            program == "/usr/bin/cryptsetup",
            "fixed independent cryptsetup required",
        )?;
        command.env("DM_DISABLE_UDEV", "1");
    }
    // Long Restic roles journal their own progress lines (one per 30 s).
    let journal_progress = local_restic
        .as_ref()
        .is_some_and(super::super::local_restic::Consumer::progresses);
    let remote = matches!(local_restic, Some(crate::local_restic::Consumer::Remote(_)));
    if let Some(task) = local_restic.as_ref() {
        let rotation_prepare = matches!(task, crate::local_restic::Consumer::RotationPrepare(_));
        let remote = matches!(task, crate::local_restic::Consumer::Remote(_));
        let readonly = matches!(task,crate::local_restic::Consumer::Remote(invocation) if invocation.read_only());
        require(
            program == "/usr/bin/restic"
                && if remote {
                    isolated_network && mapping.len() == if readonly { 2 } else { 4 }
                } else if rotation_prepare {
                    isolated_network && mapping.len() == 5
                } else {
                    isolated_network
                        && mapping.len()
                            == if matches!(
                                task,
                                crate::local_restic::Consumer::CredentialEnroll
                                    | crate::local_restic::Consumer::RestoreSystem(_)
                                    | crate::local_restic::Consumer::RestoreComplete(_)
                            ) {
                                4
                            } else {
                                3
                            }
                },
            "closed Restic execution context required",
        )?;
        crate::local_restic::environment(
            &mut command,
            mapping[if rotation_prepare {
                4
            } else if readonly {
                1
            } else if remote
                || matches!(
                    task,
                    crate::local_restic::Consumer::CredentialEnroll
                        | crate::local_restic::Consumer::RestoreSystem(_)
                        | crate::local_restic::Consumer::RestoreComplete(_)
                )
            {
                3
            } else {
                2
            }],
            task,
        );
    }
    let boot_image = if complete_boot.is_some() {
        use std::os::unix::fs::MetadataExt;
        let file = image.ok_or_else(|| Error("complete boot native image required".into()))?;
        let m = file.metadata()?;
        Some((
            image_alias
                .as_ref()
                .ok_or_else(|| Error("complete boot image alias missing".into()))?
                .as_raw_fd(),
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.size(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ))
    } else {
        None
    };
    let parent = std::process::id() as libc::pid_t;
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Only the owned child changes namespace. Failure stops spawn;
            // it never retries in the caller's network namespace.
            if let Some(crate::local_restic::Consumer::Backup(prepared)) = local_restic.as_ref() {
                prepared.enter_child()?;
            }
            if let Some(crate::local_restic::Consumer::Remote(invocation)) = local_restic.as_ref() {
                invocation.attachment.enter_child()?;
                if let Some(sources) = invocation.sources.as_ref() {
                    sources.enter_private_child()?;
                }
            }
            if let Some(context) = complete_boot.as_ref() {
                context.enter_child()?;
                // The original parent image was opened on a noexec data mount.
                // Rebind only its independently pinned inode through the actual
                // new executable root clone; never substitute another image.
                if let Some((
                    alias,
                    dev,
                    ino,
                    mode,
                    uid,
                    gid,
                    size,
                    mtime,
                    mtime_ns,
                    ctime,
                    ctime_ns,
                )) = boot_image
                {
                    let replacement = libc::open(
                        c"/usr/bin/chroot".as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    );
                    if replacement < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    let mut m: libc::stat = std::mem::zeroed();
                    if libc::fstat(replacement, &mut m) != 0
                        || (
                            m.st_dev,
                            m.st_ino,
                            m.st_mode,
                            m.st_uid,
                            m.st_gid,
                            m.st_size as u64,
                            m.st_mtime,
                            m.st_mtime_nsec,
                            m.st_ctime,
                            m.st_ctime_nsec,
                        ) != (
                            dev, ino, mode, uid, gid, size, mtime, mtime_ns, ctime, ctime_ns,
                        )
                    {
                        libc::close(replacement);
                        return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
                    }
                    if libc::dup3(replacement, alias, libc::O_CLOEXEC) < 0 {
                        libc::close(replacement);
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::close(replacement);
                }
            }
            if isolated_network {
                offline_namespace()?;
            }
            if complete_boot.is_some()
                || isolated_network
                || matches!(local_restic, Some(crate::local_restic::Consumer::Remote(_)))
            {
                // No ambient socket or supervisor channel may survive exec.
                // Explicit reviewed directory/file mappings are restored below.
                if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(task) = local_restic.as_ref() {
                crate::local_restic::confine_child(task)?;
            }
            for original in &mapping {
                if libc::fcntl(*original, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    if let Some(check) = boundary.as_mut() {
        check()?;
    }
    let mut child = OwnedChild(
        command.spawn().map_err(|e| {
            if remote {
                crate::remote_restic::mount_refusal(&e)
            } else {
                e.into()
            }
        })?,
        false,
    );
    let mut stdin = child.0.stdin.take();
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| Error("stdout unavailable".into()))?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| Error("stderr unavailable".into()))?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    if let Some(s) = &stdin {
        nonblocking(s.as_raw_fd())?;
    }
    let mut watchdog = Watchdog::new(Instant::now(), timeout, stall);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut out_done, mut err_done, mut sent) = (false, false, 0);
    let mut exited = false;
    let mut exited_at: Option<std::time::Instant> = None;
    let mut group_killed = false;
    let mut last_boundary = Instant::now();
    let mut progress_from = 0;
    loop {
        if last_boundary.elapsed() >= Duration::from_millis(200) {
            if let Some(check) = boundary.as_mut() {
                check()?;
            }
            last_boundary = Instant::now();
        }
        watchdog.check(Instant::now())?;
        if let Some(s) = &mut stdin {
            if sent < input.len() {
                match s.write(&input[sent..]) {
                    Ok(n) => sent += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                        stdin = None;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if sent == input.len() {
                stdin = None;
            }
        }
        let produced = out.len() + err.len();
        if !out_done {
            let before = out.len();
            out_done = drain(&mut stdout, &mut out, limit, program, "stdout")?;
            if out.len() > before {
                if let Some(callback) = observer.as_mut() {
                    callback(&out[before..])?;
                }
                if journal_progress
                    && let Some(end) = out[progress_from..].iter().rposition(|b| *b == b'\n')
                {
                    let end = progress_from + end;
                    if let Some(line) = crate::local_restic::progress_line(&out[progress_from..end])
                    {
                        eprintln!("{line}");
                    }
                    progress_from = end + 1;
                }
            }
        }
        if !err_done {
            let before = err.len();
            err_done = drain(
                &mut stderr,
                &mut err,
                stderr_limit(limit),
                program,
                "stderr",
            )?;
            echo(program, &err[before..]);
        }
        if out.len() + err.len() > produced {
            watchdog.activity(Instant::now());
        }
        if !exited {
            // Keep the exited leader unreaped until group cleanup, preventing its
            // PID from being reused between observation and the final signal.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.0.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            exited = unsafe { info.si_pid() } != 0;
            if exited {
                exited_at = Some(std::time::Instant::now());
            }
        }
        // A descendant that keeps stdout/stderr open after the leader exited
        // would hold this loop until the command deadline and turn a finished
        // command into "deadline exceeded". The group is killed at the end
        // anyway: do it after a short grace so the pipes reach end of file.
        if exited
            && !(out_done && err_done)
            && !group_killed
            && exited_at.is_some_and(|at| at.elapsed() >= Duration::from_secs(2))
        {
            unsafe {
                libc::kill(-(child.0.id() as i32), libc::SIGKILL);
            }
            group_killed = true;
        }
        if exited && out_done && err_done {
            unsafe {
                libc::kill(-(child.0.id() as i32), libc::SIGKILL);
            }
            let status = child.0.wait()?;
            child.1 = true;
            if let Some(check) = boundary.as_mut() {
                check()?;
            }
            return Ok(Output {
                status,
                stdout: out,
                stderr: err,
                descriptor_aliases,
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
