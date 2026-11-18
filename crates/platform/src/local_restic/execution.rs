use super::*;

pub(super) fn execute_role(
    task: Consumer,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role_extended(
        task, image, repository, credential, None, None, scratch, boundary,
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, fstatfs, geteuid).")]
pub(super) fn execute_role_extended(
    task: Consumer,
    image: &File,
    repository: &File,
    credential: &File,
    next: Option<&File>,
    target: Option<&File>,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    require(
        matches!(task, Consumer::CredentialEnroll) == next.is_some(),
        "closed enrollment descriptor roles required",
    )?;
    require(
        matches!(
            task,
            Consumer::RestoreSystem(_) | Consumer::RestoreComplete(_)
        ) == target.is_some(),
        "closed system staging descriptor role required",
    )?;
    let original_target = target
        .map(|file| -> Result<_> {
            let m = file.metadata()?;
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            require(
                m.is_dir()
                    && m.ino() == 256
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7777 == 0o700
                    && flags >= 0
                    && flags & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY,
                "original private system stage descriptor required",
            )?;
            Ok((
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()),
                flags,
                mount_identity::id(file.as_fd(), true)?,
            ))
        })
        .transpose()?;
    let extra = next
        .map(|file| -> Result<_> {
            let m = file.metadata()?;
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            let current = credential.metadata()?;
            require(
                m.is_file()
                    && m.uid() == 0
                    && m.gid() == 0
                    && matches!(m.mode() & 0o7777, 0o400 | 0o600)
                    && m.nlink() == 1
                    && (1..=4096).contains(&m.len())
                    && flags >= 0
                    && flags & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY
                    && (m.dev(), m.ino()) != (current.dev(), current.ino()),
                "original distinct protected next-password descriptor required",
            )?;
            Ok((
                files::identity(&m),
                flags,
                mount_identity::id(file.as_fd(), true)?,
            ))
        })
        .transpose()?;
    require(
        unsafe { libc::geteuid() } == 0,
        "Root local consumer required",
    )?;
    let r = repository.metadata()?;
    let c = credential.metadata()?;
    let s = scratch.metadata()?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        r.is_dir()
            && r.uid() == 0
            && r.mode() & 0o022 == 0
            && c.is_file()
            && c.uid() == 0
            && c.gid() == 0
            && if matches!(
                task,
                Consumer::CredentialReview(_)
                    | Consumer::CredentialEnroll
                    | Consumer::Retain(_)
                    | Consumer::Rewrite(_)
                    | Consumer::RestoreSystem(_)
                    | Consumer::RestoreComplete(_)
                    | Consumer::Selective(..)
                    | Consumer::SelectivePlan(..)
                    | Consumer::RotationRead(..)
            ) {
                matches!(c.mode() & 0o7777, 0o400 | 0o600)
            } else {
                c.mode() & 0o7777 == 0o600
            }
            && c.nlink() == 1
            && (1..=4096).contains(&c.len())
            && unsafe { libc::fcntl(credential.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
                == libc::O_RDONLY
            && s.is_dir()
            && s.uid() == 0
            && s.gid() == 0
            && s.mode() & 0o7777 == 0o700
            && unsafe { libc::fstatfs(scratch.as_raw_fd(), &mut fs) } == 0
            && fs.f_type == 0x01021994,
        "original protected local Restic descriptors required",
    )?;
    enforce_role(
        &task,
        &files::read_kernel(
            Path::new("/sys/kernel/security/apparmor/profiles"),
            1024 * 1024,
        )?,
    )?;
    let original = [files::identity(&image.metadata()?), files::identity(&c)];
    let directories = [
        (r.dev(), r.ino(), r.mode(), r.uid(), r.gid()),
        (s.dev(), s.ino(), s.mode(), s.uid(), s.gid()),
    ];
    let mounts = [
        mount_identity::id(repository.as_fd(), true)?,
        mount_identity::id(credential.as_fd(), true)?,
        mount_identity::id(scratch.as_fd(), true)?,
    ];
    let status = [image, repository, credential, scratch]
        .map(|file| unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) });
    require(
        status.iter().all(|flags| *flags >= 0),
        "original Restic descriptor flags unavailable",
    )?;
    let check = || -> Result<()> {
        if let (Some(target), Some((shape, expected_flags, mount))) = (target, original_target) {
            let m = target.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()) == shape
                    && unsafe { libc::fcntl(target.as_raw_fd(), libc::F_GETFL) } == expected_flags
                    && mount_identity::id(target.as_fd(), true)? == mount,
                "original system staging description changed/covered",
            )?;
        }
        for (file, flags) in [image, repository, credential, scratch]
            .into_iter()
            .zip(status)
        {
            require(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } == flags,
                "original Restic shared descriptor status changed",
            )?;
        }
        if let (Some(file), Some((epoch, flags, mount))) = (next, extra.as_ref()) {
            require(
                files::identity(&file.metadata()?) == *epoch
                    && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } == *flags
                    && mount_identity::id(file.as_fd(), true)? == *mount,
                "original next-password inode/status/mount changed; no replay",
            )?;
        }
        enforce_role(
            &task,
            &files::read_kernel(
                Path::new("/sys/kernel/security/apparmor/profiles"),
                1024 * 1024,
            )?,
        )?;
        require(
            files::identity(&image.metadata()?) == original[0]
                && files::identity(&credential.metadata()?) == original[1],
            "local consumer image/credential changed; no replay",
        )?;
        for (index, directory) in [repository, scratch].iter().enumerate() {
            let m = directory.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()) == directories[index],
                "local consumer original directory changed",
            )?;
        }
        for (index, file) in [repository, credential, scratch].iter().enumerate() {
            require(
                mount_identity::id(file.as_fd(), true)? == mounts[index],
                "local consumer mount changed",
            )?;
        }
        Ok(())
    };
    check()?;
    let mut ongoing = || {
        check()?;
        boundary()
    };
    let mut descriptors = vec![repository.as_fd(), credential.as_fd()];
    if let Some(file) = next {
        descriptors.push(file.as_fd());
    }
    if let Some(target) = target {
        descriptors.push(target.as_fd());
    }
    descriptors.push(scratch.as_fd());
    let output = process::local_restic(
        image,
        &task.arguments(),
        task.timeout(),
        task.output_limit(),
        &descriptors,
        task.clone(),
        &mut ongoing,
    )?;
    check()?;
    Ok(output)
}
/// One bounded journal line for the newest Restic JSON status row in `bytes`
/// (complete lines only): counts and elapsed time, never a path or message.
pub(crate) fn progress_line(bytes: &[u8]) -> Option<String> {
    let row = bytes.split(|b| *b == b'\n').rev().find_map(|line| {
        let v: serde_json::Value = serde_json::from_slice(line).ok()?;
        (v["message_type"] == "status" || v["message_type"] == "verbose_status").then_some(v)
    })?;
    let n = |key: &str| row[key].as_u64().unwrap_or(0);
    Some(format!(
        "restic progress: {:.1}% files {}/{} bytes {}/{} errors {} elapsed {}s",
        row["percent_done"].as_f64().unwrap_or(0.0) * 100.0,
        n("files_done"),
        n("total_files"),
        n("bytes_done"),
        n("total_bytes"),
        n("error_count"),
        n("seconds_elapsed"),
    ))
}
pub(crate) fn environment(command: &mut Command, scratch: i32, task: &Consumer) {
    if task.progresses() {
        command.env("RESTIC_PROGRESS_FPS", PROGRESS_FPS);
    }
    if matches!(task, Consumer::Remote(_)) {
        // Restic's advice for repositories on CIFS: Go's asynchronous
        // preemption interrupts file system calls with EINTR.
        command.env("GODEBUG", "asyncpreemptoff=1");
    }
    command
        .env("HOME", "/nonexistent")
        .env("TMPDIR", format!("/proc/self/fd/{scratch}/."))
        .env("GOMAXPROCS", "1")
        .env(
            "GOMEMLIMIT",
            if matches!(task, Consumer::Points) {
                "256MiB"
            } else {
                "512MiB"
            },
        );
}
// No allocations, locks or parent mutations between fork and exec. AppArmor's
// namespaced proc attribute is mandatory; an absent LSM has no fallback.
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (close, open, prctl, setrlimit and others)."
)]
pub(crate) unsafe fn confine_child(task: &Consumer) -> std::io::Result<()> {
    if matches!(
        task,
        Consumer::Backup(_)
            | Consumer::Remote(_)
            | Consumer::CredentialReview(_)
            | Consumer::CredentialEnroll
            | Consumer::Retain(_)
            | Consumer::RestoreSystem(_)
            | Consumer::RestoreComplete(_)
            | Consumer::Selective(..)
            | Consumer::SelectivePlan(..)
            | Consumer::RotationRead(..)
            | Consumer::RotationPrepare(..)
    ) {
        unsafe {
            backup_capabilities(matches!(
                task,
                Consumer::RestoreSystem(_) | Consumer::RestoreComplete(_)
            ))?;
        }
    }
    let fd = unsafe {
        libc::open(
            c"/proc/thread-self/attr/apparmor/exec".as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let name: &[u8] = match task {
        Consumer::Remote(task) => match task.profile() {
            "enzimos-restic-native-retrieve" => b"exec enzimos-restic-native-retrieve",
            "enzimos-restic-native-remote-check" => b"exec enzimos-restic-native-remote-check",
            "enzimos-restic-native-remote-initialize" => {
                b"exec enzimos-restic-native-remote-initialize"
            }
            "enzimos-restic-native-remote-rotation-read" => {
                b"exec enzimos-restic-native-remote-rotation-read"
            }
            _ => b"exec enzimos-restic-native-replicate",
        },
        Consumer::Workflow(Task::AuthenticateInput) => b"exec enzimos-restic-input-check",
        Consumer::Workflow(_) => b"exec enzimos-restic-provision",
        Consumer::CredentialReview(_) => b"exec enzimos-restic-credential-review",
        Consumer::CredentialEnroll => b"exec enzimos-restic-credential-enroll",
        Consumer::Retain(_) | Consumer::Rewrite(_) => b"exec enzimos-restic-retain",
        Consumer::RestoreSystem(_) => b"exec enzimos-restic-restore-system",
        Consumer::RestoreComplete(_) => b"exec enzimos-restic-restore-complete",
        Consumer::Points => b"exec enzimos-restic-points",
        Consumer::Selective(..) => b"exec enzimos-restic-selective",
        Consumer::SelectivePlan(..) => b"exec enzimos-restic-selective-plan",
        Consumer::RotationRead(..) => b"exec enzimos-restic-rotation-read",
        Consumer::RotationPrepare(..) => b"exec enzimos-restic-native-rotation-prepare",
        Consumer::Backup(_) => b"exec enzimos-restic-native-backup",
    };
    let written = unsafe { libc::write(fd, name.as_ptr().cast(), name.len()) };
    let error = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if written != name.len() as isize {
        return Err(error);
    }
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let file_limit = if matches!(
        task,
        Consumer::RestoreSystem(_) | Consumer::RestoreComplete(_)
    ) {
        1024u64 * 1024 * 1024 * 1024
    } else {
        64 * 1024 * 1024
    };
    let size = libc::rlimit {
        rlim_cur: file_limit,
        rlim_max: file_limit,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } != 0
        || unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &size) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
// Ordinary consumers keep DAC_OVERRIDE; staging also retains only the metadata
// capabilities needed inside its mandatory non-executable target profile. In particular,
// DAC_READ_SEARCH (open_by_handle_at), mount, ptrace and network authority cannot
// survive exec. No allocations or parent capability mutations occur here.
pub(super) fn capability_mask(restore: bool) -> u32 {
    if restore {
        (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 31)
    } else {
        1 << 1
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (prctl, syscall).")]
unsafe fn backup_capabilities(restore: bool) -> std::io::Result<()> {
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
    for capability in 0..64 {
        if capability == 1 || restore && matches!(capability, 0 | 3 | 4 | 31) {
            continue;
        }
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(error);
        }
    }
    let allowed = capability_mask(restore);
    data[0].effective &= allowed;
    data[0].permitted &= allowed;
    data[0].inheritable = 0;
    data[1] = Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
