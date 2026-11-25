// SPDX-License-Identifier: MIT
//! One RAM-only complete-data publication; no boot selection or authority replay.
use super::{Source, Target};
use crate::{
    backup_admission, backup_configuration, backup_destination, backup_ram_quiet,
    backup_ram_source,
    control_record::Observation,
    operation,
    settings_command::{BootTool, Command},
    subvolume,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
    time::Duration,
};
const FOLDER: &str = "backup-complete-stages";
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn open_member(parent: &File, name: &std::ffi::OsStr, flags: i32) -> Result<File> {
    let name =
        CString::new(name.as_bytes()).map_err(|_| Error("replacement member encoding".into()))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    require(fd >= 0, "original replacement member unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn checked_mount(file: &File, mount: u64) -> Result<()> {
    require(
        mount_identity::id(file.as_fd(), true)? == mount,
        "replacement traversal crosses a mount boundary",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn remove_contents(
    parent: &File,
    mount: u64,
    remaining: &mut usize,
    depth: usize,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    require(depth <= 64, "replacement metadata depth bound")?;
    checked_mount(parent, mount)?;
    for leaf in files::directory_names(parent, (*remaining).max(1))? {
        require(*remaining > 0, "replacement metadata count bound")?;
        *remaining -= 1;
        authorize()?;
        let held = open_member(parent, &leaf, libc::O_PATH)?;
        checked_mount(&held, mount)?;
        let before = files::identity(&held.metadata()?);
        let metadata = held.metadata()?;
        require(
            metadata.uid() == 0 && metadata.gid() == 0,
            "foreign restored service metadata refused",
        )?;
        if metadata.is_dir() {
            require(
                metadata.ino() != 256,
                "nested restored metadata subvolume refused",
            )?;
            let directory = open_member(parent, &leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
            require(
                files::identity(&directory.metadata()?) == before,
                "restored metadata directory changed",
            )?;
            remove_contents(&directory, mount, remaining, depth + 1, authorize)?;
            let named = open_member(parent, &leaf, libc::O_PATH)?;
            require(
                (named.metadata()?.dev(), named.metadata()?.ino())
                    == (metadata.dev(), metadata.ino())
                    && files::directory_names(&directory, 1)?.is_empty(),
                "original restored metadata directory replaced/not empty",
            )?;
            let name = CString::new(leaf.as_bytes())
                .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
            authorize()?;
            require(
                unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                    == 0,
                "owned restored metadata directory removal failed",
            )?;
        } else {
            require(
                metadata.is_file() || metadata.file_type().is_symlink(),
                "special restored service metadata refused",
            )?;
            let named = open_member(parent, &leaf, libc::O_PATH)?;
            require(
                files::identity(&held.metadata()?) == before
                    && files::identity(&named.metadata()?) == before,
                "original restored metadata member replaced/changed",
            )?;
            let name = CString::new(leaf.as_bytes())
                .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
            authorize()?;
            require(
                unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0,
                "owned restored metadata member removal failed",
            )?;
        }
        parent.sync_all()?;
        authorize()?;
    }
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod).")]
fn placeholder(root: &File, path: &str, mode: u32, mount: u64) -> Result<File> {
    let dir = files::ensure_directory_relative(root, Path::new(path), mode, 0)?;
    checked_mount(&dir, mount)?;
    require(
        files::directory_names(&dir, 1)?.is_empty(),
        "captured mount placeholder content refused",
    )?;
    require(
        unsafe { libc::fchmod(dir.as_raw_fd(), mode) } == 0,
        "restored placeholder mode failed",
    )?;
    dir.sync_all()?;
    Ok(dir)
}
fn publish(parent: &File, name: &str, body: &[u8], mount: u64) -> Result<File> {
    checked_mount(parent, mount)?;
    match files::optional_relative(parent, Path::new(name))? {
        Some(original) => files::atomic_replace_original(
            parent,
            Path::new(name),
            body,
            0o644,
            Some(0),
            2 * 1024 * 1024,
            &original,
        ),
        None => files::atomic_relative_retained(
            parent,
            Path::new(name),
            body,
            0o644,
            Some(0),
            false,
            2 * 1024 * 1024,
        ),
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
fn freeze(
    stage: &Target,
    guard: &Source<'_>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    authorize()?;
    stage.recheck(guard)?;
    let mut flags = 0u64;
    require(
        unsafe {
            libc::ioctl(
                stage.directory.as_raw_fd(),
                0x80089419 as libc::c_ulong,
                &mut flags,
            )
        } == 0
            && flags == 0,
        "original stage subvolume flags differ",
    )?;
    flags = 2;
    require(
        unsafe {
            libc::ioctl(
                stage.directory.as_raw_fd(),
                0x4008941a as libc::c_ulong,
                &flags,
            )
        } == 0,
        "stage readonly transition failed; publishing receipt retained",
    )?;
    stage.readonly.set(true);
    stage.recheck(guard)?;
    authorize()
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod).")]
fn copy_tree(
    command: &Command,
    source: &File,
    target: &Target,
    guard: &Source<'_>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    authorize()?;
    target.recheck(guard)?;
    require(
        files::directory_names(&target.directory, 1)?.is_empty(),
        "replacement changed before sole copy entry",
    )?;
    let m = source.metadata()?;
    require(
        m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7022 == 0,
        "original complete source root owner/mode differs",
    )?;
    // The readonly stage prevents source replacement during the archive copy.
    // Only this actual producer may advance the destination root's mode to755.
    target.copying.set(Some(m.mode() & 0o7777));
    let result = command.run_fds_authorized(
        &[
            "--archive",
            "--reflink=always",
            "--",
            "@fd-dir:0",
            "@fd-dir:1",
        ],
        Duration::from_secs(86400),
        65536,
        &[source.as_fd(), target.directory.as_fd()],
        &mut || {
            authorize()?;
            target.recheck(guard)
        },
    )?;
    authorize()?;
    require(
        result.status.success(),
        "replacement archive copy failed; publishing receipt retained",
    )?;
    require(
        unsafe { libc::fchmod(target.directory.as_raw_fd(), 0o755) } == 0,
        "replacement root mode publication failed",
    )?;
    target.final_mode.set(true);
    target.copying.set(None);
    target.recheck(guard)?;
    subvolume::sync(target.directory.as_fd())?;
    authorize()
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, openat, unlinkat).")]
pub fn prepare_locked(
    lock: &files::Lock,
    stage_uuid: &str,
    root_uuid: &str,
    home_uuid: &str,
    boot_uuid: &str,
    luks_uuid: Option<&str>,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    for uuid in [stage_uuid, root_uuid, home_uuid] {
        crate::identity::uuid(uuid)?;
    }
    require(
        stage_uuid != root_uuid && stage_uuid != home_uuid && root_uuid != home_uuid,
        "replacement aliases stage or home",
    )?;
    let ram = backup_ram_source::Source::observe()?;
    let guard = Source::Ram(&ram);
    let fresh = crate::backup_restore_layout::layout(
        enzimos_platform::json::string(&ram.configuration()["filesystem_uuid"])?,
        boot_uuid,
        luks_uuid,
        false,
    )?;
    require(
        enzimos_platform::json::object(&fresh["storage"])?
            .iter()
            .all(|(key, v)| ram.configuration()[key] == *v),
        "fixed fresh replacement storage layout required",
    )?;
    let quiet = backup_ram_quiet::Quiet::observe(&ram)?;
    let config = backup_configuration::Configuration::open()?;
    let destination = backup_destination::ram::Destination::open(&config, &ram)?;
    let pin = backup_admission::ram::Repository::open(&destination)?;
    let parent = files::directory_relative(ram.control(), Path::new(FOLDER), Some(0))?;
    require(
        parent.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(parent.as_fd(), true)? == ram.control_mount_id(),
        "private complete stage registry required",
    )?;
    let parent_shape = {
        let m = parent.metadata()?;
        (m.dev(), m.ino(), m.mode(), m.uid(), m.gid())
    };
    let mut names = std::collections::BTreeSet::new();
    let mut others = Vec::new();
    let mut chosen = None;
    for leaf in files::directory_names(&parent, 16)? {
        let leaf = leaf
            .into_string()
            .map_err(|_| Error("complete stage registry encoding".into()))?;
        let id = leaf
            .strip_suffix(".json")
            .ok_or_else(|| Error("unknown/interrupted complete stage member".into()))?;
        crate::identity::uuid(id)?;
        let original = Observation::open(
            &parent,
            Path::new(&leaf),
            256 * 1024,
            ram.control_mount_id(),
        )?;
        if id == stage_uuid {
            super::validate(original.value()?, id)?;
            require(
                original.value()?["phase"] == "staged",
                "complete stage unavailable/already published; no replay",
            )?;
            chosen = Some(original);
        } else {
            super::validate_complete(original.value()?, id)?;
            require(
                matches!(
                    original.value()?["phase"].as_str(),
                    Some("staged" | "data-prepared-not-bootable" | "uefi-boot-prepared")
                ),
                "uncertain complete stage requires review",
            )?;
            others.push(original);
        }
        names.insert(leaf);
    }
    let mut receipt =
        chosen.ok_or_else(|| Error("original complete stage receipt missing".into()))?;
    let stage = Target::observe_at(&guard, stage_uuid, super::TARGET, None, false)?;
    require(
        stage.evidence(&guard)? == receipt.value()?["target"],
        "actual complete stage differs from original receipt",
    )?;
    let root = Target::observe_at(
        &guard,
        root_uuid,
        "/restore-system",
        Some("enzimos-root"),
        true,
    )?;
    let home = Target::observe_at(
        &guard,
        home_uuid,
        "/restore-home",
        Some("enzimos-home"),
        true,
    )?;
    let command = Command::open_boot(BootTool::CopyRestore)?;
    let pacman = Command::open("/usr/bin/pacman")?;
    let base = || -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        lock.recheck()?;
        ram.recheck()?;
        quiet.recheck(&ram)?;
        config.recheck()?;
        destination.recheck()?;
        pin.recheck()?;
        stage.recheck(&guard)?;
        root.recheck(&guard)?;
        home.recheck(&guard)?;
        command.recheck()?;
        pacman.recheck()?;
        let named = files::directory_relative(ram.control(), Path::new(FOLDER), Some(0))?;
        for d in [&parent, &named] {
            let m = d.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()) == parent_shape
                    && mount_identity::id(d.as_fd(), true)? == ram.control_mount_id(),
                "original complete stage registry replaced/covered",
            )?;
        }
        let current = files::directory_names(&parent, 16)?
            .into_iter()
            .map(|n| {
                n.into_string()
                    .map_err(|_| Error("complete registry encoding".into()))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        require(current == names, "complete stage family membership changed")?;
        for original in &others {
            original.recheck()?;
        }
        Ok(())
    };
    base()?;
    receipt.recheck()?;
    let mut record = receipt.value()?.clone();
    record["phase"] = value!("publishing");
    record["replacement"] = value!({"root":{"object":root.object,"mount":root.evidence(&guard)?["mount"]},"home":{"object":home.object,"mount":home.evidence(&guard)?["mount"]},"layout":fresh});
    super::validate_complete(&record, stage_uuid)?;
    receipt.replace_original(&record)?;
    let entered = || {
        base()?;
        receipt.recheck()
    };
    freeze(&stage, &guard, &mut || entered())?;
    let source = files::directory_relative(&stage.directory, Path::new("backup-source"), Some(0))?;
    checked_mount(&source, stage.mount)?;
    let mut sources = Vec::new();
    for name in ["system", "home", "boot", "inventory"] {
        let file = files::directory_relative(&source, Path::new(name), Some(0))?;
        checked_mount(&file, stage.mount)?;
        sources.push(file);
    }
    let scope_file = files::open_relative(&sources[3], Path::new("scope.json"))?;
    checked_mount(&scope_file, stage.mount)?;
    let scope = json::decode(
        &files::read_file(&scope_file, 2 * 1024 * 1024, Some(0), true)?,
        2 * 1024 * 1024,
    )?;
    require(
        scope["sources"] == value!([["root", "/", "system"], ["home", "/home", "home"]]),
        "additional datasets require explicit replacement layout",
    )?;
    let inventory = files::open_relative(&sources[3], Path::new("packages.txt"))?;
    checked_mount(&inventory, stage.mount)?;
    let packages = files::read_file(&inventory, 2 * 1024 * 1024, Some(0), true)?;
    copy_tree(&command, &sources[0], &root, &guard, &mut || entered())?;
    copy_tree(&command, &sources[1], &home, &guard, &mut || entered())?;
    let queried = pacman.run_fds_authorized(
        &[
            "--root",
            "@fd:0",
            "--config",
            crate::recovery_context::QUERY_CONFIG,
            "-Q",
        ],
        Duration::from_secs(120),
        2 * 1024 * 1024,
        &[root.directory.as_fd()],
        &mut || entered(),
    )?;
    require(
        queried.status.success()
            && std::str::from_utf8(&queried.stdout)
                .map_err(|_| Error("replacement package output encoding".into()))?
                .trim()
                == std::str::from_utf8(&packages)
                    .map_err(|_| Error("stage package inventory encoding".into()))?
                    .trim(),
        "restored package inventory differs",
    )?;
    let config_dir = files::directory_relative(&root.directory, Path::new("etc/enzimos"), Some(0))?;
    checked_mount(&config_dir, root.mount)?;
    for name in [
        "backup.password",
        "backup.json",
        "backup.next-password",
        "backup.rotation-password",
        "backup.retired-password",
        "backup-remote.password",
        "backup-remote.identity",
        "backup-remote.share-password",
    ] {
        require(
            files::optional_relative(&config_dir, Path::new(name))?.is_none(),
            "restored backup access material refused",
        )?;
    }
    for (path, mode) in [
        ("var/lib/enzimos-control", 0o700),
        ("etc/pacman.d/gnupg", 0o700),
        ("boot", 0o755),
        ("home", 0o755),
        ("dev", 0o755),
        ("proc", 0o755),
        ("sys", 0o755),
        ("run", 0o755),
        ("tmp", 0o1777),
        ("var/tmp", 0o1777),
        ("swap", 0o700),
        ("backup-source", 0o700),
        ("backup-repository", 0o700),
        ("restore-target", 0o700),
    ] {
        entered()?;
        placeholder(&root.directory, path, mode, root.mount)?;
    }
    let state =
        files::ensure_directory_relative(&root.directory, Path::new("var/lib/enzimos"), 0o700, 0)?;
    remove_contents(&state, root.mount, &mut 262144, 0, &mut || entered())?;
    require(
        unsafe { libc::fchmod(state.as_raw_fd(), 0o700) } == 0,
        "restored service state private mode failed",
    )?;
    if let Some(timers) = files::optional_directory_relative(
        &root.directory,
        Path::new("etc/systemd/system/timers.target.wants"),
        Some(0),
    )? {
        checked_mount(&timers, root.mount)?;
        let name = c"enzimos-backup.timer";
        let raw = unsafe {
            libc::openat(
                timers.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw >= 0 {
            let original = unsafe { File::from_raw_fd(raw) };
            checked_mount(&original, root.mount)?;
            require(
                original.metadata()?.file_type().is_symlink(),
                "unexpected restored backup timer object",
            )?;
            let epoch = files::identity(&original.metadata()?);
            entered()?;
            let named = open_member(
                &timers,
                std::ffi::OsStr::new("enzimos-backup.timer"),
                libc::O_PATH,
            )?;
            require(
                files::identity(&named.metadata()?) == epoch,
                "original restored timer replaced",
            )?;
            require(
                unsafe { libc::unlinkat(timers.as_raw_fd(), name.as_ptr(), 0) } == 0,
                "restored timer retirement failed",
            )?;
            timers.sync_all()?;
        } else {
            require(
                std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
                "restored timer observation failed",
            )?;
        }
    }
    let etc = files::directory_relative(&root.directory, Path::new("etc"), Some(0))?;
    let writes = [
        publish(
            &etc,
            "fstab",
            enzimos_platform::json::string(&fresh["fstab"])?.as_bytes(),
            root.mount,
        )?,
        publish(
            &etc,
            "crypttab",
            enzimos_platform::json::string(&fresh["crypttab"])?.as_bytes(),
            root.mount,
        )?,
        publish(
            &config_dir,
            "storage.json",
            &json::canonical(&fresh["storage"])?,
            root.mount,
        )?,
    ];
    for target in [&root, &home] {
        entered()?;
        if let Some(old) =
            files::optional_directory_relative(&target.directory, Path::new(".snapshots"), Some(0))?
        {
            checked_mount(&old, target.mount)?;
            require(
                old.metadata()?.ino() != 256 && files::directory_names(&old, 1)?.is_empty(),
                "captured snapshot history refused",
            )?;
            let epoch = files::identity(&old.metadata()?);
            let named =
                files::directory_relative(&target.directory, Path::new(".snapshots"), Some(0))?;
            require(
                files::identity(&named.metadata()?) == epoch,
                "restored history directory replaced",
            )?;
            require(
                unsafe {
                    libc::unlinkat(
                        target.directory.as_raw_fd(),
                        c".snapshots".as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                } == 0,
                "restored empty history removal failed",
            )?;
        }
        entered()?;
        subvolume::new(target.directory.as_fd(), ".snapshots")?;
        let history =
            files::directory_relative(&target.directory, Path::new(".snapshots"), Some(0))?;
        checked_mount(&history, target.mount)?;
        require(
            history.metadata()?.ino() == 256
                && subvolume::observe(history.as_fd(), ".snapshots")?.0["parent_uuid"].is_null(),
            "created restored history is not a new subvolume",
        )?;
        require(
            unsafe { libc::fchmod(history.as_raw_fd(), 0o750) } == 0,
            "created history mode failed",
        )?;
        subvolume::sync(target.directory.as_fd())?;
    }
    entered()?;
    for (parent, name, file) in [
        (&etc, "fstab", &writes[0]),
        (&etc, "crypttab", &writes[1]),
        (&config_dir, "storage.json", &writes[2]),
    ] {
        let named = files::open_relative(parent, Path::new(name))?;
        require(
            files::identity(&named.metadata()?) == files::identity(&file.metadata()?),
            "fresh configuration publication replaced",
        )?;
    }
    record["phase"] = value!("data-prepared-not-bootable");
    super::validate_complete(&record, stage_uuid)?;
    receipt.replace_original(&record)?;
    receipt.recheck()?;
    base()?;
    Ok(
        value!({"status":"complete-data-prepared-not-bootable","snapshot":record["snapshot"],"layout":fresh,"authority_replayed":false,"automatic_backup_enabled":false}),
    )
}
