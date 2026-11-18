// SPDX-License-Identifier: MIT
//! Build a new native image, measure the base, then publish through durable intent.
use crate::{
    identity, initramfs, native_policy_files, operation, recovery_build_source::Source,
    recovery_image as images, recovery_image_publish, transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, json, process, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Cursor,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::Path,
    time::Duration,
};
pub const CONFIG: &str = "/usr/lib/enzimos-native/recovery-rust-mkinitcpio.conf";
pub const HOOK: &str = "/usr/lib/initcpio/install/enzimos-rust-recovery";
pub const DESCRIPTOR: &str = "usr/lib/enzimos-native/recovery-image.json";
const TOOLS: &[&str] = &[
    "cryptsetup",
    "blkid",
    "findmnt",
    "mount",
    "umount",
    "lsblk",
    "modprobe",
    "kmod",
    "btrfs",
    "pacman",
    "sbsign",
    "sbverify",
    "objcopy",
];
fn check_base(
    base: &[u8],
    release: &str,
    policy: &Value,
    builtin: &[u8],
    marker: &[u8],
) -> Result<usize> {
    let wanted = policy
        .as_object()
        .unwrap()
        .keys()
        .map(|name| format!("usr/lib/enzimos-native/{name}"))
        .chain(["init", "etc/initrd-release"].map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let seen = initramfs::inventory(base, &wanted)?;
    require(
        !seen.contains_key(DESCRIPTOR),
        "base image already contains descriptor; no adoption",
    )?;
    for (name, sha) in policy.as_object().unwrap() {
        let member = seen
            .get(&format!("usr/lib/enzimos-native/{name}"))
            .ok_or_else(|| Error("image policy member missing".into()))?;
        require(
            member.mode & libc::S_IFMT == libc::S_IFREG
                && member.mode & 0o022 == 0
                && member.sha.as_deref() == sha.as_str(),
            "image native policy bytes differ",
        )?;
        if name.starts_with("enzimos-") {
            require(
                member.mode & 0o111 != 0,
                "image native executable mode missing",
            )?;
        }
    }
    let init = seen
        .get("init")
        .ok_or_else(|| Error("native default image init missing".into()))?;
    require(
        init.mode & libc::S_IFMT == libc::S_IFREG
            && init.mode & 0o111 != 0
            && init.sha.as_deref() == policy["enzimos-recovery-image-init"].as_str(),
        "image default init differs from refusing native init",
    )?;
    let release_marker = seen
        .get("etc/initrd-release")
        .ok_or_else(|| Error("independent release marker missing from built image".into()))?;
    require(
        !marker.is_empty()
            && release_marker.mode & libc::S_IFMT == libc::S_IFREG
            && release_marker.mode & 0o022 == 0
            && release_marker.sha.as_deref() == Some(json::sha256(marker).as_str()),
        "independent release marker differs from original OS identity",
    )?;
    for tool in TOOLS {
        let name = format!("usr/bin/{tool}");
        require(
            seen.contains_key(&name),
            "image fixed coordinator tool missing",
        )?;
    }
    let builtin = std::str::from_utf8(builtin)
        .map_err(|_| Error("built-in kernel module encoding".into()))?;
    for module in ["dm-crypt", "btrfs", "vfat"] {
        let matches = |name: &str| {
            name.rsplit('/').next().is_some_and(|file| {
                file == format!("{module}.ko")
                    || file
                        .strip_prefix(&format!("{module}.ko."))
                        .is_some_and(|s| matches!(s, "xz" | "zst" | "gz"))
            })
        };
        let prefix = format!("usr/lib/modules/{release}/");
        require(
            seen.keys()
                .any(|name| name.starts_with(&prefix) && matches(name))
                || builtin.split_whitespace().any(matches),
            "image storage kernel module missing",
        )?;
    }
    Ok(seen.len())
}
/// Image payloads use the retained, verified streaming publisher. Metadata
/// atomic writers keep their separate 32 MiB cap; this role admits only the two
/// fixed image members within the existing 192 MiB image contract.
pub fn stage_artifact(parent: &File, name: &str, body: &[u8], owner: u32) -> Result<File> {
    require(
        matches!(name, "kernel" | "initrd.img")
            && !body.is_empty()
            && body.len() <= images::MAX_IMAGE as usize
            && parent.metadata()?.mode() & 0o7777 == 0o700,
        "private fixed image artifact staging bounds",
    )?;
    stream_copy::verified_reader(
        &mut Cursor::new(body),
        parent,
        name,
        body.len() as u64,
        &json::sha256(body),
        0o600,
        owner,
        false,
    )
}
struct FirstBootClaim<'a> {
    parent: &'a File,
    pending: File,
    original: files::FileIdentity,
}
impl FirstBootClaim<'_> {
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn finish(self) -> Result<()> {
        let named = files::open_relative(self.parent, Path::new("recovery-image-pending"))?;
        require(
            files::identity(&named.metadata()?) == self.original
                && files::identity(&self.pending.metadata()?) == self.original,
            "first-boot pending flag changed; attempt retained",
        )?;
        require(
            unsafe {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    c"recovery-image-pending".as_ptr(),
                    0,
                )
            } == 0,
            "first-boot pending flag removal uncertain; no replay",
        )?;
        self.parent.sync_all()?;
        require(
            self.pending.metadata()?.nlink() == 0,
            "first-boot original pending flag remained linked",
        )
    }
}
fn claim_first_boot<'a>(parent: &'a File, body: &[u8], owner: u32) -> Result<FirstBootClaim<'a>> {
    let pending = files::open_relative(parent, Path::new("recovery-image-pending"))?;
    require(
        pending.metadata()?.mode() & 0o7777 == 0o600
            && files::read_file(&pending, 1, Some(owner), true)?.is_empty(),
        "original empty first-boot pending flag required",
    )?;
    let original = files::identity(&pending.metadata()?);
    files::atomic_relative(
        parent,
        Path::new("recovery-image-attempted"),
        body,
        0o600,
        Some(owner),
        false,
        128 * 1024,
    )?;
    let named = files::open_relative(parent, Path::new("recovery-image-pending"))?;
    require(
        files::identity(&named.metadata()?) == original
            && files::identity(&pending.metadata()?) == original,
        "first-boot pending flag changed after claim; no replay",
    )?;
    Ok(FirstBootClaim {
        parent,
        pending,
        original,
    })
}
/// Automatic first boot claims one durable attempt before invoking any builder.
/// Failures retain the attempt; an administrator may separately review/build.
pub fn first_boot_locked(release: &str, options: &str, lock: &files::Lock) -> Result<Value> {
    operation::root_only()?;
    identity::safe_id(release)?;
    let idle = Snapshot::online()?;
    let parent = idle.guard.control();
    idle.recheck()?;
    lock.recheck()?;
    let body = json::canonical(&value!({"schema":1,"boot":operation::boot_id()?,
        "kernel":release,"options":options,"automatic_replay":false}))?;
    let claim = claim_first_boot(parent, &body, 0)?;
    idle.recheck()?;
    lock.recheck()?;
    let result = build_locked(release, options, lock)?;
    // Successful publication deliberately extends the image journal. Keep the
    // original mounted control identity, then observe the completed idle state.
    idle.guard.recheck()?;
    Snapshot::online()?.guard.recheck()?;
    lock.recheck()?;
    claim.finish()?;
    Ok(result)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub fn build_locked(release: &str, options: &str, lock: &files::Lock) -> Result<Value> {
    identity::safe_id(release)?;
    let idle = Snapshot::online()?;
    require(
        matches!(std::fs::symlink_metadata("/var/lib/pacman/db.lck"),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "package transaction prevents image build",
    )?;
    require(
        matches!(std::fs::symlink_metadata(recovery_image_publish::INPUT),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "stale image input requires review; no replacement",
    )?;
    let policy = native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?;
    let config = Source::observe(Path::new(CONFIG), 65536)?;
    let hook = Source::observe(Path::new(HOOK), 65536)?;
    let marker = Source::observe(Path::new("/usr/share/enzimos/os-release"), 8192)?;
    let module_path = Path::new("/usr/lib/modules").join(release);
    let modules = files::directory(&module_path, Some(0))?;
    let modules_before = files::identity(&modules.metadata()?);
    let module_mount =
        enzimos_platform::mount_identity::id(std::os::fd::AsFd::as_fd(&modules), true)?;
    let kernel_source = Source::observe(&module_path.join("vmlinuz"), images::MAX_IMAGE as usize)?;
    let kernel = &kernel_source.body;
    require(!kernel.is_empty(), "installed recovery kernel empty")?;
    let builtin = match std::fs::symlink_metadata(module_path.join("modules.builtin")) {
        Ok(_) => Some(Source::observe(
            &module_path.join("modules.builtin"),
            4 * 1024 * 1024,
        )?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    files::ensure_directory(Path::new(operation::STATE), 0o700, 0)?;
    let parent = files::ensure_directory(Path::new("/var/lib/enzimos/recovery-build"), 0o700, 0)?;
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatvfs(parent.as_raw_fd(), &mut info) } == 0
            && (info.f_bavail as u64)
                .checked_mul(info.f_frsize as u64)
                .is_some_and(|n| n >= 1024 * 1024 * 1024),
        "image build headroom",
    )?;
    let work = Path::new("/var/lib/enzimos/recovery-build")
        .join(format!("build-{}", files::random_hex(16)?));
    std::fs::DirBuilder::new().mode(0o700).create(&work)?;
    files::ensure_directory(&work, 0o700, 0)?;
    let destination = work.join("base.img");
    idle.recheck()?;
    let result = process::run(
        "/usr/bin/mkinitcpio",
        &[
            "-c",
            CONFIG,
            "-k",
            release,
            "-t",
            work.to_str().unwrap(),
            "-g",
            destination.to_str().unwrap(),
        ],
        &[],
        Duration::from_secs(900),
        2 * 1024 * 1024,
    )?;
    require(
        result.status.success(),
        "native recovery mkinitcpio failed; build retained for review",
    )?;
    let base = files::read(&destination, images::MAX_IMAGE as usize, Some(0), true)?;
    let members = check_base(
        &base,
        release,
        &policy,
        builtin.as_ref().map_or(&[][..], |b| b.body.as_slice()),
        &marker.body,
    )?;
    let descriptor = value!({"schema":2,"kernel_release":release,"kernel_sha256":json::sha256(kernel),
        "base_initrd_sha256":json::sha256(&base),"policy_files":policy});
    images::descriptor(&descriptor)?;
    let id = images::image_id(&descriptor)?;
    let mut descriptor_bytes = json::canonical(&descriptor)?;
    descriptor_bytes.push(b'\n');
    let initrd = initramfs::append(&base, DESCRIPTOR, &descriptor_bytes, 0o100644)?;
    let supplied = value!({"schema":1,"identity":descriptor,"files":{
        "kernel":{"bytes":kernel.len(),"sha256":json::sha256(kernel)},
        "initrd.img":{"bytes":initrd.len(),"sha256":json::sha256(&initrd)}}});
    images::manifest(&supplied)?;
    idle.recheck()?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))? == policy,
        "installed inputs changed during recovery build",
    )?;
    config.recheck()?;
    hook.recheck()?;
    marker.recheck()?;
    kernel_source.recheck()?;
    if let Some(builtin) = &builtin {
        builtin.recheck()?;
    } else {
        require(
            matches!(std::fs::symlink_metadata(module_path.join("modules.builtin")),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "built-in kernel module list appeared during build",
        )?;
    }
    let named_modules = files::directory(&module_path, Some(0))?;
    require(
        files::identity(&named_modules.metadata()?) == modules_before
            && files::identity(&modules.metadata()?) == modules_before
            && enzimos_platform::mount_identity::id(
                std::os::fd::AsFd::as_fd(&named_modules),
                true,
            )? == module_mount,
        "installed kernel module directory changed during build",
    )?;
    files::ensure_directory(Path::new("/run/enzimos"), 0o700, 0)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(recovery_image_publish::INPUT)?;
    let input_parent = files::ensure_directory(Path::new(recovery_image_publish::INPUT), 0o700, 0)?;
    let mut staged = Vec::new();
    for (name, bytes) in [
        ("kernel", kernel.as_slice()),
        ("initrd.img", initrd.as_slice()),
    ] {
        idle.recheck()?;
        let file = stage_artifact(&input_parent, name, bytes, 0)?;
        let epoch = files::identity(&file.metadata()?);
        staged.push((name, file, epoch));
        idle.recheck()?;
    }
    let mut manifest_bytes = json::canonical(&supplied)?;
    manifest_bytes.push(b'\n');
    files::atomic(
        &Path::new(recovery_image_publish::INPUT).join("manifest.json"),
        &manifest_bytes,
        0o600,
        Some(0),
        false,
    )?;
    for (name, file, epoch) in &staged {
        require(
            files::identity(&file.metadata()?) == *epoch
                && files::identity(
                    &files::open_relative(&input_parent, Path::new(name))?.metadata()?,
                ) == *epoch,
            "original staged image artifact changed",
        )?;
    }
    let published = recovery_image_publish::publish_locked(options, lock)?;
    for (name, file, epoch) in &staged {
        require(
            files::identity(&file.metadata()?) == *epoch
                && files::identity(
                    &files::open_relative(&input_parent, Path::new(name))?.metadata()?,
                ) == *epoch,
            "original staged image artifact changed",
        )?;
    }

    require(
        published["id"] == id,
        "published native recovery identity differs from build",
    )?;
    // Completed inputs are archived by the publisher. Failed fixed input and
    // persistent build artifacts remain for explicit guarded inspection/cleanup.
    Ok(
        value!({"status":"recovery-image-built-and-published","id":id,"kernel_release":release,"phase":published["phase"],
        "members":members,"policy_files_checked":policy.as_object().unwrap().len(),"default_init":"refuse-and-power-off",
        "base_initrd_sha256":descriptor["base_initrd_sha256"],"initrd_bytes":initrd.len(),
        "general_recovery_environment":false,"byte_reproducible":false,"firmware_trust":false,"selection_changed":false}),
    )
}
