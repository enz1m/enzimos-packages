// SPDX-License-Identifier: MIT
//! One original ESP tree copied under a durable intent. No mount/transfer authority.
use crate::{
    backup_attempt::Attempt, backup_flatpak_capture::Capture as FlatpakCapture,
    backup_package_capture::Capture as PackageCapture, backup_source::Snapshot,
    backup_source_capture::Released, boot_volume::Volume, control_record::Retained, identity,
    operation, recovery_records,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use openssl::sha::Sha256;
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const FOLDER: &str = "backup-boot-captures";
const MAX_FILE: u64 = 4 * 1024 * 1024 * 1024;
/// Longest interval between full barriers while one boot file is copied.
const CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// Capture bound: fixed work plus the copied bytes at a slow-disk rate, for
/// the copy, its readback and the final output hash.
fn capture_bound(bytes: u64) -> Duration {
    Duration::from_secs(600) + Duration::from_secs(3 * bytes / (2 * 1024 * 1024))
}
const MAX_TREE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_NODES: usize = 4096;
const RECORD_MAX: usize = 4 * 1024 * 1024;
fn boot_uuid(body: &[u8]) -> Result<String> {
    require(
        body.len() <= 1024 * 1024 && !body.contains(&0),
        "captured fstab bound",
    )?;
    let text = std::str::from_utf8(body).map_err(|_| Error("captured fstab encoding".into()))?;
    let mut found = None;
    for line in text.lines() {
        let line = line
            .split('#')
            .next()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .trim();
        if line.is_empty() {
            continue;
        }
        let row = line.split_whitespace().collect::<Vec<_>>();
        require((3..=6).contains(&row.len()), "captured fstab row shape")?;
        for numeric in row.iter().skip(4) {
            require(
                !numeric.is_empty()
                    && numeric.bytes().all(|b| b.is_ascii_digit())
                    && numeric.parse::<u32>().is_ok(),
                "captured fstab numeric field",
            )?;
        }
        if row[1] != "/boot" {
            continue;
        }
        let uuid = row[0]
            .strip_prefix("UUID=")
            .ok_or_else(|| Error("explicit ESP UUID required".into()))?;
        recovery_records::fat_uuid(uuid)?;
        require(
            row[2] == "vfat" && found.is_none(),
            "captured fstab ESP binding ambiguous",
        )?;
        found = Some(uuid.to_owned());
    }
    found.ok_or_else(|| Error("captured root has no explicit ESP binding".into()))
}
struct Node {
    relative: PathBuf,
    file: File,
    epoch: files::FileIdentity,
    names: Option<BTreeSet<String>>,
}
struct Tree {
    nodes: Vec<Node>,
    mount: u64,
    bytes: u64,
    owner: u32,
}
impl Tree {
    fn scan(root: &File, owner: u32, checkpoint: &mut dyn FnMut() -> Result<()>) -> Result<Self> {
        let mount = mount_identity::id(root.as_fd(), true)?;
        let mut tree = Self {
            nodes: Vec::new(),
            mount,
            bytes: 0,
            owner,
        };
        tree.visit(root.try_clone()?, PathBuf::new(), 0, checkpoint)?;
        tree.recheck()?;
        Ok(tree)
    }
    fn visit(
        &mut self,
        file: File,
        relative: PathBuf,
        depth: usize,
        checkpoint: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        checkpoint()?;
        let m = file.metadata()?;
        require(
            self.nodes.len() < MAX_NODES
                && depth <= 16
                && relative.as_os_str().len() <= 4096
                && m.uid() == self.owner
                && m.mode() & 0o7022 == 0
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "original boot tree ownership, mount or traversal bound",
        )?;
        let epoch = files::identity(&m);
        if m.is_dir() {
            let names = files::directory_names(&file, MAX_NODES)?
                .into_iter()
                .map(|name| {
                    name.into_string()
                        .map_err(|_| Error("boot member encoding".into()))
                })
                .collect::<Result<BTreeSet<_>>>()?;
            let parent = file.try_clone()?;
            self.nodes.push(Node {
                relative: relative.clone(),
                file,
                epoch,
                names: Some(names.clone()),
            });
            for name in names {
                let entry = crate::boot_capture_member::open(&parent, &name, self.owner)?;
                self.visit(entry, relative.join(name), depth + 1, checkpoint)?;
            }
        } else {
            require(
                m.is_file() && m.nlink() == 1 && m.len() <= MAX_FILE,
                "boot data must be a bounded original regular file",
            )?;
            self.bytes = self
                .bytes
                .checked_add(m.len())
                .ok_or_else(|| Error("boot tree byte overflow".into()))?;
            require(self.bytes <= MAX_TREE, "boot tree byte bound")?;
            self.nodes.push(Node {
                relative,
                file,
                epoch,
                names: None,
            });
        }
        Ok(())
    }
    fn recheck(&self) -> Result<()> {
        for node in &self.nodes {
            require(
                files::identity(&node.file.metadata()?) == node.epoch
                    && mount_identity::id(node.file.as_fd(), true)? == self.mount,
                "original boot tree member changed",
            )?;
            if let Some(names) = &node.names {
                let actual = files::directory_names(&node.file, MAX_NODES)?
                    .into_iter()
                    .map(|name| {
                        name.into_string()
                            .map_err(|_| Error("boot member encoding".into()))
                    })
                    .collect::<Result<BTreeSet<_>>>()?;
                require(
                    &actual == names,
                    "original boot directory membership changed",
                )?;
            }
            if !node.relative.as_os_str().is_empty() {
                let relative = node
                    .relative
                    .parent()
                    .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?;
                let parent = if relative.as_os_str().is_empty() {
                    self.nodes[0].file.try_clone()?
                } else {
                    files::directory_relative(&self.nodes[0].file, relative, Some(self.owner))?
                };
                let named = crate::boot_capture_member::open(
                    &parent,
                    node.relative
                        .file_name()
                        .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
                        .to_str()
                        .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
                    self.owner,
                )?;
                require(
                    files::identity(&named.metadata()?) == node.epoch
                        && mount_identity::id(named.as_fd(), true)? == self.mount,
                    "boot member name no longer denotes the retained original",
                )?;
            }
        }
        Ok(())
    }
    /// Original directories change timestamps only after actual child-retirement
    /// actors are returned. Track exact remaining membership on held descriptions.
    fn retire(
        self,
        parent: &File,
        name: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<RetiredTree> {
        authorize()?;
        self.recheck()?;
        let root = &self.nodes[0];
        let root_entered = std::cell::Cell::new(false);
        let mut checkpoint = || {
            authorize()?;
            if root_entered.get() {
                return Ok(());
            }
            let named = files::directory_relative(parent, Path::new(name), Some(self.owner))?;
            let actual = files::identity(&named.metadata()?);
            let held = files::identity(&root.file.metadata()?);
            let fixed = |e: files::FileIdentity| (e.0, e.1, e.7, e.8, e.9);
            require(
                fixed(actual) == fixed(root.epoch)
                    && fixed(held) == fixed(root.epoch)
                    && mount_identity::id(named.as_fd(), true)? == self.mount,
                "original named boot root changed during retirement",
            )
        };
        let mut remaining = self
            .nodes
            .iter()
            .map(|n| n.names.clone())
            .collect::<Vec<_>>();
        let indices = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.relative.clone(), i))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut removed = Vec::new();
        // The full barrier (approval, and for an owned destination its device
        // checks) costs far more than retiring one member, which hashes the
        // file and syncs its directory twice. Run per member and per hashed
        // chunk it made retiring a normal ESP take 7-12 minutes. It runs at the
        // start and end of the tree and at least once a second in between.
        checkpoint()?;
        let mut checked = Instant::now();
        let mut barriers = 1u64;
        let mut throttled = || {
            if checked.elapsed() >= CHECK_INTERVAL {
                checkpoint()?;
                checked = Instant::now();
                barriers += 1;
            }
            Ok(())
        };
        for index in (0..self.nodes.len()).rev() {
            throttled()?;
            let node = &self.nodes[index];
            let (parent_file, member, parent_index) = if index == 0 {
                (parent, name, None)
            } else {
                let p = node
                    .relative
                    .parent()
                    .ok_or_else(|| Error("boot retirement parent missing".into()))?;
                let pi = *indices
                    .get(p)
                    .ok_or_else(|| Error("boot retirement original parent missing".into()))?;
                (
                    &self.nodes[pi].file,
                    node.relative
                        .file_name()
                        .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
                        .to_str()
                        .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
                    Some(pi),
                )
            };
            let epoch = files::identity(&node.file.metadata()?);
            require(
                mount_identity::id(node.file.as_fd(), true)? == self.mount,
                "boot retirement source mount changed",
            )?;
            if let Some(expected) = &remaining[index] {
                require(
                    expected.is_empty()
                        && files::directory_is_empty(&node.file)?
                        && (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9)
                            == (
                                node.epoch.0,
                                node.epoch.1,
                                node.epoch.7,
                                node.epoch.8,
                                node.epoch.9,
                            ),
                    "boot retirement original directory changed or has unknown members",
                )?;
            } else {
                require(
                    epoch == node.epoch,
                    "original boot file epoch changed before retirement",
                )?;
            }
            if let Some(pi) = parent_index {
                let actual = files::directory_names(parent_file, MAX_NODES)?
                    .into_iter()
                    .map(|n| {
                        n.into_string()
                            .map_err(|_| Error("boot retirement name encoding".into()))
                    })
                    .collect::<Result<BTreeSet<_>>>()?;
                require(
                    remaining[pi].as_ref() == Some(&actual),
                    "original boot parent membership changed during retirement",
                )?;
            }
            if index == 0 {
                root_entered.set(true);
            }
            let retired = enzimos_platform::named_retirement::Quarantined::enter_bounded(
                parent_file,
                &node.file,
                Path::new(member),
                self.owner,
                MAX_FILE,
                &mut throttled,
            )?
            .unlink(&mut throttled)?;
            retired.recheck()?;
            if let Some(pi) = parent_index {
                require(
                    remaining[pi]
                        .as_mut()
                        .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
                        .remove(member),
                    "retired boot member was not in original parent",
                )?;
            }
            removed.push(retired);
        }
        checkpoint()?;
        eprintln!(
            "enzimos-backup: finishing boot-capture members={} barriers={}",
            self.nodes.len(),
            barriers + 1
        );
        let retired = RetiredTree { removed };
        retired.recheck()?;
        Ok(retired)
    }
    fn evidence(&self) -> Value {
        value!({"mount":self.mount,"bytes":self.bytes,"members":self.nodes.iter().map(|node|
            value!({"path":node.relative,"inode":node.epoch,"directory":node.names.is_some()})).collect::<Vec<_>>()})
    }
}
struct RetiredTree {
    removed: Vec<enzimos_platform::named_retirement::Removed>,
}
impl RetiredTree {
    fn recheck(&self) -> Result<()> {
        require(
            !self.removed.is_empty() && self.removed.len() <= MAX_NODES,
            "complete original boot retirement set required",
        )?;
        for member in &self.removed {
            member.recheck()?;
        }
        Ok(())
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (mkdirat).")]
fn create_directory(parent: &File, name: &str) -> Result<File> {
    let component =
        std::ffi::CString::new(name).map_err(|_| Error("boot directory component".into()))?;
    require(
        !name.is_empty()
            && !name.contains('/')
            && !matches!(name, "." | "..")
            // SAFETY: `component` is a NUL-terminated C string and `parent` keeps the descriptor
            // open.
            && unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) } == 0,
        "exclusive boot directory creation failed; intent retained",
    )?;
    parent.sync_all()?;
    files::directory_relative(
        parent,
        Path::new(name),
        Some(enzimos_platform::process_identity::effective_uid()),
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (futimens).")]
fn preserve_mtime(file: &File, epoch: &files::FileIdentity) -> Result<()> {
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: epoch.3,
            tv_nsec: epoch.4,
        },
    ];
    require(
        // SAFETY: `times` holds the two timespecs futimens reads, and `file` stays open.
        unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } == 0,
        "boot copy modification time preservation failed",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod, openat).")]
fn copy_file(
    input: &File,
    parent: &File,
    name: &str,
    owner: u32,
    checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<(File, String)> {
    checkpoint()?;
    let before = files::identity(&input.metadata()?);
    let c = std::ffi::CString::new(name).map_err(|_| Error("boot file component".into()))?;
    require(
        !name.is_empty()
            && !name.contains('/')
            && !matches!(name, "." | "..")
            && before.2 <= MAX_FILE
            && before.8 == owner
            && before.10 == 1
            && before.7 & libc::S_IFMT == libc::S_IFREG
            && before.7 & 0o7022 == 0,
        "original boot file copy authority",
    )?;
    // SAFETY: `c` is a NUL-terminated C string and `parent` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(
        raw >= 0,
        "exclusive boot file creation failed; intent retained",
    )?;
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    let mut output = unsafe { File::from_raw_fd(raw) };
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut buffer = vec![0; 256 * 1024];
    // The full barrier (approval, attempt, package/Flatpak barriers, ESP and,
    // for an owned destination, its device inventory) costs far more than one
    // 256 KiB chunk; run per chunk it made copying a normal ESP exceed the
    // capture bound. Each chunk keeps the cheap source identity check; the full
    // barrier runs at file start and end and at least every CHECK_INTERVAL.
    let mut checked = Instant::now();
    loop {
        if checked.elapsed() >= CHECK_INTERVAL {
            checkpoint()?;
            checked = Instant::now();
        }
        let count = input.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        offset += count as u64;
        require(
            offset <= before.2 && files::identity(&input.metadata()?) == before,
            "original boot file changed during copy",
        )?;
        output.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
    }
    let sha = hash
        .finish()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    require(
        offset == before.2 && files::identity(&input.metadata()?) == before,
        "original boot file copy incomplete",
    )?;
    checkpoint()?;
    require(
        // SAFETY: fchmod takes no pointers and `output` keeps the descriptor open.
        unsafe { libc::fchmod(output.as_raw_fd(), before.7 & 0o777) } == 0,
        "boot output permission preservation failed",
    )?;
    preserve_mtime(&output, &before)?;
    output.sync_all()?;
    parent.sync_all()?;
    require(
        stream_copy::hash_borrowed(&output, MAX_FILE, Some(owner))? == (offset, sha.clone()),
        "boot copy readback differs",
    )?;
    let readonly = files::open_relative(parent, Path::new(name))?;
    require(
        files::identity(&readonly.metadata()?) == files::identity(&output.metadata()?),
        "boot output replaced before read-only retention",
    )?;
    Ok((readonly, sha))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchmod).")]
fn copy_tree(
    source: &Tree,
    target: &File,
    checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    source.recheck()?;
    require(
        files::directory_is_empty(target)?,
        "boot copy destination must be new and empty",
    )?;
    let mut hashes = serde_json::Map::new();
    for node in source.nodes.iter().skip(1) {
        checkpoint()?;
        require(
            files::identity(&node.file.metadata()?) == node.epoch
                && mount_identity::id(node.file.as_fd(), true)? == source.mount,
            "original boot member changed before copying",
        )?;
        let relative = node
            .relative
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?;
        let parent = if relative.as_os_str().is_empty() {
            target.try_clone()?
        } else {
            files::directory_relative(target, relative, Some(source.owner))?
        };
        let name = node
            .relative
            .file_name()
            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?;
        if node.names.is_some() {
            create_directory(&parent, name)?;
        } else {
            let (_, sha) = copy_file(&node.file, &parent, name, source.owner, checkpoint)?;
            hashes.insert(
                node.relative
                    .to_str()
                    .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?
                    .into(),
                value!(sha),
            );
        }
    }
    for node in source
        .nodes
        .iter()
        .rev()
        .filter(|node| node.names.is_some())
    {
        let directory = if node.relative.as_os_str().is_empty() {
            target.try_clone()?
        } else {
            files::directory_relative(target, &node.relative, Some(source.owner))?
        };
        checkpoint()?;
        require(
            // SAFETY: fchmod takes no pointers and `directory` keeps the descriptor open.
            unsafe { libc::fchmod(directory.as_raw_fd(), node.epoch.7 & 0o777) } == 0,
            "boot directory permission preservation failed",
        )?;
        preserve_mtime(&directory, &node.epoch)?;
        directory.sync_all()?;
    }
    source.recheck()?;
    Ok(Value::Object(hashes))
}
pub(crate) struct Captured<'s, 'g> {
    snapshot: Snapshot<'s, 'g>,
    attempt: &'s Attempt<'g>,
    lock: &'s files::Lock,
    volume: Volume,
    fstab: File,
    fstab_epoch: files::FileIdentity,
    registry: File,
    registry_epoch: files::FileIdentity,
    id: String,
    output: Tree,
    hashes: Value,
    record: Retained,
    value: Value,
}
impl<'s, 'g> Captured<'s, 'g> {
    pub(crate) fn original_root(&self) -> Result<Value> {
        self.recheck()?;
        self.snapshot.guard().backup_root_binding()
    }
    pub(crate) fn retire(
        mut self,
        closed: &crate::backup_transfer_observation::ClosedObservation<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Retired<'s, 'g>> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck()?;
        closed.require_boot(&self)?;
        let guard = self.snapshot.guard();
        self.value["phase"] = value!("retirement-entered");
        self.value["closed_transfer"] = closed.evidence()?;
        self.record.replace(&self.value)?;
        let mut boundary = || {
            authorize()?;
            crate::namespaces::initial()?;
            closed.recheck()?;
            guard.recheck()?;
            self.lock.recheck()?;
            self.record.recheck()?;
            let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
            let epoch = files::identity(&named.metadata()?);
            require(
                (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9)
                    == (
                        self.registry_epoch.0,
                        self.registry_epoch.1,
                        self.registry_epoch.7,
                        self.registry_epoch.8,
                        self.registry_epoch.9,
                    )
                    && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
                "original boot retirement registry changed",
            )
        };
        let output = self
            .output
            .retire(&self.registry, &self.id, &mut boundary)?;
        boundary()?;
        self.value["phase"] = value!("retired");
        self.value["boot_tree_removed"] = value!(true);
        self.record.replace(&self.value)?;
        let retired = Retired {
            guard,
            lock: self.lock,
            registry: self.registry,
            registry_epoch: self.registry_epoch,
            record: self.record,
            value: self.value,
            output,
        };
        retired.evidence()?;
        Ok(retired)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        enzimos_platform::recheck_scope::once(self, "boot-capture", || self.recheck_fresh())
    }
    fn recheck_fresh(&self) -> Result<()> {
        self.snapshot.recheck()?;
        self.attempt
            .require_original(self.snapshot.guard(), self.lock)?;
        self.volume.recheck()?;
        self.record.recheck()?;
        let named_registry =
            files::directory_relative(self.snapshot.guard().control(), Path::new(FOLDER), Some(0))?;
        let a = self.registry.metadata()?;
        let b = named_registry.metadata()?;
        require(
            (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                == (b.dev(), b.ino(), b.mode(), b.uid(), b.gid())
                && (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                    == (
                        self.registry_epoch.0,
                        self.registry_epoch.1,
                        self.registry_epoch.7,
                        self.registry_epoch.8,
                        self.registry_epoch.9,
                    )
                && mount_identity::id(self.registry.as_fd(), true)?
                    == self.snapshot.guard().control_mount_id()
                && mount_identity::id(named_registry.as_fd(), true)?
                    == self.snapshot.guard().control_mount_id(),
            "original boot capture registry changed",
        )?;
        let named = files::directory_relative(&self.registry, Path::new(&self.id), Some(0))?;
        require(
            files::identity(&named.metadata()?) == self.output.nodes[0].epoch
                && mount_identity::id(named.as_fd(), true)? == self.output.mount,
            "original boot capture directory replaced",
        )?;
        let named_fstab =
            files::open_relative(self.snapshot.original_directory()?, Path::new("etc/fstab"))?;
        require(
            files::identity(&named_fstab.metadata()?) == self.fstab_epoch
                && mount_identity::id(named_fstab.as_fd(), true)?
                    == mount_identity::id(self.fstab.as_fd(), true)?
                && files::identity(&self.fstab.metadata()?) == self.fstab_epoch
                && self.record.value()? == &self.value
                && self.value["phase"] == "data-copied"
                && self.value["captured_under_barriers"] == true
                && self.value["root_snapshot"] == self.snapshot.evidence()?
                && self.value["attempt"] == self.attempt.evidence()?,
            "original boot capture binding changed",
        )?;
        self.output.recheck()?;
        for node in self.output.nodes.iter().filter(|node| node.names.is_none()) {
            require(
                self.hashes[node
                    .relative
                    .to_str()
                    .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?]
                .as_str()
                .is_some(),
                "boot copy manifest missing member",
            )?;
        }
        Ok(())
    }
    pub(crate) fn require_original(&self, capture: &Released<'_, '_, '_>) -> Result<()> {
        self.recheck()?;
        require(
            self.attempt.same_actor(capture.attempt())
                && std::ptr::eq(self.lock, capture.lock())
                && std::ptr::eq(self.snapshot.guard(), capture.guard())
                && capture
                    .snapshots()?
                    .first()
                    .ok_or_else(|| Error("missing original root capture".into()))?
                    .snapshot()?
                    .evidence()?
                    == self.snapshot.evidence()?,
            "original boot/source capture pair required",
        )
    }
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.output.nodes[0].file)
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(value!({"receipt":self.value,"record_epoch":self.record.evidence()?}))
    }
}
pub(crate) fn capture<'s, 'g>(
    root: &Snapshot<'s, 'g>,
    attempt: &'s Attempt<'g>,
    lock: &'s files::Lock,
    packages: &PackageCapture<'_, 'g>,
    flatpak: &FlatpakCapture<'_, 'g>,
    id: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Captured<'s, 'g>> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    identity::safe_id(id)?;
    require(id.len() <= 64, "boot capture ID bound")?;
    attempt.require_original(root.guard(), lock)?;
    packages.require_original(attempt, lock)?;
    flatpak.require_original(attempt, lock)?;
    authorize()?;
    require(
        root.dataset().name == "root",
        "original root capture required",
    )?;
    let snapshot = root.duplicate_original()?;
    let fstab = files::open_relative(snapshot.original_directory()?, Path::new("etc/fstab"))?;
    let body = files::read_file(&fstab, 1024 * 1024, Some(0), true)?;
    let expected = boot_uuid(&body)?;
    let fstab_epoch = files::identity(&fstab.metadata()?);
    let volume = Volume::observe()?;
    require(
        volume.uuid.eq_ignore_ascii_case(&expected),
        "current ESP differs from captured root fstab",
    )?;
    let started = Instant::now();
    let bound = std::cell::Cell::new(Duration::from_secs(600));
    let mut check = || {
        authorize()?;
        attempt.require_original(snapshot.guard(), lock)?;
        packages.require_original(attempt, lock)?;
        flatpak.require_original(attempt, lock)?;
        volume.recheck()?;
        require(
            started.elapsed() < bound.get(),
            "bounded original boot capture deadline",
        )?;
        require(
            files::identity(&fstab.metadata()?) == fstab_epoch
                && files::identity(
                    &files::open_relative(snapshot.original_directory()?, Path::new("etc/fstab"))?
                        .metadata()?,
                ) == fstab_epoch,
            "captured fstab changed",
        )
    };
    let original = Tree::scan(&volume.directory, 0, &mut check)?;
    require(original.bytes > 0, "original boot tree has no artifacts")?;
    bound.set(capture_bound(original.bytes));
    check()?;
    let registry =
        files::ensure_directory_relative(snapshot.guard().control(), Path::new(FOLDER), 0o700, 0)?;
    let registry_epoch = files::identity(&registry.metadata()?);
    require(
        mount_identity::id(registry.as_fd(), true)? == snapshot.guard().control_mount_id()
            && files::directory_names(&registry, 256)?.len() < 256,
        "boot capture registry bound or mount",
    )?;
    let name = format!("{id}.json");
    require(
        files::optional_directory_relative(&registry, Path::new(id), Some(0))?.is_none()
            && files::optional_relative(&registry, Path::new(&name))?.is_none(),
        "boot capture already entered; no replay",
    )?;
    let mut value = value!({"schema":1,"id":id,"role":"backup-boot-capture","phase":"entered","boot_id":operation::boot_id()?,
        "root_snapshot":snapshot.evidence()?,"attempt":attempt.evidence()?,
        "package_capture":packages.evidence()?,"flatpak_capture":flatpak.evidence()?,"captured_under_barriers":true,"esp_uuid":volume.uuid,"fstab":fstab_epoch,"fstab_sha256":json::sha256(&body),
        "source_tree":original.evidence(),"output_tree":null,"sha256":null,"source_mounts_admitted":false,"transfer_complete":false,"backup_complete":false});
    let mut record = Retained::create(
        &registry,
        Path::new(&name),
        &value,
        RECORD_MAX,
        snapshot.guard().control_mount_id(),
    )?;
    let mut checkpoint = || {
        check()?;
        record.recheck()?;
        let named =
            files::directory_relative(snapshot.guard().control(), Path::new(FOLDER), Some(0))?;
        let a = registry.metadata()?;
        let b = named.metadata()?;
        require(
            (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                == (b.dev(), b.ino(), b.mode(), b.uid(), b.gid())
                && (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                    == (
                        registry_epoch.0,
                        registry_epoch.1,
                        registry_epoch.7,
                        registry_epoch.8,
                        registry_epoch.9,
                    )
                && mount_identity::id(registry.as_fd(), true)?
                    == snapshot.guard().control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == snapshot.guard().control_mount_id(),
            "boot capture registry replaced",
        )
    };
    checkpoint()?;
    let directory = create_directory(&registry, id)?;
    let hashes = copy_tree(&original, &directory, &mut checkpoint)?;
    checkpoint()?;
    let output = Tree::scan(&directory, 0, &mut checkpoint)?;
    require(
        output.bytes == original.bytes && output.nodes.len() == original.nodes.len(),
        "boot tree copy membership/bytes differ",
    )?;
    for node in output.nodes.iter().filter(|node| node.names.is_none()) {
        require(
            hashes[node
                .relative
                .to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?]
            .as_str()
                == Some(
                    stream_copy::hash_borrowed(&node.file, MAX_FILE, Some(0))?
                        .1
                        .as_str(),
                ),
            "boot tree final hash differs",
        )?;
    }
    checkpoint()?;
    original.recheck()?;
    output.recheck()?;
    let named_output = files::directory_relative(&registry, Path::new(id), Some(0))?;
    require(
        files::identity(&named_output.metadata()?) == output.nodes[0].epoch
            && mount_identity::id(named_output.as_fd(), true)? == output.mount,
        "original boot copy replaced before receipt",
    )?;
    value["phase"] = value!("data-copied");
    value["output_tree"] = output.evidence();
    value["sha256"] = hashes.clone();
    record.replace(&value)?;
    let captured = Captured {
        snapshot,
        attempt,
        lock,
        volume,
        fstab,
        fstab_epoch,
        registry,
        registry_epoch,
        id: id.into(),
        output,
        hashes,
        record,
        value,
    };
    captured.recheck()?;
    authorize()?;
    captured.recheck()?;
    Ok(captured)
}
#[cfg(test)]
mod tests;

/// Actual original copied boot tree retired; no source snapshot borrow persists.
pub struct Retired<'s, 'g> {
    guard: &'g crate::storage_runtime::Guard,
    lock: &'s files::Lock,
    registry: File,
    registry_epoch: files::FileIdentity,
    record: Retained,
    value: Value,
    output: RetiredTree,
}
impl Retired<'_, '_> {
    pub fn evidence(&self) -> Result<Value> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.record.recheck()?;
        self.output.recheck()?;
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        for registry in [&self.registry, &named] {
            let epoch = files::identity(&registry.metadata()?);
            require(
                (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9)
                    == (
                        self.registry_epoch.0,
                        self.registry_epoch.1,
                        self.registry_epoch.7,
                        self.registry_epoch.8,
                        self.registry_epoch.9,
                    )
                    && mount_identity::id(registry.as_fd(), true)? == self.guard.control_mount_id(),
                "original retired boot registry changed",
            )?;
        }
        require(
            self.record.value()? == &self.value && self.value["phase"] == "retired",
            "original retired boot receipt changed",
        )?;
        Ok(
            value!({"receipt":self.value,"boot_tree_removed":true,"source_cleanup_complete":false,"backup_complete":false}),
        )
    }
}
