// SPDX-License-Identifier: MIT
//! A frozen copied system must equal its frozen authenticated source, except
//! the closed configuration/state placeholders published by complete prepare.
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};
const SKIP: &[&str] = &[
    "etc/fstab",
    "etc/crypttab",
    "etc/enzimos/storage.json",
    "var/lib/enzimos",
    ".snapshots",
    "etc/systemd/system/timers.target.wants/enzimos-backup.timer",
    "var/lib/enzimos-control",
    "etc/pacman.d/gnupg",
    "boot",
    "home",
    "dev",
    "proc",
    "sys",
    "run",
    "tmp",
    "var/tmp",
    "swap",
    "backup-source",
    "backup-repository",
    "restore-target",
];
fn ignored(path: &Path) -> bool {
    SKIP.iter().any(|skip| path == Path::new(skip))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
fn open(parent: &File, name: &OsStr, flags: i32) -> Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| Error("complete system member encoding".into()))?;
    // SAFETY: `name` is a NUL-terminated C string and `parent` keeps the descriptor open.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    require(fd >= 0, "original complete system member unavailable")?;
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[allow(unsafe_code, reason = "Linux syscall ABI (readlinkat).")]
fn symlink(file: &File) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; 4097];
    // SAFETY: The empty path is NUL-terminated, the buffer pointer and length describe `bytes`, and
    // `file` stays open.
    let size = unsafe {
        libc::readlinkat(
            file.as_raw_fd(),
            c"".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    require(
        size >= 0 && (size as usize) < bytes.len(),
        "complete system symlink bound",
    )?;
    bytes.truncate(size as usize);
    Ok(bytes)
}
fn hash(file: &mut File, authorize: &mut dyn FnMut() -> Result<()>) -> Result<[u8; 32]> {
    let before = files::identity(&file.metadata()?);
    require(
        before.2 <= 1024 * 1024 * 1024 * 1024,
        "complete system file byte bound",
    )?;
    let mut sum = openssl::sha::Sha256::new();
    let mut buffer = vec![0u8; 65536];
    let mut total = 0u64;
    let mut checkpoint = std::time::Instant::now();
    authorize()?;
    loop {
        if checkpoint.elapsed() >= std::time::Duration::from_millis(200) {
            authorize()?;
            checkpoint = std::time::Instant::now();
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| Error("complete file size overflow".into()))?;
        require(total <= before.2, "complete file grew during comparison")?;
        sum.update(&buffer[..count]);
    }
    require(
        total == before.2 && files::identity(&file.metadata()?) == before,
        "complete file changed during comparison",
    )?;
    Ok(sum.finish())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fgetxattr, flistxattr).")]
fn attributes(file: &File) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut names = vec![0u8; 65536];
    let length =
        // SAFETY: The buffer pointer and length describe `names`, and `file` stays open.
        unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
    require(
        length >= 0 && (length as usize) <= names.len(),
        "complete system attribute name bound",
    )?;
    names.truncate(length as usize);
    let mut result = std::collections::BTreeMap::new();
    let mut total = 0usize;
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let key =
            CString::new(name).map_err(|_| Error("complete attribute name encoding".into()))?;
        let mut bytes = vec![0u8; 1024 * 1024];
        // SAFETY: The name is NUL-terminated, the buffer pointer and length describe `bytes`, and
        // `file` stays open.
        let length = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                key.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        require(
            length >= 0,
            "complete system attribute unavailable/oversized",
        )?;
        bytes.truncate(length as usize);
        total += bytes.len();
        require(total <= 1024 * 1024, "complete system attribute byte bound")?;
        require(
            result.insert(name.to_vec(), bytes).is_none(),
            "duplicate complete system attribute",
        )?;
    }
    Ok(result)
}
struct Scan {
    left_mount: u64,
    right_mount: u64,
    remaining: usize,
    bytes: u64,
}
impl Scan {
    fn visit(
        &mut self,
        left: &File,
        right: &File,
        prefix: &Path,
        depth: usize,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        require(
            depth <= 128
                && mount_identity::id(left.as_fd(), true)? == self.left_mount
                && mount_identity::id(right.as_fd(), true)? == self.right_mount,
            "complete system depth/mount boundary",
        )?;
        require(
            attributes(left)? == attributes(right)?,
            "prepared directory ACL/attributes differ from authenticated source",
        )?;
        let left_epoch = files::identity(&left.metadata()?);
        let right_epoch = files::identity(&right.metadata()?);
        let names = |dir: &File| -> Result<std::collections::BTreeSet<std::ffi::OsString>> {
            Ok(files::directory_names(dir, 131072)?
                .into_iter()
                .filter(|n| !ignored(&prefix.join(n)))
                .collect())
        };
        let expected = names(left)?;
        require(
            expected == names(right)?,
            "prepared system namespace differs from frozen authenticated source",
        )?;
        for name in expected {
            require(self.remaining > 0, "complete system member count bound")?;
            self.remaining -= 1;
            authorize()?;
            let a = open(left, &name, libc::O_PATH)?;
            let b = open(right, &name, libc::O_PATH)?;
            let am = a.metadata()?;
            let bm = b.metadata()?;
            require(
                (am.mode(), am.uid(), am.gid(), am.len())
                    == (bm.mode(), bm.uid(), bm.gid(), bm.len())
                    || (am.is_dir()
                        && bm.is_dir()
                        && (am.mode(), am.uid(), am.gid()) == (bm.mode(), bm.uid(), bm.gid())),
                "prepared system member metadata differs",
            )?;
            require(
                mount_identity::id(a.as_fd(), true)? == self.left_mount
                    && mount_identity::id(b.as_fd(), true)? == self.right_mount,
                "nested complete system mount refused",
            )?;
            let ae = files::identity(&am);
            let be = files::identity(&bm);
            if am.is_dir() {
                require(
                    am.ino() != 256 && bm.ino() != 256,
                    "unexpected nested complete system subvolume refused",
                )?;
                let ad = open(left, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                let bd = open(right, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                require(
                    files::identity(&ad.metadata()?) == ae
                        && files::identity(&bd.metadata()?) == be,
                    "complete directory changed during opening",
                )?;
                self.visit(&ad, &bd, &prefix.join(&name), depth + 1, authorize)?;
            } else if am.file_type().is_symlink() {
                require(
                    symlink(&a)? == symlink(&b)?,
                    "prepared system symlink differs",
                )?;
            } else {
                require(
                    am.is_file() && bm.is_file(),
                    "special complete system members require separate qualification",
                )?;
                self.bytes = self
                    .bytes
                    .checked_add(am.len())
                    .ok_or_else(|| Error("complete system bytes overflow".into()))?;
                require(
                    self.bytes <= 2 * 1024 * 1024 * 1024 * 1024,
                    "complete system total byte bound",
                )?;
                let mut af = open(left, &name, libc::O_RDONLY)?;
                let mut bf = open(right, &name, libc::O_RDONLY)?;
                require(
                    files::identity(&af.metadata()?) == ae
                        && files::identity(&bf.metadata()?) == be,
                    "complete file changed during opening",
                )?;
                require(
                    attributes(&af)? == attributes(&bf)?,
                    "prepared executable/file capabilities or attributes differ",
                )?;
                require(
                    hash(&mut af, authorize)? == hash(&mut bf, authorize)?,
                    "prepared executable/system bytes differ from frozen authenticated source",
                )?;
            }
            let an = open(left, &name, libc::O_PATH)?;
            let bn = open(right, &name, libc::O_PATH)?;
            require(
                files::identity(&a.metadata()?) == ae
                    && files::identity(&b.metadata()?) == be
                    && files::identity(&an.metadata()?) == ae
                    && files::identity(&bn.metadata()?) == be,
                "complete member changed/replaced during comparison",
            )?;
        }
        require(
            files::identity(&left.metadata()?) == left_epoch
                && files::identity(&right.metadata()?) == right_epoch,
            "complete directory changed during comparison",
        )?;
        authorize()
    }
}
pub(super) fn compare(
    source: &File,
    target: &File,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    Scan {
        left_mount: mount_identity::id(source.as_fd(), true)?,
        right_mount: mount_identity::id(target.as_fd(), true)?,
        remaining: 1048576,
        bytes: 0,
    }
    .visit(source, target, Path::new(""), 0, authorize)
}
