// SPDX-License-Identifier: MIT
//! One private recovery copy from an immutable RAM descriptor. No confirmation API.
use enzimos_platform::{Error, Result, files, mount_identity, mountinfo, require};
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const PROTECTED: [&str; 4] = [
    "/",
    "/home",
    "/var/lib/enzimos-control",
    "/etc/pacman.d/gnupg",
];
fn filename(name: &str) -> Result<()> {
    require(
        !name.is_empty()
            && name.len() <= 255
            && !matches!(name, "." | "..")
            && !name.contains('/')
            && !name.chars().any(|c| c < '\u{20}' || c == '\u{7f}'),
        "one recovery filename required",
    )
}
fn shape(f: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = f.metadata()?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn row(f: &File) -> Result<mountinfo::Row> {
    let id = mount_identity::id(f.as_fd(), false)?;
    let rows = crate::storage_runtime::rows()?;
    let mut selected = rows.into_iter().filter(|r| r.id == id);
    let row = selected
        .next()
        .ok_or_else(|| Error("recovery destination mount unavailable".into()))?;
    require(
        selected.next().is_none(),
        "ambiguous recovery destination mount",
    )?;
    Ok(row)
}
fn fs_uuid(f: &File, row: &mountinfo::Row) -> Result<Option<String>> {
    if row.filesystem == "btrfs" {
        let info = crate::filesystem::observe(f.as_fd())?;
        Ok(Some(
            info["filesystem_uuid"]
                .as_str()
                .ok_or_else(|| Error("actual recovery filesystem UUID required".into()))?
                .into(),
        ))
    } else {
        Ok(None)
    }
}
struct Protected {
    path: &'static str,
    file: File,
    shape: (u64, u64, u32, u32, u32),
    row: mountinfo::Row,
    uuid: Option<String>,
    unique: u64,
}
struct Destination {
    file: File,
    shape: (u64, u64, u32, u32, u32),
    row: mountinfo::Row,
    unique: u64,
    uuid: Option<String>,
    protected: Vec<Protected>,
}
impl Destination {
    fn open(path: &Path, backup_uuid: &str) -> Result<Self> {
        require(
            path.is_absolute() && std::fs::canonicalize(path)? == path,
            "canonical recovery folder required",
        )?;
        let file = files::directory(path, None)?;
        let m = file.metadata()?;
        require(
            m.uid() == enzimos_platform::process_identity::effective_uid() && m.mode() & 0o022 == 0,
            "private account-owned recovery folder required",
        )?;
        let shape = shape(&file)?;
        let row = row(&file)?;
        require(
            matches!(
                row.filesystem.as_str(),
                "btrfs" | "ext4" | "xfs" | "f2fs" | "vfat" | "exfat" | "ntfs3"
            ),
            "persistent supported recovery filesystem required",
        )?;
        let unique = mount_identity::id(file.as_fd(), true)?;
        let uuid = fs_uuid(&file, &row)?;
        require(
            uuid.as_deref() != Some(backup_uuid),
            "recovery password must be separate from backup filesystem",
        )?;
        let mut protected = Vec::new();
        for path in PROTECTED {
            let original = match files::directory(Path::new(path), None) {
                Ok(f) => f,
                Err(e) => {
                    if std::fs::symlink_metadata(path)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                    {
                        continue;
                    }
                    return Err(e);
                }
            };
            let original_shape = shape_fn(&original)?;
            let original_row = row_fn(&original)?;
            let original_uuid = fs_uuid(&original, &original_row)?;
            require(
                m.dev() != original_shape.0 && (uuid.is_none() || uuid != original_uuid),
                "choose recovery folder outside system filesystems",
            )?;
            let original_unique = mount_identity::id(original.as_fd(), true)?;
            protected.push(Protected {
                path,
                file: original,
                shape: original_shape,
                row: original_row,
                uuid: original_uuid,
                unique: original_unique,
            });
        }
        let this = Self {
            file,
            shape,
            row,
            unique,
            uuid,
            protected,
        };
        this.recheck(path, backup_uuid)?;
        Ok(this)
    }
    fn recheck(&self, path: &Path, backup_uuid: &str) -> Result<()> {
        let named = files::directory(path, None)?;
        require(
            shape(&self.file)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.file.as_fd(), true)? == self.unique
                && mount_identity::id(named.as_fd(), true)? == self.unique
                && row(&self.file)? == self.row
                && fs_uuid(&self.file, &self.row)? == self.uuid
                && self.uuid.as_deref() != Some(backup_uuid),
            "original recovery destination changed",
        )?;
        for p in &self.protected {
            let named = files::directory(Path::new(p.path), None)?;
            require(
                shape(&p.file)? == p.shape
                    && shape(&named)? == p.shape
                    && mount_identity::id(p.file.as_fd(), true)? == p.unique
                    && mount_identity::id(named.as_fd(), true)? == p.unique
                    && row(&p.file)? == p.row
                    && fs_uuid(&p.file, &p.row)? == p.uuid
                    && self.shape.0 != p.shape.0
                    && (self.uuid.is_none() || self.uuid != p.uuid),
                "original protected filesystem changed",
            )?;
        }
        Ok(())
    }
}
// Avoid local immutable observations shadowing the observation functions.
fn shape_fn(f: &File) -> Result<(u64, u64, u32, u32, u32)> {
    shape(f)
}
fn row_fn(f: &File) -> Result<mountinfo::Row> {
    row(f)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
fn source(file: &File) -> Result<files::FileIdentity> {
    let m = file.metadata()?;
    let flags = enzimos_platform::files::status_flags(&file);
    // SAFETY: F_GET_SEALS takes no pointers and `file` keeps the descriptor open.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    require(
        m.is_file()
            && m.uid() == enzimos_platform::process_identity::effective_uid()
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 0
            && (1..=4096).contains(&m.len())
            && flags >= 0
            && flags & libc::O_ACCMODE != libc::O_WRONLY
            && seals >= 0
            && seals & SEALS == SEALS,
        "owned sealed recovery descriptor required",
    )?;
    Ok(files::identity(&m))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (openat, sendfile).")]
pub fn save(input: File, directory: &Path, name: &str, backup_uuid: &str) -> Result<Value> {
    crate::identity::uuid(backup_uuid)?;
    filename(name)?;
    let epoch = source(&input)?;
    let destination = Destination::open(directory, backup_uuid)?;
    let name = CString::new(name).map_err(|_| Error("recovery filename encoding".into()))?;
    // SAFETY: `name` is a NUL-terminated C string and `destination.file` keeps the descriptor open.
    let raw = unsafe {
        libc::openat(
            destination.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `raw` was just returned by openat and is owned by nothing else.
    let output = unsafe { File::from_raw_fd(raw) };
    let created = files::identity(&output.metadata()?);
    let attempt = (|| {
        let m = output.metadata()?;
        require(
            m.is_file()
                && m.uid() == enzimos_platform::process_identity::effective_uid()
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && m.dev() == destination.shape.0
                && mount_identity::id(output.as_fd(), true)? == destination.unique,
            "filesystem must support a private recovery file",
        )?;
        let mut offset: libc::off_t = 0;
        let length = input.metadata()?.len();
        let mut interrupted = 0;
        while (offset as u64) < length {
            require(source(&input)? == epoch, "sealed recovery input changed")?;
            destination.recheck(directory, backup_uuid)?;
            // SAFETY: A null offset uses the file position, and both descriptors stay open.
            let count = unsafe {
                libc::sendfile(
                    output.as_raw_fd(),
                    input.as_raw_fd(),
                    &mut offset,
                    (length - offset as u64) as usize,
                )
            };
            if count < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted && interrupted < 8 {
                    interrupted += 1;
                    continue;
                }
                return Err(e.into());
            }
            require(count > 0, "recovery copy did not complete")?;
        }
        output.sync_all()?;
        destination.recheck(directory, backup_uuid)?;
        require(source(&input)? == epoch, "sealed recovery input changed")?;
        let named = files::open_relative(
            &destination.file,
            Path::new(
                name.to_str()
                    .map_err(|_| enzimos_platform::Error("path encoding".into()))?,
            ),
        )?;
        let m = output.metadata()?;
        require(
            (m.dev(), m.ino()) == (created.0, created.1)
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && m.len() == length
                && files::identity(&named.metadata()?) == files::identity(&m)
                && mount_identity::id(named.as_fd(), true)? == destination.unique,
            "saved recovery file changed",
        )?;
        destination.file.sync_all()?;
        destination.recheck(directory, backup_uuid)?;
        Ok(
            json!({"schema":1,"status":"recovery-file-saved","confirmation_recorded":false,"physical_copy_verified":false}),
        )
    })();
    // A failed copy remains private for review. No pathname-based error cleanup
    // can safely delete the original inode in the presence of a concurrent rename;
    // never remove a caller replacement or silently retry an uncertain copy.
    attempt
}
