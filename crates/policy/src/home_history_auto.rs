// SPDX-License-Identifier: MIT
//! Opt-out admission precedes any home or snapshot observation.
use crate::{home_history_create, operation};
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
// The unit's guard leaves this marker only after it made room for a snapshot;
// create-auto consumes it, so a run whose guard deferred to a busy lock retries.
const ROOM_CHECKED: &str = "/run/enzimos/home-history-room-checked";
struct Gate {
    directory: File,
    path: PathBuf,
    owner: u32,
    shape: (u64, u64, u32, u32, u32),
    mount: u64,
}
fn shape(file: &File, owner: u32) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.gid() == owner && m.mode() & 0o022 == 0,
        "automatic history control protection",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
impl Gate {
    fn open() -> Result<Self> {
        crate::namespaces::initial()?;
        operation::root_only()?;
        Self::retained(Path::new(operation::CONTROL), 0)
    }
    fn retained(path: &Path, owner: u32) -> Result<Self> {
        let directory = files::directory(path, Some(owner))?;
        Ok(Self {
            shape: shape(&directory, owner)?,
            path: path.into(),
            owner,
            mount: mount_identity::id(directory.as_fd(), true)?,
            directory,
        })
    }
    fn admit<F: FnOnce() -> Result<Value>>(&self, body: F) -> Result<Value> {
        if self.disabled()? {
            Ok(json!({"status":"disabled-no-source-scan"}))
        } else {
            body()
        }
    }
    fn disabled(&self) -> Result<bool> {
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.shape
                && shape(&self.directory, self.owner)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount,
            "original automatic history control changed",
        )?;
        let marker = files::optional_relative(&self.directory, Path::new("home-history.disabled"))?;
        if let Some(file) = marker {
            let m = file.metadata()?;
            require(
                m.is_file()
                    && m.uid() == self.owner
                    && m.gid() == self.owner
                    && m.nlink() == 1
                    && m.mode() & 0o022 == 0
                    && mount_identity::id(file.as_fd(), true)? == self.mount,
                "unsafe automatic history disable marker",
            )?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
/// Create a scheduled home history snapshot when enabled and there is room.
///
/// # Errors
///
/// Fails when the snapshot cannot be created.
pub fn create() -> Result<Value> {
    let gate = Gate::open()?;
    gate.admit(|| {
        let room_checked = take_room_check()?;
        // A backup or another operation can hold the lock for hours; this run
        // is skipped (exit 75) and the unit retries it, see `busy`.
        let Some(lock) = operation::try_lock()? else {
            eprintln!("enzimos-policy: home history skipped: a backup or another system operation is running");
            return Ok(busy());
        };
        if !room_checked {
            eprintln!("enzimos-policy: home history skipped: free space was not checked for this run");
            return Ok(busy());
        }
        if gate.disabled()? {
            return Ok(json!({"status":"disabled-no-source-scan"}));
        }
        home_history_create::create_locked(&lock, None, || {
            require(
                !gate.disabled()?,
                "automatic history disabled before mutation",
            )?;
            lock.recheck()
        })
    })
}
/// The skipped-run result: the policy binary exits 75 for it and the unit's
/// `RestartForceExitStatus=75` runs home history again shortly, without the
/// unit ever failing.
fn busy() -> Value {
    json!({"status":"operation-lock-busy","retry":true})
}
/// Forgets an earlier space check; the guard calls this before checking.
///
/// # Errors
///
/// Fails when the marker cannot be removed.
pub fn forget_room_check() -> Result<()> {
    take_room_check().map(drop)
}
/// Records that the guard made room for the next automatic snapshot.
///
/// # Errors
///
/// Fails when the marker cannot be written.
pub fn record_room_check() -> Result<()> {
    operation::root_only()?;
    files::ensure_directory(Path::new("/run/enzimos"), 0o700, 0)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROOM_CHECKED)?;
    Ok(())
}
fn take_room_check() -> Result<bool> {
    operation::root_only()?;
    match std::fs::remove_file(ROOM_CHECKED) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
