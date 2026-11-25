// SPDX-License-Identifier: MIT
//! MainPID exit cannot authorize cleanup while the owned subtree remains populated.
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
/// Parse the `populated` flag from a cgroup.events body.
///
/// # Errors
///
/// Fails when the body is oversized, malformed, or lacks exactly one `populated` row.
pub fn populated(body: &str) -> Result<bool> {
    require(
        body.len() <= 4096 && !body.contains('\0'),
        "worker cgroup events bound",
    )?;
    let mut values = BTreeMap::new();
    for line in body.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 2
                && fields[0].len() <= 64
                && fields[0]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
                && values.len() < 16,
            "worker cgroup events shape",
        )?;
        let value = fields[1]
            .parse::<u64>()
            .map_err(|_| Error("worker cgroup event integer required".into()))?;
        require(
            values.insert(fields[0], value).is_none(),
            "duplicate worker cgroup event",
        )?;
    }
    match values.get("populated") {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(Error("worker cgroup population unavailable".into())),
    }
}
fn identity(file: &File) -> Result<(u64, u64, u32, u32, u32, u64)> {
    let m = file.metadata()?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn genuine(file: &File) -> Result<()> {
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `filesystem` is a writable `libc::statfs` and `file` keeps the descriptor open.
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } == 0
            && filesystem.f_type == 0x63677270,
        "actual cgroup v2 filesystem required",
    )
}
/// A worker unit's cgroup directory, retained by descriptor.
pub struct Group {
    directory: File,
    path: PathBuf,
    identity: (u64, u64, u32, u32, u32, u64),
}
impl Group {
    pub(crate) fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.directory)
    }
    /// [`Group::observe_for`] with the update worker definition of job `id`.
    ///
    /// # Errors
    ///
    /// Fails unless `id` is valid, or as [`Group::observe_for`] does.
    pub fn observe(id: &str) -> Result<Self> {
        Self::observe_for(&crate::update_worker_contract::Definition::updater(id)?)
    }
    /// Open the worker unit's cgroup below `system.slice`.
    ///
    /// # Errors
    ///
    /// Fails outside the initial namespaces or when the cgroup is not a genuine cgroup v2
    /// directory.
    pub fn observe_for(definition: &crate::update_worker_contract::Definition) -> Result<Self> {
        enzimos_policy::namespaces::initial()?;
        let path = Path::new("/sys/fs/cgroup/system.slice").join(&definition.unit);
        let directory = files::directory(&path, Some(0))?;
        genuine(&directory)?;
        let group = Self {
            identity: identity(&directory)?,
            directory,
            path,
        };
        group.recheck()?;
        Ok(group)
    }
    fn recheck(&self) -> Result<()> {
        enzimos_policy::namespaces::initial()?;
        genuine(&self.directory)?;
        require(
            identity(&self.directory)? == self.identity,
            "retained worker cgroup changed",
        )
    }
    /// Whether the cgroup has no processes, accepting its deletion only as proof of emptiness.
    ///
    /// # Errors
    ///
    /// Fails when the cgroup was replaced or its events cannot be read.
    pub fn empty(&self) -> Result<bool> {
        self.recheck()?;
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Kernel cgroup removal requires no live processes/children. A renamed
                // group is refused: the retained kernel path must actually be deleted.
                let alias = PathBuf::from(format!(
                    "/proc/{}/fd/{}",
                    std::process::id(),
                    self.directory.as_raw_fd()
                ));
                require(
                    std::fs::read_link(alias)?.as_os_str()
                        == std::ffi::OsStr::new(&format!("{} (deleted)", self.path.display())),
                    "worker cgroup disappeared without retained deletion proof",
                )?;
                self.recheck()?;
                Ok(true)
            }
            Err(error) => Err(error.into()),
            Ok(_) => {
                let current = files::directory(&self.path, Some(0))?;
                require(
                    identity(&current)? == self.identity,
                    "worker cgroup replaced",
                )?;
                let file = files::open_relative(&self.directory, Path::new("cgroup.events"))?;
                let before = file.metadata()?;
                require(
                    before.uid() == 0
                        && before.mode() & 0o022 == 0
                        && mount_identity::id(file.as_fd(), true)? == self.identity.5,
                    "worker cgroup event source changed",
                )?;
                let mut body = Vec::new();
                (&file).take(4097).read_to_end(&mut body)?;
                let result = !populated(
                    std::str::from_utf8(&body)
                        .map_err(|_| Error("worker cgroup event encoding".into()))?,
                )?;
                let after = file.metadata()?;
                require(
                    (before.dev(), before.ino()) == (after.dev(), after.ino())
                        && identity(&files::directory(&self.path, Some(0))?)? == self.identity,
                    "worker cgroup changed during event read",
                )?;
                self.recheck()?;
                Ok(result)
            }
        }
    }
}
