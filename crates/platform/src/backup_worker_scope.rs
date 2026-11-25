// SPDX-License-Identifier: MIT
//! Kernel-backed original backup worker closure. No JSON or Boolean constructor.
use crate::{
    Error, Result, files, mount_identity,
    process_identity::{self, Retained},
    require,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
const IMAGE: &str = "/usr/lib/enzimos-backend/enzimos-backup-worker";
const KINDS: &[&str] = &["mnt", "pid", "user", "net", "uts", "ipc", "cgroup"];
fn initial() -> Result<()> {
    require(
        crate::process_identity::effective_uid() == 0,
        "Root worker closure authority required",
    )?;
    let body = files::read_kernel(Path::new("/proc/2/stat"), 8192)?;
    let body =
        std::str::from_utf8(&body).map_err(|_| Error("kernel namespace anchor encoding".into()))?;
    process_identity::parse_stat(body, 2)?;
    let (head, rest) = body
        .rsplit_once(')')
        .ok_or_else(|| Error("unterminated kernel process name".into()))?;
    let (_, name) = head
        .split_once('(')
        .ok_or_else(|| Error("missing kernel process name".into()))?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    let flags = fields[6]
        .parse::<u64>()
        .map_err(|_| Error("kernel namespace anchor flags".into()))?;
    require(
        name == "kthreadd" && flags & 0x00200000 != 0,
        "actual initial kernel thread required",
    )?;
    for kind in KINDS {
        let own = std::fs::metadata(format!("/proc/{}/ns/{kind}", std::process::id()))?;
        let anchor = std::fs::metadata(format!("/proc/2/ns/{kind}"))?;
        require(
            (own.dev(), own.ino()) == (anchor.dev(), anchor.ino()),
            "worker closure left initial namespace",
        )?;
    }
    Ok(())
}
/// Systemd unit name of the backup worker with the 32-digit hex uid=1000(userm) gid=1000(userm)
/// groups=1000(userm),959(docker),986(uucp),998(wheel).
///
/// # Errors
///
/// Fails unless `id` is 32 lowercase hex digits.
pub fn unit(id: &str) -> Result<String> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "fresh original backup worker ID required",
    )?;
    Ok(format!("enzimos-backup-local-{id}.service"))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
fn shape(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original cgroup required",
    )?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `fs` is a writable `libc::statfs` and `file` keeps the descriptor open.
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x63677270,
        "actual cgroup v2 required",
    )?;
    Ok(
        json!({"device":m.dev(),"inode":m.ino(),"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),"mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
fn populated(body: &str) -> Result<bool> {
    require(
        body.len() <= 4096 && !body.contains('\0'),
        "original cgroup event bound",
    )?;
    let mut rows = BTreeMap::new();
    for row in body.lines() {
        let fields = row.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 2
                && rows.len() < 16
                && fields[0].len() <= 64
                && fields[0]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_'),
            "original cgroup event shape",
        )?;
        let n = fields[1]
            .parse::<u64>()
            .map_err(|_| Error("original cgroup event integer required".into()))?;
        require(
            rows.insert(fields[0], n).is_none(),
            "duplicate original cgroup event",
        )?;
    }
    match rows.get("populated") {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(Error("original cgroup population unavailable".into())),
    }
}
/// What remains of a recorded worker scope after its owning backend died.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remains {
    /// No process of the scope can exist: its cgroup is gone, or it is the
    /// recorded cgroup and reports no population.
    Gone,
    /// The worker or another member of its cgroup is still alive.
    Live,
    /// Neither could be proven.
    Unproven,
}
/// Decide from a fresh observation: `alive` is the recorded worker (PID and
/// start time), `cgroup` the named unit cgroup's shape and population.
fn judge(alive: bool, cgroup: Option<(Value, bool)>, recorded: &Value) -> Remains {
    match (alive, cgroup) {
        (true, _) => Remains::Live,
        // cgroup v2 refuses to remove a populated cgroup.
        (false, None) => Remains::Gone,
        (false, Some((shape, populated))) if shape == *recorded => {
            if populated {
                Remains::Live
            } else {
                Remains::Gone
            }
        }
        (false, Some(_)) => Remains::Unproven,
    }
}
/// What remains of the worker scope `binding` (as recorded by `Scope`) when
/// no retained descriptor of it survives. Any observation failure is
/// [`Remains::Unproven`].
#[must_use]
pub fn remains(binding: &Value) -> Remains {
    observe_remains(binding).unwrap_or(Remains::Unproven)
}
fn observe_remains(binding: &Value) -> Result<Remains> {
    initial()?;
    let id = binding["id"]
        .as_str()
        .ok_or_else(|| Error("recorded worker scope ID required".into()))?;
    let unit = unit(id)?;
    let worker = &binding["worker"];
    let (Some(pid), Some(start)) = (worker["pid"].as_u64(), worker["start_ticks"].as_u64()) else {
        return Err(Error("recorded worker identity required".into()));
    };
    require(
        binding["unit"] == unit.as_str() && (1..i32::MAX as u64).contains(&pid) && start > 0,
        "recorded worker scope shape",
    )?;
    let alive = match files::read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 8192) {
        Ok(body) => process_identity::parse_stat(
            std::str::from_utf8(&body).map_err(|_| Error("worker stat encoding".into()))?,
            pid as u32,
        )
        .is_ok_and(|stat| stat.start_ticks == start),
        Err(_) if std::fs::symlink_metadata(format!("/proc/{pid}")).is_err() => false,
        Err(error) => return Err(error),
    };
    let path = Path::new("/sys/fs/cgroup/system.slice").join(&unit);
    let cgroup = match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
        Ok(_) => {
            let directory = files::directory(&path, Some(0))?;
            let mut bytes = Vec::new();
            (&files::open_relative(&directory, Path::new("cgroup.events"))?)
                .take(4097)
                .read_to_end(&mut bytes)?;
            let populated = populated(
                std::str::from_utf8(&bytes).map_err(|_| Error("cgroup event encoding".into()))?,
            )?;
            Some((shape(&directory)?, populated))
        }
    };
    Ok(judge(alive, cgroup, &binding["cgroup"]))
}
/// A live backup worker bound to its cgroup, namespaces and executable.
pub struct Scope {
    process: Retained,
    directory: File,
    path: PathBuf,
    shape: Value,
    binding: Value,
}
impl Scope {
    /// Capture while the measured original task is alive and belongs to this
    /// exact cgroup. The backend separately verifies the registered PID1 unit.
    ///
    /// # Errors
    ///
    /// Fails when the process is not the expected Root worker, is in another cgroup or namespace,
    /// or the cgroup directory differs.
    pub fn capture(id: &str, process: &Retained, directory: &File) -> Result<Self> {
        initial()?;
        let unit = unit(id)?;
        let (image, sha) = process.root_image_binding()?;
        require(
            image == Path::new(IMAGE),
            "backup closure cannot substitute another Root role",
        )?;
        let path = Path::new("/sys/fs/cgroup/system.slice").join(&unit);
        let named = files::directory(&path, Some(0))?;
        let expected = shape(directory)?;
        require(
            shape(&named)? == expected,
            "original live cgroup differs from named group",
        )?;
        let group = format!("/system.slice/{unit}");
        let body = files::read_kernel(
            &PathBuf::from(format!("/proc/{}/cgroup", process.stat.pid)),
            8192,
        )?;
        require(
            body.split(|b| *b == b'\n')
                .filter(|row| !row.is_empty())
                .collect::<Vec<_>>()
                == vec![format!("0::{group}").as_bytes()],
            "original live worker does not belong to captured cgroup",
        )?;
        for kind in KINDS {
            let worker = std::fs::metadata(format!("/proc/{}/ns/{kind}", process.stat.pid))?;
            let anchor = std::fs::metadata(format!("/proc/2/ns/{kind}"))?;
            require(
                (worker.dev(), worker.ino()) == (anchor.dev(), anchor.ino()),
                "captured worker left initial namespace",
            )?;
        }
        let binding = json!({"schema":1,"id":id,"unit":unit,"group":group,
            "worker":{"pid":process.stat.pid,"start_ticks":process.stat.start_ticks,"executable_sha256":sha},"cgroup":expected});
        let this = Self {
            process: process.duplicate_root()?,
            directory: directory.try_clone()?,
            path,
            shape: expected,
            binding,
        };
        this.binding()?;
        Ok(this)
    }
    fn original(&self) -> Result<()> {
        initial()?;
        require(
            shape(&self.directory)? == self.shape,
            "captured original cgroup changed",
        )
    }
    /// Recorded binding after checking the worker is still in its original cgroup.
    ///
    /// # Errors
    ///
    /// Fails when the cgroup or the worker's membership changed.
    pub fn binding(&self) -> Result<&Value> {
        self.process.recheck()?;
        self.original()?;
        require(
            shape(&files::directory(&self.path, Some(0))?)? == self.shape,
            "named original cgroup changed",
        )?;
        let body = files::read_kernel(
            &PathBuf::from(format!("/proc/{}/cgroup", self.process.stat.pid)),
            8192,
        )?;
        require(
            body.split(|b| *b == b'\n')
                .filter(|row| !row.is_empty())
                .collect::<Vec<_>>()
                == vec![
                    format!(
                        "0::{}",
                        self.binding["group"]
                            .as_str()
                            .ok_or_else(|| Error("worker cgroup binding missing".into()))?
                    )
                    .as_bytes(),
                ],
            "original worker changed cgroup before closure",
        )?;
        self.process.recheck()?;
        Ok(&self.binding)
    }
    /// Verify a received descriptor against the original still-live worker's
    /// advertised open file description, while the worker awaits caller receipt.
    ///
    /// # Errors
    ///
    /// Fails when the binding changed or the descriptor is not the advertised open description.
    pub fn require_description(&self, file: BorrowedFd<'_>, number: u32) -> Result<()> {
        self.binding()?;
        self.process.require_description(file, number)?;
        self.binding()?;
        Ok(())
    }
    /// Observability only; immutable original metadata grants no execution or cleanup.
    ///
    /// # Errors
    ///
    /// Fails when the original scope changed.
    pub fn original_binding(&self) -> Result<&Value> {
        self.original()?;
        Ok(&self.binding)
    }
    fn empty(&self) -> Result<bool> {
        self.original()?;
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let alias = format!(
                    "/proc/{}/fd/{}",
                    std::process::id(),
                    self.directory.as_raw_fd()
                );
                require(
                    std::fs::read_link(alias)?.as_os_str()
                        == std::ffi::OsStr::new(&format!("{} (deleted)", self.path.display())),
                    "original cgroup disappeared without retained deletion proof",
                )?;
                self.original()?;
                Ok(true)
            }
            Err(error) => Err(error.into()),
            Ok(_) => {
                require(
                    shape(&files::directory(&self.path, Some(0))?)? == self.shape,
                    "original cgroup replaced",
                )?;
                let file = files::open_relative(&self.directory, Path::new("cgroup.events"))?;
                let before = file.metadata()?;
                require(
                    before.uid() == 0
                        && before.gid() == 0
                        && before.mode() & 0o022 == 0
                        && mount_identity::id(file.as_fd(), true)? == self.shape["mount"],
                    "original cgroup event authority changed",
                )?;
                let mut bytes = Vec::new();
                (&file).take(4097).read_to_end(&mut bytes)?;
                let empty = !populated(
                    std::str::from_utf8(&bytes)
                        .map_err(|_| Error("original cgroup event encoding".into()))?,
                )?;
                let after = file.metadata()?;
                require(
                    (before.dev(), before.ino()) == (after.dev(), after.ino())
                        && shape(&files::directory(&self.path, Some(0))?)? == self.shape,
                    "original cgroup changed during observation",
                )?;
                self.original()?;
                Ok(empty)
            }
        }
    }
    /// Whether the worker exited and its cgroup has no remaining processes.
    ///
    /// # Errors
    ///
    /// Fails when the scope changed or cannot be observed.
    pub fn exited_and_empty(&self) -> Result<bool> {
        self.original()?;
        Ok(self.process.exited()? && self.empty()?)
    }
    /// Close the scope once the worker and all descendants are gone.
    ///
    /// # Errors
    ///
    /// Fails while the worker or a descendant is still live.
    pub fn close(self) -> Result<Closed> {
        require(
            self.exited_and_empty()?,
            "original worker or descendants still live",
        )?;
        Ok(Closed { scope: self })
    }
}
/// A worker scope proven empty.
pub struct Closed {
    scope: Scope,
}
impl Closed {
    /// Verify the scope is still empty.
    ///
    /// # Errors
    ///
    /// Fails when a process reappeared or the scope changed.
    pub fn recheck(&self) -> Result<()> {
        require(
            self.scope.exited_and_empty()?,
            "original closed worker scope no longer empty",
        )
    }
    /// Recorded binding after a [`Closed::recheck`].
    ///
    /// # Errors
    ///
    /// Fails on [`Closed::recheck`].
    pub fn binding(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.scope.binding)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_dead_worker_scope_is_gone_only_with_its_cgroup_removed_or_empty() {
        let recorded = json!({"device":30,"inode":4,"mode":16877,"uid":0,"gid":0,"mount":9});
        assert_eq!(judge(false, None, &recorded), Remains::Gone);
        assert_eq!(
            judge(false, Some((recorded.clone(), false)), &recorded),
            Remains::Gone
        );
        assert_eq!(
            judge(false, Some((recorded.clone(), true)), &recorded),
            Remains::Live
        );
        assert_eq!(judge(true, None, &recorded), Remains::Live);
        let mut other = recorded.clone();
        other["inode"] = json!(5);
        assert_eq!(
            judge(false, Some((other, false)), &recorded),
            Remains::Unproven
        );
        assert_eq!(remains(&json!({"id":"not-an-id"})), Remains::Unproven);
    }
    #[test]
    fn complete_subtree_population_is_mandatory_and_ambiguous_events_refused() {
        assert!(!populated("populated 0\nfrozen 0\n").unwrap());
        assert!(populated("populated 1\nfrozen 0\n").unwrap());
        for body in [
            "frozen 0\n",
            "populated 0\npopulated 1\n",
            "populated 2\n",
            "populated 0 extra\n",
            "populated -1\n",
        ] {
            assert!(populated(body).is_err());
        }
        assert!(unit("../../other").is_err());
    }
}
