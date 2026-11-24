// SPDX-License-Identifier: MIT
//! Durable backup attempts complete only after the caller's actual cleanup succeeds.
use enzimos_platform::{
    Result, backup_worker_scope::Remains, files, json, mount_identity, require,
};
use serde_json::{Value, json as value};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const LIMIT: usize = 8192;
const CAPACITY: usize = 128;
/// Finished attempts kept as history once the journal reaches capacity.
/// Older records are retired, so daily backups never exhaust it; a record
/// still running in the current boot is never removed and still blocks.
const RETAINED: usize = 32;
/// Whether an attempt row still blocks a new attempt: only one recorded as
/// running in this boot. A failed attempt publishes `uncertain` itself; a
/// `running` row from an earlier boot was interrupted by that boot ending, so
/// no process of it survives. Both stay visible (status reports them as
/// uncertain) and keep their objects for review, but never block forever.
pub fn blocks(row: &Value, boot: &str) -> bool {
    row["state"] == "running" && row["boot_id"] == boot
}
/// Like [`blocks`], and an `uncertain` attempt of this boot also blocks while
/// its transfer worker's kernel scope was never proven closed: that worker may
/// still be writing to the destination.
pub fn blocks_live(row: &Value, boot: &str, control: &Path) -> bool {
    if blocks(row, boot) {
        return true;
    }
    if row["state"] != "uncertain" || row["boot_id"] != boot {
        return false;
    }
    let Some(id) = row["id"].as_str().filter(|id| identifier(id)) else {
        return true;
    };
    let workers = control.join("backup-transfer-workers");
    if std::fs::symlink_metadata(&workers).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        // No transfer worker was ever reserved on this system.
        return false;
    }
    // Workers are named by the backup job (worker request) ID, not by the
    // attempt ID: find the job through the source capture naming this attempt.
    let Ok(jobs) = jobs_of(control, id) else {
        return true;
    };
    jobs.iter().any(|job| {
        match files::read_optional(
            &workers.join(format!("{job}.json")),
            LIMIT * 8,
            Some(0),
            true,
        ) {
            Ok(None) => false,
            Ok(Some(body)) => json::decode(&body, LIMIT * 8)
                .map_or(true, |worker| worker["phase"] != "worker-kernel-closed"),
            Err(_) => true,
        }
    })
}
/// Whether a blocking attempt row may be abandoned so a new backup can start
/// in the same boot. Every backend and transfer worker of an attempt holds
/// the operation lock's open description, so `lock_held` (this backup holds
/// it exclusively) means none of them is alive; additionally no other process
/// may record a running backup, no Restic process may exist, and every
/// transfer worker scope of the attempt must be proven gone.
pub(crate) fn may_abandon(
    lock_held: bool,
    foreign_run: bool,
    restic: bool,
    workers: &[Remains],
) -> bool {
    lock_held && !foreign_run && !restic && workers.iter().all(|w| *w == Remains::Gone)
}
/// What remains of each transfer worker recorded for attempt `id`. A record
/// that cannot be read or matched is [`Remains::Unproven`].
fn worker_remains(control: &Path, id: &str) -> Vec<Remains> {
    let workers = control.join("backup-transfer-workers");
    if std::fs::symlink_metadata(&workers).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return Vec::new();
    }
    let Ok(jobs) = jobs_of(control, id) else {
        return vec![Remains::Unproven];
    };
    jobs.iter()
        .filter_map(|job| {
            match files::read_optional(
                &workers.join(format!("{job}.json")),
                LIMIT * 8,
                Some(0),
                true,
            ) {
                Ok(None) => None,
                Ok(Some(body)) => Some(json::decode(&body, LIMIT * 8).map_or(
                    Remains::Unproven,
                    |record| {
                        if record["phase"] == "worker-kernel-closed" {
                            Remains::Gone
                        } else {
                            enzimos_platform::backup_worker_scope::remains(&record["worker"])
                        }
                    },
                )),
                Err(_) => Some(Remains::Unproven),
            }
        })
        .collect()
}
/// Whether any Restic process exists; an unreadable process list counts.
/// Restic is executed through its pinned descriptor, so its `comm` is a
/// descriptor number: the executable link names it.
fn restic_running() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return true;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.bytes().all(|b| b.is_ascii_digit()))
            && std::fs::read_link(entry.path().join("exe"))
                .is_ok_and(|exe| restic_image(exe.as_os_str().as_encoded_bytes()))
    })
}
/// The executable link of a Restic process, also after its file was replaced.
fn restic_image(link: &[u8]) -> bool {
    link == b"/usr/bin/restic" || link == b"/usr/bin/restic (deleted)"
}
/// Whether `lock` is the operation lock and this process holds it exclusively.
fn holds_operation_lock(lock: &files::Lock) -> bool {
    lock.recheck().is_ok()
        && std::fs::metadata(Path::new("/run/enzimos/operation.lock")).is_ok_and(|named| {
            lock.as_file()
                .metadata()
                .is_ok_and(|held| (held.dev(), held.ino()) == (named.dev(), named.ino()))
        })
        && enzimos_platform::flock_identity::exclusive(lock.as_file()).is_ok()
}
/// Job IDs whose source capture records attempt `id` (and `id` itself).
fn jobs_of(control: &Path, id: &str) -> Result<Vec<String>> {
    let mut jobs = vec![id.to_owned()];
    let captures = control.join("backup-source-captures");
    let Some(directory) = files::optional_directory_relative(
        &files::directory(control, Some(0))?,
        Path::new("backup-source-captures"),
        Some(0),
    )?
    else {
        return Ok(jobs);
    };
    for name in files::directory_names(&directory, 256)? {
        let Some(job) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        if crate::identity::safe_id(job).is_err() {
            continue;
        }
        let Some(body) =
            files::read_optional(&captures.join(&name), 8 * 1024 * 1024, Some(0), true)?
        else {
            continue;
        };
        if json::decode(&body, 8 * 1024 * 1024)?["attempt"]["id"] == id {
            jobs.push(job.to_owned());
        }
    }
    Ok(jobs)
}
fn identifier(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn snapshot(s: &str) -> bool {
    (8..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(v, "schema id boot_id started_unix state snapshot_id")?;
    require(
        identifier(id)
            && v["id"] == id
            && v["schema"].as_u64() == Some(1)
            && v["started_unix"].as_u64().is_some(),
        "invalid backup attempt identity/time",
    )?;
    crate::identity::uuid(
        v["boot_id"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("backup attempt boot required".into()))?,
    )?;
    require(
        match v["state"].as_str() {
            Some("running" | "uncertain" | "abandoned") => v["snapshot_id"].is_null(),
            Some("completed") => v["snapshot_id"].as_str().is_some_and(snapshot),
            _ => false,
        },
        "invalid backup attempt outcome",
    )
}
fn advance(before: &Value, after: &Value) -> Result<()> {
    let id = before["id"].as_str().unwrap();
    validate(after, id)?;
    require(
        ["schema", "id", "boot_id", "started_unix"]
            .iter()
            .all(|key| before[*key] == after[*key])
            && before["state"] == "running"
            && matches!(after["state"].as_str(), Some("completed" | "uncertain")),
        "backup attempt cannot replay or alter its original identity",
    )
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == 0o700,
        "private backup attempt directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
struct Record {
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    value: Value,
}
struct Store<'g> {
    path: PathBuf,
    directory: File,
    shape: Shape,
    mount: u64,
    owner: u32,
    records: BTreeMap<String, Record>,
    guard: Box<dyn Fn() -> Result<()> + 'g>,
}
impl<'g> Store<'g> {
    fn names(&self) -> Result<Vec<String>> {
        let mut result = Vec::new();
        for entry in files::directory_names(&self.directory, CAPACITY)? {
            require(
                result.len() < CAPACITY,
                "backup attempt capacity or interrupted files require review",
            )?;
            let name = entry
                .into_string()
                .map_err(|_| enzimos_platform::Error("backup attempt filename encoding".into()))?;
            require(
                name.strip_suffix(".json").is_some_and(identifier),
                "unknown/interrupted backup attempt file requires review",
            )?;
            result.push(name);
        }
        result.sort();
        Ok(result)
    }
    fn read(&self, name: &str) -> Result<Record> {
        let file = files::open_relative(&self.directory, Path::new(name))?;
        let m = file.metadata()?;
        require(
            m.uid() == self.owner
                && m.gid() == self.directory.metadata()?.gid()
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && mount_identity::id(file.as_fd(), true)? == self.mount,
            "protected backup attempt inode required",
        )?;
        let bytes = files::read_file(&file, LIMIT, Some(self.owner), true)?;
        let value = json::decode(&bytes, LIMIT)?;
        validate(&value, name.strip_suffix(".json").unwrap())?;
        let identity = files::identity(&m);
        require(
            files::identity(&file.metadata()?) == identity,
            "backup attempt changed during read",
        )?;
        Ok(Record {
            file,
            identity,
            bytes,
            value,
        })
    }
    fn retained(
        path: &Path,
        owner: u32,
        mount: u64,
        guard: Box<dyn Fn() -> Result<()> + 'g>,
    ) -> Result<Self> {
        guard()?;
        let directory = files::directory(path, Some(owner))?;
        require(
            mount_identity::id(directory.as_fd(), true)? == mount,
            "backup attempt directory outside original control mount",
        )?;
        let mut this = Self {
            path: path.into(),
            shape: shape(&directory, owner)?,
            directory,
            mount,
            owner,
            records: BTreeMap::new(),
            guard,
        };
        for name in this.names()? {
            this.records.insert(name.clone(), this.read(&name)?);
        }
        this.recheck()?;
        Ok(this)
    }
    fn recheck(&self) -> Result<()> {
        (self.guard)()?;
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.shape
                && shape(&self.directory, self.owner)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && self.names()? == self.records.keys().cloned().collect::<Vec<_>>(),
            "original backup attempt directory/membership changed",
        )?;
        for (name, row) in &self.records {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&row.file.metadata()?) == row.identity
                    && files::identity(&named.metadata()?) == row.identity
                    && mount_identity::id(row.file.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && files::read_file(&row.file, LIMIT, Some(self.owner), true)? == row.bytes
                    && files::identity(&row.file.metadata()?) == row.identity
                    && files::identity(&named.metadata()?) == row.identity,
                "original backup attempt epoch changed or replaced",
            )?;
        }
        (self.guard)()
    }
    /// Remove the oldest finished records beyond `RETAINED`, by exact inode.
    /// Rows still running in this boot are never removed.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn retire_completed(&mut self, boot: &str) -> Result<()> {
        if self.records.len() < CAPACITY - 1 {
            return Ok(());
        }
        let mut completed = self
            .records
            .iter()
            .filter(|(_, row)| {
                !blocks_live(
                    &row.value,
                    boot,
                    self.path
                        .parent()
                        .unwrap_or(Path::new(crate::operation::CONTROL)),
                )
            })
            .map(|(name, row)| {
                (
                    row.value["started_unix"].as_u64().unwrap_or(0),
                    name.clone(),
                )
            })
            .collect::<Vec<_>>();
        completed.sort();
        let excess = completed.len().saturating_sub(RETAINED);
        for (_, name) in completed.into_iter().take(excess) {
            self.recheck()?;
            let row = &self.records[&name];
            let named = files::open_relative(&self.directory, Path::new(&name))?;
            require(
                files::identity(&named.metadata()?) == row.identity,
                "retired backup attempt changed",
            )?;
            let c_name = std::ffi::CString::new(name.as_bytes())
                .map_err(|_| enzimos_platform::Error("backup attempt filename encoding".into()))?;
            require(
                unsafe {
                    libc::unlinkat(
                        std::os::fd::AsRawFd::as_raw_fd(&self.directory),
                        c_name.as_ptr(),
                        0,
                    )
                } == 0,
                "completed backup attempt retirement failed",
            )?;
            self.records.remove(&name);
        }
        self.directory.sync_all()?;
        self.recheck()
    }
    fn start(
        &mut self,
        id: &str,
        boot: &str,
        started: u64,
        abandon: &dyn Fn(&Value) -> bool,
    ) -> Result<usize> {
        self.recheck()?;
        self.retire_completed(boot)?;
        let control = self.path.parent().map_or_else(
            || PathBuf::from(crate::operation::CONTROL),
            Path::to_path_buf,
        );
        let blocking = self
            .records
            .iter()
            .filter(|(_, r)| blocks_live(&r.value, boot, &control))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let mut abandoned = 0;
        for name in blocking {
            if abandon(&self.records[&name].value) {
                self.abandon(&name)?;
                abandoned += 1;
            }
        }
        require(
            !self.records.values().any(|r| {
                blocks_live(
                    &r.value,
                    boot,
                    self.path
                        .parent()
                        .unwrap_or(Path::new(crate::operation::CONTROL)),
                )
            }),
            "backup-attempt-needs-restart",
        )?;
        require(self.records.len() < CAPACITY, "backup-attempt-capacity")?;
        let name = format!("{id}.json");
        require(
            !self.records.contains_key(&name),
            "backup attempt ID collision; no replay",
        )?;
        let v = value!({"schema":1,"id":id,"boot_id":boot,"started_unix":started,"state":"running","snapshot_id":null});
        validate(&v, id)?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_relative_retained(
            &self.directory,
            Path::new(&name),
            &bytes,
            0o600,
            Some(self.owner),
            false,
            LIMIT,
        )?;
        self.records.insert(
            name,
            Record {
                identity: files::identity(&file.metadata()?),
                file,
                bytes,
                value: v,
            },
        );
        self.recheck()?;
        Ok(abandoned)
    }
    /// Keep an interrupted attempt as `abandoned`, its audit record.
    fn abandon(&mut self, name: &str) -> Result<()> {
        self.recheck()?;
        let row = self
            .records
            .get(name)
            .ok_or_else(|| enzimos_platform::Error("abandoned backup attempt missing".into()))?;
        require(
            matches!(row.value["state"].as_str(), Some("running" | "uncertain")),
            "only an interrupted backup attempt can be abandoned",
        )?;
        let mut v = row.value.clone();
        v["state"] = value!("abandoned");
        validate(&v, name.strip_suffix(".json").unwrap_or(""))?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_replace_original(
            &self.directory,
            Path::new(name),
            &bytes,
            0o600,
            Some(self.owner),
            LIMIT,
            &row.file,
        )?;
        eprintln!(
            "enzimos-backup: abandoned interrupted attempt {} (was {}); its owner, workers and Restic are gone",
            v["id"].as_str().unwrap_or(""),
            row.value["state"].as_str().unwrap_or("")
        );
        self.records.insert(
            name.to_owned(),
            Record {
                identity: files::identity(&file.metadata()?),
                file,
                bytes,
                value: v,
            },
        );
        self.recheck()
    }
    fn finish(&mut self, id: &str, snapshot_id: Option<&str>) -> Result<Value> {
        self.finish_authorized(id, snapshot_id, &mut || Ok(()))
    }
    fn finish_authorized(
        &mut self,
        id: &str,
        snapshot_id: Option<&str>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        authorize()?;
        self.recheck()?;
        let name = format!("{id}.json");
        let row = self
            .records
            .get(&name)
            .ok_or_else(|| enzimos_platform::Error("original backup attempt missing".into()))?;
        let mut v = row.value.clone();
        v["state"] = value!(if snapshot_id.is_some() {
            "completed"
        } else {
            "uncertain"
        });
        v["snapshot_id"] = value!(snapshot_id);
        advance(&row.value, &v)?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_replace_original(
            &self.directory,
            Path::new(&name),
            &bytes,
            0o600,
            Some(self.owner),
            LIMIT,
            &row.file,
        )?;
        self.records.insert(
            name,
            Record {
                identity: files::identity(&file.metadata()?),
                file,
                bytes,
                value: v.clone(),
            },
        );
        self.recheck()?;
        Ok(v)
    }
}
pub struct Attempt<'g> {
    store: RefCell<Store<'g>>,
    id: String,
    active: Cell<bool>,
    original: Option<(&'g crate::storage_runtime::Guard, &'g files::Lock)>,
}
impl<'g> Attempt<'g> {
    /// Compare the actual retained actor address across invariant journal lifetimes.
    pub(crate) fn same_actor(&self, other: &Attempt<'_>) -> bool {
        std::ptr::from_ref(self).cast::<()>() == std::ptr::from_ref(other).cast::<()>()
    }
    pub fn begin(guard: &'g crate::storage_runtime::Guard, lock: &'g files::Lock) -> Result<Self> {
        guard.recheck()?;
        lock.recheck()?;
        let directory = files::ensure_directory_relative(
            guard.control(),
            Path::new("backup-attempts"),
            0o700,
            0,
        )?;
        require(
            mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
            "backup attempt journal outside control mount",
        )?;
        // Best effort: the per-backup registries' own bounds still decide.
        let _ = crate::backup_history::retire_locked(guard, lock);
        // Failed backups are never finished history; without this a machine
        // whose backups keep failing fills the snapshot registry and stops.
        let _ = crate::backup_history::retire_failed_locked(guard, lock);
        let mut store = Store::retained(
            &Path::new(crate::operation::CONTROL).join("backup-attempts"),
            0,
            guard.control_mount_id(),
            Box::new(move || {
                guard.recheck()?;
                lock.recheck()
            }),
        )?;
        let id = files::random_hex(16)?;
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| enzimos_platform::Error("backup attempt clock unavailable".into()))?
            .as_secs();
        let control = Path::new(crate::operation::CONTROL);
        let abandoned = store.start(&id, &crate::operation::boot_id()?, started, &|row| {
            may_abandon(
                holds_operation_lock(lock),
                crate::backup_running::foreign(),
                restic_running(),
                &worker_remains(control, row["id"].as_str().unwrap_or("")),
            )
        })?;
        if abandoned > 0 {
            // An abandoned attempt's snapshots and staging are no one's any more.
            let _ = crate::backup_history::retire_failed_locked(guard, lock);
        }
        Ok(Self {
            store: RefCell::new(store),
            id,
            active: Cell::new(true),
            original: Some((guard, lock)),
        })
    }
    pub(crate) fn id(&self) -> Result<&str> {
        self.evidence()?;
        Ok(&self.id)
    }
    /// Explicitly publish uncertainty while the original store is still checked.
    /// This never grants transfer, cleanup or permission to replay the attempt.
    pub(crate) fn fence(self) -> Result<Value> {
        self.evidence()?;
        let record = self.store.borrow_mut().finish(&self.id, None)?;
        self.active.set(false);
        Ok(record)
    }
    pub fn recheck(&self) -> Result<()> {
        self.store.borrow().recheck()
    }
    pub(crate) fn require_lock(&self, lock: &files::Lock) -> Result<()> {
        self.evidence()?;
        require(
            self.original
                .is_some_and(|(_, original)| std::ptr::eq(original, lock)),
            "capture requires the original attempt operation lock actor",
        )?;
        lock.recheck()
    }
    pub(crate) fn require_original(
        &self,
        guard: &crate::storage_runtime::Guard,
        lock: &files::Lock,
    ) -> Result<()> {
        self.require_lock(lock)?;
        require(
            self.original
                .is_some_and(|(original, _)| std::ptr::eq(original, guard)),
            "capture requires the original attempt storage guard actor",
        )?;
        guard.recheck()
    }
    /// Review data only. The original running attempt and its lock remain borrowed actors.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let store = self.store.borrow();
        let original = store
            .records
            .get(&format!("{}.json", self.id))
            .ok_or_else(|| {
                enzimos_platform::Error("original running backup attempt missing".into())
            })?;
        require(
            self.active.get() && original.value["state"] == "running",
            "source capture requires original running backup attempt",
        )?;
        Ok(
            value!({"id":self.id,"record":original.value,"file":original.identity,
            "bytes_sha256":json::sha256(&original.bytes),"mount":store.mount,
            "directory":store.shape}),
        )
    }
    /// Terminal evidence still comes from the original retained journal inode.
    pub(crate) fn completed_record(&self) -> Result<Value> {
        self.recheck()?;
        let store = self.store.borrow();
        let row = store
            .records
            .get(&format!("{}.json", self.id))
            .ok_or_else(|| enzimos_platform::Error("original completed attempt missing".into()))?;
        require(
            !self.active.get() && row.value["state"] == "completed",
            "original attempt is not durably completed",
        )?;
        Ok(row.value.clone())
    }
    /// Only the original typed final publication actor may commit success while
    /// retained cleanup evidence still borrows the original running attempt.
    pub(crate) fn commit_completed(
        &self,
        proof: &crate::backup_completion::Prepared<'_, '_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        authorize()?;
        proof.require_attempt(self)?;
        let id = proof.snapshot_id()?;
        let result = self
            .store
            .borrow_mut()
            .finish_authorized(&self.id, Some(&id), authorize)?;
        self.active.set(false);
        Ok(result)
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.active.get() {
            let _ = self.store.get_mut().finish(&self.id, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> tempfile::TempDir {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
    fn store(dir: &tempfile::TempDir) -> Store<'static> {
        let f = files::directory(dir.path(), Some(unsafe { libc::getuid() })).unwrap();
        Store::retained(
            dir.path(),
            unsafe { libc::getuid() },
            mount_identity::id(f.as_fd(), true).unwrap(),
            Box::new(|| Ok(())),
        )
        .unwrap()
    }
    const ID: &str = "11111111111111111111111111111111";
    const NEXT: &str = "22222222222222222222222222222222";
    const BOOT: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn actual_durable_attempt_never_replays_running_uncertain_or_completed_ids() {
        let dir = fixture();
        let mut s = store(&dir);
        s.start(ID, BOOT, 1, &|_| false).unwrap();
        assert!(s.start(NEXT, BOOT, 2, &|_| false).is_err());
        drop(s);
        let mut s = store(&dir);
        assert!(s.start(NEXT, BOOT, 2, &|_| false).is_err());
        s.finish(ID, Some("aabbccdd")).unwrap();
        assert!(s.finish(ID, Some("aabbccdd")).is_err());
        assert!(s.start(ID, BOOT, 2, &|_| false).is_err());
        s.start(NEXT, BOOT, 2, &|_| false).unwrap();
        let a = Attempt {
            store: RefCell::new(s),
            id: NEXT.into(),
            active: Cell::new(true),
            original: None,
        };
        let evidence = a.evidence().unwrap();
        assert_eq!(evidence["id"], NEXT);
        assert_eq!(evidence["record"]["state"], "running");
        assert_eq!(
            evidence["file"],
            value!(files::identity(
                &a.store.borrow().records[&format!("{NEXT}.json")]
                    .file
                    .metadata()
                    .unwrap()
            ))
        );
        drop(a);
        let mut s = store(&dir);
        assert_eq!(
            s.records[&format!("{NEXT}.json")].value["state"],
            "uncertain"
        );
        assert!(s.start(NEXT, BOOT, 3, &|_| false).is_err());
        s.start("33333333333333333333333333333333", BOOT, 3, &|_| false)
            .unwrap();
    }

    #[test]
    fn only_a_dead_owner_with_every_worker_gone_may_be_abandoned() {
        assert!(may_abandon(true, false, false, &[]));
        assert!(may_abandon(
            true,
            false,
            false,
            &[Remains::Gone, Remains::Gone]
        ));
        // A live owner: the lock is held elsewhere, or another process records a run.
        assert!(!may_abandon(false, false, false, &[]));
        assert!(!may_abandon(true, true, false, &[]));
        assert!(!may_abandon(true, false, true, &[]));
        assert!(!may_abandon(
            true,
            false,
            false,
            &[Remains::Gone, Remains::Live]
        ));
        assert!(!may_abandon(true, false, false, &[Remains::Unproven]));
    }
    #[test]
    fn a_dead_owner_unblocks_with_an_audit_record_and_a_live_one_still_blocks() {
        let dir = fixture();
        let mut s = store(&dir);
        s.start(ID, BOOT, 1, &|_| false).unwrap();
        let refused = s.start(NEXT, BOOT, 2, &|_| false).unwrap_err();
        assert_eq!(refused.0, "backup-attempt-needs-restart");
        assert_eq!(s.records[&format!("{ID}.json")].value["state"], "running");
        let asked = std::cell::RefCell::new(Vec::new());
        s.start(NEXT, BOOT, 2, &|row| {
            asked.borrow_mut().push(row["id"].clone());
            true
        })
        .unwrap();
        assert_eq!(*asked.borrow(), [value!(ID)]);
        drop(s);
        let s = store(&dir);
        let audit = &s.records[&format!("{ID}.json")].value;
        assert_eq!(audit["state"], "abandoned");
        assert_eq!(audit["boot_id"], BOOT);
        assert_eq!(audit["started_unix"], 1);
        assert!(!blocks_live(audit, BOOT, dir.path()));
        assert_eq!(s.records[&format!("{NEXT}.json")].value["state"], "running");
    }
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (getuid).")]
    fn an_unproven_scope_keeps_an_uncertain_attempt_blocking() {
        let dir = fixture();
        let attempts = dir.path().join("backup-attempts");
        std::fs::create_dir(&attempts).unwrap();
        std::fs::set_permissions(&attempts, std::fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let held = files::directory(&attempts, Some(uid)).unwrap();
        let mut s = Store::retained(
            &attempts,
            uid,
            mount_identity::id(held.as_fd(), true).unwrap(),
            Box::new(|| Ok(())),
        )
        .unwrap();
        s.start(ID, BOOT, 1, &|_| false).unwrap();
        s.finish(ID, None).unwrap();
        std::fs::create_dir(dir.path().join("backup-transfer-workers")).unwrap();
        std::fs::write(
            dir.path()
                .join(format!("backup-transfer-workers/{ID}.json")),
            br#"{"phase":"send-entered","worker":{"id":"not-a-scope"}}"#,
        )
        .unwrap();
        assert!(blocks_live(
            &s.records[&format!("{ID}.json")].value,
            BOOT,
            dir.path()
        ));
        let workers = worker_remains(dir.path(), ID);
        assert_eq!(workers, [Remains::Unproven]);
        let refused = s
            .start(NEXT, BOOT, 2, &|_| {
                may_abandon(true, false, false, &workers)
            })
            .unwrap_err();
        assert_eq!(refused.0, "backup-attempt-needs-restart");
        assert_eq!(s.records[&format!("{ID}.json")].value["state"], "uncertain");
    }
}
