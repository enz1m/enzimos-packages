// SPDX-License-Identifier: MIT
//! Private durable review intent: an interrupted row never authorizes retry.
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
const LIMIT: usize = 32768;
const CAPACITY: usize = 32;
fn identifier(s: &str) -> bool {
    crate::identity::safe_id(s).is_ok()
}
#[derive(Clone, Copy)]
enum Kind {
    Review,
    Setup,
    Area,
}
impl Kind {
    fn validate(self, v: &Value, id: &str) -> Result<()> {
        match self {
            Self::Review => crate::backup_mount_review::validate_receipt(v, id),
            Self::Setup => crate::backup_setup_mount::validate_receipt(v, id),
            Self::Area => crate::backup_private_area::validate_receipt(v, id),
        }
    }
}
/// Terminal phases. `rolled-back` is a setup/area intent whose mount was
/// detached again by its owner's rollback or the explicit reset; it never
/// authorizes replay and never claims a completed operation.
pub(crate) fn terminal(phase: &Value) -> bool {
    phase == "complete" || phase == "rolled-back"
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File, owner: u32) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == 0o700,
        "private device review directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
struct Record {
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    value: Value,
}
pub(crate) struct Store<'g> {
    kind: Kind,
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
                "device review capacity or interrupted files require review",
            )?;
            let name = entry
                .into_string()
                .map_err(|_| enzimos_platform::Error("device review filename encoding".into()))?;
            require(
                name.strip_suffix(".json").is_some_and(identifier),
                "unknown/interrupted device review file requires review",
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
            "protected device review inode required",
        )?;
        let bytes = files::read_file(&file, LIMIT, Some(self.owner), true)?;
        let value = json::decode(&bytes, LIMIT)?;
        self.kind.validate(
            &value,
            name.strip_suffix(".json")
                .ok_or_else(|| enzimos_platform::Error("unexpected name".into()))?,
        )?;
        let identity = files::identity(&m);
        require(
            files::identity(&file.metadata()?) == identity,
            "device review changed during read",
        )?;
        Ok(Record {
            file,
            identity,
            bytes,
            value,
        })
    }
    pub(crate) fn retained(
        path: &Path,
        owner: u32,
        mount: u64,
        guard: Box<dyn Fn() -> Result<()> + 'g>,
    ) -> Result<Self> {
        Self::retained_kind(path, owner, mount, guard, Kind::Review)
    }
    pub(crate) fn retained_setup(
        path: &Path,
        owner: u32,
        mount: u64,
        guard: Box<dyn Fn() -> Result<()> + 'g>,
    ) -> Result<Self> {
        Self::retained_kind(path, owner, mount, guard, Kind::Setup)
    }
    pub(crate) fn retained_area(
        path: &Path,
        owner: u32,
        mount: u64,
        guard: Box<dyn Fn() -> Result<()> + 'g>,
    ) -> Result<Self> {
        Self::retained_kind(path, owner, mount, guard, Kind::Area)
    }
    fn retained_kind(
        path: &Path,
        owner: u32,
        mount: u64,
        guard: Box<dyn Fn() -> Result<()> + 'g>,
        kind: Kind,
    ) -> Result<Self> {
        guard()?;
        let directory = files::directory(path, Some(owner))?;
        require(
            mount_identity::id(directory.as_fd(), true)? == mount,
            "device review directory outside original control mount",
        )?;
        let mut this = Self {
            kind,
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
    pub(crate) fn recheck(&self) -> Result<()> {
        (self.guard)()?;
        let named = files::directory(&self.path, Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.shape
                && shape(&self.directory, self.owner)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.directory.as_fd(), true)? == self.mount
                && self.names()? == self.records.keys().cloned().collect::<Vec<_>>(),
            "original device review directory/membership changed",
        )?;
        for (name, row) in &self.records {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&row.file.metadata()?) == row.identity
                    && files::identity(&named.metadata()?) == row.identity
                    && mount_identity::id(row.file.as_fd(), true)? == self.mount
                    && mount_identity::id(named.as_fd(), true)? == self.mount
                    && files::read_file(&row.file, LIMIT, Some(self.owner), true)? == row.bytes,
                "original device review epoch changed or replaced",
            )?;
        }
        (self.guard)()
    }
    /// Completed receipts of runtime attachments (`runtime-*`, one review,
    /// mount and private area per backup, cleanup, restore or export) carry no
    /// later authority. Retire them before they fill the bounded store; setup
    /// and unfinished records are never touched.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fsync).")]
    fn prune_runtime(&mut self) -> Result<()> {
        use std::os::fd::AsRawFd;
        let names = self
            .records
            .iter()
            .filter(|(name, row)| name.starts_with("runtime-") && terminal(&row.value["phase"]))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if names.is_empty() {
            return Ok(());
        }
        for name in names {
            self.unlink(&name)?;
        }
        require(
            unsafe { libc::fsync(self.directory.as_raw_fd()) } == 0,
            "runtime receipt retirement durability unknown",
        )?;
        self.recheck()
    }
    /// Remove one retained record after proving it is still the original.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    fn unlink(&mut self, name: &str) -> Result<()> {
        use std::os::fd::AsRawFd;
        let row = &self.records[name];
        let named = files::open_relative(&self.directory, Path::new(name))?;
        require(
            files::identity(&named.metadata()?) == row.identity
                && files::read_file(&named, LIMIT, Some(self.owner), true)? == row.bytes,
            "runtime receipt changed before retirement",
        )?;
        drop(named);
        let c = std::ffi::CString::new(name)
            .map_err(|_| enzimos_platform::Error("receipt name encoding".into()))?;
        require(
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), c.as_ptr(), 0) } == 0,
            "runtime receipt retirement refused",
        )?;
        self.records.remove(name);
        Ok(())
    }
    /// A runtime read-only review interrupted before completion. Its mount
    /// was a detached descriptor of the process that held the operation lock;
    /// a caller holding that lock now proves the process and mount are gone.
    /// The record authorizes nothing, so it is removed rather than replayed.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fsync).")]
    pub(crate) fn retire_interrupted_review(&mut self, id: &str) -> Result<()> {
        use std::os::fd::AsRawFd;
        self.recheck()?;
        let name = format!("{id}.json");
        require(
            matches!(self.kind, Kind::Review)
                && id.starts_with("runtime-")
                && self
                    .records
                    .get(&name)
                    .is_some_and(|r| r.value["phase"] == "prepared"),
            "only an interrupted runtime review may be retired",
        )?;
        self.unlink(&name)?;
        require(
            unsafe { libc::fsync(self.directory.as_raw_fd()) } == 0,
            "runtime receipt retirement durability unknown",
        )?;
        self.recheck()
    }
    pub(crate) fn prepare(&mut self, v: Value) -> Result<()> {
        self.recheck()?;
        if self.records.len() >= CAPACITY / 2 {
            self.prune_runtime()?;
        }
        let id = v["id"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("review ID required".into()))?;
        self.kind.validate(&v, id)?;
        require(
            v["schema"].as_u64() == Some(2)
                && v["phase"] == "prepared"
                && self.records.len() < CAPACITY
                && self.records.values().all(|r| terminal(&r.value["phase"])),
            "interrupted device review/capacity requires inspection; no replay",
        )?;
        let name = format!("{id}.json");
        require(!self.records.contains_key(&name), "review ID cannot replay")?;
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
        self.recheck()
    }
    pub(crate) fn completed(&self, id: &str) -> Result<Value> {
        self.recheck()?;
        crate::identity::safe_id(id)?;
        require(
            self.records.values().all(|r| terminal(&r.value["phase"])),
            "interrupted review requires inspection",
        )?;
        let v = &self
            .records
            .get(&format!("{id}.json"))
            .ok_or_else(|| enzimos_platform::Error("completed review missing".into()))?
            .value;
        require(
            v["schema"].as_u64() == Some(2) && v["phase"] == "complete",
            "fresh native completed review required",
        )?;
        Ok(v.clone())
    }
    pub(crate) fn mount_recorded(&mut self, id: &str, binding: Value) -> Result<Value> {
        require(
            matches!(self.kind, Kind::Setup | Kind::Area),
            "setup journal required",
        )?;
        self.change(id, &["prepared"], "mounted", None, Some(binding))
    }
    pub(crate) fn mount_closed(&mut self, id: &str) -> Result<Value> {
        require(
            matches!(self.kind, Kind::Setup | Kind::Area),
            "setup journal required",
        )?;
        self.change(id, &["mounted"], "complete", None, None)
    }
    /// The owner detached its mount (or none was attached) after a failure.
    /// Callers must first prove the fixed target no longer holds the mount.
    pub(crate) fn rolled_back(&mut self, id: &str) -> Result<Value> {
        require(
            matches!(self.kind, Kind::Setup | Kind::Area),
            "setup journal required",
        )?;
        self.change(id, &["prepared", "mounted"], "rolled-back", None, None)
    }
    /// IDs of setup/area intents that never reached a terminal phase.
    pub(crate) fn unfinished(&self) -> Result<Vec<String>> {
        self.recheck()?;
        Ok(self
            .records
            .iter()
            .filter(|(_, r)| !terminal(&r.value["phase"]))
            .map(|(name, _)| name.trim_end_matches(".json").to_owned())
            .collect())
    }
    pub(crate) fn complete(&mut self, id: &str, result: Value) -> Result<Value> {
        require(
            matches!(self.kind, Kind::Review),
            "readonly journal required",
        )?;
        self.change(id, &["prepared"], "complete", Some(result), None)
    }
    fn change(
        &mut self,
        id: &str,
        before: &[&str],
        after: &str,
        result: Option<Value>,
        binding: Option<Value>,
    ) -> Result<Value> {
        self.recheck()?;
        let name = format!("{id}.json");
        let row = self
            .records
            .get(&name)
            .ok_or_else(|| enzimos_platform::Error("original review missing".into()))?;
        require(
            row.value["schema"].as_u64() == Some(2)
                && row.value["phase"]
                    .as_str()
                    .is_some_and(|phase| before.contains(&phase)),
            "review already terminal; no replay",
        )?;
        let mut v = row.value.clone();
        v["phase"] = Value::String(after.into());
        match self.kind {
            Kind::Review => {
                v["descriptor_scope_closed"] = Value::Bool(true);
                v["result"] = result.unwrap();
            }
            Kind::Setup | Kind::Area => {
                v["mount_closed"] = Value::Bool(after == "complete" || after == "rolled-back");
                if let Some(binding) = binding {
                    v["mount_binding"] = binding;
                }
            }
        }
        self.kind.validate(&v, id)?;
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
