// SPDX-License-Identifier: MIT
//! Read-only, original-file observations of the two legacy backup receipt stores.
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use enzimos_policy::storage_runtime::Guard;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

pub struct Receipt {
    pub seconds: i64,
    pub nanoseconds: i64,
    pub state: String,
    pub point: Option<String>,
}
struct Record {
    name: String,
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    value: Option<Value>,
}
struct Folder {
    name: &'static str,
    original: File,
    identity: files::FileIdentity,
    names: BTreeSet<String>,
    records: Vec<Record>,
}
fn names(folder: &File, jobs: bool) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", folder.as_raw_fd()))? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| Error("backup status receipt filename encoding".into()))?;
        require(
            result.len() < if jobs { 129 } else { 128 },
            "backup status receipt count bound",
        )?;
        require(
            (jobs && name == "lock")
                || name
                    .strip_suffix(".json")
                    .is_some_and(|id| crate::system_wire::hex(id, 32)),
            "backup status unknown receipt requires review",
        )?;
        require(result.insert(name), "duplicate backup status receipt")?;
    }
    Ok(result)
}
impl Folder {
    fn observe(guard: &Guard, name: &'static str) -> Result<Option<Self>> {
        require(
            matches!(name, "backup-attempts" | "backend-operations"),
            "backup status store outside registry",
        )?;
        guard.recheck()?;
        let Some(original) =
            files::optional_directory_relative(guard.control(), Path::new(name), Some(0))?
        else {
            return Ok(None);
        };
        let m = original.metadata()?;
        require(
            m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o700
                && mount_identity::id(original.as_fd(), true)? == guard.control_mount_id(),
            "backup status original private store required",
        )?;
        let identity = files::identity(&m);
        let members = names(&original, name == "backend-operations")?;
        let mut records = Vec::new();
        for name in &members {
            let file = files::open_relative(&original, Path::new(name))?;
            let m = file.metadata()?;
            require(
                m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7777 == 0o600
                    && m.nlink() == 1
                    && mount_identity::id(file.as_fd(), true)? == guard.control_mount_id(),
                "backup status private original receipt required",
            )?;
            let identity = files::identity(&m);
            let bytes = files::read_file(&file, 8192, Some(0), true)?;
            let value = if name == "lock" {
                None
            } else {
                Some(json::decode(&bytes, 8192)?)
            };
            require(
                files::identity(&file.metadata()?) == identity,
                "backup status receipt changed during read",
            )?;
            records.push(Record {
                name: name.clone(),
                file,
                identity,
                bytes,
                value,
            });
        }
        let folder = Self {
            name,
            original,
            identity,
            names: members,
            records,
        };
        folder.recheck(guard)?;
        Ok(Some(folder))
    }
    fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let named = files::directory_relative(guard.control(), Path::new(self.name), Some(0))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.original.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id()
                && mount_identity::id(self.original.as_fd(), true)? == guard.control_mount_id()
                && names(&self.original, self.name == "backend-operations")? == self.names,
            "backup status original store inventory changed",
        )?;
        for record in &self.records {
            let named = files::open_relative(&self.original, Path::new(&record.name))?;
            require(
                files::identity(&named.metadata()?) == record.identity
                    && files::identity(&record.file.metadata()?) == record.identity
                    && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id()
                    && mount_identity::id(record.file.as_fd(), true)? == guard.control_mount_id()
                    && files::read_file(&record.file, 8192, Some(0), true)? == record.bytes,
                "backup status receipt changed or replaced",
            )?;
        }
        Ok(())
    }
}
pub struct Snapshot<'a> {
    guard: &'a Guard,
    control: files::FileIdentity,
    attempts: Option<Folder>,
    jobs: Option<Folder>,
}
impl<'a> Snapshot<'a> {
    pub fn observe(guard: &'a Guard) -> Result<Self> {
        guard.recheck()?;
        let control = files::identity(&guard.control().metadata()?);
        let attempts = Folder::observe(guard, "backup-attempts")?;
        let jobs = Folder::observe(guard, "backend-operations")?;
        let snapshot = Self {
            guard,
            control,
            attempts,
            jobs,
        };
        snapshot.recheck()?;
        Ok(snapshot)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        for folder in self.attempts.iter().chain(self.jobs.iter()) {
            folder.recheck(self.guard)?;
        }
        require(
            files::identity(&self.guard.control().metadata()?) == self.control,
            "backup status control inventory changed",
        )
    }
    pub fn latest(&self) -> Result<Option<Receipt>> {
        self.recheck()?;
        let value = project(self)?;
        self.recheck()?;
        Ok(value)
    }
}
pub fn latest(guard: &Guard) -> Result<Option<Receipt>> {
    Snapshot::observe(guard)?.latest()
}
fn project(snapshot: &Snapshot<'_>) -> Result<Option<Receipt>> {
    let guard = snapshot.guard;
    guard.recheck()?;
    let boot = enzimos_policy::operation::boot_id()?;
    let mut receipts = Vec::new();
    for folder in snapshot.attempts.iter().chain(snapshot.jobs.iter()) {
        for record in &folder.records {
            let Some(value) = &record.value else {
                continue;
            };
            let id = record.name.strip_suffix(".json").unwrap();
            let outcome = if folder.name == "backup-attempts" {
                enzimos_policy::backup_attempt::validate(value, id)?;
                match value["state"].as_str().unwrap() {
                    "running" if value["boot_id"] == boot => None,
                    "running" | "uncertain" => Some(("uncertain", None)),
                    "completed" => Some((
                        "completed",
                        value["snapshot_id"]
                            .as_str()
                            .filter(|id| id.len() == 64)
                            .map(str::to_owned),
                    )),
                    _ => return Err(Error("backup status invalid attempt state".into())),
                }
            } else {
                crate::operation_record::validate(value)?;
                require(
                    value["request_id"] == id,
                    "backup status operation receipt name differs",
                )?;
                if value["operation"] != "backup-create" {
                    None
                } else {
                    match value["state"].as_str().unwrap() {
                        "completed" => Some((
                            "completed",
                            Some(
                                value["result"]["snapshot_id"]
                                    .as_str()
                                    .ok_or_else(|| {
                                        Error("backup status completed point missing".into())
                                    })?
                                    .to_owned(),
                            ),
                        )),
                        "uncertain" => Some(("uncertain", None)),
                        _ => None,
                    }
                }
            };
            if let Some((state, point)) = outcome {
                receipts.push(Receipt {
                    seconds: record.identity.3,
                    nanoseconds: record.identity.4,
                    state: state.into(),
                    point,
                });
            }
        }
        folder.recheck(guard)?;
    }
    guard.recheck()?;
    snapshot.recheck()?;
    newest(receipts)
}
fn newest(receipts: Vec<Receipt>) -> Result<Option<Receipt>> {
    require(
        receipts.iter().all(|r| {
            r.seconds >= 0
                && r.seconds < 253402300799
                && (0..1_000_000_000).contains(&r.nanoseconds)
        }),
        "backup status receipt timestamp bound",
    )?;
    let Some(latest) = receipts.iter().map(|r| (r.seconds, r.nanoseconds)).max() else {
        return Ok(None);
    };
    let mut tied = receipts
        .into_iter()
        .filter(|r| (r.seconds, r.nanoseconds) == latest)
        .collect::<Vec<_>>();
    let uncertain = tied.iter().any(|r| r.state == "uncertain")
        || tied.iter().map(|r| &r.point).collect::<BTreeSet<_>>().len() > 1;
    let mut result = tied.remove(0);
    if uncertain {
        result.state = "uncertain".into();
        result.point = None;
    }
    Ok(Some(result))
}
