// SPDX-License-Identifier: MIT
//! Original read-only backend protection for native retirement previews.
//! This actor cannot exempt a row, mutate a ledger or authorize deletion.
use crate::{control_record::Retained, identity, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "backend-operations";
const MAX: usize = 8192;
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn validate(row: &Value, id: &str) -> Result<()> {
    json::fields(
        row,
        "schema request_id owner_uid operation state progress plan plan_sha256 result",
    )?;
    require(
        hex(id, 32)
            && row["request_id"] == id
            && row["schema"] == 3
            && row["owner_uid"]
                .as_u64()
                .is_some_and(|n| n < u64::from(u32::MAX))
            && row["operation"]
                .as_str()
                .is_some_and(|s| enzimos_platform::system_contract::OPERATIONS.contains(&s))
            && row["plan"].is_object(),
        "original backend reference envelope",
    )?;
    let mut canonical = json::canonical(&row["plan"])?;
    canonical.push(b'\n');
    require(
        row["plan_sha256"] == json::sha256(&canonical),
        "original backend reference plan seal",
    )?;
    let state = row["state"]
        .as_str()
        .ok_or_else(|| Error("backend reference state".into()))?;
    require(
        matches!(
            state,
            "planned" | "queued" | "running" | "completed" | "cancelled" | "uncertain"
        ),
        "unknown backend reference state",
    )?;
    require(
        row["progress"].as_str().is_some_and(|p| match state {
            "planned" | "queued" => p == state,
            "running" => matches!(p, "validating" | "capturing" | "transferring" | "finishing"),
            "completed" => p == "completed",
            _ => matches!(
                p,
                "planned" | "queued" | "validating" | "capturing" | "transferring" | "finishing"
            ),
        }) && if state == "completed" {
            row["result"].is_object()
        } else {
            row["result"].is_null()
        },
        "original backend reference phase/result",
    )
}
fn directory(parent: &File, mount: u64) -> Result<files::FileIdentity> {
    let m = parent.metadata()?;
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && mount_identity::id(parent.as_fd(), true)? == mount,
        "original private backend reference directory",
    )?;
    Ok(files::identity(&m))
}
fn members(parent: &File) -> Result<BTreeSet<String>> {
    files::directory_names(parent, 129)?
        .into_iter()
        .map(|n| {
            n.into_string()
                .map_err(|_| Error("backend reference filename encoding".into()))
        })
        .collect()
}
pub struct Observation<'g> {
    guard: &'g Guard,
    parent: Option<File>,
    epoch: Option<files::FileIdentity>,
    names: BTreeSet<String>,
    lock: Option<File>,
    lock_epoch: Option<files::FileIdentity>,
    records: BTreeMap<String, Retained>,
}
impl<'g> Observation<'g> {
    pub(crate) fn observe(guard: &'g Guard) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let parent =
            files::optional_directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        let mut this = Self {
            guard,
            parent,
            epoch: None,
            names: BTreeSet::new(),
            lock: None,
            lock_epoch: None,
            records: BTreeMap::new(),
        };
        if let Some(parent) = &this.parent {
            this.epoch = Some(directory(parent, guard.control_mount_id())?);
            this.names = members(parent)?;
            require(
                this.names.contains("lock"),
                "original backend ledger lock missing",
            )?;
            let lock = files::open_relative(parent, Path::new("lock"))?;
            let m = lock.metadata()?;
            require(
                m.is_file()
                    && m.nlink() == 1
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7777 == 0o600
                    && mount_identity::id(lock.as_fd(), true)? == guard.control_mount_id(),
                "original backend ledger lock protection",
            )?;
            this.lock_epoch = Some(files::identity(&m));
            this.lock = Some(lock);
            for name in this.names.iter().filter(|n| n.as_str() != "lock") {
                let id = name
                    .strip_suffix(".json")
                    .filter(|s| hex(s, 32))
                    .ok_or_else(|| {
                        Error("unknown/interrupted original backend reference member".into())
                    })?;
                let record =
                    Retained::open(parent, Path::new(name), MAX, guard.control_mount_id())?;
                validate(record.value()?, id)?;
                this.records.insert(id.into(), record);
            }
        }
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let named =
            files::optional_directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        match (&self.parent, named, self.epoch) {
            (None, None, None) => (),
            (Some(parent), Some(named), Some(epoch)) => {
                require(
                    directory(parent, self.guard.control_mount_id())? == epoch
                        && directory(&named, self.guard.control_mount_id())? == epoch
                        && members(parent)? == self.names
                        && members(&named)? == self.names,
                    "original backend reference directory/membership changed",
                )?;
                let lock = self
                    .lock
                    .as_ref()
                    .ok_or_else(|| Error("original ledger lock missing".into()))?;
                let named_lock = files::open_relative(&named, Path::new("lock"))?;
                require(
                    Some(files::identity(&lock.metadata()?)) == self.lock_epoch
                        && Some(files::identity(&named_lock.metadata()?)) == self.lock_epoch
                        && mount_identity::id(lock.as_fd(), true)? == self.guard.control_mount_id()
                        && mount_identity::id(named_lock.as_fd(), true)?
                            == self.guard.control_mount_id(),
                    "original backend ledger lock changed/covered",
                )?;
                for (id, record) in &self.records {
                    record.recheck()?;
                    validate(record.value()?, id)?;
                }
            }
            _ => {
                return Err(Error(
                    "original backend reference directory appeared/disappeared".into(),
                ));
            }
        }
        self.guard.recheck()
    }
    pub fn require_unmentioned(&self, generation: &str) -> Result<()> {
        let conclusions = crate::recovery_conclusions::Observation::observe(self.guard)?;
        self.require_unmentioned_with_conclusions(generation, &conclusions)
    }
    pub(crate) fn require_unmentioned_with_conclusions(
        &self,
        generation: &str,
        conclusions: &crate::recovery_conclusions::Observation<'_>,
    ) -> Result<()> {
        conclusions.recheck()?;
        identity::safe_id(generation)?;
        self.recheck()?;
        for record in self.records.values() {
            let row = record.value()?;
            require(
                matches!(
                    row["state"].as_str(),
                    Some("planned" | "completed" | "cancelled")
                ),
                "unfinished backend operation prevents boot retirement",
            )?;
            if row["state"] != "cancelled" {
                require(
                    !crate::boot_retirement_plan::mentions(row, generation)?
                        || conclusions.historical_backend_record(row)?,
                    "original backend record protects generation",
                )?;
            }
        }
        conclusions.recheck()?;
        self.recheck()
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let records = self
            .records
            .iter()
            .map(|(id, r)| Ok((id.clone(), r.value()?.clone())))
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(
            value!({"directory":self.epoch,"lock":self.lock_epoch,"records":records,"retirement_authorized":false}),
        )
    }
}
