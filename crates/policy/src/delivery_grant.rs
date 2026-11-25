// SPDX-License-Identifier: MIT
//! Fresh administrative approval publishes one original, unused delivery grant.
use crate::{
    control_record::Retained, delivery_account::Recipient, delivery_export::Export, identity,
    operation, storage_runtime::Guard,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "restore-delivery-grants";
const MAXIMUM: usize = 16;
const LIMIT: usize = 32768;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("delivery selection text required".into()))
}
fn selection(body: &Value) -> Result<(&str, &str, u32)> {
    json::fields(body, "id export uid")?;
    let uid = body["uid"]
        .as_u64()
        .filter(|n| (1000..i32::MAX as u64).contains(n))
        .ok_or_else(|| Error("explicit ordinary recipient required".into()))? as u32;
    Ok((
        identity::safe_id(text(body, "id")?)?,
        identity::safe_id(text(body, "export")?)?,
        uid,
    ))
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "private delivery registry required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(crate) struct Registry {
    directory: Option<File>,
    shape: Option<(u64, u64, u32, u32, u32)>,
    records: BTreeMap<String, Retained>,
}
impl Registry {
    pub(crate) fn open(guard: &Guard) -> Result<Self> {
        let directory =
            files::optional_directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        let mut records = BTreeMap::new();
        let shape = if let Some(dir) = &directory {
            let shape = shape(dir)?;
            require(
                mount_identity::id(dir.as_fd(), true)? == guard.control_mount_id(),
                "delivery registry left original control",
            )?;
            for name in files::directory_names(dir, MAXIMUM)? {
                let name = name
                    .to_str()
                    .ok_or_else(|| Error("delivery registry name encoding".into()))?;
                let id = name
                    .strip_suffix(".json")
                    .ok_or_else(|| Error("interrupted delivery grant requires review".into()))?;
                identity::safe_id(id)?;
                let record = Retained::open(dir, Path::new(name), LIMIT, guard.control_mount_id())?;
                crate::delivery_cancel::validate(record.value()?, id)?;
                records.insert(id.into(), record);
            }
            Some(shape)
        } else {
            None
        };
        let this = Self {
            directory,
            shape,
            records,
        };
        this.recheck(guard)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let named =
            files::optional_directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        match (&self.directory, &named) {
            (None, None) => require(
                self.records.is_empty(),
                "missing original grant registry has records",
            )?,
            (Some(dir), Some(named)) => {
                require(
                    Some(shape(dir)?) == self.shape
                        && Some(shape(named)?) == self.shape
                        && mount_identity::id(dir.as_fd(), true)? == guard.control_mount_id()
                        && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
                    "original grant registry changed or covered",
                )?;
                let mut actual = files::directory_names(dir, MAXIMUM)?
                    .into_iter()
                    .map(|n| {
                        n.into_string()
                            .map_err(|_| Error("delivery registry name encoding".into()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                actual.sort();
                let expected = self
                    .records
                    .keys()
                    .map(|id| format!("{id}.json"))
                    .collect::<Vec<_>>();
                require(
                    actual == expected,
                    "original grant registry members changed",
                )?;
                for record in self.records.values() {
                    record.recheck()?;
                }
            }
            _ => {
                return Err(Error(
                    "original grant registry appeared or disappeared".into(),
                ));
            }
        }
        guard.recheck()
    }
    pub(crate) fn vacant(&self, guard: &Guard, id: &str) -> Result<()> {
        self.recheck(guard)?;
        identity::safe_id(id)?;
        require(
            self.records.len() < MAXIMUM && !self.records.contains_key(id),
            "delivery grant capacity or ID used; no replay",
        )
    }
    pub(crate) fn into_published(mut self, guard: &Guard, id: &str) -> Result<(File, Retained)> {
        self.recheck(guard)?;
        let record = self
            .records
            .remove(id)
            .ok_or_else(|| Error("original published grant absent".into()))?;
        require(
            record.value()?["phase"] == "granted",
            "original new grant required",
        )?;
        Ok((
            self.directory
                .take()
                .ok_or_else(|| Error("original grant directory absent".into()))?,
            record,
        ))
    }
    pub(crate) fn evidence(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        let records = self
            .records
            .iter()
            .map(|(id, r)| Ok((id.clone(), r.evidence()?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(value!({"directory":self.shape,"records":records,"mount":guard.control_mount_id()}))
    }
    pub(crate) fn publish<F: FnMut() -> Result<()>>(
        &mut self,
        guard: &Guard,
        id: &str,
        record: &Value,
        authorize: &mut F,
    ) -> Result<()> {
        self.recheck(guard)?;
        require(
            self.records.len() < MAXIMUM && !self.records.contains_key(id),
            "delivery grant capacity or ID already used; no replay",
        )?;
        if self.directory.is_none() {
            authorize()?;
            self.recheck(guard)?;
            let directory =
                files::create_directory(&Path::new(operation::CONTROL).join(FOLDER), 0o700, 0)?;
            require(
                mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
                "new delivery registry left original control",
            )?;
            self.shape = Some(shape(&directory)?);
            self.directory = Some(directory);
            self.recheck(guard)?;
        }
        authorize()?;
        self.recheck(guard)?;
        let receipt = Retained::create(
            self.directory
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
            Path::new(&format!("{id}.json")),
            record,
            LIMIT,
            guard.control_mount_id(),
        )?;
        require(
            receipt.value()? == record,
            "original delivery grant publication differs",
        )?;
        self.records.insert(id.into(), receipt);
        self.recheck(guard)
    }
}
struct Scope {
    guard: Guard,
    recipient: Recipient,
    export: Export,
    registry: Registry,
    id: String,
    uid: u32,
}
impl Scope {
    fn open(body: &Value) -> Result<Self> {
        crate::namespaces::initial()?;
        let (id, export, uid) = selection(body)?;
        let guard = Guard::observe()?;
        let recipient = Recipient::open(uid, &guard)?;
        let export = Export::open(&guard, export)?;
        let registry = Registry::open(&guard)?;
        require(
            registry.records.len() < MAXIMUM && !registry.records.contains_key(id),
            "delivery grant capacity or ID already used; no replay",
        )?;
        let this = Self {
            guard,
            recipient,
            export,
            registry,
            id: id.into(),
            uid,
        };
        this.view()?;
        Ok(this)
    }
    fn view(&self) -> Result<Value> {
        let result = value!({"recipient":self.recipient.evidence(&self.guard)?,"export":self.export.evidence(&self.guard)?,"registry":self.registry.evidence(&self.guard)?,"boot_id":operation::boot_id()?,"storage":self.guard.configuration});
        self.recipient.recheck(&self.guard)?;
        self.export.recheck(&self.guard)?;
        self.registry.recheck(&self.guard)?;
        Ok(result)
    }
}
/// Retire finished grants under the operation lock before observing the
/// registry. Deterministic, so a later grant under the lock retires nothing
/// new unless the registry changed in between (which already changes review).
fn retire(lock: &files::Lock) {
    if let Ok(guard) = Guard::observe() {
        let _ = crate::restore_history::retire_grants(&guard, lock);
    }
}
/// Read-only: it never takes the operation lock (that would make concurrent
/// operations fail) and never retires rows; `grant` retires near capacity.
pub fn observation(body: &Value) -> Result<Value> {
    Scope::open(body)?.view()
}
pub fn grant<F: FnMut() -> Result<()>>(
    body: &Value,
    expected: &Value,
    authorize: &mut F,
) -> Result<Value> {
    let lock = operation::lock()?;
    retire(&lock);
    let mut scope = Scope::open(body)?;
    require(scope.view()? == *expected, "delivery grant review changed")?;
    authorize()?;
    lock.recheck()?;
    require(
        scope.view()? == *expected,
        "delivery grant review changed before publication",
    )?;
    let filename = format!("enzimos-restored-{}.bin", scope.id);
    let mut record = value!({"schema":1,"id":scope.id,"phase":"granted","boot_id":operation::boot_id()?,"account":scope.recipient.account(&scope.guard)?,"export":scope.export.binding(&scope.guard)?,"filename":filename,"metadata_restored":false});
    record["grant_sha256"] = value!(json::fingerprint(&record)?);
    crate::delivery_cancel::validate(&record, &scope.id)?;
    scope
        .registry
        .publish(&scope.guard, &scope.id, &record, &mut || {
            authorize()?;
            lock.recheck()?;
            scope.recipient.recheck(&scope.guard)?;
            scope.export.recheck(&scope.guard)
        })?;
    scope.recipient.recheck(&scope.guard)?;
    scope.export.recheck(&scope.guard)?;
    scope.registry.recheck(&scope.guard)?;
    lock.recheck()?;
    completion(&scope.id, scope.uid, text(&record, "grant_sha256")?)
}
/// Closed System1 data only; constructing a reply grants no delivery authority.
pub fn completion(id: &str, uid: u32, digest: &str) -> Result<Value> {
    identity::safe_id(id)?;
    identity::sha(digest)?;
    require(
        (1000..i32::MAX as u32).contains(&uid),
        "ordinary delivery recipient required",
    )?;
    Ok(
        value!({"id":id,"recipient_uid":uid,"grant_sha256":digest,"filename":format!("enzimos-restored-{id}.bin")}),
    )
}
