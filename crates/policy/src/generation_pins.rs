// SPDX-License-Identifier: MIT
//! Original Root generation pins are protection records, never deletion grants.
use crate::{catalog, control_record::Retained, identity, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "generation-pins";
pub(crate) const MAXIMUM: usize = 128;
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original Root-private pin directory required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub(crate) fn validate(v: &Value, id: &str, filesystem: &str) -> Result<()> {
    json::fields(
        v,
        "schema id filesystem_uuid generation created_boot material material_sha256",
    )?;
    identity::safe_id(id)?;
    identity::uuid(filesystem)?;
    identity::uuid(v["created_boot"].as_str().unwrap_or(""))?;
    let generation = v["generation"].as_str().unwrap_or("");
    identity::safe_id(generation)?;
    catalog::material(&v["material"], generation)?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["id"] == id
            && v["filesystem_uuid"] == filesystem
            && v["material_sha256"] == json::fingerprint(&v["material"])?,
        "generation pin identity or material changed",
    )
}
fn names(parent: &File) -> Result<BTreeSet<String>> {
    files::directory_names(parent, MAXIMUM)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| Error("pin filename encoding".into()))?;
            identity::safe_id(
                name.strip_suffix(".json")
                    .ok_or_else(|| Error("unknown/interrupted generation pin".into()))?,
            )?;
            Ok(name)
        })
        .collect()
}
pub(crate) struct Snapshot<'g> {
    guard: &'g Guard,
    parent: Option<File>,
    shape: Option<Shape>,
    names: BTreeSet<String>,
    records: BTreeMap<String, Retained>,
    values: Value,
}
impl<'g> Snapshot<'g> {
    pub(crate) fn observe(guard: &'g Guard) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let parent =
            files::optional_directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        let mut this = Self {
            guard,
            parent,
            shape: None,
            names: BTreeSet::new(),
            records: BTreeMap::new(),
            values: value!({}),
        };
        if let Some(parent) = &this.parent {
            this.shape = Some(shape(parent)?);
            require(
                mount_identity::id(parent.as_fd(), true)? == guard.control_mount_id(),
                "pin directory crossed original control mount",
            )?;
            this.names = names(parent)?;
            for name in &this.names {
                let id = name
                    .strip_suffix(".json")
                    .ok_or_else(|| enzimos_platform::Error("unexpected name".into()))?;
                let record = Retained::open(
                    parent,
                    Path::new(name),
                    catalog::MAX_CATALOG,
                    guard.control_mount_id(),
                )?;
                validate(
                    record.value()?,
                    id,
                    enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?,
                )?;
                this.values[id] = record.value()?.clone();
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
        match (&self.parent, named, self.shape) {
            (None, None, None) => (),
            (Some(parent), Some(named), Some(original)) => {
                require(
                    shape(parent)? == original
                        && shape(&named)? == original
                        && mount_identity::id(parent.as_fd(), true)?
                            == self.guard.control_mount_id()
                        && mount_identity::id(named.as_fd(), true)?
                            == self.guard.control_mount_id()
                        && names(parent)? == self.names
                        && names(&named)? == self.names,
                    "original pin directory or membership changed",
                )?;
                for (id, record) in &self.records {
                    require(
                        record.value()? == &self.values[id],
                        "original generation pin changed",
                    )?;
                }
            }
            _ => return Err(Error("pin directory appeared/disappeared/replaced".into())),
        }
        self.guard.recheck()
    }
    pub(crate) fn insert_original(
        &mut self,
        id: &str,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        validate(
            record,
            id,
            enzimos_platform::json::string(&self.guard.configuration["filesystem_uuid"])?,
        )?;
        self.recheck()?;
        require(
            !self.records.contains_key(id) && self.records.len() < MAXIMUM,
            "generation pin exists or capacity reached",
        )?;
        authorize()?;
        if self.parent.is_none() {
            let created = files::create_directory_relative(
                self.guard.control(),
                Path::new(FOLDER),
                0o700,
                0,
            )?;
            require(
                names(&created)?.is_empty()
                    && mount_identity::id(created.as_fd(), true)? == self.guard.control_mount_id(),
                "new generation pin directory identity",
            )?;
            self.shape = Some(shape(&created)?);
            self.parent = Some(created);
        }
        self.recheck()?;
        authorize()?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?;
        let name = format!("{id}.json");
        let produced = Retained::create(
            parent,
            Path::new(&name),
            record,
            catalog::MAX_CATALOG,
            self.guard.control_mount_id(),
        )?;
        produced.recheck()?;
        require(
            produced.value()? == record && Some(shape(parent)?) == self.shape,
            "actual generation pin producer differs",
        )?;
        let mut expected = self.names.clone();
        expected.insert(name);
        require(
            names(parent)? == expected,
            "unknown concurrent generation pin publication",
        )?;
        for original in self.records.values() {
            original.recheck()?;
        }
        self.names = expected;
        self.values[id] = record.clone();
        self.records.insert(id.to_owned(), produced);
        self.recheck()?;
        authorize()?;
        Ok(())
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let epochs = self
            .records
            .iter()
            .map(|(id, r)| Ok((id.clone(), r.evidence()?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(
            value!({"pins":self.values,"epochs":epochs,"directory":self.shape,"mount":self.guard.control_mount_id()}),
        )
    }
}

pub fn status_locked(lock: &files::Lock) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    let guard = Guard::observe()?;
    let original = Snapshot::observe(&guard)?;
    let data = original.evidence()?;
    original.recheck()?;
    lock.recheck()?;
    Ok(value!({"pins":data["pins"],"removal_available":false,"deletion_authorized":false}))
}

pub fn pin_locked(id: &str, generation: &str, lock: &files::Lock) -> Result<Value> {
    identity::safe_id(id)?;
    identity::safe_id(generation)?;
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    let guard = Guard::observe()?;
    let mut boot = crate::boot_retirement_context::Context::observe(
        &guard,
        lock,
        generation,
        &mut crate::operation::root_only,
    )?;
    let catalog = boot.evidence(&mut crate::operation::root_only)?["catalog"].clone();
    let row = &catalog["generations"][generation];
    require(
        row["state"] == "ready",
        "only recorded ready generation can be pinned",
    )?;
    let material = &row["material"];
    let path = material["root_identity"]["path"]
        .as_str()
        .ok_or_else(|| Error("generation root path required".into()))?;
    let mut top = crate::storage_runtime::TopMount::open_retained(&guard)?;
    let root = files::directory_relative(top.directory()?, Path::new(path), Some(0))?;
    let epoch = files::identity(&root.metadata()?);
    let mount = mount_identity::id(root.as_fd(), true)?;
    let observed = crate::subvolume::observe(root.as_fd(), path)?.0;
    let mut authorize = || {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        top.recheck()?;
        let named = files::directory_relative(top.directory()?, Path::new(path), Some(0))?;
        require(
            files::identity(&root.metadata()?) == epoch
                && files::identity(&named.metadata()?) == epoch
                && mount_identity::id(root.as_fd(), true)? == mount
                && mount_identity::id(named.as_fd(), true)? == mount
                && crate::subvolume::observe(root.as_fd(), path)?.0 == observed
                && ["path", "id", "uuid"]
                    .iter()
                    .all(|k| observed[*k] == material["root_identity"][*k]),
            "original generation pin root changed",
        )
    };
    authorize()?;
    let record = value!({"schema":1,"id":id,"generation":generation,"filesystem_uuid":guard.configuration["filesystem_uuid"],"created_boot":crate::operation::boot_id()?,"material":material,"material_sha256":json::fingerprint(material)?});
    boot.publish_pin(id, &record, &mut authorize)?;
    authorize()?;
    drop(root);
    drop(boot);
    top.close()?;
    lock.recheck()?;
    Ok(value!({"status":"generation-material-pinned","pin":record,"deletion_authorized":false}))
}
