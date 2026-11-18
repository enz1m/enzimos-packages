// SPDX-License-Identifier: MIT
//! Publisher-origin fallback records, with interruption retained for review.
use crate::{
    birth, catalog, filesystem, identity, operation,
    storage_runtime::{Guard, TopMount},
    subvolume,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
pub const MAX_RECORDS: usize = 64;
pub type Records = BTreeMap<String, Value>;
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| Error("birth text field".into()))
}
pub fn parse_inventory(body: &str) -> Result<Records> {
    require(
        body.len() <= catalog::MAX_CATALOG,
        "birth inventory byte bound",
    )?;
    let mut records = Records::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut uuids = std::collections::BTreeSet::new();
    for line in body.lines() {
        require(records.len() < 4096, "birth inventory count bound")?;
        let (prefix, path) = line
            .split_once(" path ")
            .ok_or_else(|| Error("invalid birth inventory row".into()))?;
        let path = path.strip_prefix("<FS_TREE>/").unwrap_or(path);
        require(
            !path.is_empty()
                && !path.starts_with('/')
                && !path.chars().any(char::is_control)
                && path.split('/').all(|p| !matches!(p, "" | "." | "..")),
            "invalid birth inventory path",
        )?;
        let fields = prefix.split_whitespace().collect::<Vec<_>>();
        require(fields.first() == Some(&"ID"), "invalid birth inventory ID")?;
        let id = fields
            .get(1)
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n >= 256)
            .ok_or_else(|| Error("invalid birth inventory ID".into()))?;
        let field = |key: &str| -> Result<&str> {
            let found = fields
                .windows(2)
                .filter(|p| p[0] == key)
                .map(|p| p[1])
                .collect::<Vec<_>>();
            require(found.len() == 1, "ambiguous birth inventory field")?;
            Ok(found[0])
        };
        let uuid = identity::uuid(field("uuid")?)?;
        require(
            ids.insert(id) && uuids.insert(uuid.to_owned()),
            "ambiguous birth inventory identity",
        )?;
        let parent = match field("parent_uuid")? {
            "-" => Value::Null,
            p => value!(identity::uuid(p)?),
        };
        require(
            records
                .insert(
                    path.into(),
                    value!({"path":path,"id":id,"uuid":uuid,"parent_uuid":parent}),
                )
                .is_none(),
            "duplicate birth inventory path",
        )?;
    }
    Ok(records)
}
pub fn evaluate(records: &Records, inventory: &Records, readonly: &Records) -> Result<Value> {
    let mut resources = serde_json::Map::new();
    let mut pending = Vec::new();
    let mut drift = Vec::new();
    for (identifier, record) in records {
        birth::validate(record, identifier, text(record, "filesystem_uuid")?)?;
        match text(record, "phase")? {
            "retired" => continue,
            "ready" => (),
            _ => {
                pending.push(identifier);
                continue;
            }
        }
        for (role, object) in [
            ("source-snapshot", &record["snapshot"]["object"]),
            ("root-subvolume", &record["root"]),
            ("history-store", &record["history"]),
        ] {
            let key = text(object, "uuid")?;
            require(
                !resources.contains_key(key),
                "birth object claimed by multiple transactions",
            )?;
            let path = text(object, "path")?;
            let valid = inventory.get(path) == Some(object)
                && (role != "source-snapshot" || readonly.get(path) == Some(object));
            if !valid {
                drift.push(format!("{identifier}:{role}"));
            }
            resources.insert(key.into(), value!({"identity":object,"kind":role,"transaction":identifier,"created_boot":record["created_boot"],"publisher_origin_observed":valid,"deletion_authorized":false}));
        }
    }
    Ok(
        value!({"resources":resources,"pending":pending,"drift":drift,"retirement_enabled":false,"scope":"exact live identity against new-resource birth records; not boot health or deletion authority"}),
    )
}
pub struct Store {
    guard: Guard,
    path: PathBuf,
    directory: Option<File>,
    mount: Option<u64>,
    pub records: Records,
    original_records: BTreeMap<String, crate::control_record::Retained>,
}
impl Store {
    pub fn configuration(&self) -> &Value {
        &self.guard.configuration
    }
    pub(crate) fn control(&self) -> &File {
        self.guard.control()
    }
    pub fn control_mount_id(&self) -> u64 {
        self.guard.control_mount_id()
    }
    pub fn open(create: bool) -> Result<Self> {
        let guard = Guard::observe()?;
        let path = Path::new(operation::CONTROL).join("root-births");
        if create {
            files::ensure_directory(&path, 0o700, 0)?;
        }
        let directory =
            files::optional_directory_relative(guard.control(), Path::new("root-births"), Some(0))?;
        let mut records = Records::new();
        let mut original_records = BTreeMap::new();
        let mount = if let Some(dir) = &directory {
            require(
                dir.metadata()?.mode() & 0o7777 == 0o700,
                "unsafe birth registry directory",
            )?;
            let mount = mount_identity::id(dir.as_fd(), true)?;
            require(
                mount == guard.control_mount_id(),
                "birth registry mounted independently",
            )?;
            let entries = files::directory_names(dir, MAX_RECORDS + 16)?;
            require(
                entries.len() <= MAX_RECORDS + 16,
                "birth registry entry bound",
            )?;
            for entry in entries {
                let name = entry
                    .into_string()
                    .map_err(|_| Error("birth registry filename encoding".into()))?;
                let identifier = name.strip_suffix(".json").ok_or_else(|| {
                    Error("unrecognized or interrupted birth registry object".into())
                })?;
                identity::safe_id(identifier)?;
                require(records.len() < MAX_RECORDS, "birth registry record bound")?;
                let entry =
                    enzimos_platform::directory_entry::Entry::observe(dir, Path::new(&name))?;
                require(
                    entry.metadata()?.mode() & 0o077 == 0,
                    "unsafe birth record mode",
                )?;
                let original = crate::control_record::Retained::open(
                    dir,
                    Path::new(&name),
                    catalog::MAX_CATALOG,
                    mount,
                )?;
                let record = original.value()?.clone();
                birth::validate(
                    &record,
                    identifier,
                    text(&guard.configuration, "filesystem_uuid")?,
                )?;
                entry.recheck()?;
                records.insert(identifier.into(), record);
                original_records.insert(identifier.into(), original);
            }
            Some(mount)
        } else {
            None
        };
        let store = Self {
            guard,
            path,
            directory,
            mount,
            records,
            original_records,
        };
        store.recheck()?;
        Ok(store)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        require(
            self.original_records.len() == self.records.len(),
            "birth record epoch inventory differs",
        )?;
        for (id, original) in &self.original_records {
            require(
                original.value()? == &self.records[id],
                "birth record differs from original epoch",
            )?;
        }
        if let Some(directory) = &self.directory {
            let current = files::directory(&self.path, Some(0))?;
            let before = directory.metadata()?;
            let now = current.metadata()?;
            require(
                (before.dev(), before.ino(), before.mode()) == (now.dev(), now.ino(), now.mode())
                    && Some(mount_identity::id(current.as_fd(), true)?) == self.mount
                    && Some(mount_identity::id(directory.as_fd(), true)?) == self.mount,
                "birth registry replaced",
            )?;
        } else {
            require(
                matches!(std::fs::symlink_metadata(&self.path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "birth registry appeared during observation",
            )?;
        }
        Ok(())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let records = self
            .original_records
            .iter()
            .map(|(id, r)| Ok((id.clone(), r.evidence()?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let directory = self
            .directory
            .as_ref()
            .map(|f| f.metadata().map(|m| files::identity(&m)))
            .transpose()?;
        Ok(
            serde_json::json!({"records":records,"directory":directory,"mount":self.mount,
            "control_mount":self.guard.control_mount_id()}),
        )
    }
    pub fn assert_no_pending(&self) -> Result<()> {
        require(
            self.records
                .values()
                .all(|r| matches!(r["phase"].as_str(), Some("ready" | "retired"))),
            "fallback creation incomplete; explicit ownership review required",
        )
    }
    pub fn save(&mut self, identifier: &str, record: Value, new: bool) -> Result<()> {
        self.recheck()?;
        require(self.directory.is_some(), "birth registry missing")?;
        birth::validate(
            &record,
            identifier,
            text(&self.guard.configuration, "filesystem_uuid")?,
        )?;
        require(
            if new {
                record["phase"] == "intent"
                    && !self.records.contains_key(identifier)
                    && self.records.len() < MAX_RECORDS
            } else {
                self.records.contains_key(identifier)
            },
            "birth record cannot be adopted or reused",
        )?;
        let name = format!("{identifier}.json");
        if new {
            let original = crate::control_record::Retained::create(
                self.directory.as_ref().unwrap(),
                Path::new(&name),
                &record,
                catalog::MAX_CATALOG,
                self.guard.control_mount_id(),
            )?;
            self.original_records.insert(identifier.into(), original);
        } else {
            let expected = self.records.get(identifier).unwrap();
            birth::advance(expected, &record)?;
            let original = self
                .original_records
                .get_mut(identifier)
                .ok_or_else(|| Error("original birth record epoch missing".into()))?;
            require(original.value()? == expected, "birth record changed")?;
            original.replace(&record)?;
        }
        self.records.insert(identifier.into(), record);
        self.recheck()
    }
}
pub fn status() -> Result<Value> {
    let _lock = operation::lock()?;
    let store = Store::open(false)?;
    let observed = inventory(false)?;
    let readonly = inventory(true)?;
    store.recheck()?;
    evaluate(&store.records, &observed, &readonly)
}
pub(crate) fn inventory(readonly: bool) -> Result<Records> {
    let mut args = vec!["subvolume", "list", "-a", "-u", "-q"];
    if readonly {
        args.push("-r");
    }
    args.push("/");
    let body = operation::query(
        "/usr/bin/btrfs",
        &args,
        Duration::from_secs(30),
        catalog::MAX_CATALOG,
        &[0],
    )?;
    parse_inventory(
        std::str::from_utf8(&body).map_err(|_| Error("birth inventory encoding".into()))?,
    )
}
/// Pure normalization preserves unrelated mount options and exactly one root row.
pub fn normalize_fstab(body: &str, fs_uuid: &str, name: &str) -> Result<String> {
    identity::uuid(fs_uuid)?;
    identity::safe_id(name)?;
    require(
        body.len() <= catalog::MAX_CATALOG && !body.contains('\0'),
        "fallback fstab byte bound",
    )?;
    let mut lines = Vec::new();
    let mut roots = 0;
    for line in body.lines() {
        let mut fields = line
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if fields.first().is_some_and(|s| !s.starts_with('#'))
            && fields.len() >= 4
            && fields[1] == "/"
        {
            require(
                fields[0] == format!("UUID={fs_uuid}") && fields[2] == "btrfs",
                "unsupported fallback fstab root",
            )?;
            let mut options = fields[3]
                .split(',')
                .filter(|s| !s.starts_with("subvol=") && !s.starts_with("subvolid="))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            options.push(format!("subvol={name}"));
            fields[3] = options.join(",");
            lines.push(fields.join(" "));
            roots += 1;
        } else {
            lines.push(line.into());
        }
    }
    require(roots == 1, "one fallback fstab root required")?;
    Ok(format!("{}\n", lines.join("\n")))
}
pub fn observe(path: &Path, relative: &str, fs_uuid: &str) -> Result<(File, Value, bool)> {
    let file = files::directory(path, Some(0))?;
    require(
        file.metadata()?.mode() & 0o022 == 0,
        "unsafe birth directory",
    )?;
    let mount = mount_identity::id(file.as_fd(), true)?;
    require(
        filesystem::observe(file.as_fd())?["filesystem_uuid"] == fs_uuid,
        "birth object on wrong filesystem",
    )?;
    let (object, readonly) = subvolume::observe(file.as_fd(), relative)?;
    let current = files::directory(path, Some(0))?;
    let a = file.metadata()?;
    let b = current.metadata()?;
    require(
        (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
            && mount_identity::id(current.as_fd(), true)? == mount
            && subvolume::observe(current.as_fd(), relative)? == (object.clone(), readonly),
        "birth object replaced during observation",
    )?;
    Ok((file, object, readonly))
}
pub fn top(store: &Store) -> Result<TopMount> {
    TopMount::open(&store.guard)
}
