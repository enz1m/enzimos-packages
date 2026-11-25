// SPDX-License-Identifier: MIT
//! Original exclusive retrieval intent. Only whole-worker closure may complete it.
use crate::{backup_remote_handoff::Handoff, control_record::Retained, storage_runtime::Guard};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) const FOLDER: &str = "backup-retrievals";
pub(crate) const LIMIT: usize = 32768;
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original private retrieval registry",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub(crate) fn record(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema id phase remote_snapshot original remote_repository local_binding boot_id local_snapshot",
    )?;
    require(
        v["schema"].as_u64() == Some(1)
            && matches!(v["phase"].as_str(), Some("copying" | "complete")),
        "closed retrieval receipt phase",
    )?;
    crate::identity::safe_id(v["id"].as_str().unwrap_or(""))?;
    for key in ["remote_snapshot", "original"] {
        crate::identity::sha(v[key].as_str().unwrap_or(""))?;
    }
    crate::identity::uuid(v["boot_id"].as_str().unwrap_or(""))?;
    crate::backup_remote_record::pin(&v["remote_repository"])?;
    json::fields(
        &v["local_binding"],
        "filesystem_uuid mount repository_sha256 storage_topology",
    )?;
    crate::identity::uuid(v["local_binding"]["filesystem_uuid"].as_str().unwrap_or(""))?;
    crate::identity::sha(
        v["local_binding"]["repository_sha256"]
            .as_str()
            .unwrap_or(""),
    )?;
    json::fields(
        &v["local_binding"]["mount"],
        "mount_id unique_mount_id device root target fstype",
    )?;
    let mount = &v["local_binding"]["mount"];
    require(
        mount["mount_id"].as_u64().is_some_and(|n| n > 0)
            && mount["unique_mount_id"].as_u64().is_some_and(|n| n > 0)
            && mount["root"] == "/"
            && mount["target"] == "/backup-repository"
            && mount["fstype"] == "btrfs"
            && mount["device"].as_str().is_some_and(|s| {
                let p = s.split(':').collect::<Vec<_>>();
                p.len() == 2
                    && p.iter()
                        .all(|v| v.parse::<u32>().is_ok_and(|n| n.to_string() == *v))
            }),
        "retrieval original destination mount",
    )?;
    json::fields(
        &v["local_binding"]["storage_topology"],
        "destination sources",
    )?;
    require(
        v["local_binding"]["storage_topology"]["destination"].is_object()
            && v["local_binding"]["storage_topology"]["sources"].is_object(),
        "retrieval original topology",
    )?;
    if v["phase"] == "complete" {
        crate::identity::sha(v["local_snapshot"].as_str().unwrap_or(""))?;
    } else {
        require(
            v["local_snapshot"].is_null(),
            "copying receipt cannot adopt a local snapshot",
        )?;
    }
    require(
        json::canonical(v)?.len() <= LIMIT,
        "bounded durable retrieval receipt",
    )
}
pub(crate) struct Intent {
    parent: File,
    shape: (u64, u64, u32, u32, u32),
    mount: u64,
    record: Retained,
    value: Value,
}
impl Intent {
    pub(crate) fn enter(
        handoff: &Handoff<'_>,
        source: &Value,
        before: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        let request = handoff.request()?;
        let ctx = &request["context"];
        require(
            ctx["direction"] == "retrieve",
            "retrieval receipt requires original retrieve worker",
        )?;
        let snapshot = ctx["snapshot"].as_str().unwrap();
        crate::backup_remote_points::retrieval_admission(source, snapshot, before)?;
        let selected = crate::backup_remote_points::selected(source, snapshot)?;
        let original = selected.get("original").unwrap_or_else(|| &selected["id"]);
        let guard = handoff.guard()?;
        let parent =
            files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let shape = shape(&parent)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        let names = files::directory_names(&parent, 16)?;
        require(
            mount == guard.control_mount_id() && names.len() < 16,
            "retrieval original receipt capacity/mount",
        )?;
        for name in &names {
            let id = name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .ok_or_else(|| {
                    enzimos_platform::Error("interrupted retrieval receipt requires review".into())
                })?;
            crate::identity::safe_id(id)?;
            let old = Retained::open(&parent, Path::new(name), LIMIT, mount)?;
            record(old.value()?)?;
            // A copying receipt from an earlier boot was interrupted with its
            // worker; it stays as history but no longer blocks retrievals.
            require(
                old.value()?["id"] == id
                    && crate::restore_history::retrieval_finished(
                        old.value()?,
                        &crate::operation::boot_id()?,
                    ),
                "uncertain retrieval requires review; no replay",
            )?;
        }
        authorize()?;
        handoff.recheck()?;
        let value = value!({"schema":1,"id":ctx["receipt_id"],"phase":"copying","remote_snapshot":snapshot,"original":original,"remote_repository":ctx["remote"]["pin"],"local_binding":handoff.legacy_binding()?,"boot_id":request["boot_id"],"local_snapshot":null});
        record(&value)?;
        let record = Retained::create(
            &parent,
            Path::new(&format!("{}.json", ctx["receipt_id"].as_str().unwrap())),
            &value,
            LIMIT,
            mount,
        )?;
        let this = Self {
            parent,
            shape,
            mount,
            record,
            value,
        };
        this.recheck(guard)?;
        authorize()?;
        handoff.recheck()?;
        Ok(this)
    }
    pub(crate) fn admit(guard: &Guard, id: &str, file: File) -> Result<Self> {
        guard.recheck()?;
        crate::identity::safe_id(id)?;
        let parent = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        let shape = shape(&parent)?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == guard.control_mount_id(),
            "original admitted retrieval receipt mount",
        )?;
        let retained = Retained::admit_original(
            &parent,
            Path::new(&format!("{id}.json")),
            file,
            LIMIT,
            mount,
        )?;
        let value = retained.value()?.clone();
        record(&value)?;
        require(
            value["id"] == id && value["phase"] == "copying",
            "admitted original receipt cannot adopt or replay",
        )?;
        let this = Self {
            parent,
            shape,
            mount,
            record: retained,
            value,
        };
        this.recheck(guard)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&self.parent)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && self.mount == guard.control_mount_id(),
            "original retrieval registry changed",
        )?;
        self.record.recheck()?;
        require(
            self.record.value()? == &self.value,
            "original retrieval receipt changed",
        )
    }
    pub(crate) fn finish(
        mut self,
        guard: &Guard,
        snapshot: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::sha(snapshot)?;
        authorize()?;
        self.recheck(guard)?;
        require(
            self.value["phase"] == "copying",
            "original retrieval cannot replay completion",
        )?;
        let mut next = self.value.clone();
        next["phase"] = value!("complete");
        next["local_snapshot"] = value!(snapshot);
        record(&next)?;
        self.record.replace(&next)?;
        self.value = next;
        self.recheck(guard)?;
        authorize()?;
        self.recheck(guard)?;
        Ok(self.value)
    }
    pub(crate) fn descriptor(&self, guard: &Guard) -> Result<&File> {
        self.recheck(guard)?;
        self.record.descriptor()
    }
    pub(crate) fn evidence(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        self.record.evidence()
    }
    pub(crate) fn value(&self, guard: &Guard) -> Result<&Value> {
        self.recheck(guard)?;
        Ok(&self.value)
    }
}
