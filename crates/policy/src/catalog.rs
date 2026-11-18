// SPDX-License-Identifier: MIT
//! Bounded generation registry on independently mounted control storage.
use crate::{
    boot_options,
    identity::{safe_id, sha, uuid},
    operation,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
pub const MAX_CATALOG: usize = 2 * 1024 * 1024;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("registry text field".into()))
}
pub fn material(v: &Value, generation: &str) -> Result<()> {
    json::fields(v, "kernels files options root_identity inventory_sha256")?;
    let kernels = &v["kernels"];
    json::fields(kernels, "linux linux-lts")?;
    let kernel = text(kernels, "linux")?;
    let lts = text(kernels, "linux-lts")?;
    safe_id(kernel)?;
    safe_id(lts)?;
    require(kernel != lts, "ambiguous registered kernels")?;
    let options = text(v, "options")?;
    require(
        boot_options::generation_options(options, generation)? == options,
        "invalid registered options",
    )?;
    let root = &v["root_identity"];
    json::fields(root, "path id uuid ownership")?;
    require(
        root["ownership"] == "not-established" && root["id"].as_u64().is_some_and(|n| n >= 256),
        "unproven root ownership or ID",
    )?;
    uuid(text(root, "uuid")?)?;
    require(
        boot_options::subvolume_from_options(options)? == text(root, "path")?,
        "root binding/options mismatch",
    )?;
    sha(text(v, "inventory_sha256")?)?;
    let artifacts = v["files"]
        .as_array()
        .ok_or_else(|| Error("registered artifacts".into()))?;
    require(artifacts.len() == 4, "four registered artifacts required")?;
    let expected = BTreeSet::from([
        "vmlinuz-linux",
        "vmlinuz-linux-lts",
        "initramfs-linux.img",
        "initramfs-linux-lts.img",
    ]);
    let mut seen = BTreeSet::new();
    for f in artifacts {
        json::fields(f, "name bytes sha256")?;
        let name = text(f, "name")?;
        require(
            expected.contains(name) && seen.insert(name),
            "invalid duplicate artifact",
        )?;
        require(
            f["bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 128 * 1024 * 1024),
            "artifact size bound",
        )?;
        sha(text(f, "sha256")?)?;
    }
    Ok(())
}
pub fn empty(fs_uuid: &str) -> Result<Value> {
    uuid(fs_uuid)?;
    Ok(value!({"schema":1,"filesystem_uuid":fs_uuid,"next_ordinal":1,"generations":{}}))
}
pub fn validate(v: &Value, fs_uuid: &str) -> Result<()> {
    if v.get("retired").is_some() {
        json::fields(v, "schema filesystem_uuid next_ordinal generations retired")?;
    } else {
        json::fields(v, "schema filesystem_uuid next_ordinal generations")?;
    }
    uuid(fs_uuid)?;
    require(
        v["schema"].as_u64() == Some(1) && text(v, "filesystem_uuid")? == fs_uuid,
        "registry filesystem/schema mismatch",
    )?;
    let next = v["next_ordinal"]
        .as_u64()
        .filter(|n| *n > 0 && *n < i64::MAX as u64)
        .ok_or_else(|| Error("invalid registry ordinal".into()))?;
    let generations = v["generations"]
        .as_object()
        .ok_or_else(|| Error("registry generations".into()))?;
    require(generations.len() <= 64, "registry generation bound")?;
    let mut ordinals = BTreeSet::new();
    if let Some(retired) = v.get("retired") {
        let retired = retired
            .as_object()
            .ok_or_else(|| Error("retired generation tombstones".into()))?;
        require(retired.len() <= 4096, "retired generation tombstone bound")?;
        for (name, row) in retired {
            safe_id(name)?;
            require(
                !generations.contains_key(name),
                "retired generation name reused",
            )?;
            json::fields(row, "ordinal material_sha256 retired_boot")?;
            let ordinal = row["ordinal"]
                .as_u64()
                .filter(|n| *n > 0 && *n < next)
                .ok_or_else(|| Error("invalid retired ordinal".into()))?;
            require(ordinals.insert(ordinal), "ambiguous registry order")?;
            sha(text(row, "material_sha256")?)?;
            uuid(text(row, "retired_boot")?)?;
        }
    }
    for (name, row) in generations {
        safe_id(name)?;
        json::fields(
            row,
            "generation ordinal state created_boot material entry_fingerprints first_confirmation last_confirmation",
        )?;
        require(
            text(row, "generation")? == name,
            "generation record name mismatch",
        )?;
        let ordinal = row["ordinal"]
            .as_u64()
            .filter(|n| *n > 0 && *n < next)
            .ok_or_else(|| Error("invalid registry ordinal".into()))?;
        require(ordinals.insert(ordinal), "ambiguous registry order")?;
        uuid(text(row, "created_boot")?)?;
        material(&row["material"], name)?;
        match text(row, "state")? {
            "preparing" => require(
                row["entry_fingerprints"].is_null()
                    && row["first_confirmation"].is_null()
                    && row["last_confirmation"].is_null(),
                "preparing publication cannot be confirmed",
            )?,
            "ready" => {
                let fps = &row["entry_fingerprints"];
                json::fields(fps, "uefi bios")?;
                for kind in ["uefi", "bios"] {
                    let entries = fps[kind]
                        .as_object()
                        .ok_or_else(|| Error("publisher entry fingerprints".into()))?;
                    let expected = ["linux", "linux-lts"]
                        .iter()
                        .map(|flavor| {
                            if kind == "uefi" {
                                format!("enzimos-{name}-{flavor}.conf")
                            } else {
                                format!("enzimOS {name} {flavor}")
                            }
                        })
                        .collect::<BTreeSet<_>>();
                    require(
                        entries.keys().cloned().collect::<BTreeSet<_>>() == expected,
                        "invalid entry identities",
                    )?;
                    for digest in entries.values() {
                        sha(digest
                            .as_str()
                            .ok_or_else(|| Error("invalid entry digest".into()))?)?;
                    }
                }
                require(
                    row["first_confirmation"].is_null() == row["last_confirmation"].is_null(),
                    "partial confirmation state",
                )?;
            }
            _ => return Err(Error("invalid publication state".into())),
        }
        for key in ["first_confirmation", "last_confirmation"] {
            let c = &row[key];
            if c.is_null() {
                continue;
            }
            json::fields(
                c,
                "boot_id kernel uefi filesystem_uuid root_uuid material_sha256 assurance",
            )?;
            uuid(text(c, "boot_id")?)?;
            require(
                c["boot_id"] != row["created_boot"],
                "publication boot cannot confirm itself",
            )?;
            require(
                c["uefi"].is_boolean()
                    && [
                        &row["material"]["kernels"]["linux"],
                        &row["material"]["kernels"]["linux-lts"],
                    ]
                    .contains(&&c["kernel"]),
                "invalid confirmed kernel/mode",
            )?;
            require(
                c["filesystem_uuid"] == fs_uuid
                    && c["root_uuid"] == row["material"]["root_identity"]["uuid"]
                    && c["material_sha256"] == json::fingerprint(&row["material"])?
                    && c["assurance"] == "software-local-observed-boot-not-firmware-authentication",
                "confirmation binding/assurance changed",
            )?;
        }
    }
    Ok(())
}
pub fn save_document(path: &Path, v: &Value) -> Result<()> {
    let mut body = json::canonical(v)?;
    body.push(b'\n');
    require(body.len() <= MAX_CATALOG, "registry document byte bound")?;
    if files::read_optional(path, MAX_CATALOG, Some(0), true)?.is_some() {
        require(
            std::fs::symlink_metadata(path)?.mode() & 0o077 == 0,
            "unsafe private registry object",
        )?;
    }
    files::atomic(path, &body, 0o600, Some(0), true)
}
/// Pure ledger transition. Callers must collect material under the operation lock
/// and recheck the mounted storage before committing the returned document.
pub fn reserve_document(data: &Value, name: &str, input: &Value, boot: &str) -> Result<Value> {
    let fs = text(data, "filesystem_uuid")?;
    validate(data, fs)?;
    safe_id(name)?;
    uuid(boot)?;
    material(input, name)?;
    require(
        data.get("retired")
            .and_then(Value::as_object)
            .is_none_or(|r| !r.contains_key(name)),
        "retired generation name cannot be reused",
    )?;
    if let Some(old) = data["generations"].get(name) {
        require(
            old["state"] == "preparing" && old["material"] == *input,
            "generation already registered or material changed",
        )?;
        return Ok(data.clone());
    }
    require(
        data["generations"].as_object().unwrap().len() < 64,
        "registry full; no automatic retirement",
    )?;
    let mut next = data.clone();
    let ordinal = data["next_ordinal"].as_u64().unwrap();
    next["next_ordinal"] = value!(
        ordinal
            .checked_add(1)
            .ok_or_else(|| Error("registry ordinal overflow".into()))?
    );
    next["generations"][name] = value!({"generation":name,"ordinal":ordinal,"state":"preparing","created_boot":boot,"material":input,"entry_fingerprints":null,"first_confirmation":null,"last_confirmation":null});
    validate(&next, fs)?;
    Ok(next)
}
/// Fingerprints are observations of both actual loader entries, not declarations
/// from an untrusted request. This function provides no filesystem authority.
pub fn publish_document(data: &Value, name: &str, fingerprints: &Value) -> Result<Value> {
    validate(data, text(data, "filesystem_uuid")?)?;
    require(
        data["generations"]
            .get(name)
            .is_some_and(|r| r["state"] == "preparing"),
        "publication state mismatch",
    )?;
    let mut next = data.clone();
    next["generations"][name]["entry_fingerprints"] = fingerprints.clone();
    next["generations"][name]["state"] = value!("ready");
    validate(&next, text(data, "filesystem_uuid")?)?;
    Ok(next)
}
/// The runtime observer must additionally verify the live mount, root UUID,
/// package inventory, selected entry and unchanged loader fingerprints.
pub fn confirm_document(data: &Value, name: &str, observation: &Value) -> Result<Value> {
    validate(data, text(data, "filesystem_uuid")?)?;
    require(
        data["generations"]
            .get(name)
            .is_some_and(|r| r["state"] == "ready"),
        "running generation publication is incomplete",
    )?;
    let mut next = data.clone();
    let row = &mut next["generations"][name];
    if row["first_confirmation"].is_null() {
        row["first_confirmation"] = observation.clone();
    }
    row["last_confirmation"] = observation.clone();
    validate(&next, text(data, "filesystem_uuid")?)?;
    Ok(next)
}
pub struct Transaction {
    pub config: Value,
    directory: PathBuf,
    pub data: Value,
    _lock: files::Lock,
    guard: crate::storage_runtime::Guard,
    held: std::fs::File,
    before: Option<Value>,
    original: Option<crate::control_record::Retained>,
    owned: Option<enzimos_platform::publication::Committed>,
}
impl Transaction {
    pub fn begin() -> Result<Self> {
        let guard = crate::storage_runtime::Guard::observe()?;
        let config = guard.configuration.clone();
        let directory = Path::new(operation::CONTROL).join("generation-registry");
        let held = files::ensure_directory(&directory, 0o700, 0)?;
        require(
            enzimos_platform::mount_identity::id(held.as_fd(), true)? == guard.control_mount_id(),
            "generation registry mounted independently",
        )?;
        let lock = files::Lock::acquire(&directory.join("lock"), 0)?;
        for name in files::directory_names(&held, 128)? {
            require(
                matches!(name.to_str(), Some("lock" | "catalog.json")),
                "interrupted registry publication requires review",
            )?;
        }
        let original = crate::control_record::Retained::optional_open(
            &held,
            Path::new("catalog.json"),
            MAX_CATALOG,
            guard.control_mount_id(),
        )?;
        let before = original.as_ref().map(|r| r.value().cloned()).transpose()?;
        let data = match &before {
            Some(value) => value.clone(),
            None => empty(text(&config, "filesystem_uuid")?)?,
        };
        validate(&data, text(&config, "filesystem_uuid")?)?;
        Ok(Self {
            config,
            directory,
            data,
            _lock: lock,
            guard,
            held,
            before,
            original,
            owned: None,
        })
    }
    pub fn recheck(&self) -> Result<()> {
        if let Some(owned) = &self.owned {
            owned.recheck()?;
        }
        self.guard.recheck()?;
        require(
            self.guard.configuration == self.config,
            "registry configuration changed",
        )?;
        let current = files::directory(&self.directory, Some(0))?;
        let a = self.held.metadata()?;
        let b = current.metadata()?;
        require(
            (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
                == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode())
                && a.uid() == 0
                && a.gid() == 0
                && a.mode() & 0o7777 == 0o700
                && enzimos_platform::mount_identity::id(self.held.as_fd(), true)?
                    == self.guard.control_mount_id()
                && enzimos_platform::mount_identity::id(current.as_fd(), true)?
                    == self.guard.control_mount_id(),
            "generation registry directory replaced",
        )?;
        self._lock.recheck()?;
        for name in files::directory_names(&self.held, 128)? {
            require(
                matches!(name.to_str(), Some("lock" | "catalog.json")),
                "generation registry has interrupted or unknown members",
            )?;
        }
        match &self.original {
            Some(original) => require(
                Some(original.value()?.clone()) == self.before,
                "generation registry original record differs",
            )?,
            None => require(
                files::optional_relative(&self.held, Path::new("catalog.json"))?.is_none(),
                "generation registry appeared during transaction",
            )?,
        }
        self.guard.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let original = self
            .original
            .as_ref()
            .map(super::control_record::Retained::evidence)
            .transpose()?;
        Ok(
            value!({"record":original,"data_sha256":json::fingerprint(&self.data)?,
            "lock":files::identity(&self._lock.as_file().metadata()?),
            "directory":files::identity(&self.held.metadata()?),"mount":self.guard.control_mount_id()}),
        )
    }
    /// One actual original replacement retains its predecessor and output
    /// through completion, with fresh caller/source checks before publication.
    pub fn commit_owned_authorized(
        &mut self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.recheck()?;
        require(
            self.owned.is_none(),
            "original owned catalog commit cannot replay",
        )?;
        validate(&self.data, text(&self.config, "filesystem_uuid")?)?;
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| Error("owned catalog replacement requires original record".into()))?
            .descriptor()?
            .try_clone()?;
        let mut bytes = json::canonical(&self.data)?;
        bytes.push(b'\n');
        let pending = enzimos_platform::publication::Prepared::write_authorized(
            &self.directory.join("catalog.json"),
            &bytes,
            0,
            authorize,
        )?;
        pending.require_original(&original)?;
        self.original
            .as_ref()
            .unwrap()
            .require_original_publication(&pending)?;
        let committed = pending.commit_retained_authorized(true, authorize)?;
        committed.require_destination(&self.held, Path::new("catalog.json"))?;
        let record = crate::control_record::Retained::admit_original(
            &self.held,
            Path::new("catalog.json"),
            committed.file()?.try_clone()?,
            MAX_CATALOG,
            self.guard.control_mount_id(),
        )?;
        require(
            record.value()? == &self.data,
            "actual owned catalog publication differs",
        )?;
        self.original = Some(record);
        self.owned = Some(committed);
        self.before = Some(self.data.clone());
        self.recheck()?;
        authorize()
    }
    /// Exact owned catalog temporary is admitted only by the live writer while
    /// every other transition record is freshly checked by the original snapshot.
    pub(crate) fn commit_idle_authorized(
        &mut self,
        idle: &crate::transition_idle::Snapshot,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        idle.recheck()?;
        self.recheck()?;
        require(
            self.owned.is_none(),
            "original owned catalog commit cannot replay",
        )?;
        validate(&self.data, text(&self.config, "filesystem_uuid")?)?;
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| Error("owned catalog requires original record".into()))?;
        let mut bytes = json::canonical(&self.data)?;
        bytes.push(b'\n');
        let pending = enzimos_platform::publication::Prepared::write(
            &self.directory.join("catalog.json"),
            &bytes,
            0,
        )?;
        original.require_original_publication(&pending)?;
        authorize()?;
        idle.recheck_catalog_pending(&pending)?;
        pending.recheck()?;
        authorize()?;
        let committed = pending.commit_retained(true)?;
        committed.require_destination(&self.held, Path::new("catalog.json"))?;
        authorize()?;
        idle.recheck()?;
        let record = crate::control_record::Retained::admit_original(
            &self.held,
            Path::new("catalog.json"),
            committed.file()?.try_clone()?,
            MAX_CATALOG,
            self.guard.control_mount_id(),
        )?;
        require(
            record.value()? == &self.data,
            "actual owned catalog publication differs",
        )?;
        self.original = Some(record);
        self.owned = Some(committed);
        self.before = Some(self.data.clone());
        self.recheck()?;
        idle.recheck()?;
        authorize()
    }
    pub fn commit(&mut self) -> Result<()> {
        require(
            self.owned.is_none(),
            "owned catalog replacement cannot use untracked later commit",
        )?;
        self.recheck()?;
        validate(&self.data, text(&self.config, "filesystem_uuid")?)?;
        match &mut self.original {
            Some(original) => original.replace(&self.data)?,
            None => {
                self.original = Some(crate::control_record::Retained::create(
                    &self.held,
                    Path::new("catalog.json"),
                    &self.data,
                    MAX_CATALOG,
                    self.guard.control_mount_id(),
                )?);
            }
        }
        self.before = Some(self.data.clone());
        self.recheck()
    }
}
