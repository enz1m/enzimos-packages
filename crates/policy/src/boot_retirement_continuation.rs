// SPDX-License-Identifier: MIT
//! Fresh original-descriptor inspection of an interrupted boot retirement.
//! A report never constructs an executor, grants deletion, or replays a journal.
use crate::{
    boot_volume::{Artifact, Volume},
    catalog,
    control_record::Observation,
    control_registry, identity, operation, retirement_journal,
    storage_runtime::Guard,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
#[path = "boot_retirement_continuation_references.rs"]
mod reference_protection;
use reference_protection::References;
#[path = "boot_retirement_continuation_loaders.rs"]
mod loader_protection;
use loader_protection::Loaders;
#[path = "boot_retirement_continuation_signed.rs"]
mod signed_protection;
use signed_protection::Signed;
#[path = "boot_retirement_continuation_journal.rs"]
mod owned_journal;
pub(crate) use owned_journal::Journal as ContinuationJournal;
#[path = "boot_retirement_continuation_runtime.rs"]
mod runtime;
pub use runtime::resume_locked;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Role {
    File(PathBuf),
    Directory(PathBuf),
    Catalog,
}
fn roles(intent: &Value) -> Result<Vec<Role>> {
    retirement_journal::intent(intent)?;
    let id = intent["id"].as_str().unwrap();
    let generation = id
        .strip_prefix("boot-")
        .ok_or_else(|| Error("fixed boot continuation ID required".into()))?;
    identity::safe_id(generation)?;
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut uefi = BTreeSet::new();
    let mut bios = 0;
    let mut members = BTreeSet::new();
    let mut directory = 0;
    let mut tombstone = 0;
    let mut ukis = 0;
    for step in intent["steps"].as_array().unwrap() {
        let name = step["id"].as_str().unwrap();
        let role = match (step["kind"].as_str().unwrap(), name) {
            ("uefi-entry", name) => {
                let flavor = name
                    .strip_prefix("uefi-")
                    .ok_or_else(|| Error("fixed UEFI continuation role required".into()))?;
                require(
                    matches!(flavor, "linux" | "linux-lts") && uefi.insert(flavor.to_owned()),
                    "two distinct UEFI continuation roles required",
                )?;
                Role::File(format!("loader/entries/enzimos-{generation}-{flavor}.conf").into())
            }
            ("bios-menu", "bios") => {
                bios += 1;
                Role::File("limine/limine.conf".into())
            }
            ("boot-file", name) if name.starts_with("file-") => {
                let leaf = &name[5..];
                require(
                    crate::boot_retirement_plan::MEMBERS.contains(&leaf)
                        && members.insert(leaf.to_owned()),
                    "fixed publisher continuation member required",
                )?;
                Role::File(format!("enzimos/generations/{generation}/{leaf}").into())
            }
            ("boot-file", name) if name.starts_with("uki-") => {
                let sha = &name[4..];
                identity::sha(sha)?;
                ukis += 1;
                require(ukis <= 2, "owned UKI continuation bound")?;
                Role::File(format!("enzimos/secure-boot/{sha}.efi").into())
            }
            ("boot-directory", "directory") => {
                directory += 1;
                Role::Directory(format!("enzimos/generations/{generation}").into())
            }
            ("catalog", "catalog") => {
                tombstone += 1;
                Role::Catalog
            }
            _ => {
                return Err(Error(
                    "non-boot or arbitrary continuation resource refused".into(),
                ));
            }
        };
        let key = format!("{role:?}");
        require(seen.insert(key), "duplicate continuation resource refused")?;
        result.push(role);
    }
    require(
        uefi == BTreeSet::from(["linux".into(), "linux-lts".into()])
            && bios == 1
            && members
                == crate::boot_retirement_plan::MEMBERS
                    .iter()
                    .map(|s| (*s).into())
                    .collect()
            && directory == 1
            && tombstone == 1,
        "exact boot continuation resource closure required",
    )?;
    Ok(result)
}
fn classify(record: &Value, states: &[String]) -> Result<Vec<&'static str>> {
    let id = record["intent"]["id"]
        .as_str()
        .ok_or_else(|| Error("continuation ID required".into()))?;
    retirement_journal::validate(record, id)?;
    let steps = record["intent"]["steps"].as_array().unwrap();
    require(
        states.len() == steps.len(),
        "exact continuation observation count required",
    )?;
    let next = record["next_step"].as_u64().unwrap() as usize;
    let inflight = record["inflight"].as_u64().map(|n| n as usize);
    let complete = record["phase"] == "complete";
    states
        .iter()
        .enumerate()
        .map(|(i, observed)| {
            let step = &steps[i];
            identity::sha(observed)?;
            if complete || i < next {
                require(
                    step["after"] == observed.as_str(),
                    "completed continuation resource drift",
                )?;
                Ok("completed-after")
            } else if inflight == Some(i) {
                if step["before"] == observed.as_str() {
                    Ok("inflight-before")
                } else {
                    require(
                        step["after"] == observed.as_str(),
                        "interrupted outcome unknown; continuation refused",
                    )?;
                    Ok("inflight-after")
                }
            } else {
                require(
                    step["before"] == observed.as_str(),
                    "unstarted resource changed; adoption refused",
                )?;
                Ok("unstarted-before")
            }
        })
        .collect()
}
fn directory_precondition(
    names: &BTreeSet<String>,
    retained: &BTreeSet<String>,
    next: usize,
    index: usize,
) -> Result<(String, String)> {
    require(
        names == retained
            && names
                .iter()
                .all(|n| crate::boot_retirement_plan::MEMBERS.contains(&n.as_str())),
        "unknown or unretained generation member; continuation refused",
    )?;
    let current = json::fingerprint(&value!({"absent":false,"members":names}))?;
    let precondition = if next < index {
        json::fingerprint(&value!({"absent":false,"members":[]}))?
    } else {
        current.clone()
    };
    Ok((current, precondition))
}
struct Directory {
    relative: PathBuf,
    file: File,
    epoch: files::FileIdentity,
    names: BTreeSet<String>,
}
impl Directory {
    fn observe(volume: &Volume, path: &Path) -> Result<Self> {
        let file = volume.directory(path)?;
        let epoch = files::identity(&file.metadata()?);
        let names = files::directory_names(&file, 256)?
            .into_iter()
            .map(|n| {
                n.into_string()
                    .map_err(|_| Error("boot continuation member encoding".into()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let result = Self {
            relative: path.into(),
            file,
            epoch,
            names,
        };
        result.recheck(volume)?;
        Ok(result)
    }
    fn advance_removed(
        &mut self,
        volume: &Volume,
        removed: &enzimos_platform::named_retirement::Removed,
        leaf: &str,
    ) -> Result<()> {
        removed.recheck()?;
        identity::safe_id(leaf)?;
        require(
            removed.original_name()? == Path::new(leaf) && self.names.contains(leaf),
            "owned continuation removal does not name an original member",
        )?;
        let parent = removed.parent()?;
        let actual = parent.metadata()?;
        let held = self.file.metadata()?;
        require(
            (
                actual.dev(),
                actual.ino(),
                actual.mode(),
                actual.uid(),
                actual.gid(),
            ) == (
                self.epoch.0,
                self.epoch.1,
                self.epoch.7,
                self.epoch.8,
                self.epoch.9,
            ) && files::identity(&actual) == files::identity(&held)
                && mount_identity::id(parent.as_fd(), true)? == volume.unique,
            "owned removal belongs to a different original continuation parent",
        )?;
        let mut expected = self.names.clone();
        expected.remove(leaf);
        let current = files::directory_names(&self.file, 256)?
            .into_iter()
            .map(|n| {
                n.into_string()
                    .map_err(|_| Error("owned continuation directory member encoding".into()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            current == expected,
            "independent continuation directory changed during owned removal",
        )?;
        self.names = expected;
        self.epoch = files::identity(&held);
        self.recheck(volume)?;
        removed.recheck()
    }
    fn advance_replaced(
        &mut self,
        volume: &Volume,
        replaced: &crate::boot_volume::ReplacedArtifact,
        leaf: &str,
    ) -> Result<()> {
        replaced.require_parent_member(&self.file, Path::new(leaf))?;
        require(
            self.names.contains(leaf),
            "owned replacement lacks original directory member",
        )?;
        let m = self.file.metadata()?;
        require(
            (m.dev(), m.ino(), m.mode(), m.uid(), m.gid(), m.nlink())
                == (
                    self.epoch.0,
                    self.epoch.1,
                    self.epoch.7,
                    self.epoch.8,
                    self.epoch.9,
                    self.epoch.10,
                ),
            "original continuation replacement parent shape changed",
        )?;
        let current = files::directory_names(&self.file, 256)?
            .into_iter()
            .map(|n| {
                n.into_string()
                    .map_err(|_| Error("owned replacement member encoding".into()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        require(
            current == self.names,
            "independent continuation member changed during owned replacement",
        )?;
        self.epoch = files::identity(&m);
        self.recheck(volume)?;
        replaced.recheck()
    }
    fn recheck(&self, volume: &Volume) -> Result<()> {
        volume.recheck()?;
        let named = volume.directory(&self.relative)?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == volume.unique
                && mount_identity::id(named.as_fd(), true)? == volume.unique
                && files::directory_names(&self.file, 256)?
                    .into_iter()
                    .map(|s| {
                        s.into_string()
                            .map_err(|_| Error("boot continuation member encoding".into()))
                    })
                    .collect::<Result<BTreeSet<_>>>()?
                    == self.names,
            "original continuation directory changed",
        )
    }
}
/// Only freshly opened original Root objects construct this inspection admission.
/// Private fields deliberately prevent report/JSON-based reconstruction.
struct Admission<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    volume: Volume,
    catalog: catalog::Transaction,
    registry: control_registry::Snapshot<'a>,
    record: Observation,
    roles: Vec<Role>,
    directories: BTreeMap<PathBuf, Directory>,
    artifacts: BTreeMap<PathBuf, Artifact>,
    states: Vec<String>,
    observed_states: Vec<String>,
    classification: Vec<&'static str>,
    source: Value,
    references: Option<References<'a>>,
    loaders: Option<Loaders>,
    signed: Option<Signed>,
}
impl<'a> Admission<'a> {
    fn retain_parent(&mut self, path: &Path) -> Result<bool> {
        let parent = path
            .parent()
            .ok_or_else(|| Error("boot resource parent required".into()))?;
        if !self.directories.contains_key(parent) {
            // A deleted generation directory is observed through its retained
            // original parent membership. No absent child is reopened/adopted.
            if let Some(grandparent) = parent.parent() {
                if !self.directories.contains_key(grandparent) {
                    self.directories.insert(
                        grandparent.into(),
                        Directory::observe(&self.volume, grandparent)?,
                    );
                }
                let leaf = parent
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| Error("boot resource parent encoding".into()))?;
                if !self.directories[grandparent].names.contains(leaf) {
                    return Ok(false);
                }
            }
            self.directories
                .insert(parent.into(), Directory::observe(&self.volume, parent)?);
        }
        Ok(true)
    }
    fn observe(guard: &'a Guard, lock: &'a files::Lock, id: &str) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        identity::safe_id(id)?;
        require(id.starts_with("boot-"), "fixed boot retirement ID required")?;
        guard.recheck()?;
        lock.recheck()?;
        let rows = control_registry::read(
            guard,
            "boot-retirements",
            retirement_journal::MAX_RECORDS,
            retirement_journal::validate,
        )?;
        require(rows.contains_key(id), "boot retirement receipt missing")?;
        let registry =
            control_registry::Snapshot::observe(guard, "boot-retirements", &value!(rows))?;
        let folder =
            files::directory_relative(guard.control(), Path::new("boot-retirements"), Some(0))?;
        let record = Observation::open(
            &folder,
            Path::new(&format!("{id}.json")),
            catalog::MAX_CATALOG,
            guard.control_mount_id(),
        )?;
        require(
            record.value()? == &rows[id],
            "original continuation receipt changed during admission",
        )?;
        let intent = &record.value()?["intent"];
        let roles = roles(intent)?;
        require(
            intent["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "continuation source filesystem differs",
        )?;
        let volume = Volume::observe()?;
        require(
            intent["boot_uuid"] == volume.uuid,
            "continuation ESP differs",
        )?;
        let catalog = catalog::Transaction::begin()?;
        require(
            catalog.config == guard.configuration,
            "continuation publisher/source differs",
        )?;
        let source = guard.backup_root_binding()?;
        let mut admission = Self {
            guard,
            lock,
            volume,
            catalog,
            registry,
            record,
            roles,
            directories: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            states: Vec::new(),
            observed_states: Vec::new(),
            classification: Vec::new(),
            source,
            references: None,
            loaders: None,
            signed: None,
        };
        let absent = json::fingerprint(&value!({"absent":true}))?;
        for (index, role) in admission.roles.clone().into_iter().enumerate() {
            let mut projection = None;
            let state = match role {
                Role::Catalog => json::fingerprint(&admission.catalog.data)?,
                Role::File(path) => {
                    if !admission.retain_parent(&path)? {
                        absent.clone()
                    } else {
                        let parent = path.parent().unwrap();
                        let leaf = path.file_name().unwrap().to_str().unwrap();
                        if !admission.directories[parent].names.contains(leaf) {
                            absent.clone()
                        } else {
                            let artifact = admission.volume.artifact(&path, 256 * 1024 * 1024)?;
                            let state = crate::boot_retirement_plan::file_state(&artifact.sha)?;
                            admission.artifacts.insert(path, artifact);
                            state
                        }
                    }
                }
                Role::Directory(path) => {
                    let parent = path.parent().unwrap();
                    if !admission.directories.contains_key(parent) {
                        admission.directories.insert(
                            parent.into(),
                            Directory::observe(&admission.volume, parent)?,
                        );
                    }
                    if !admission.directories[parent]
                        .names
                        .contains(path.file_name().unwrap().to_str().unwrap())
                    {
                        absent.clone()
                    } else {
                        if !admission.directories.contains_key(&path) {
                            admission.directories.insert(
                                path.clone(),
                                Directory::observe(&admission.volume, &path)?,
                            );
                        }
                        let current_names = &admission.directories[&path].names;
                        let actual_members: BTreeSet<_> = admission
                            .artifacts
                            .keys()
                            .filter(|p| p.parent() == Some(path.as_path()))
                            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
                            .collect();
                        let (current, precondition) = directory_precondition(
                            current_names,
                            &actual_members,
                            admission.record.value()?["next_step"].as_u64().unwrap() as usize,
                            index,
                        )?;
                        projection = Some(precondition);
                        current
                    }
                }
            };
            admission
                .states
                .push(projection.unwrap_or_else(|| state.clone()));
            admission.observed_states.push(state);
        }
        admission.references = Some(References::observe(guard, &admission.record)?);
        admission.classification = classify(admission.record.value()?, &admission.states)?;
        admission.loaders = Some(Loaders::observe(&admission)?);
        admission.signed = Some(Signed::observe(&admission)?);
        admission.recheck()?;
        Ok(admission)
    }
    fn recheck(&self) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.volume.recheck()?;
        self.catalog.recheck()?;
        self.registry.recheck()?;
        self.record.recheck()?;
        require(
            self.guard.backup_root_binding()? == self.source,
            "original continuation source changed",
        )?;
        if let Some(references) = &self.references {
            references.recheck(&self.record)?;
        }
        if let Some(loaders) = &self.loaders {
            loaders.recheck(self)?;
        }
        if let Some(signed) = &self.signed {
            signed.recheck(self)?;
        }
        for directory in self.directories.values() {
            directory.recheck(&self.volume)?;
        }
        for artifact in self.artifacts.values() {
            artifact.recheck()?;
        }
        require(
            classify(self.record.value()?, &self.states)? == self.classification,
            "continuation recorded states changed",
        )?;
        self.guard.recheck()?;
        self.lock.recheck()
    }
    fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let record = self.record.value()?;
        let steps:Vec<_>=record["intent"]["steps"].as_array().unwrap().iter().enumerate().map(|(i,s)|value!({"id":s["id"],"kind":s["kind"],"current_state":self.observed_states[i],"step_precondition_state":self.states[i],"future_directory_precondition":self.observed_states[i]!=self.states[i],"classification":self.classification[i]})).collect();
        let mut report = value!({"schema":1,"status":"boot-retirement-continuation-observed","id":record["intent"]["id"],"phase":record["phase"],"next_step":record["next_step"],"inflight":record["inflight"],"source":self.source,"receipt":self.record.evidence()?,"registry":self.registry.evidence()?,"signed_protection":self.signed.as_ref().ok_or_else(||Error("original continuation signed closure absent".into()))?.evidence(self)?,"loader_protection":self.loaders.as_ref().ok_or_else(||Error("original continuation loader protection absent".into()))?.evidence(self)?,"reference_protection":self.references.as_ref().ok_or_else(||Error("original continuation references absent".into()))?.evidence(&self.record)?,"catalog":self.catalog.evidence()?,"steps":steps,"execution_available":false,"root_subvolume_retained":true,"automatic_replay":false,"blockers":["explicit-fresh-execution-admission-required"]});
        report["review_sha256"] = value!(json::fingerprint(&report)?);
        self.recheck()?;
        Ok(report)
    }
}
/// A fresh Root request may bind only these actual still-held observation objects.
/// It is deliberately private and has no serialized/report constructor.
struct Approval {
    review_sha256: String,
    original_receipt_sha256: String,
}
impl Approval {
    fn admit(admission: &Admission<'_>, review_sha256: &str) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        identity::sha(review_sha256)?;
        admission.recheck()?;
        let report = admission.evidence()?;
        require(
            report["review_sha256"] == review_sha256,
            "fresh continuation review changed; review again",
        )?;
        let original_receipt_sha256 = json::fingerprint(admission.record.value()?)?;
        admission.recheck()?;
        Ok(Self {
            review_sha256: review_sha256.into(),
            original_receipt_sha256,
        })
    }
    fn require_journal(&self, journal: &ContinuationJournal) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        journal.recheck()?;
        identity::sha(&self.review_sha256)?;
        require(
            json::fingerprint(journal.before())? == self.original_receipt_sha256,
            "fresh reviewed continuation receipt differs from actual owned chain",
        )?;
        journal.recheck()
    }
}
pub fn review_locked(guard: &Guard, lock: &files::Lock, id: &str) -> Result<Value> {
    Admission::observe(guard, lock, id)?.evidence()
}
