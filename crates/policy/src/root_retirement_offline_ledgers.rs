// SPDX-License-Identifier: MIT
//! Original offline protection ledgers. Complete schemas and actual descriptions
//! are retained; values and diagnostic snapshots never grant deletion.
use crate::{
    control_record::Retained, recovery_journal::Kind, root_retirement_offline_control::Control,
    root_retirement_offline_journal::Journal,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const BYTE_BUDGET: u64 = 32 * 1024 * 1024;
pub(crate) fn backend_unmentioned(row: &Value, targets: &Value) -> Result<()> {
    if row["state"] == "cancelled" {
        return Ok(());
    }
    let rows = targets
        .as_array()
        .filter(|rows| (1..=64).contains(&rows.len()))
        .ok_or_else(|| Error("original backend target bound".into()))?;
    let root = rows.last().unwrap()["path"]
        .as_str()
        .ok_or_else(|| Error("original backend target root".into()))?;
    crate::identity::safe_id(root)?;
    let mut identifiers = vec![root];
    for target in rows {
        identifiers.push(crate::identity::uuid(
            target["uuid"].as_str().unwrap_or(""),
        )?);
    }
    let mut stack = vec![(&row["plan"], 0), (&row["result"], 0)];
    let mut nodes = 0;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        require(
            nodes <= 32768 && depth <= 32,
            "original backend reference traversal bound; review required",
        )?;
        match value {
            Value::Object(object) => {
                if ["path", "id", "uuid"]
                    .iter()
                    .all(|key| object.contains_key(*key))
                {
                    identity_unmentioned(value, targets)?;
                }
                stack.extend(object.values().map(|value| (value, depth + 1)));
            }
            Value::Array(array) => stack.extend(array.iter().map(|value| (value, depth + 1))),
            Value::String(text) => {
                let identifier = |byte: u8| byte.is_ascii_alphanumeric() || b"._-".contains(&byte);
                require(
                    identifiers.iter().all(|needle| {
                        !text.match_indices(*needle).any(|(offset, _)| {
                            (offset == 0 || !identifier(text.as_bytes()[offset - 1]))
                                && (offset + needle.len() == text.len()
                                    || !identifier(text.as_bytes()[offset + needle.len()]))
                        })
                    }),
                    "original backend plan or result protects retirement target",
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}
pub(crate) fn concluded_activation(activation: &Value, job: &Value) -> Result<bool> {
    require(
        activation["intent"]["job"] == *job && job["phase"] == "staged",
        "original recovery conclusion differs from retained staged job",
    )?;
    Ok(activation["phase"] == "adopted" && activation["superseded"]["legacy_detached"] == true)
}
pub(crate) fn staging_unmentioned(job: &Value, targets: &Value, concluded: bool) -> Result<()> {
    for field in ["root", "history"] {
        identity_unmentioned(&job[field], targets)?;
    }
    if !concluded {
        let plan = &job["plan"];
        let birth = &plan["source_birth"];
        for object in [
            &birth["source"],
            &birth["snapshot"]["object"],
            &birth["root"],
            &birth["history"],
        ] {
            identity_unmentioned(object, targets)?;
        }
        for object in plan["protected"]
            .as_object()
            .ok_or_else(|| Error("original staged protected identities missing".into()))?
            .values()
        {
            identity_unmentioned(object, targets)?;
        }
    }
    Ok(())
}
pub(crate) fn identity_unmentioned(identity: &Value, targets: &Value) -> Result<()> {
    let path = identity["path"]
        .as_str()
        .ok_or_else(|| Error("original protected root path missing".into()))?;
    let id = identity["id"]
        .as_u64()
        .filter(|id| *id >= 256)
        .ok_or_else(|| Error("original protected root ID missing".into()))?;
    let uuid = identity["uuid"]
        .as_str()
        .ok_or_else(|| Error("original protected root UUID missing".into()))?;
    crate::identity::uuid(uuid)?;
    let rows = targets
        .as_array()
        .filter(|rows| (1..=64).contains(&rows.len()))
        .ok_or_else(|| Error("original protected root target bound".into()))?;
    let root = rows.last().unwrap()["path"]
        .as_str()
        .ok_or_else(|| Error("original protected target root missing".into()))?;
    crate::identity::safe_id(root)?;
    require(
        path != root
            && !path.starts_with(&format!("{root}/"))
            && rows
                .iter()
                .all(|row| row["path"] != path && row["id"] != id && row["uuid"] != uuid),
        "original pin or rebind source protects retirement target",
    )
}
#[derive(Clone, Copy)]
enum Role {
    Boot,
    Workers,
    Modules,
    Authority,
    Births,
    Rebinds,
    Retirement,
    BootRetirement,
    RootRetirement,
    Recovery(Kind),
    Pins,
    Backend,
}
const ROLES: &[Role] = &[
    Role::Boot,
    Role::Workers,
    Role::Modules,
    Role::Authority,
    Role::Births,
    Role::Rebinds,
    Role::Retirement,
    Role::BootRetirement,
    Role::RootRetirement,
    Role::Recovery(Kind::Jobs),
    Role::Recovery(Kind::Runs),
    Role::Recovery(Kind::Activations),
    Role::Recovery(Kind::Workflows),
    Role::Recovery(Kind::Images),
    Role::Recovery(Kind::Publications),
    Role::Recovery(Kind::Media),
    Role::Pins,
    Role::Backend,
];
impl Role {
    fn folder(self) -> &'static str {
        match self {
            Self::Boot => "boot-publications",
            Self::Workers => "update-workers",
            Self::Modules => "module-views",
            Self::Authority => "authority-refresh",
            Self::Births => "root-births",
            Self::Rebinds => "root-rebind-journal",
            Self::Retirement => "retirement-journals",
            Self::BootRetirement => "boot-retirements",
            Self::RootRetirement => "root-retirements",
            Self::Recovery(kind) => kind.folder(),
            Self::Pins => "generation-pins",
            Self::Backend => "backend-operations",
        }
    }
    fn maximum(self) -> usize {
        match self {
            Self::Boot => 128,
            Self::Workers => crate::update_worker_record::MAXIMUM,
            Self::Modules => crate::module_view_record::MAXIMUM,
            Self::Authority => crate::authority_record::MAXIMUM,
            Self::Births => crate::birth_runtime::MAX_RECORDS,
            Self::RootRetirement => 16,
            Self::Recovery(kind) => kind.maximum(),
            Self::Pins => crate::generation_pins::MAXIMUM,
            Self::Backend => 8192,
            _ => 32,
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::Recovery(kind) => kind.limit(),
            _ => crate::catalog::MAX_CATALOG,
        }
    }
    fn validate(self, row: &Value, id: &str, filesystem: &str) -> Result<()> {
        match self {
            Self::Boot => crate::generation_publication::validate(row, id),
            Self::Workers => crate::update_worker_record::validate(row, id),
            Self::Modules => crate::module_view_record::validate(row, id),
            Self::Authority => crate::authority_record::validate(row, id),
            Self::Births => crate::birth::validate(row, id, filesystem),
            Self::Rebinds => crate::root_rebind_record::validate(row, id),
            Self::Retirement | Self::BootRetirement => crate::retirement_journal::validate(row, id),
            Self::RootRetirement => crate::root_retirement_record::validate(row, id),
            Self::Recovery(kind) => {
                kind.identifier(id)?;
                kind.validate(row, id)
            }
            Self::Pins => crate::generation_pins::validate(row, id, filesystem),
            Self::Backend => crate::boot_backend_references::validate(row, id),
        }
    }
    fn owns_journal(self) -> bool {
        matches!(self, Self::RootRetirement)
    }
    fn idle(self, row: &Value, filesystem: &str) -> Result<()> {
        let fs = match self {
            Self::Boot
            | Self::Modules
            | Self::Authority
            | Self::Births
            | Self::Rebinds
            | Self::RootRetirement
            | Self::Recovery(Kind::Images) => Some(&row["filesystem_uuid"]),
            Self::Workers => Some(&row["request"]["filesystem_uuid"]),
            Self::BootRetirement => Some(&row["intent"]["filesystem_uuid"]),
            Self::Recovery(Kind::Jobs) => Some(&row["plan"]["filesystem_uuid"]),
            Self::Recovery(Kind::Activations) => {
                Some(&row["intent"]["job"]["plan"]["filesystem_uuid"])
            }
            _ => None,
        };
        require(
            fs.is_none_or(|value| value == filesystem),
            "foreign original offline transition ledger requires review",
        )?;
        let idle = match self {
            Self::Boot
            | Self::Workers
            | Self::Modules
            | Self::Authority
            | Self::Rebinds
            | Self::BootRetirement => row["phase"] == "complete",
            Self::Births => matches!(row["phase"].as_str(), Some("ready" | "retired")),
            Self::Retirement => false,
            Self::RootRetirement | Self::Recovery(Kind::Runs) => {
                matches!(row["phase"].as_str(), Some("complete" | "abandoned"))
            }
            Self::Recovery(Kind::Jobs) => row["phase"] == "staged",
            Self::Recovery(Kind::Workflows) => row["state"] == "complete",
            Self::Recovery(Kind::Images) => row["phase"] == "ready",
            Self::Recovery(Kind::Activations) => matches!(
                row["phase"].as_str(),
                Some("published" | "selected" | "adopted")
            ),
            Self::Recovery(Kind::Media) => row["phase"] == "complete",
            Self::Recovery(Kind::Publications) | Self::Pins => true,
            Self::Backend => matches!(
                row["state"].as_str(),
                Some("planned" | "completed" | "cancelled")
            ),
        };
        require(
            idle,
            "unfinished original offline transition ledger prevents execution",
        )
    }
}
fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline ledger read-only descriptor required",
    )?;
    Ok(value)
}
fn epoch(file: &File, mount: u64) -> Result<files::FileIdentity> {
    let metadata = file.metadata()?;
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o700
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original Root-private offline ledger directory required",
    )?;
    Ok(files::identity(&metadata))
}
fn identifier(name: &str) -> Result<&str> {
    let id = name
        .strip_suffix(".json")
        .ok_or_else(|| Error("interrupted or unknown offline ledger member".into()))?;
    crate::identity::safe_id(id)?;
    Ok(id)
}
fn names(file: &File, maximum: usize) -> Result<BTreeSet<String>> {
    files::directory_names(file, maximum)?
        .into_iter()
        .map(|name| {
            let name = name
                .into_string()
                .map_err(|_| Error("offline ledger filename encoding".into()))?;
            identifier(&name)?;
            Ok(name)
        })
        .collect()
}
struct Registry {
    role: Role,
    folder: Option<File>,
    epoch: Option<files::FileIdentity>,
    flags: Option<i32>,
    records: BTreeMap<String, (Retained, i32)>,
}
impl Registry {
    fn observe(
        control: &Control<'_, '_>,
        journal: &Journal<'_, '_>,
        role: Role,
        filesystem: &str,
        bytes: &mut u64,
    ) -> Result<Self> {
        control.recheck()?;
        journal.recheck()?;
        let mount = control.mount_id()?;
        let folder = files::optional_directory_relative(
            control.descriptor()?,
            Path::new(role.folder()),
            Some(0),
        )?;
        let mut result = Self {
            role,
            folder,
            epoch: None,
            flags: None,
            records: BTreeMap::new(),
        };
        if let Some(folder) = &result.folder {
            result.epoch = Some(epoch(folder, mount)?);
            result.flags = Some(flags(folder)?);
            if role.owns_journal() {
                journal.require_original_folder(folder)?;
            }
            for name in names(folder, role.maximum())? {
                let id = identifier(&name)?;
                if role.owns_journal() && id == journal.identifier()? {
                    continue;
                }
                let record = Retained::open(folder, Path::new(&name), role.limit(), mount)?;
                role.validate(record.value()?, id, filesystem)?;
                *bytes = bytes
                    .checked_add(record.checkpoint_descriptor()?.metadata()?.len())
                    .ok_or_else(|| Error("offline ledger byte budget overflow".into()))?;
                require(
                    *bytes <= BYTE_BUDGET,
                    "complete offline ledger byte budget exceeded; no execution",
                )?;
                let original_flags = flags(record.checkpoint_descriptor()?)?;
                result.records.insert(id.into(), (record, original_flags));
            }
        }
        result.recheck(control, journal, filesystem)?;
        Ok(result)
    }
    fn recheck(
        &self,
        control: &Control<'_, '_>,
        journal: &Journal<'_, '_>,
        filesystem: &str,
    ) -> Result<()> {
        control.recheck()?;
        journal.recheck()?;
        let mount = control.mount_id()?;
        let named = files::optional_directory_relative(
            control.descriptor()?,
            Path::new(self.role.folder()),
            Some(0),
        )?;
        match (&self.folder, named) {
            (None, None) => require(
                !self.role.owns_journal() && self.records.is_empty(),
                "required original offline ledger absent",
            )?,
            (Some(held), Some(named)) => {
                let expected_epoch = if self.role.owns_journal() {
                    Some(journal.require_original_folder(held)?)
                } else {
                    self.epoch
                };
                require(
                    Some(epoch(held, mount)?) == expected_epoch
                        && Some(epoch(&named, mount)?) == expected_epoch
                        && Some(flags(held)?) == self.flags,
                    "original offline ledger directory replaced, changed or covered",
                )?;
                let mut expected = self
                    .records
                    .keys()
                    .map(|id| format!("{id}.json"))
                    .collect::<BTreeSet<_>>();
                if self.role.owns_journal() {
                    expected.insert(format!("{}.json", journal.identifier()?));
                }
                require(
                    names(held, self.role.maximum())? == expected
                        && names(&named, self.role.maximum())? == expected,
                    "original offline ledger membership changed",
                )?;
                for (id, (record, original_flags)) in &self.records {
                    record.recheck()?;
                    require(
                        flags(record.checkpoint_descriptor()?)? == *original_flags,
                        "original offline ledger shared description flags changed",
                    )?;
                    self.role.validate(record.value()?, id, filesystem)?;
                    let member = files::open_relative(held, Path::new(&format!("{id}.json")))?;
                    require(
                        files::identity(&member.metadata()?)
                            == files::identity(&record.checkpoint_descriptor()?.metadata()?)
                            && mount_identity::id(member.as_fd(), true)? == mount,
                        "original offline ledger member no longer names retained inode",
                    )?;
                }
            }
            _ => {
                return Err(Error(
                    "original offline ledger appeared, disappeared or changed type".into(),
                ));
            }
        }
        control.recheck()?;
        journal.recheck()
    }
}
pub struct Ledgers<'a, 's> {
    control: &'a Control<'a, 's>,
    journal: &'a Journal<'a, 's>,
    filesystem: String,
    registries: Vec<Registry>,
    bytes: u64,
}
impl<'a, 's> Ledgers<'a, 's> {
    pub(crate) fn require_unmentioned_sources(
        &self,
        targets: &crate::root_retirement_offline_targets::Targets<'a, 's>,
    ) -> Result<()> {
        targets.require_original_ledgers(self)?;
        self.require_idle()?;
        let rows = targets.rows()?;
        let jobs = self.recovery_rows(Kind::Jobs)?;
        let activations = self.recovery_rows(Kind::Activations)?;
        let mut concluded_jobs = BTreeSet::new();
        for (id, job) in &jobs {
            let concluded = match activations.get(id) {
                Some(activation) => concluded_activation(activation, job)?,
                None => false,
            };
            staging_unmentioned(job, rows, concluded)?;
            if concluded {
                concluded_jobs.insert((*id).to_owned());
            }
        }
        for (id, activation) in activations {
            let job = jobs
                .get(id)
                .ok_or_else(|| Error("original activation staging row missing".into()))?;
            if !concluded_activation(activation, job)? {
                let roots = crate::root_retirement_offline_publications::historical_roots(
                    &activation["intent"],
                )?;
                let root = rows.as_array().unwrap().last().unwrap()["path"]
                    .as_str()
                    .unwrap();
                require(
                    roots
                        .iter()
                        .all(|path| path != root && !path.starts_with(&format!("{root}/"))),
                    "original activation before-state loader protects retirement target",
                )?;
            }
        }
        let historical_jobs: crate::recovery_journal::Records = jobs
            .iter()
            .map(|(id, row)| ((*id).to_owned(), (*row).clone()))
            .collect();
        let original_prepared = self.journal.prepared_record()?;
        for registry in &self.registries {
            for (record, _) in registry.records.values() {
                let row = record.value()?;
                match registry.role {
                    Role::Pins => identity_unmentioned(&row["material"]["root_identity"], rows)?,
                    Role::Rebinds => {
                        // Only before/after catalog and target edges can be history.
                        // A completed rebind still uses its source and snapshot.
                        identity_unmentioned(&row["source"], rows)?;
                        let uuid = crate::recovery_records::text(&row["snapshot"], "uuid")?;
                        require(
                            rows.as_array()
                                .unwrap()
                                .iter()
                                .all(|target| target["uuid"] != uuid),
                            "original rebind source snapshot protects retirement target",
                        )?;
                    }
                    Role::Backend
                        if !crate::recovery_conclusions::historical(
                            row,
                            &historical_jobs,
                            &concluded_jobs,
                        ) && !crate::root_retirement_conclusions::historical(
                            row,
                            &original_prepared,
                        ) =>
                    {
                        backend_unmentioned(row, rows)?;
                    }
                    _ => {}
                }
            }
        }
        self.recheck()
    }
    /// No caller-supplied owner ID or phase exempts another pending receipt.
    /// The one actual owned receipt is held separately by the original Journal.
    pub fn require_idle(&self) -> Result<()> {
        self.recheck()?;
        for registry in &self.registries {
            for (record, _) in registry.records.values() {
                registry.role.idle(record.value()?, &self.filesystem)?;
            }
        }
        let jobs = self.recovery_rows(Kind::Jobs)?;
        for (id, activation) in self.recovery_rows(Kind::Activations)? {
            require(
                jobs.get(id).copied() == Some(&activation["intent"]["job"]),
                "original offline activation differs from retained staged job",
            )?;
        }
        let images = self.recovery_rows(Kind::Images)?;
        for (id, publication) in self.recovery_rows(Kind::Publications)? {
            let image = images
                .get(id)
                .ok_or_else(|| Error("original offline publication image missing".into()))?;
            crate::recovery_publication::expected_record(publication, image)?;
            require(
                image["phase"] == "ready",
                "original offline publication is not ready",
            )?;
        }
        self.recheck()
    }
    pub(crate) fn recovery_rows(&self, kind: Kind) -> Result<BTreeMap<&str, &Value>> {
        self.recheck()?;
        let registry = self.registries.iter().find(|registry| {
            matches!(registry.role, Role::Recovery(role) if role.folder() == kind.folder())
        }).ok_or_else(|| Error("original recovery ledger family missing".into()))?;
        registry
            .records
            .iter()
            .map(|(id, (record, _))| Ok((id.as_str(), record.value()?)))
            .collect()
    }
    pub(crate) fn require_original_control(&self, control: &Control<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.control, control),
            "original offline ledgers belong to another control actor",
        )?;
        self.recheck()
    }
    pub(crate) fn require_original_journal(&self, journal: &Journal<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.journal, journal),
            "original offline ledgers belong to another receipt",
        )?;
        self.recheck()
    }
    pub fn observe(control: &'a Control<'a, 's>, journal: &'a Journal<'a, 's>) -> Result<Self> {
        journal.require_original_control(control)?;
        journal.prepared_record()?;
        let filesystem =
            crate::filesystem::observe(control.descriptor()?.as_fd())?["filesystem_uuid"]
                .as_str()
                .ok_or_else(|| Error("original offline filesystem UUID encoding".into()))?
                .to_owned();
        let mut bytes = 0;
        let mut registries = Vec::new();
        for role in ROLES {
            registries.push(Registry::observe(
                control,
                journal,
                *role,
                &filesystem,
                &mut bytes,
            )?);
        }
        let result = Self {
            control,
            journal,
            filesystem,
            registries,
            bytes,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.journal.require_original_control(self.control)?;
        require(
            crate::filesystem::observe(self.control.descriptor()?.as_fd())?["filesystem_uuid"]
                == self.filesystem,
            "original offline ledger filesystem changed",
        )?;
        require(
            self.registries.len() == ROLES.len() && self.bytes <= BYTE_BUDGET,
            "incomplete original offline ledger retention",
        )?;
        for registry in &self.registries {
            registry.recheck(self.control, self.journal, &self.filesystem)?;
        }
        self.journal.require_original_control(self.control)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"original_offline_registry_families_retained":self.registries.len(),"retained_record_bytes":self.bytes,
            "own_receipt_tracks_actual_publication_lineage":true,"catalog_and_loader_closure_verified":false,"execution_authorized":false}),
        )
    }
}
