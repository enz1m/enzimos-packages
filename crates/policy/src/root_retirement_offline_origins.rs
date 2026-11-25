// SPDX-License-Identifier: MIT
//! Retain actual birth/activation/job registries for offline ownership comparison.
//! This observation is neither deletion authority nor a cold replay capability.
use crate::{control_record::Retained, root_retirement_offline_control::Control};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
#[derive(Clone, Copy)]
enum Role {
    Births,
    Activations,
    Jobs,
}
impl Role {
    fn folder(self) -> &'static str {
        match self {
            Self::Births => "root-births",
            Self::Activations => "recovery-activations",
            Self::Jobs => "recovery-jobs",
        }
    }
    fn maximum(self) -> usize {
        match self {
            Self::Births => crate::birth_runtime::MAX_RECORDS,
            _ => crate::recovery_records::MAX_JOBS,
        }
    }
    fn validate(self, row: &Value, id: &str, fs: &str) -> Result<()> {
        match self {
            Self::Births => crate::birth::validate(row, id, fs),
            Self::Activations => crate::recovery_activation::validate(row, id),
            Self::Jobs => crate::recovery_records::job(row, id),
        }
    }
}
fn flags(file: &File) -> Result<i32> {
    let n = enzimos_platform::files::status_flags(&file);
    require(
        n >= 0 && n & libc::O_ACCMODE == libc::O_RDONLY,
        "original offline origin descriptor flags",
    )?;
    Ok(n)
}
fn epoch(file: &File, mount: u64) -> Result<files::FileIdentity> {
    let m = file.metadata()?;
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && mount_identity::id(file.as_fd(), true)? == mount,
        "actual private offline origin registry required",
    )?;
    Ok(files::identity(&m))
}
struct Registry {
    role: Role,
    folder: Option<File>,
    epoch: Option<files::FileIdentity>,
    flags: Option<i32>,
    records: BTreeMap<String, (Retained, i32)>,
}
impl Registry {
    fn observe(control: &Control<'_, '_>, role: Role, fs: &str) -> Result<Self> {
        control.recheck()?;
        let mount = control.mount_id()?;
        let folder = files::optional_directory_relative(
            control.descriptor()?,
            Path::new(role.folder()),
            Some(0),
        )?;
        let mut this = Self {
            role,
            folder,
            epoch: None,
            flags: None,
            records: BTreeMap::new(),
        };
        if let Some(folder) = &this.folder {
            this.epoch = Some(epoch(folder, mount)?);
            this.flags = Some(flags(folder)?);
            for name in files::directory_names(folder, role.maximum().max(1))? {
                let name = name
                    .into_string()
                    .map_err(|_| Error("offline origin registry filename".into()))?;
                let id = name
                    .strip_suffix(".json")
                    .ok_or_else(|| Error("interrupted offline origin registry".into()))?;
                crate::identity::safe_id(id)?;
                let record =
                    Retained::open(folder, Path::new(&name), crate::catalog::MAX_CATALOG, mount)?;
                role.validate(record.value()?, id, fs)?;
                let original_flags = flags(record.checkpoint_descriptor()?)?;
                this.records.insert(id.into(), (record, original_flags));
            }
        }
        this.recheck(control, fs)?;
        Ok(this)
    }
    fn recheck(&self, control: &Control<'_, '_>, fs: &str) -> Result<()> {
        control.recheck()?;
        let mount = control.mount_id()?;
        let named = files::optional_directory_relative(
            control.descriptor()?,
            Path::new(self.role.folder()),
            Some(0),
        )?;
        match (&self.folder, named) {
            (None, None) => require(
                self.records.is_empty(),
                "absent original registry acquired records",
            )?,
            (Some(held), Some(named)) => {
                require(
                    Some(epoch(held, mount)?) == self.epoch
                        && Some(epoch(&named, mount)?) == self.epoch
                        && Some(flags(held)?) == self.flags,
                    "original offline origin registry replaced/changed",
                )?;
                let expected = self
                    .records
                    .keys()
                    .map(|id| format!("{id}.json"))
                    .collect::<BTreeSet<_>>();
                for folder in [held, &named] {
                    let names = files::directory_names(folder, self.role.maximum().max(1))?
                        .into_iter()
                        .map(|name| {
                            name.into_string()
                                .map_err(|_| Error("offline registry filename".into()))
                        })
                        .collect::<Result<BTreeSet<_>>>()?;
                    require(
                        names == expected,
                        "original offline origin membership changed",
                    )?;
                    for (id, (record, original_flags)) in &self.records {
                        self.role.validate(record.checkpoint_value()?, id, fs)?;
                        let file = files::open_relative(folder, Path::new(&format!("{id}.json")))?;
                        require(
                            files::identity(&file.metadata()?)
                                == files::identity(&record.checkpoint_descriptor()?.metadata()?)
                                && mount_identity::id(file.as_fd(), true)? == mount
                                && flags(record.checkpoint_descriptor()?)? == *original_flags,
                            "original offline origin record replaced or flags changed",
                        )?;
                    }
                }
            }
            _ => {
                return Err(Error(
                    "original offline origin registry absence changed".into(),
                ));
            }
        }
        control.recheck()
    }
    fn evidence(&self) -> Result<Value> {
        Ok(value!({"folder":self.role.folder(),"epoch":self.epoch,
            "records":self.records.iter().map(|(id,(r,_))|Ok((id.clone(),r.evidence()?)))
                .collect::<Result<BTreeMap<_,_>>>()?}))
    }
}
pub struct Origins<'a, 's> {
    control: &'a Control<'a, 's>,
    filesystem: String,
    births: Registry,
    activations: Registry,
    jobs: Registry,
}
impl<'a, 's> Origins<'a, 's> {
    pub(crate) fn observe(control: &'a Control<'a, 's>) -> Result<Self> {
        control.recheck()?;
        let fs = enzimos_platform::json::string(
            &crate::filesystem::observe(control.descriptor()?.as_fd())?["filesystem_uuid"],
        )?
        .to_owned();
        let this = Self {
            control,
            births: Registry::observe(control, Role::Births, &fs)?,
            activations: Registry::observe(control, Role::Activations, &fs)?,
            jobs: Registry::observe(control, Role::Jobs, &fs)?,
            filesystem: fs,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.control.recheck()?;
        require(
            crate::filesystem::observe(self.control.descriptor()?.as_fd())?["filesystem_uuid"]
                == self.filesystem,
            "original offline origin source filesystem changed",
        )?;
        for registry in [&self.births, &self.activations, &self.jobs] {
            registry.recheck(self.control, &self.filesystem)?;
        }
        self.control.recheck()
    }
    pub(crate) fn require_original_control(&self, control: &Control<'a, 's>) -> Result<()> {
        require(
            std::ptr::eq(self.control, control),
            "original offline origin/control actor differs",
        )?;
        self.recheck()
    }
    /// Join ownership only to original retained records and actual target identity.
    /// Result remains comparison data; current loader/kernel protection is separate.
    pub(crate) fn require_owner(&self, record: &Value, actual_root: &Value) -> Result<()> {
        self.recheck()?;
        crate::root_retirement_record::validate(record, record["id"].as_str().unwrap_or(""))?;
        require(
            record["filesystem_uuid"] == self.filesystem,
            "retirement origin filesystem differs",
        )?;
        let mut owners = Vec::new();
        for (id, (original, _)) in &self.activations.records {
            let row = original.checkpoint_value()?;
            if row["phase"] == "adopted"
                && row["superseded"]["identity"]["uuid"] == actual_root["uuid"]
            {
                owners.push((id, row));
            }
        }
        require(
            owners.len() <= 1,
            "ambiguous original superseded Root ownership",
        )?;
        let birth = enzimos_platform::json::string(&record["birth"])?;
        if let Some(id) = birth.strip_prefix("superseded-") {
            let (owner, row) = owners
                .first()
                .ok_or_else(|| Error("original superseded activation missing".into()))?;
            let job = self
                .jobs
                .records
                .get(id)
                .ok_or_else(|| Error("original activation staging job missing".into()))?
                .0
                .checkpoint_value()?;
            require(
                owner.as_str() == id
                    && row["superseded"]["identity"] == *actual_root
                    && row["superseded"]["legacy_detached"] == true
                    && row["superseded"]["retired"] == false
                    && *job == row["intent"]["job"]
                    && job["phase"] == "staged",
                "original superseded activation/job does not own exact detached unretired Root",
            )?;
        } else {
            require(
                owners.is_empty(),
                "new superseded ownership differs from original birth plan",
            )?;
            let row = self
                .births
                .records
                .get(birth)
                .ok_or_else(|| Error("original publisher birth missing".into()))?
                .0
                .checkpoint_value()?;
            let mut matches = 0;
            for (original, _) in self.births.records.values() {
                if original.checkpoint_value()?["root"]["uuid"] == actual_root["uuid"] {
                    matches += 1;
                }
            }
            require(
                matches == 1 && row["phase"] == "ready" && row["root"] == *actual_root,
                "actual Root differs from unique original ready publisher birth",
            )?;
            let expected = value!([{ "role":"history-store","path":row["history"]["path"],"id":row["history"]["id"],
                "uuid":row["history"]["uuid"],"parent_uuid":row["history"]["parent_uuid"]},
                {"role":"root-subvolume","path":row["root"]["path"],"id":row["root"]["id"],
                "uuid":row["root"]["uuid"],"parent_uuid":row["root"]["parent_uuid"]}]);
            require(
                record["targets"] == expected,
                "publisher retirement targets differ from actual original birth",
            )?;
        }
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let result = value!({"births":self.births.evidence()?,"activations":self.activations.evidence()?,
            "jobs":self.jobs.evidence()?,"execution_authorized":false});
        self.recheck()?;
        Ok(result)
    }
}
