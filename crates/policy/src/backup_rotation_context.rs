// SPDX-License-Identifier: MIT
//! Original Root rotation review inputs. Journal data cannot confer object ownership.
use crate::backup_rotation_objects::{Credential, CredentialName, Repository, RepositoryName};
use crate::{
    backup_configuration::Configuration, backup_rotation_mount::Mount,
    backup_rotation_record as codec, control_record::Retained, control_registry,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const FOLDER: &str = "backup-rotation";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "Root-private rotation journal directory required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
fn quiescent(guard: &Guard, schedule_allowed: bool) -> Result<Value> {
    guard.recheck()?;
    require(
        schedule_allowed
            || files::optional_relative(guard.control(), Path::new("backup.enabled"))?.is_none(),
        "disable automatic backup before rotation",
    )?;
    let attempts = control_registry::read_bounded(
        guard,
        "backup-attempts",
        128,
        8192,
        crate::backup_attempt::validate,
    )?;
    let boot = crate::operation::boot_id()?;
    require(
        !attempts.values().any(|row| {
            crate::backup_attempt::blocks_live(row, &boot, Path::new(crate::operation::CONTROL))
        }),
        "running automatic backup requires review before rotation",
    )?;
    let credentials = control_registry::read_bounded(
        guard,
        "backup-credentials",
        crate::backup_credential_record::CAPACITY,
        crate::backup_credential_record::LIMIT,
        crate::backup_credential_record::validate,
    )?;
    require(
        credentials.values().all(|row| row["phase"] == "complete"),
        "uncertain credential enrollment requires review before rotation",
    )?;
    Ok(
        value!({"attempts":attempts,"credentials":credentials,"automatic_backup_enabled":schedule_allowed}),
    )
}
pub(crate) struct Quiet {
    value: Value,
    schedule_allowed: bool,
    control_epoch: files::FileIdentity,
    parents: Vec<(&'static str, Option<(File, files::FileIdentity)>)>,
    documents: Vec<crate::control_record::Observation>,
}
impl Quiet {
    pub(crate) fn observe(guard: &Guard) -> Result<Self> {
        Self::observe_with(guard, false)
    }
    /// Retention may run while automatic backup stays enabled (it runs right
    /// after a backup, under the same operation lock); every other quiescence
    /// condition is unchanged.
    pub(crate) fn observe_with(guard: &Guard, schedule_allowed: bool) -> Result<Self> {
        let value = quiescent(guard, schedule_allowed)?;
        let control_epoch = files::identity(&guard.control().metadata()?);
        let mut parents = Vec::new();
        let mut documents = Vec::new();
        for (folder, key, limit) in [
            ("backup-attempts", "attempts", 8192),
            (
                "backup-credentials",
                "credentials",
                crate::backup_credential_record::LIMIT,
            ),
        ] {
            let parent =
                files::optional_directory_relative(guard.control(), Path::new(folder), Some(0))?;
            if let Some(parent) = &parent {
                require(
                    shape(parent)?.2 & 0o7777 == 0o700
                        && mount_identity::id(parent.as_fd(), true)? == guard.control_mount_id(),
                    "rotation quiescence original directory differs",
                )?;
                for (id, row) in value[key].as_object().unwrap() {
                    let document = crate::control_record::Observation::open(
                        parent,
                        Path::new(&format!("{id}.json")),
                        limit,
                        guard.control_mount_id(),
                    )?;
                    require(
                        document.value()? == row,
                        "quiescence row changed while retaining original",
                    )?;
                    documents.push(document);
                }
            }
            let parent = parent
                .map(|file| {
                    Ok::<_, enzimos_platform::Error>((
                        file.try_clone()?,
                        files::identity(&file.metadata()?),
                    ))
                })
                .transpose()?;
            parents.push((folder, parent));
        }
        let original = Self {
            value,
            schedule_allowed,
            control_epoch,
            parents,
            documents,
        };
        original.recheck(guard)?;
        Ok(original)
    }
    pub(crate) fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        require(
            files::identity(&guard.control().metadata()?) == self.control_epoch,
            "original quiescence control epoch changed",
        )?;
        for document in &self.documents {
            document.recheck()?;
        }
        for (folder, original) in &self.parents {
            let named =
                files::optional_directory_relative(guard.control(), Path::new(folder), Some(0))?;
            match (original, named) {
                (None, None) => {}
                (Some((held, epoch)), Some(named)) => require(
                    files::identity(&held.metadata()?) == *epoch
                        && files::identity(&named.metadata()?) == *epoch
                        && mount_identity::id(held.as_fd(), true)? == guard.control_mount_id()
                        && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
                    "original quiescence directory replaced/changed",
                )?,
                _ => {
                    return Err(enzimos_platform::Error(
                        "quiescence registry appeared/disappeared".into(),
                    ));
                }
            }
        }
        require(
            quiescent(guard, self.schedule_allowed)? == self.value,
            "rotation quiescence changed",
        )
    }
}
pub struct Context<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    mount: Mount<'a>,
    parent: File,
    shape: Shape,
    record: Retained,
    id: String,
    rows_sha256: String,
    repositories: [Option<Repository>; 3],
    credentials: [Option<Credential>; 3],
    pin: crate::control_record::Observation,
    image: crate::backup_restic_runtime::Image,
    layouts: [Option<crate::backup_rotation_layout::Layout>; 3],
    quiet: Quiet,
    other_records: Vec<crate::control_record::Observation>,
    parent_epoch: files::FileIdentity,
}
impl<'a> Context<'a> {
    /// Observe an existing nonterminal journal under the original operation lock.
    /// No directory, receipt, scratch or repository is created by this admission.
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        configuration: &'a Configuration,
        id: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::safe_id(id)?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        let rows = control_registry::read_bounded(
            guard,
            FOLDER,
            codec::MAXIMUM,
            codec::LIMIT,
            codec::validate,
        )?;
        let row = rows
            .get(id)
            .ok_or_else(|| enzimos_platform::Error("rotation not found".into()))?;
        require(
            !matches!(row["phase"].as_str(), Some("complete" | "abandoned")),
            "rotation already finished; no replay",
        )?;
        require(
            rows.iter().all(|(name, row)| {
                name == id || matches!(row["phase"].as_str(), Some("complete" | "abandoned"))
            }),
            "other unfinished rotation requires review",
        )?;
        let parent = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            mount_identity::id(parent.as_fd(), true)? == guard.control_mount_id(),
            "rotation journal crossed control mount",
        )?;
        let record = Retained::open(
            &parent,
            Path::new(&format!("{id}.json")),
            codec::LIMIT,
            guard.control_mount_id(),
        )?;
        require(
            record.value()? == row,
            "rotation selected record changed during admission",
        )?;
        require(
            row["repository_binding"]["filesystem_uuid"]
                == configuration.value()["destination_uuid"],
            "rotation journal bound to foreign destination filesystem",
        )?;
        let mount = Mount::observe(guard, configuration)?;
        let repositories = [
            Repository::observe(&mount, RepositoryName::Current)?,
            Repository::observe(&mount, RepositoryName::Stage)?,
            Repository::observe(&mount, RepositoryName::Retired)?,
        ];
        let mut layouts = [None, None, None];
        for (i, repository) in repositories.iter().enumerate() {
            if let Some(repository) = repository {
                let partial = (i == 1 && row["phase"] == "prepared")
                    || (i == 2 && row["phase"] == "discarding");
                layouts[i] = Some(crate::backup_rotation_layout::Layout::capture(
                    repository.descriptor(&mount)?,
                    0,
                    partial,
                )?);
            }
        }
        let credentials = [
            Credential::observe(guard, CredentialName::Current)?,
            Credential::observe(guard, CredentialName::Input)?,
            Credential::observe(guard, CredentialName::Retired)?,
        ];
        let pin = crate::control_record::Observation::open(
            guard.control(),
            Path::new("backup-destination.json"),
            codec::LIMIT,
            guard.control_mount_id(),
        )?;
        let mut other_records = Vec::new();
        for (name, row) in &rows {
            if name == id {
                continue;
            }
            let observation = crate::control_record::Observation::open(
                &parent,
                Path::new(&format!("{name}.json")),
                codec::LIMIT,
                guard.control_mount_id(),
            )?;
            require(
                observation.value()? == row,
                "rotation registry row changed while retaining",
            )?;
            other_records.push(observation);
        }
        let parent_epoch = files::identity(&parent.metadata()?);
        let quiet = Quiet::observe(guard)?;
        let context = Self {
            guard,
            lock,
            mount,
            shape: shape(&parent)?,
            parent,
            record,
            id: id.into(),
            rows_sha256: json::fingerprint(&serde_json::to_value(&rows)?)?,
            repositories,
            credentials,
            pin,
            image: crate::backup_restic_runtime::Image::open()?,
            layouts,
            quiet,
            other_records,
            parent_epoch,
        };
        context.recheck(authorize)?;
        Ok(context)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.mount.recheck()?;
        self.record.recheck()?;
        for record in &self.other_records {
            record.recheck()?;
        }
        require(
            files::identity(&self.parent.metadata()?) == self.parent_epoch,
            "original rotation registry directory epoch changed",
        )?;
        self.quiet.recheck(self.guard)?;
        self.pin.recheck()?;
        for layout in self.layouts.iter().flatten() {
            layout.recheck()?;
        }
        json::fields(
            self.pin.value()?,
            "schema filesystem_uuid fsroot repository repository_sha256",
        )?;
        require(
            self.pin.value()?["schema"] == 1
                && self.pin.value()?["fsroot"] == "/"
                && self.pin.value()?["repository"] == crate::backup_configuration::REPOSITORY
                && self.pin.value()?["filesystem_uuid"]
                    == self.record.value()?["repository_binding"]["filesystem_uuid"],
            "rotation original destination pin changed or foreign",
        )?;
        for (object, name) in self.repositories.iter().zip([
            RepositoryName::Current,
            RepositoryName::Stage,
            RepositoryName::Retired,
        ]) {
            if let Some(object) = object {
                object.recheck(&self.mount)?;
            } else {
                require(
                    Repository::observe(&self.mount, name)?.is_none(),
                    "rotation repository appeared at original absent name",
                )?;
            }
        }
        for (object, name) in self.credentials.iter().zip([
            CredentialName::Current,
            CredentialName::Input,
            CredentialName::Retired,
        ]) {
            if let Some(object) = object {
                object.recheck(self.guard)?;
            } else {
                require(
                    Credential::observe(self.guard, name)?.is_none(),
                    "rotation credential appeared at original absent name",
                )?;
            }
        }
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        let rows = control_registry::read_bounded(
            self.guard,
            FOLDER,
            codec::MAXIMUM,
            codec::LIMIT,
            codec::validate,
        )?;
        require(
            shape(&self.parent)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == self.guard.control_mount_id()
                && json::fingerprint(&serde_json::to_value(&rows)?)? == self.rows_sha256
                && rows.get(&self.id) == Some(self.record.value()?),
            "original rotation records replaced/drifted; no adoption/replay",
        )?;
        authorize()
    }
    /// Authenticated inventories are observations only. Only fixed key/list and
    /// snapshot queries run, using the original actual retained descriptions.
    pub(crate) fn authenticated_inventory(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        use enzimos_platform::local_restic::{self, RotationTask};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        self.recheck(authorize)?;
        let record = self.record.value()?;
        require(
            record["phase"] != "prepared",
            "prepared rotation requires explicit abandon, not inventory admission",
        )?;
        let find_repo = |kind| -> Result<Option<&Repository>> {
            for object in self.repositories.iter().flatten() {
                if object.classify(&self.mount, record)? == kind {
                    return Ok(Some(object));
                }
            }
            Ok(None)
        };
        let find_credential = |kind| -> Result<Option<&Credential>> {
            for object in self.credentials.iter().flatten() {
                if object.classify(self.guard, record)? == kind {
                    return Ok(Some(object));
                }
            }
            Ok(None)
        };
        let scratch = files::directory(Path::new("/run/enzimos"), Some(0))?;
        let epoch = files::identity(&scratch.metadata()?);
        let mount = mount_identity::id(scratch.as_fd(), true)?;
        let mut boundary = || {
            self.recheck(authorize)?;
            self.image.evidence()?;
            let named = files::directory(Path::new("/run/enzimos"), Some(0))?;
            require(
                files::identity(&scratch.metadata()?) == epoch
                    && files::identity(&named.metadata()?) == epoch
                    && mount_identity::id(scratch.as_fd(), true)? == mount
                    && mount_identity::id(named.as_fd(), true)? == mount,
                "original rotation query scratch replaced/changed",
            )
        };
        let mut query = |repository: &Repository, credential: &Credential, task| {
            boundary()?;
            let output = local_restic::rotation_read(
                task,
                self.image.descriptor()?,
                repository.descriptor(&self.mount)?,
                credential.descriptor(self.guard)?,
                &scratch,
                &mut boundary,
            )?;
            boundary()?;
            Ok::<_, enzimos_platform::Error>(output)
        };
        let new = find_repo("new")?
            .ok_or_else(|| enzimos_platform::Error("original new repository unavailable".into()))?;
        let new_credential = find_credential("new")?
            .ok_or_else(|| enzimos_platform::Error("original new credential unavailable".into()))?;
        let keys = query(new, new_credential, RotationTask::Keys)?;
        let keys = crate::backup_restic_result::keys(keys.status.code(), &keys.stdout)?;
        require(
            keys.len() == 1 && keys.values().all(|current| *current),
            "new rotation repository key set changed",
        )?;
        let points = query(new, new_credential, RotationTask::Points)?;
        let points = crate::backup_rotation_record::points(points.status.code(), &points.stdout)?;
        let copies = record["copies"]
            .as_object()
            .ok_or_else(|| enzimos_platform::Error("copied rotation mapping unavailable".into()))?;
        require(
            copies
                .values()
                .all(|target| points.contains_key(target.as_str().unwrap())),
            "new repository lost copied points",
        )?;
        let old_credential = find_credential("old")?;
        let old_points = if let (Some(old), Some(credential)) = (find_repo("old")?, old_credential)
        {
            let output = query(old, credential, RotationTask::Points)?;
            serde_json::to_value(crate::backup_rotation_record::points(
                output.status.code(),
                &output.stdout,
            )?)?
        } else {
            Value::Null
        };
        let refused = if let Some(credential) = old_credential {
            let output = query(new, credential, RotationTask::Keys)?;
            require(
                output.status.code() == Some(12),
                "retired password refusal unknown or current repository remains accessible",
            )?;
            true
        } else {
            false
        };
        boundary()?;
        Ok(
            value!({"new_keys":keys,"new_points":points,"old_points":old_points,
            "old_password_refused_by_new":refused,"execution_authorized":false}),
        )
    }
    fn ambient(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.mount.recheck()?;
        self.record.recheck()?;
        self.pin.recheck()?;
        self.quiet.recheck(self.guard)?;
        for record in &self.other_records {
            record.recheck()?;
        }
        require(
            files::identity(&self.parent.metadata()?) == self.parent_epoch,
            "original rotation registry epoch changed",
        )?;
        let rows = control_registry::read_bounded(
            self.guard,
            FOLDER,
            codec::MAXIMUM,
            codec::LIMIT,
            codec::validate,
        )?;
        require(
            json::fingerprint(&serde_json::to_value(&rows)?)? == self.rows_sha256
                && rows.get(&self.id) == Some(self.record.value()?),
            "original rotation journal changed during known removal",
        )?;
        for object in self.repositories.iter().flatten() {
            object.recheck(&self.mount)?;
        }
        for object in self.credentials.iter().flatten() {
            object.recheck(self.guard)?;
        }
        authorize()
    }
    /// Explicit reviewed abandonment removes only the original staged objects.
    /// Current repository and credential remain retained throughout the action.
    pub fn abandon(
        mut self,
        review_sha256: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::sha(review_sha256)?;
        let review = self.review(authorize)?;
        require(
            review["review_sha256"] == review_sha256 && review["next_action"] == "abandon",
            "rotation review changed or requires another action",
        )?;
        self.recheck(authorize)?;
        let original = self.repositories[1].take();
        let layout = self.layouts[1].take();
        let removed = match (original, layout) {
            (None, None) => None,
            (Some(original), Some(layout)) => Some(original.remove_original(
                &self.mount,
                layout,
                &mut || self.ambient(authorize),
            )?),
            _ => {
                return Err(enzimos_platform::Error(
                    "original staged removal actors differ".into(),
                ));
            }
        };
        self.recheck(authorize)?;
        if let Some(removed) = &removed {
            removed.recheck(&self.mount)?;
        }
        self.phase("abandoned", authorize)?;
        if let Some(removed) = &removed {
            removed.recheck(&self.mount)?;
        }
        self.recheck(authorize)?;
        Ok(
            value!({"status":"rotation-abandoned","rotation":self.id,"current_repository_changed":false}),
        )
    }
    /// Durable discarding precedes consuming the original retired repository and
    /// credential. Removed actors stay retained through actual receipt completion.
    pub fn discard(
        mut self,
        review_sha256: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::sha(review_sha256)?;
        let review = self.review(authorize)?;
        require(
            review["review_sha256"] == review_sha256 && review["next_action"] == "discard",
            "rotation review changed or requires another action",
        )?;
        if self.record.value()?["phase"] == "switched" {
            self.phase("discarding", authorize)?;
        }
        self.recheck(authorize)?;
        let original = self.repositories[2].take();
        let layout = self.layouts[2].take();
        let removed_repository = match (original, layout) {
            (None, None) => None,
            (Some(original), Some(layout)) => Some(original.remove_original(
                &self.mount,
                layout,
                &mut || self.ambient(authorize),
            )?),
            _ => {
                return Err(enzimos_platform::Error(
                    "original retired removal actors differ".into(),
                ));
            }
        };
        self.recheck(authorize)?;
        let removed_credential = if let Some(original) = self.credentials[2].take() {
            Some(original.unlink_original(self.guard, &mut || self.ambient(authorize))?)
        } else {
            None
        };
        self.recheck(authorize)?;
        self.authenticated_inventory(authorize)?;
        if let Some(removed) = &removed_repository {
            removed.recheck(&self.mount)?;
        }
        if let Some(removed) = &removed_credential {
            removed.recheck(self.guard)?;
        }
        self.phase("complete", authorize)?;
        if let Some(removed) = &removed_repository {
            removed.recheck(&self.mount)?;
        }
        if let Some(removed) = &removed_credential {
            removed.recheck(self.guard)?;
        }
        self.recheck(authorize)?;
        Ok(
            value!({"status":"rotation-complete","rotation":self.id,"retired_repository_removed":true,
            "retired_password_removed":true,"external_copies_revoked":false,"media_remanence_addressed":false}),
        )
    }
    fn phase(&mut self, next: &str, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck(authorize)?;
        let before = self.record.value()?.clone();
        require(
            matches!(
                (before["phase"].as_str(), next),
                (Some("copied"), "switching")
                    | (Some("switching"), "switched")
                    | (Some("switched"), "discarding")
                    | (Some("discarding"), "complete")
                    | (Some("prepared" | "copied" | "switching"), "abandoned")
            ),
            "rotation phase transition refused",
        )?;
        let mut rows = control_registry::read_bounded(
            self.guard,
            FOLDER,
            codec::MAXIMUM,
            codec::LIMIT,
            codec::validate,
        )?;
        let parent_before = files::identity(&self.parent.metadata()?);
        let mut record = before;
        record["phase"] = value!(next);
        codec::validate(&record, &self.id)?;
        self.record.replace(&record)?;
        let after = files::identity(&self.parent.metadata()?);
        crate::backup_rotation_epoch::parent_changed(parent_before, after, false)?;
        self.parent_epoch = after;
        rows.insert(self.id.clone(), record);
        self.rows_sha256 = json::fingerprint(&serde_json::to_value(&rows)?)?;
        self.recheck(authorize)
    }
    /// Consumes the actual original review context; no journal bytes can call a
    /// switch. The original switching receipt is durable before the first rename.
    pub fn switch(
        mut self,
        review_sha256: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::sha(review_sha256)?;
        let review = self.review(authorize)?;
        require(
            review["review_sha256"] == review_sha256 && review["next_action"] == "switch",
            "rotation review changed or requires another action",
        )?;
        if self.record.value()?["phase"] == "copied" {
            self.phase("switching", authorize)?;
        }
        let start = review["boundary"].as_u64().unwrap() as usize;
        for index in start..5 {
            self.recheck(authorize)?;
            match index {
                0 | 1 => {
                    let (from, to, target) = if index == 0 {
                        (0, 2, RepositoryName::Retired)
                    } else {
                        (1, 0, RepositoryName::Current)
                    };
                    require(
                        self.repositories[to].is_none() && self.layouts[to].is_none(),
                        "original repository target is not vacant",
                    )?;
                    let original = self.repositories[from].take().ok_or_else(|| {
                        enzimos_platform::Error("original repository source missing".into())
                    })?;
                    let mut layout = self.layouts[from].take().ok_or_else(|| {
                        enzimos_platform::Error("original repository layout missing".into())
                    })?;
                    let renamed = original.rename(&self.mount, target, authorize)?;
                    layout.renamed_root()?;
                    self.repositories[to] = Some(renamed);
                    self.layouts[to] = Some(layout);
                }
                2 | 3 => {
                    let (from, to, target) = if index == 2 {
                        (0, 2, CredentialName::Retired)
                    } else {
                        (1, 0, CredentialName::Current)
                    };
                    require(
                        self.credentials[to].is_none(),
                        "original credential target is not vacant",
                    )?;
                    let original = self.credentials[from].take().ok_or_else(|| {
                        enzimos_platform::Error("original credential source missing".into())
                    })?;
                    self.credentials[to] = Some(original.rename(self.guard, target, authorize)?);
                }
                4 => {
                    let mut pin = self.pin.value()?.clone();
                    require(
                        pin["repository_sha256"]
                            == self.record.value()?["repository_binding"]["repository_sha256"],
                        "original destination pin changed",
                    )?;
                    pin["repository_sha256"] =
                        self.record.value()?["new_repository_sha256"].clone();
                    let before = files::identity(&self.guard.control().metadata()?);
                    self.pin.replace_original(&pin)?;
                    let after = files::identity(&self.guard.control().metadata()?);
                    crate::backup_rotation_epoch::parent_changed(before, after, false)?;
                    self.quiet.control_epoch = after;
                }
                _ => unreachable!(),
            }
            self.recheck(authorize)?;
            require(
                self.evidence(authorize)?["exact_switch_boundary"] == index + 1,
                "original rotation boundary not reached",
            )?;
        }
        self.authenticated_inventory(authorize)?;
        self.phase("switched", authorize)?;
        let result = value!({"status":"rotation-switched","rotation":self.id,"points":self.record.value()?["copies"].as_object().unwrap().len(),
            "retired_repository_kept":true,"automatic_backup_reapproval_required":true,"old_access_revoked":false});
        self.recheck(authorize)?;
        Ok(result)
    }
    /// Exact legacy review material, backed by original retained objects and
    /// authenticated fixed queries. This grants no switch/discard authority.
    pub fn review(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let observed = self.evidence(authorize)?;
        let record = self.record.value()?;
        let phase = record["phase"].as_str().unwrap();
        let state = &observed["actual_boundary_state"];
        let mut material = value!({"record":record,"review_boot":crate::operation::boot_id()?});
        let action = match phase {
            "prepared" => {
                require(
                    state[0] == "old" && state[3] == "old" && state[6] == "old",
                    "current repository changed after interrupted rotation copy",
                )?;
                material["stage"] = self.repositories[1]
                    .as_ref()
                    .map(|repository| repository.identity(&self.mount))
                    .transpose()?
                    .unwrap_or(Value::Null);
                "abandon"
            }
            "copied" | "switching" => {
                let index = observed["exact_switch_boundary"].as_u64().ok_or_else(|| {
                    enzimos_platform::Error("rotation state outside exact switch boundaries".into())
                })?;
                require(
                    phase == "switching" || index == 0,
                    "copied rotation moved without switch receipt",
                )?;
                material["boundary"] = value!(index);
                if index == 0 {
                    let inventory = self.authenticated_inventory(authorize)?;
                    let old = inventory["old_points"].as_object().ok_or_else(|| {
                        enzimos_platform::Error("original old repository inventory missing".into())
                    })?;
                    if value!(old.keys().collect::<Vec<_>>()) != record["old_points"] {
                        "abandon"
                    } else {
                        "switch"
                    }
                } else {
                    "switch"
                }
            }
            "switched" => {
                require(
                    observed["exact_switch_boundary"] == 5,
                    "switched rotation state drifted",
                )?;
                let inventory = self.authenticated_inventory(authorize)?;
                let old = inventory["old_points"].as_object().ok_or_else(|| {
                    enzimos_platform::Error("retired repository inventory missing".into())
                })?;
                require(
                    value!(old.keys().collect::<Vec<_>>()) == record["old_points"],
                    "retired repository points changed",
                )?;
                material["retired"] = self.repositories[2]
                    .as_ref()
                    .unwrap()
                    .identity(&self.mount)?;
                "discard"
            }
            "discarding" => {
                require(
                    state[0] == "new"
                        && state[1].is_null()
                        && state[3] == "new"
                        && state[4].is_null()
                        && state[6] == "new"
                        && (state[2].is_null() || state[2] == "old")
                        && (state[5].is_null() || state[5] == "old"),
                    "discarding rotation original objects drifted",
                )?;
                self.authenticated_inventory(authorize)?;
                material["retired_remaining"] = value!(self.repositories[2].is_some());
                "discard"
            }
            _ => {
                return Err(enzimos_platform::Error(
                    "rotation finished; no replay".into(),
                ));
            }
        };
        let review = value!({"status":"rotation-reviewed","rotation":self.id,"phase":phase,"next_action":action,
            "boundary":material.get("boundary").cloned().unwrap_or(Value::Null),"review_sha256":json::fingerprint(&material)?,"automatic_replay":false});
        self.recheck(authorize)?;
        Ok(review)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let root = self.mount.descriptor()?;
        require(
            mount_identity::id(root.as_fd(), true)? == self.mount.mount_id(),
            "original rotation mount descriptor differs",
        )?;
        let record = self.record.value()?;
        let mut state = [None; 7];
        for (i, object) in self.repositories.iter().enumerate() {
            state[i] = object
                .as_ref()
                .map(|o| o.classify(&self.mount, record))
                .transpose()?;
        }
        for (i, object) in self.credentials.iter().enumerate() {
            state[i + 3] = object
                .as_ref()
                .map(|o| o.classify(self.guard, record))
                .transpose()?;
        }
        let pin = &self.pin.value()?["repository_sha256"];
        state[6] = Some(
            if *pin == record["repository_binding"]["repository_sha256"] {
                "old"
            } else if *pin == record["new_repository_sha256"] {
                "new"
            } else {
                "foreign"
            },
        );
        Ok(
            value!({"record":self.record.value()?,"registry_sha256":self.rows_sha256,
            "review_boot":crate::operation::boot_id()?,"destination":self.mount.evidence()?,
            "quiescence":{"state":self.quiet.value,"records":self.quiet.documents.iter().map(super::control_record::Observation::evidence).collect::<Result<Vec<_>>>()?},
            "original_objects":{"repositories":self.repositories.iter().map(|o|o.as_ref().map(|r|r.evidence(&self.mount)).transpose()).collect::<Result<Vec<_>>>()?,
            "credentials":self.credentials.iter().map(|o|o.as_ref().map(|r|r.evidence(self.guard)).transpose()).collect::<Result<Vec<_>>>()?,
            "layouts":self.layouts.iter().map(|o|o.as_ref().map(super::backup_rotation_layout::Layout::evidence).transpose()).collect::<Result<Vec<_>>>()?},
            "actual_boundary_state":state,"exact_switch_boundary":codec::boundary(&state).ok(),"execution_authorized":false,"switched":false,"old_access_revoked":false}),
        )
    }
}
