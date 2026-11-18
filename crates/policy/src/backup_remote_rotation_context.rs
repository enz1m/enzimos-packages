// SPDX-License-Identifier: MIT
//! Original Root remote rotation review. No JSON row becomes a mutation actor.
use crate::{
    backup_remote_rotation_inputs::{Inventory, Role},
    backup_remote_rotation_journal::{Journal, Role as JournalRole},
    backup_restic_runtime::Image,
    backup_transfer_caller::Caller,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, json, require};
use serde_json::{Value, json as value};
use std::path::Path;
const BOUNDARIES: [[Option<&str>; 7]; 7] = [
    [
        Some("old"),
        Some("new"),
        None,
        Some("old"),
        Some("new"),
        None,
        Some("old"),
    ],
    [
        None,
        Some("new"),
        Some("old"),
        Some("old"),
        Some("new"),
        None,
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        Some("old"),
        Some("new"),
        None,
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        None,
        Some("new"),
        Some("old"),
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        Some("new"),
        None,
        Some("old"),
        Some("old"),
    ],
    [
        Some("new"),
        None,
        Some("old"),
        Some("new"),
        None,
        Some("old"),
        Some("new"),
    ],
    [
        Some("new"),
        None,
        None,
        Some("new"),
        None,
        None,
        Some("new"),
    ],
];
pub(crate) fn legacy_boundaries() -> &'static [[Option<&'static str>; 7]; 7] {
    &BOUNDARIES
}
fn boundary(state: &[Option<&str>; 7]) -> Result<usize> {
    BOUNDARIES.iter().position(|s| s == state).ok_or_else(|| {
        enzimos_platform::Error(
            "remote rotation outside exact recorded boundary; manual review required".into(),
        )
    })
}
fn next(phase: &str, state: &[Option<&str>; 7]) -> Result<(Option<usize>, Option<&'static str>)> {
    match phase {
        "initializing" | "copying" => {
            require(
                boundary(state)? == 0,
                "uncopied remote rotation moved material",
            )?;
            Ok((None, Some("abandon")))
        }
        "copied" => {
            require(
                boundary(state)? == 0,
                "copied remote rotation moved without switching intent",
            )?;
            Ok((Some(0), Some("switch")))
        }
        "switching" => {
            let n = boundary(state)?;
            require(n <= 5, "switching remote rotation discarded material")?;
            Ok((Some(n), Some("switch")))
        }
        "switched" => {
            require(
                boundary(state)? == 5,
                "switched remote rotation material differs",
            )?;
            Ok((Some(5), Some("discard")))
        }
        "complete" => {
            require(
                boundary(state)? == 6,
                "completed remote rotation retains old local material",
            )?;
            Ok((None, None))
        }
        "abandoned" => Ok((None, None)),
        "discarding"=>Err(enzimos_platform::Error("interrupted remote discard requires manual review; original execution actors unavailable".into())),
        _ => Err(enzimos_platform::Error("remote rotation phase".into())),
    }
}
pub struct Context<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    inventory: Inventory,
    record: Journal<'a>,
    pin: Journal<'a>,
    caller: Caller,
    restic: Image,
}
impl<'a> Context<'a> {
    pub fn observe(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        let record = Journal::observe(guard, lock, JournalRole::Rotation)?;
        let pin = Journal::observe(guard, lock, JournalRole::Pin)?;
        let this = Self {
            guard,
            lock,
            inventory: Inventory::observe(guard)?,
            record,
            pin,
            caller: Caller::current()?,
            restic: Image::open()?,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        self.guard.recheck()?;
        self.lock.recheck()?;
        self.caller.recheck()?;
        self.restic.descriptor()?;
        self.inventory.recheck(self.guard)?;
        self.record.recheck()?;
        self.pin.recheck()?;
        authorize()
    }
    fn state(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<[Option<&'static str>; 7]> {
        self.state_record(self.record.value()?, authorize)
    }
    fn state_record(
        &self,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<[Option<&'static str>; 7]> {
        self.recheck(authorize)?;
        let slots = self.inventory.state(record, self.guard)?;
        let mut state = [None; 7];
        state[..6].copy_from_slice(&slots);
        let pin = self.pin.value()?;
        state[6] = Some(if pin == &record["old_identity"] {
            "old"
        } else if pin == &record["new_identity"] {
            "new"
        } else {
            "foreign"
        });
        // Rotation never reads the share password; it must stay present and
        // distinct from every repository password role.
        let share = self
            .inventory
            .object(Role::SharePassword, self.guard)?
            .ok_or_else(|| {
                enzimos_platform::Error("original remote share password missing".into())
            })?;
        for role in [
            Role::CurrentPassword,
            Role::StagedPassword,
            Role::RetiredPassword,
        ] {
            if let Some(object) = self.inventory.object(role, self.guard)? {
                share.require_distinct(object, self.guard)?;
            }
        }
        let mut old = None;
        let mut new = None;
        for role in [
            Role::CurrentConfiguration,
            Role::StagedConfiguration,
            Role::RetiredConfiguration,
        ] {
            if let Some(object) = self.inventory.object(role, self.guard)? {
                let config = object.configuration(self.guard)?;
                let sha = object.public_sha256(self.guard)?;
                if record["old_config_sha256"] == sha {
                    old = Some(config);
                } else if record["new_config_sha256"] == sha {
                    new = Some(config);
                } else {
                    return Err(enzimos_platform::Error(
                        "foreign remote rotation configuration".into(),
                    ));
                }
            }
        }
        require(
            old.is_some() || new.is_some(),
            "remote rotation has no retained configuration",
        )?;
        if let (Some(old), Some(new)) = (old, new) {
            crate::backup_remote_rotation_inputs::staged_endpoint(old, new)?;
        }
        self.recheck(authorize)?;
        Ok(state)
    }
    pub fn review(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        let state = self.state(authorize)?;
        let record = self.record.value()?;
        let (step, action) = next(record["phase"].as_str().unwrap(), &state)?;
        let mut result = value!({"phase":record["phase"],"boundary":step,"next_action":action,"journal_sha256":json::fingerprint(record)?});
        result["review_sha256"] = value!(json::fingerprint(&result)?);
        self.recheck(authorize)?;
        Ok(result)
    }
    /// Fresh actual vendor observations over the original descriptions. This
    /// result is review data; it cannot construct a switch/discard actor.
    pub fn authenticated_inventory(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.review(authorize)?;
        self.authenticated_record(self.record.value()?, authorize)
    }
    fn authenticated_record(
        &self,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        use enzimos_platform::remote_restic::{self, Task};
        use std::os::{fd::AsFd, unix::fs::MetadataExt};
        self.recheck(authorize)?;
        let state = self.state_record(record, authorize)?;
        next(record["phase"].as_str().unwrap(), &state)?;
        let early = matches!(record["phase"].as_str(), Some("initializing" | "copying"));
        if !early {
            require(
                !record["new_identity"].is_null() && !record["points"].is_null(),
                "remote rotation has no completed copy identity/map",
            )?;
        }
        let mut old_config = None;
        let mut new_config = None;
        let mut old_password = None;
        let mut new_password = None;
        for role in [
            Role::CurrentConfiguration,
            Role::StagedConfiguration,
            Role::RetiredConfiguration,
        ] {
            if let Some(object) = self.inventory.object(role, self.guard)? {
                let sha = object.public_sha256(self.guard)?;
                if record["old_config_sha256"] == sha {
                    old_config = Some(object);
                } else if record["new_config_sha256"] == sha {
                    new_config = Some(object);
                }
            }
        }
        for role in [
            Role::CurrentPassword,
            Role::StagedPassword,
            Role::RetiredPassword,
        ] {
            if let Some(object) = self.inventory.object(role, self.guard)? {
                let identity = object.credential_identity(self.guard)?;
                if identity == &record["old_password_identity"] {
                    old_password = Some(object);
                } else if identity == &record["new_password_identity"] {
                    new_password = Some(object);
                }
            }
        }
        let new_config = new_config.ok_or_else(|| {
            enzimos_platform::Error("original new remote configuration unavailable".into())
        })?;
        let new_password = new_password.ok_or_else(|| {
            enzimos_platform::Error("original new remote credential unavailable".into())
        })?;
        let share_password = self
            .inventory
            .object(Role::SharePassword, self.guard)?
            .ok_or_else(|| {
                enzimos_platform::Error("original remote share password unavailable".into())
            })?;
        // Rotation keeps the share and account, so one attachment serves the
        // old and the new repository folder.
        let (attachment, _) = crate::backup_restic_runtime::remote_share(
            new_config.configuration(self.guard)?,
            share_password.descriptor(self.guard)?,
        )?;
        let scratch = files::directory(Path::new("/run/enzimos"), Some(0))?;
        let epoch = files::identity(&scratch.metadata()?);
        let mount = enzimos_platform::mount_identity::id(scratch.as_fd(), true)?;
        let mut boundary = || {
            self.recheck(authorize)?;
            attachment.recheck()?;
            let named = files::directory(Path::new("/run/enzimos"), Some(0))?;
            let held = scratch.metadata()?;
            let current = named.metadata()?;
            require(
                (
                    held.dev(),
                    held.ino(),
                    held.mode(),
                    held.uid(),
                    held.gid(),
                    held.nlink(),
                ) == (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9, epoch.10)
                    && (
                        current.dev(),
                        current.ino(),
                        current.mode(),
                        current.uid(),
                        current.gid(),
                        current.nlink(),
                    ) == (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9, epoch.10)
                    && enzimos_platform::mount_identity::id(scratch.as_fd(), true)? == mount
                    && enzimos_platform::mount_identity::id(named.as_fd(), true)? == mount,
                "original remote rotation scratch changed/replaced/covered",
            )
        };
        let mut query = |configuration: &crate::backup_remote_rotation_inputs::Object,
                         password: &crate::backup_remote_rotation_inputs::Object,
                         task| {
            boundary()?;
            let endpoint =
                crate::backup_remote_endpoint::endpoint(configuration.configuration(self.guard)?)?;
            let out = remote_restic::rotation_read(
                &attachment,
                &endpoint,
                task,
                &"0".repeat(64),
                self.restic.descriptor()?,
                password.descriptor(self.guard)?,
                &scratch,
                &mut boundary,
            )?;
            boundary()?;
            Ok::<_, enzimos_platform::Error>(out)
        };
        if early {
            // An interrupted initialization/copy has no complete new copy proof.
            // Authenticate the original repository and prove the staged credential
            // cannot unlock it; publication only enables the closed abandon action.
            let old_config = old_config.ok_or_else(|| {
                enzimos_platform::Error("original old remote configuration unavailable".into())
            })?;
            let old_password = old_password.ok_or_else(|| {
                enzimos_platform::Error("original old remote credential unavailable".into())
            })?;
            let first = query(old_config, old_password, Task::RemoteIdentity)?;
            crate::backup_remote_observation::identity_data(
                first.status.code(),
                &first.stdout,
                &record["old_identity"],
            )?;
            let points = query(old_config, old_password, Task::RemoteInventory)?;
            require(
                points.status.code() == Some(0),
                "original early remote inventory uncertain",
            )?;
            let points = json::decode(&points.stdout, crate::backup_remote_points::LIMIT)?;
            crate::backup_remote_points::inventory(&points)?;
            let refusal = query(old_config, new_password, Task::RemoteKeys)?;
            require(
                refusal.status.code() == Some(12),
                "staged credential refusal unknown or still unlocks old repository",
            )?;
            let last = query(old_config, old_password, Task::RemoteIdentity)?;
            crate::backup_remote_observation::identity_data(
                last.status.code(),
                &last.stdout,
                &record["old_identity"],
            )?;
            boundary()?;
            return Ok(
                value!({"old_points":points,"staged_password_refused_by_old":true,
                "new_repository_verified":false,"completed_copy_verified":false,
                "credential_bytes_read":false,"execution_authorized":false}),
            );
        }
        let first = query(new_config, new_password, Task::RemoteIdentity)?;
        crate::backup_remote_observation::identity_data(
            first.status.code(),
            &first.stdout,
            &record["new_identity"],
        )?;
        let keys = query(new_config, new_password, Task::RemoteKeys)?;
        let keys = crate::backup_restic_result::keys(keys.status.code(), &keys.stdout)?;
        require(
            keys.len() == 1 && keys.values().all(|key| *key),
            "new remote repository key set changed",
        )?;
        let points = query(new_config, new_password, Task::RemoteInventory)?;
        require(
            points.status.code() == Some(0),
            "new remote rotation inventory failed/uncertain",
        )?;
        let new_points = json::decode(&points.stdout, crate::backup_remote_points::LIMIT)?;
        let new_rows = crate::backup_remote_points::inventory(&new_points)?;
        let copies = record["points"].as_object().unwrap();
        require(
            new_rows.len() == copies.len()
                && copies
                    .values()
                    .all(|id| new_rows.contains_key(id.as_str().unwrap())),
            "new remote rotation copied inventory differs from original map",
        )?;
        let old_points = if let (Some(configuration), Some(password)) = (old_config, old_password) {
            let old = query(configuration, password, Task::RemoteIdentity)?;
            crate::backup_remote_observation::identity_data(
                old.status.code(),
                &old.stdout,
                &record["old_identity"],
            )?;
            let points = query(configuration, password, Task::RemoteInventory)?;
            require(
                points.status.code() == Some(0),
                "old remote rotation inventory failed/uncertain",
            )?;
            let points = json::decode(&points.stdout, crate::backup_remote_points::LIMIT)?;
            let old_rows = crate::backup_remote_points::inventory(&points)?;
            require(
                old_rows.len() == copies.len()
                    && copies.keys().all(|id| old_rows.contains_key(id.as_str())),
                "old remote point inventory differs from original copy map",
            )?;
            crate::backup_remote_points::rotation_copies(&points, &new_points, copies)?;
            let last = query(configuration, password, Task::RemoteIdentity)?;
            crate::backup_remote_observation::identity_data(
                last.status.code(),
                &last.stdout,
                &record["old_identity"],
            )?;
            points
        } else {
            Value::Null
        };
        let old_refused = if let Some(password) = old_password {
            let out = query(new_config, password, Task::RemoteKeys)?;
            require(
                out.status.code() == Some(12),
                "old remote password refusal unknown or new repository remains accessible",
            )?;
            true
        } else {
            false
        };
        let last = query(new_config, new_password, Task::RemoteIdentity)?;
        crate::backup_remote_observation::identity_data(
            last.status.code(),
            &last.stdout,
            &record["new_identity"],
        )?;
        boundary()?;
        Ok(
            value!({"new_keys":keys,"new_points":new_points,"old_points":old_points,"old_password_refused_by_new":old_refused,
            "credential_bytes_read":false,"execution_authorized":false}),
        )
    }
    /// Explicit exact-argv Root entry only. The original legacy journal and
    /// original inputs stay alive across vendor checks and owned v2 publication.
    pub fn migrate_metadata(
        guard: &'a Guard,
        lock: &'a files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        lock.recheck()?;
        let mut context = Self {
            guard,
            lock,
            inventory: Inventory::observe(guard)?,
            record: Journal::observe_legacy(guard, lock)?,
            pin: Journal::observe(guard, lock, JournalRole::Pin)?,
            caller: Caller::metadata_migration_current()?,
            restic: Image::open()?,
        };
        context.recheck(authorize)?;
        if matches!(
            context.record.value()?["phase"].as_str(),
            Some("complete" | "abandoned")
        ) {
            // Terminal legacy rows are retained as diagnostics. In particular a
            // complete row cannot reconstruct the already deleted old credential.
            // This result is neither an authenticated review nor an execution actor.
            let result = value!({"status":"remote-rotation-legacy-terminal-retained",
                "schema":1,"phase":context.record.value()?["phase"],
                "journal_sha256":json::fingerprint(context.record.value()?)?,
                "metadata_mutated":false,"files_moved":false,
                "execution_authorized":false,"policy_credential_bytes_read":false});
            context.recheck(authorize)?;
            return Ok(result);
        }
        require(
            matches!(
                context.record.value()?["phase"].as_str(),
                Some("initializing" | "copying" | "copied" | "switching" | "switched")
            ),
            "explicit metadata migration requires a live nonterminal legacy phase",
        )?;
        let candidate = context.inventory.legacy_candidate(
            context.record.value()?,
            context.pin.value()?,
            guard,
        )?;
        let observed = context.authenticated_record(&candidate, authorize)?;
        let early = matches!(
            candidate["phase"].as_str(),
            Some("initializing" | "copying")
        );
        require(
            !observed["old_points"].is_null()
                && if early {
                    observed["staged_password_refused_by_old"] == true
                } else {
                    observed["old_password_refused_by_new"] == true
                },
            "original legacy credential authentication required before metadata publication",
        )?;
        let caller = &context.caller;
        let restic = &context.restic;
        let pin = &context.pin;
        let inventory = &context.inventory;
        context.record.migrate_metadata(&candidate, &mut || {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            caller.recheck()?;
            restic.descriptor()?;
            pin.recheck()?;
            inventory.recheck(guard)
        })?;
        context.recheck(authorize)?;
        let review = context.review(authorize)?;
        context.recheck(authorize)?;
        Ok(
            value!({"status":"remote-rotation-metadata-migrated","schema":2,"phase":review["phase"],"boundary":review["boundary"],
            "files_moved":false,"old_remote_repository_deleted":false,"policy_credential_bytes_read":false,
            "completed_copy_verified":!early,"new_repository_verified":!early}),
        )
    }
    fn phase(&mut self, next: &str, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck(authorize)?;
        self.record
            .require_scope(self.guard, self.lock, JournalRole::Rotation)?;
        let mut record = self.record.value()?.clone();
        let before = record["phase"].as_str().unwrap();
        require(
            matches!(
                (before, next),
                ("copied", "switching")
                    | ("switching", "switched")
                    | ("switched", "discarding")
                    | ("discarding", "complete")
                    | ("initializing" | "copying", "abandoned")
            ),
            "closed original remote phase transition",
        )?;
        record["phase"] = value!(next);
        let guard = self.guard;
        let lock = self.lock;
        let caller = &self.caller;
        let restic = &self.restic;
        let pin = &self.pin;
        let inventory = &self.inventory;
        self.record.replace(&record, &mut || {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            caller.recheck()?;
            restic.descriptor()?;
            pin.recheck()?;
            inventory.recheck(guard)
        })?;
        self.recheck(authorize)
    }
    /// Consumes the original context and exact reviewed action. No decoded row
    /// or newly opened inode can replace its live inventory during execution.
    pub fn advance(
        mut self,
        sha: &str,
        action: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::identity::sha(sha)?;
        self.recheck(authorize)?;
        let review = self.review(authorize)?;
        require(
            review["review_sha256"] == sha && review["next_action"] == action,
            "remote rotation review changed; review again",
        )?;
        if action == "abandon" {
            self.phase("abandoned", authorize)?;
            return Ok(value!({"status":"remote-rotation-abandoned",
            "new_remote_repository_left_on_server":true,"old_remote_repository_deleted":false}));
        }
        require(
            matches!(action, "switch" | "discard"),
            "closed remote rotation action required",
        )?;
        let authenticated = self.authenticated_inventory(authorize)?;
        require(
            authenticated["old_password_refused_by_new"] == true
                && !authenticated["old_points"].is_null(),
            "original old/new authenticated remote evidence required before mutation",
        )?;
        if action == "switch" {
            if self.record.value()?["phase"] == "copied" {
                self.phase("switching", authorize)?;
            }
            let start = boundary(&self.state(authorize)?)?;
            require(start <= 5, "remote switch outside original boundary")?;
            for index in start..5 {
                self.recheck(authorize)?;
                let guard = self.guard;
                let lock = self.lock;
                let caller = &self.caller;
                let restic = &self.restic;
                let record = &self.record;
                if index < 4 {
                    let pin = &self.pin;
                    let mut permission = || {
                        authorize()?;
                        guard.recheck()?;
                        lock.recheck()?;
                        caller.recheck()?;
                        restic.descriptor()?;
                        record.recheck()?;
                        pin.recheck()
                    };
                    let (source, target) = match index {
                        0 => (Role::CurrentConfiguration, Role::RetiredConfiguration),
                        1 => (Role::StagedConfiguration, Role::CurrentConfiguration),
                        2 => (Role::CurrentPassword, Role::RetiredPassword),
                        3 => (Role::StagedPassword, Role::CurrentPassword),
                        _ => unreachable!(),
                    };
                    self.inventory
                        .rename(guard, source, target, &mut permission)?;
                } else {
                    self.pin.require_scope(guard, lock, JournalRole::Pin)?;
                    let next = record.value()?["new_identity"].clone();
                    let inventory = &self.inventory;
                    self.pin.replace(&next, &mut || {
                        authorize()?;
                        guard.recheck()?;
                        lock.recheck()?;
                        caller.recheck()?;
                        restic.descriptor()?;
                        record.recheck()?;
                        inventory.recheck(guard)
                    })?;
                }
                require(
                    boundary(&self.state(authorize)?)? == index + 1,
                    "original remote switch did not reach known boundary",
                )?;
                self.recheck(authorize)?;
            }
            let final_observation = self.authenticated_inventory(authorize)?;
            require(
                final_observation["old_password_refused_by_new"] == true,
                "original old remote credential is not refused after switch",
            )?;
            self.phase("switched", authorize)?;
            self.recheck(authorize)?;
            return Ok(
                value!({"status":"remote-rotation-switched","repository_id":self.pin.value()?["repository_id"],"old_remote_repository_deleted":false}),
            );
        }
        require(
            self.record.value()?["phase"] == "switched" && boundary(&self.state(authorize)?)? == 5,
            "original switched remote boundary required",
        )?;
        // This versioned phase fences an interrupted discard. A cold context
        // cannot resume it from JSON; only these original actual actors finish.
        self.phase("discarding", authorize)?;
        for role in [Role::RetiredConfiguration, Role::RetiredPassword] {
            let guard = self.guard;
            let lock = self.lock;
            let caller = &self.caller;
            let restic = &self.restic;
            let record = &self.record;
            let pin = &self.pin;
            self.inventory.retire(guard, role, &mut || {
                authorize()?;
                guard.recheck()?;
                lock.recheck()?;
                caller.recheck()?;
                restic.descriptor()?;
                record.recheck()?;
                pin.recheck()
            })?;
            self.recheck(authorize)?;
        }
        self.inventory.retired_pair(self.guard)?;
        require(
            boundary(&self.state(authorize)?)? == 6,
            "original remote discard did not reach exact completed boundary",
        )?;
        self.phase("complete", authorize)?;
        self.inventory.retired_pair(self.guard)?;
        self.recheck(authorize)?;
        Ok(
            value!({"status":"remote-rotation-complete","retired_local_material_removed":true,"old_remote_repository_deleted":false}),
        )
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let result = value!({"inventory":self.inventory.evidence(self.guard)?,"record":self.record.evidence()?,"pin":self.pin.evidence()?,
            "caller":self.caller.evidence()?,"credential_bytes_read":false,"remote_repository_verified":false});
        self.recheck(authorize)?;
        Ok(result)
    }
}
