// SPDX-License-Identifier: MIT
//! The job runtime accepts server-made plans, never arbitrary programs or paths.
use enzimos_platform::{Error, Result, files, json, process_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
pub const EXECUTABLE: &str = "/usr/lib/enzimos-backend/enzimos-system-backend";
pub trait Provider: Send + Sync + 'static {
    /// Whether this native provider serves the owner-bound appearance publisher.
    fn login_appearance_supported(&self) -> bool {
        false
    }
    fn backup_supported(&self) -> bool {
        false
    }
    fn backup_review(
        &self,
        _initial: &Value,
        _authorize: &dyn Fn() -> Result<()>,
        _publish: &mut dyn FnMut(
            &enzimos_policy::backup_setup_plan::Plan<'_, '_, '_>,
        ) -> Result<()>,
    ) -> Result<()> {
        Err(Error("operation-unavailable".into()))
    }
    fn backup_setup(
        &self,
        _plan: &Value,
        _sha: &str,
        _input: &enzimos_platform::secret::Retained,
        _authorize: &dyn Fn() -> Result<()>,
    ) -> Result<super::backup_setup_coordinator::Finished> {
        Err(Error("operation-unavailable".into()))
    }
    /// The recovery password for approved owner `uid`: public result plus a
    /// sealed private copy. Never replayed; a new export issues a new ticket.
    fn backup_recovery_export(
        &self,
        _uid: u32,
        _authorize: &dyn Fn() -> Result<()>,
    ) -> Result<(Value, File)> {
        Err(Error("operation-unavailable".into()))
    }
    /// Record `uid`'s statement that the export `ticket` was saved elsewhere.
    fn backup_recovery_confirm(
        &self,
        _uid: u32,
        _ticket: &str,
        _assertion: &str,
        _authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        Err(Error("operation-unavailable".into()))
    }
    /// The NAS share: `request` is the admitted `BackupRemoteShare`
    /// or `BackupRemoteShareSetup` body. Setup brings the sealed share password
    /// and, without a local backup, the sealed repository password.
    fn backup_remote_share(
        &self,
        _request: &Value,
        _share: Option<&enzimos_platform::secret::Retained>,
        _repository: Option<&enzimos_platform::secret::Retained>,
        _authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        Err(Error("operation-unavailable".into()))
    }
    fn operations(&self) -> &[&'static str];
    fn plan(&self, operation: &str, selection: &Value, request_id: &str, uid: u32)
    -> Result<Value>;
    fn plan_referenced(
        &self,
        operation: &str,
        selection: &Value,
        request_id: &str,
        uid: u32,
        references: &super::system_jobs::ReferenceView,
    ) -> Result<Value> {
        references.recheck()?;
        let result = self.plan(operation, selection, request_id, uid)?;
        references.recheck()?;
        Ok(result)
    }
    /// Verification retains the original ledger, including the server-owned
    /// planned row. Decoded plan data cannot create the own-record exemption.
    fn verify_referenced(
        &self,
        plan: &Value,
        references: &super::system_jobs::ReferenceView,
    ) -> Result<()> {
        references.recheck()?;
        self.verify(plan)?;
        references.recheck()
    }
    fn run_referenced(
        &self,
        plan: &Value,
        owner: u32,
        references: &super::system_jobs::ReferenceView,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        references.recheck()?;
        let result = self.run_owned(plan, owner, progress, &mut || {
            references.recheck()?;
            commit()
        })?;
        references.recheck()?;
        Ok(result)
    }
    fn verify(&self, plan: &Value) -> Result<()>;
    fn run(
        &self,
        plan: &Value,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value>;
    /// Authoritative owner comes from the original server ledger/ticket.
    /// Providers needing caller ownership must not infer it from selection JSON.
    fn run_owned(
        &self,
        plan: &Value,
        owner: u32,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        let _ = owner;
        self.run(plan, progress, commit)
    }
    fn history(&self, commit: &mut dyn FnMut() -> Result<()>) -> Result<u64>;
    fn query(&self, query: &str) -> Result<Value>;
}
pub struct Native {
    image: File,
    image_identity: files::FileIdentity,
    sha: String,
    process: process_identity::Retained,
    guard: enzimos_policy::storage_runtime::Guard,
}
impl Native {
    pub fn open() -> Result<Self> {
        enzimos_policy::namespaces::initial()?;
        enzimos_policy::operation::root_only()?;
        let path = Path::new(EXECUTABLE);
        let directory = files::directory(path.parent().unwrap(), Some(0))?;
        let image = files::open_relative(&directory, Path::new(path.file_name().unwrap()))?;
        require(
            image.metadata()?.gid() == 0 && image.metadata()?.mode() & 0o7777 == 0o755,
            "installed native backend image required",
        )?;
        let (_, sha) = stream_copy::hash_borrowed(&image, 128 * 1024 * 1024, Some(0))?;
        let pid = std::process::id();
        let raw = files::read_kernel(&PathBuf::from(format!("/proc/{pid}/stat")), 8192)?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&raw).map_err(|_| Error("backend process identity".into()))?,
            pid,
        )?;
        let process = process_identity::Retained::open(pid, stat.start_ticks, 0, &[path.into()])?
            .pin_executable(&image)?;
        let this = Self {
            image_identity: files::identity(&image.metadata()?),
            image,
            sha,
            process,
            guard: enzimos_policy::storage_runtime::Guard::observe()?,
        };
        this.recheck()?;
        Ok(this)
    }
    /// Recovery points of the configured local repository. A mounted drive is
    /// read in place; otherwise the pinned drive is attached for this read
    /// only (one reviewed temporary mount under the operation lock, closed
    /// before the reply), so the list works after a backup has unmounted it.
    /// While another operation holds the lock the query refuses with
    /// `backup-destination-busy` instead of waiting.
    fn backup_points(&self) -> Result<Value> {
        use enzimos_policy::{backup_destination_attach as attach, backup_status::Status};
        if attach::mounted()? || !Status::observe(&self.guard)?.configured() {
            return Status::observe(&self.guard)?.points();
        }
        let lock = enzimos_policy::operation::try_lock()?
            .ok_or_else(|| Error("backup-destination-busy".into()))?;
        attach::with_destination(&self.guard, &lock, &|| self.recheck(), || {
            Status::observe(&self.guard)?.points()
        })
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.process.recheck()?;
        self.guard.recheck()?;
        require(
            files::identity(&self.image.metadata()?) == self.image_identity,
            "original backend executable epoch changed",
        )
    }
    fn observe(&self, role: &str, selection: &Value) -> Result<Value> {
        self.recheck()?;
        let body = match role {
            "backup-create" => enzimos_policy::backup_create_review::observe(&self.guard)?,
            "remote-replicate" | "remote-retrieve" => {
                super::backup_remote_coordinator::observe(&self.guard, role, selection)?
            }
            "rotation-advance" => {
                enzimos_policy::backup_rotation_review::observe_advance(&self.guard, selection)?
            }
            "remote-rotation-advance" => {
                enzimos_policy::backup_remote_rotation_review::observe_advance(
                    &self.guard,
                    selection,
                )?
            }
            "remote-rotation-review" => {
                enzimos_policy::backup_remote_rotation_review::observe(&self.guard, selection)?
            }
            "rotation-review" => {
                enzimos_policy::backup_rotation_review::observe(&self.guard, selection)?
            }
            "tree-restore-export" => {
                enzimos_policy::backup_selective_review::observe_tree(&self.guard, selection)?
            }
            "file-restore-export" => {
                enzimos_policy::backup_selective_review::observe(&self.guard, selection)?
            }
            "credential-review" | "credential-complete" => {
                enzimos_policy::backup_credential_review::observe(
                    &self.guard,
                    role,
                    selection["id"]
                        .as_str()
                        .ok_or_else(|| Error("job-plan-invalid".into()))?,
                )?
            }
            "update-apply" => {
                let lock = enzimos_policy::operation::lock()?;
                // Retire old generations first so a reviewable plan is not
                // refused merely because the daily retention has not run.
                enzimos_policy::generation_retention::before_update_locked(&lock, &mut || {
                    lock.recheck()
                });
                let plan = enzimos_policy::update_plan::Plan::observe_locked(&lock)?;
                plan.recheck_before_mutation()?;
                plan.document().clone()
            }
            "recovery-prepare" => enzimos_policy::recovery_prepare::observation(selection)?,
            "file-restore-deliver" => enzimos_policy::delivery_control::observation(selection)?,
            "file-restore-grant" => enzimos_policy::delivery_grant::observation(selection)?,
            "delivery-cancel" => enzimos_policy::delivery_cancel::observation(selection)?,
            "network-trust-set" => enzimos_policy::network_trust::plan(
                selection["connection"]
                    .as_str()
                    .ok_or_else(|| Error("job-plan-invalid".into()))?,
            )?,
            "home-history-set" => enzimos_policy::home_history_control::plan()?,
            "memory-policy-set" => enzimos_policy::memory::observation()?,
            "battery-action-set" => enzimos_policy::power::observation()?,
            "home-retention-set" => enzimos_policy::home_retention::observation()?,
            "backup-retention-set" => enzimos_policy::backup_retention::observation()?,
            "recovery-run-stage" => enzimos_policy::recovery_run_control::observation(selection)?,
            "recovery-run-finish" => enzimos_policy::recovery_run_finish::observation(selection)?,
            "backup-schedule-set" => enzimos_policy::backup_schedule::observation(
                selection["enabled"]
                    .as_bool()
                    .ok_or_else(|| Error("job-plan-invalid".into()))?,
            )?,
            _ => return Err(Error("operation-unavailable".into())),
        };
        self.recheck()?;
        Ok(body)
    }
}
impl Provider for Native {
    fn login_appearance_supported(&self) -> bool {
        true
    }
    fn backup_supported(&self) -> bool {
        true
    }
    fn backup_review(
        &self,
        initial: &Value,
        authorize: &dyn Fn() -> Result<()>,
        publish: &mut dyn FnMut(&enzimos_policy::backup_setup_plan::Plan<'_, '_, '_>) -> Result<()>,
    ) -> Result<()> {
        self.recheck()?;
        super::backup_setup_provider::review(
            initial,
            &|| {
                self.recheck()?;
                authorize()
            },
            publish,
        )
    }
    fn backup_setup(
        &self,
        plan: &Value,
        sha: &str,
        input: &enzimos_platform::secret::Retained,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<super::backup_setup_coordinator::Finished> {
        self.recheck()?;
        super::backup_setup_provider::run(plan, sha, input, &|| {
            self.recheck()?;
            authorize()
        })
    }
    fn backup_recovery_export(
        &self,
        uid: u32,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<(Value, File)> {
        self.recheck()?;
        super::backup_recovery_coordinator::export(&self.guard, uid, &|| {
            self.recheck()?;
            authorize()
        })
    }
    fn backup_recovery_confirm(
        &self,
        uid: u32,
        ticket: &str,
        assertion: &str,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        self.recheck()?;
        super::backup_recovery_coordinator::confirm(&self.guard, uid, ticket, assertion, &|| {
            self.recheck()?;
            authorize()
        })
    }
    fn backup_remote_share(
        &self,
        request: &Value,
        share: Option<&enzimos_platform::secret::Retained>,
        repository: Option<&enzimos_platform::secret::Retained>,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        self.recheck()?;
        super::backup_remote_share_coordinator::run(
            &self.guard,
            request,
            share,
            repository,
            &|| {
                self.recheck()?;
                authorize()
            },
        )
    }
    fn operations(&self) -> &[&'static str] {
        &[
            "backup-create",
            "boot-retire",
            "root-retire-prepare",
            "root-retire-stage",
            "root-retire-finish",
            "remote-replicate",
            "remote-retrieve",
            "remote-rotation-advance",
            "remote-rotation-review",
            "rotation-review",
            "rotation-advance",
            "file-restore-export",
            "tree-restore-export",
            "own-file-restore",
            "credential-review",
            "credential-complete",
            "recovery-prepare",
            "file-restore-deliver",
            "file-restore-grant",
            "delivery-cancel",
            "network-trust-set",
            "home-history-set",
            "memory-policy-set",
            "battery-action-set",
            "home-retention-set",
            "backup-retention-set",
            "backup-schedule-set",
            "recovery-run-stage",
            "recovery-run-finish",
            "update-apply",
        ]
    }
    fn plan_referenced(
        &self,
        operation: &str,
        selection: &Value,
        request_id: &str,
        uid: u32,
        references: &super::system_jobs::ReferenceView,
    ) -> Result<Value> {
        if !matches!(
            operation,
            "boot-retire" | "root-retire-prepare" | "root-retire-stage" | "root-retire-finish"
        ) {
            references.recheck()?;
            let plan = self.plan(operation, selection, request_id, uid)?;
            references.recheck()?;
            return Ok(plan);
        }
        self.recheck()?;
        super::system_selection::validate(
            match operation {
                "boot-retire" => 9,
                "root-retire-prepare" => 12,
                "root-retire-stage" => 13,
                _ => 14,
            },
            selection,
        )?;
        require(
            super::system_wire::hex(request_id, 32),
            "job-request-invalid",
        )?;
        let observed = if operation == "boot-retire" {
            super::boot_retirement_coordinator::observe(&self.guard, selection, references)?
        } else if operation == "root-retire-prepare" {
            super::root_retirement_prepare_coordinator::observe(&self.guard, selection, references)?
        } else if operation == "root-retire-finish" {
            super::root_retirement_finish_coordinator::observe(&self.guard, selection, references)?
        } else {
            super::root_retirement_stage_coordinator::observe(&self.guard, selection, references)?
        };
        self.recheck()?;
        references.recheck()?;
        Ok(
            value!({"schema":1,"operation":operation,"selection":selection,"request_id":request_id,
            "boot_id":enzimos_policy::operation::boot_id()?,"implementation_sha256":self.sha,
            "record_sha256":json::fingerprint(&observed)?,"observation":observed}),
        )
    }
    fn verify_referenced(
        &self,
        plan: &Value,
        references: &super::system_jobs::ReferenceView,
    ) -> Result<()> {
        if !matches!(
            plan["operation"].as_str(),
            Some(
                "boot-retire" | "root-retire-prepare" | "root-retire-stage" | "root-retire-finish"
            )
        ) {
            references.recheck()?;
            self.verify(plan)?;
            return references.recheck();
        }
        json::fields(
            plan,
            "schema operation selection request_id boot_id implementation_sha256 record_sha256 observation",
        )?;
        let id = plan["request_id"]
            .as_str()
            .filter(|s| super::system_wire::hex(s, 32))
            .ok_or_else(|| Error("job-request-invalid".into()))?;
        require(
            self.plan_referenced(
                plan["operation"].as_str().unwrap(),
                &plan["selection"],
                id,
                0,
                references,
            )? == *plan,
            "job-plan-changed",
        )
    }
    fn run_referenced(
        &self,
        plan: &Value,
        _owner: u32,
        references: &super::system_jobs::ReferenceView,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        if !matches!(
            plan["operation"].as_str(),
            Some(
                "boot-retire" | "root-retire-prepare" | "root-retire-stage" | "root-retire-finish"
            )
        ) {
            references.recheck()?;
            let result = self.run_owned(plan, _owner, progress, &mut || {
                references.recheck()?;
                commit()
            })?;
            references.recheck()?;
            return Ok(result);
        }
        self.verify_referenced(plan, references)?;
        let mut permission = || {
            self.recheck()?;
            references.recheck()?;
            commit()
        };
        let result = if plan["operation"] == "boot-retire" {
            super::boot_retirement_coordinator::run(
                &self.guard,
                &plan["selection"],
                &plan["observation"],
                references,
                &mut permission,
                progress,
            )?
        } else if plan["operation"] == "root-retire-prepare" {
            super::root_retirement_prepare_coordinator::run(
                &self.guard,
                &plan["selection"],
                &plan["observation"],
                references,
                &mut permission,
                progress,
            )?
        } else if plan["operation"] == "root-retire-finish" {
            super::root_retirement_finish_coordinator::run(
                &self.guard,
                &plan["selection"],
                &plan["observation"],
                references,
                &mut permission,
                progress,
            )?
        } else {
            super::root_retirement_stage_coordinator::run(
                &self.guard,
                &plan["selection"],
                &plan["observation"],
                references,
                &mut permission,
                progress,
            )?
        };
        permission()?;
        references.recheck()?;
        Ok(result)
    }
    fn plan(
        &self,
        operation: &str,
        selection: &Value,
        request_id: &str,
        uid: u32,
    ) -> Result<Value> {
        require(
            !super::operation_store::retirement_operation(operation),
            "original backend reference view required",
        )?;
        let schema = super::system_wire::OPERATIONS
            .iter()
            .position(|s| *s == operation)
            .ok_or_else(|| Error("operation-unavailable".into()))? as u64
            + 3;
        super::system_selection::validate(schema, selection)?;
        if operation == "own-file-restore" {
            let observed =
                super::own_file_restore_coordinator::observe(&self.guard, selection, uid)?;
            return Ok(
                value!({"schema":1,"operation":operation,"selection":selection,"request_id":request_id,
                "boot_id":enzimos_policy::operation::boot_id()?,"implementation_sha256":self.sha,
                "record_sha256":json::fingerprint(&observed)?,"observation":observed,
                "uid":uid,"account":observed["account"],"filename":observed["filename"]}),
            );
        }
        let observed = self.observe(operation, selection)?;
        Ok(
            value!({"schema":1,"operation":operation,"selection":selection,"request_id":request_id,
            "boot_id":enzimos_policy::operation::boot_id()?,"implementation_sha256":self.sha,
            "record_sha256":json::fingerprint(&observed)?,"observation":observed}),
        )
    }
    fn verify(&self, plan: &Value) -> Result<()> {
        json::fields(
            plan,
            if plan["operation"] == "own-file-restore" {
                "schema operation selection request_id boot_id implementation_sha256 record_sha256 observation uid account filename"
            } else {
                "schema operation selection request_id boot_id implementation_sha256 record_sha256 observation"
            },
        )?;
        let role = plan["operation"]
            .as_str()
            .ok_or_else(|| Error("job-plan-invalid".into()))?;
        let id = plan["request_id"]
            .as_str()
            .filter(|s| super::system_wire::hex(s, 32))
            .ok_or_else(|| Error("job-request-invalid".into()))?;
        require(
            self.plan(
                role,
                &plan["selection"],
                id,
                if role == "own-file-restore" {
                    plan["uid"]
                        .as_u64()
                        .filter(|n| (1000..i32::MAX as u64).contains(n))
                        .ok_or_else(|| Error("job-plan-invalid".into()))? as u32
                } else {
                    0
                },
            )? == *plan,
            "job-plan-changed",
        )
    }
    fn run_owned(
        &self,
        plan: &Value,
        owner: u32,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        if plan["operation"] != "own-file-restore" {
            return self.run(plan, progress, commit);
        }
        self.verify(plan)?;
        require(
            plan["uid"] == owner && plan["account"]["uid"] == owner,
            "own-file execution differs from original ledger owner",
        )?;
        let permission = std::cell::RefCell::new(commit);
        let authorize = || {
            self.recheck()?;
            let mut callback = permission
                .try_borrow_mut()
                .map_err(|_| Error("own-file authorization reentered".into()))?;
            callback()
        };
        super::own_file_restore_coordinator::run(
            &self.guard,
            plan["request_id"].as_str().unwrap(),
            &plan["selection"],
            &plan["observation"],
            owner,
            &authorize,
            progress,
        )
    }
    fn run(
        &self,
        plan: &Value,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.verify(plan)?;
        require(
            plan["operation"] != "own-file-restore",
            "own-file execution requires original ledger owner",
        )?;
        if matches!(
            plan["operation"].as_str(),
            Some("remote-replicate" | "remote-retrieve")
        ) {
            let permission = std::cell::RefCell::new(commit);
            let authorize = || {
                self.recheck()?;
                let mut callback = permission
                    .try_borrow_mut()
                    .map_err(|_| Error("remote copy authorization reentered".into()))?;
                callback()
            };
            return super::backup_remote_coordinator::run(
                &self.guard,
                plan["operation"].as_str().unwrap(),
                &plan["selection"],
                &plan["observation"],
                &authorize,
                progress,
            );
        }
        if matches!(
            plan["operation"].as_str(),
            Some("remote-rotation-review" | "remote-rotation-advance")
        ) {
            let permission = std::cell::RefCell::new(commit);
            let authorize = || {
                self.recheck()?;
                let mut callback = permission
                    .try_borrow_mut()
                    .map_err(|_| Error("remote rotation review authorization reentered".into()))?;
                callback()
            };
            let runner = if plan["operation"] == "remote-rotation-review" {
                super::backup_remote_rotation_coordinator::review
            } else {
                super::backup_remote_rotation_coordinator::advance
            };
            return runner(
                &self.guard,
                &plan["selection"],
                &plan["observation"],
                &authorize,
                progress,
            );
        }
        if matches!(
            plan["operation"].as_str(),
            Some("rotation-review" | "rotation-advance")
        ) {
            let permission = std::cell::RefCell::new(commit);
            let authorize = || {
                self.recheck()?;
                let mut callback = permission
                    .try_borrow_mut()
                    .map_err(|_| Error("rotation authorization reentered".into()))?;
                callback()
            };
            let runner = if plan["operation"] == "rotation-review" {
                super::backup_rotation_coordinator::review
            } else {
                super::backup_rotation_coordinator::advance
            };
            return runner(
                &self.guard,
                &plan["selection"],
                &plan["observation"],
                &authorize,
                progress,
            );
        }
        if matches!(
            plan["operation"].as_str(),
            Some("credential-review" | "credential-complete")
        ) {
            let permission = std::cell::RefCell::new(commit);
            let authorize = || {
                self.recheck()?;
                let mut callback = permission
                    .try_borrow_mut()
                    .map_err(|_| Error("credential authorization reentered".into()))?;
                callback()
            };
            return super::backup_credential_coordinator::run(
                &self.guard,
                plan["operation"].as_str().unwrap(),
                plan["request_id"].as_str().unwrap(),
                &plan["selection"],
                &plan["observation"],
                &authorize,
                progress,
            );
        }
        if matches!(
            plan["operation"].as_str(),
            Some("file-restore-export" | "tree-restore-export")
        ) {
            let permission = std::cell::RefCell::new(commit);
            let authorize = || {
                self.recheck()?;
                let mut callback = permission
                    .try_borrow_mut()
                    .map_err(|_| Error("selective export authorization reentered".into()))?;
                callback()
            };
            let runner = if plan["operation"] == "tree-restore-export" {
                super::backup_selective_coordinator::run_tree
            } else {
                super::backup_selective_coordinator::run
            };
            return runner(
                &self.guard,
                plan["request_id"].as_str().unwrap(),
                &plan["selection"],
                &plan["observation"],
                &authorize,
                progress,
            );
        }
        if plan["operation"] == "backup-create" {
            // The worker launcher requests fresh permission on this same owning
            // thread. RefCell adapts the job's FnMut without caching its grant.
            let permission = std::cell::RefCell::new(commit);
            let authorize = || {
                self.recheck()?;
                let mut callback = permission
                    .try_borrow_mut()
                    .map_err(|_| Error("backup authorization reentered".into()))?;
                callback()
            };
            return super::backup_create_coordinator::run(
                &self.guard,
                plan["request_id"].as_str().unwrap(),
                &plan["observation"],
                &authorize,
                progress,
            );
        }
        if plan["operation"] == "update-apply" {
            let lock = enzimos_policy::operation::lock()?;
            let result = enzimos_policy::update_apply_runtime::apply_reviewed_backend(
                &lock,
                &plan["observation"],
                plan["request_id"].as_str().unwrap(),
                progress,
                &mut || {
                    self.recheck()?;
                    commit()
                },
            )?;
            self.recheck()?;
            commit()?;
            return Ok(value!({"generation":result["generation"],
                "status":if result["status"] == "up-to-date-no-new-generation" {"up-to-date"} else {"prepared-not-rebooted"},
                "reboot_requested":false}));
        }
        progress("capturing")?;
        let selection = &plan["selection"];
        let expected = &plan["observation"];
        let mut first = true;
        let mut preflight = || -> Result<()> {
            // The first boundary checks the reviewed state. A later boundary
            // may follow this provider's own zone change; the policy provider
            // retains and checks that known change before live reapplication.
            if first {
                self.verify(plan)?;
                first = false;
            } else {
                self.recheck()?;
            }
            commit()
        };
        let out = match plan["operation"].as_str() {
            Some("recovery-prepare") => enzimos_policy::recovery_prepare::prepare(
                selection,
                plan["request_id"].as_str().unwrap(),
                expected,
                &mut preflight,
            )?,
            Some("file-restore-deliver") => {
                enzimos_policy::delivery_control::deliver(selection, expected, &mut preflight)?
            }
            Some("file-restore-grant") => {
                enzimos_policy::delivery_grant::grant(selection, expected, &mut preflight)?
            }
            Some("delivery-cancel") => {
                enzimos_policy::delivery_cancel::cancel(selection, expected, &mut preflight)?
            }
            Some("network-trust-set") => enzimos_policy::network_trust::set(
                selection["connection"].as_str().unwrap(),
                selection["trusted"].as_bool().unwrap(),
                expected,
                &mut preflight,
            )?,
            Some("home-history-set") => enzimos_policy::home_history_control::set(
                selection["enabled"].as_bool().unwrap(),
                expected,
                &mut preflight,
            )?,
            Some("memory-policy-set") => {
                enzimos_policy::memory::set_policy(selection, &mut preflight)?
            }
            Some("home-retention-set") => {
                enzimos_policy::home_retention::set(selection, expected, &mut preflight)?
            }
            Some("backup-retention-set") => {
                enzimos_policy::backup_retention::set(selection, expected, &mut preflight)?
            }
            Some("recovery-run-stage") => {
                enzimos_policy::recovery_run_control::stage(selection, expected, &mut preflight)?
            }
            Some("recovery-run-finish") => {
                enzimos_policy::recovery_run_finish::finish(selection, expected, &mut preflight)?
            }
            Some("backup-schedule-set") => enzimos_policy::backup_schedule::set(
                selection["enabled"].as_bool().unwrap(),
                plan["request_id"].as_str().unwrap(),
                expected,
                &mut preflight,
            )?,
            Some("battery-action-set") => enzimos_policy::power::set_action(
                selection["action"].as_str().unwrap(),
                selection["risk_acknowledged"].as_bool().unwrap(),
                &mut preflight,
            )?,
            _ => return Err(Error("operation-unavailable".into())),
        };
        self.recheck()?;
        progress("finishing")?;
        Ok(out)
    }
    fn history(&self, commit: &mut dyn FnMut() -> Result<()>) -> Result<u64> {
        self.recheck()?;
        let result = enzimos_policy::home_history_create::create(None, || {
            self.recheck()?;
            commit()
        })?;
        self.recheck()?;
        result["snapshot"]
            .as_u64()
            .ok_or_else(|| Error("backend-result-unknown-do-not-retry-automatically".into()))
    }
    fn query(&self, query: &str) -> Result<Value> {
        self.recheck()?;
        let result = match query {
            "system" => enzimos_policy::system_query::system()?,
            "backups" => crate::backup_status_query::query(&self.guard)?,
            "backup-points" => self.backup_points()?,
            "network-trust" => enzimos_policy::network_trust::connections()?,
            "memory-policy" => enzimos_policy::memory::policy()?,
            "power-policy" => enzimos_policy::power::policy()?,
            "history" => enzimos_policy::snapshot_queries::history()?,
            "snapshots" => enzimos_policy::snapshot_queries::snapshots()?,
            "backup-candidates" => {
                enzimos_policy::backup_candidates::Discovery::observe()?.inventory()?
            }
            _ => return Err(Error("operation-unavailable".into())),
        };
        self.recheck()?;
        Ok(result)
    }
}
