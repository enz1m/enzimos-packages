// SPDX-License-Identifier: MIT
//! Publish one pin using the original reported header and closed worker proof.
use crate::{
    backup_input_authentication::Confirmed, backup_setup_configuration::Configuration,
    backup_setup_context::Prepared, backup_setup_mount::Scope, backup_setup_plan::Plan,
    backup_worker_intent::Intent, backup_worker_observation::Observation, storage_runtime::Guard,
};
use enzimos_platform::{Result, backup_worker_scope::Closed, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const NAME: &str = "backup-destination.json";
pub struct Bound<'g> {
    guard: &'g Guard,
    lock: &'g files::Lock,
    authorize: &'g dyn Fn() -> Result<()>,
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    value: Value,
}
impl<'g> Bound<'g> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument is a distinct retained input of this step."
    )]
    pub fn publish(
        plan: &'g Plan<'_, '_, '_>,
        intent: &Intent<'_>,
        observation: &Observation,
        closed: &Closed,
        scope: &Scope<'_, '_, '_>,
        configuration: &Configuration<'_>,
        outer: &Prepared<'_, '_, '_, '_>,
        confirmation: Option<&Confirmed<'_, '_, '_>>,
        lock: &'g files::Lock,
        authorize: &'g dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        crate::namespaces::initial()?;
        intent.recheck()?;
        scope.recheck()?;
        configuration.recheck()?;
        outer.recheck()?;
        lock.recheck()?;
        authorize()?;
        let record = intent.value()?;
        let request = &record["request"];
        require(
            record["phase"] == "starting"
                && request["stage"] == "provision"
                && request["plan"] == *outer.plan_value()?
                && outer.plan_value()? == plan.original()
                && request["mount"] == scope.evidence()?
                && request["configuration"]["value"] == configuration.value()?
                && request["configuration"]["identity"]
                    == serde_json::to_value(files::identity(
                        &configuration.descriptor()?.metadata()?,
                    ))?,
            "pin publication differs from original active plan/mount/publication/intent",
        )?;
        let result = observation.observed_closed(request, closed)?;
        require(
            result["status"] == "provisioned",
            "pin requires original composite provision observation",
        )?;
        require(
            confirmation.is_some() == (request["plan"]["mode"] == "adopt"),
            "pin adoption requires original confirmation",
        )?;
        if let Some(confirmed) = confirmation {
            confirmed.matches_plan(plan)?;
            require(
                result["key_id"] == confirmed.key_id()?,
                "pin key differs from original confirmation",
            )?;
        }
        let root = File::from(scope.descriptor()?.try_clone_to_owned()?);
        let repository = files::directory_relative(&root, Path::new("restic"), Some(0))?;
        let header = crate::backup_repository_header::Header::received(
            &repository,
            observation.original_header()?.try_clone()?,
        )?;
        require(
            header.evidence(&repository)? == result["header"],
            "pin header differs from original measured report",
        )?;
        let value = value!({"schema":1,"filesystem_uuid":request["mount"]["filesystem_uuid"],
            "fsroot":"/","repository":crate::backup_configuration::REPOSITORY,"repository_sha256":result["header"]["sha256"]});
        let bytes = json::canonical(&value)?;
        crate::backup_binding::pin(&bytes)?;
        let guard = plan.source_guard()?;
        require(
            files::optional_relative(guard.control(), Path::new(NAME))?.is_none()
                && files::optional_relative(guard.control(), Path::new("backup.enabled"))?
                    .is_none(),
            "existing pin or automatic work refuses publication; no replay",
        )?;
        intent.recheck()?;
        scope.recheck()?;
        header.recheck(&repository)?;
        closed.recheck()?;
        configuration.recheck()?;
        outer.recheck()?;
        lock.recheck()?;
        authorize()?;
        let file = files::atomic_relative_retained(
            guard.control(),
            Path::new(NAME),
            &bytes,
            0o600,
            Some(0),
            false,
            32768,
        )?;
        let this = Self {
            guard,
            lock,
            authorize,
            identity: files::identity(&file.metadata()?),
            file,
            bytes,
            value,
        };
        this.recheck()?;
        header.recheck(&repository)?;
        scope.recheck()?;
        intent.recheck()?;
        closed.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        (self.authorize)()?;
        let named = files::open_relative(self.guard.control(), Path::new(NAME))?;
        let m = self.file.metadata()?;
        require(
            files::identity(&m) == self.identity
                && files::identity(&named.metadata()?) == self.identity
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && mount_identity::id(self.file.as_fd(), true)? == self.guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == self.guard.control_mount_id()
                && files::read_file(&self.file, 32768, Some(0), true)? == self.bytes
                && crate::backup_binding::pin(&self.bytes)? == self.value
                && files::optional_relative(self.guard.control(), Path::new("backup.enabled"))?
                    .is_none(),
            "original newly published pin changed or automatic work enabled",
        )
    }
    pub(crate) fn value(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.value)
    }
}
