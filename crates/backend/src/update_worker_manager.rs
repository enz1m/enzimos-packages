// SPDX-License-Identifier: MIT
//! A start request is not ownership: observe the exact native PID1 service first.
use crate::{
    system_manager::{MANAGER, Manager, PATH},
    update_worker_contract as contract,
};
use enzimos_platform::{Error, Result, files, json, process_identity, require};
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zbus::zvariant::{OwnedObjectPath, Value};
/// A started worker unit held by its process and cgroup.
pub struct Owner {
    /// Unit state when the worker was retained.
    pub state: contract::Snapshot,
    /// The retained worker process.
    pub process: process_identity::Retained,
    /// SHA-256 of the installed worker executable.
    pub executable_sha256: String,
    group: crate::update_worker_cgroup::Group,
}
impl Owner {
    pub(crate) fn backup_scope(
        &self,
        id: &str,
    ) -> Result<enzimos_platform::backup_worker_scope::Scope> {
        self.recheck()?;
        let unit = enzimos_platform::backup_worker_scope::unit(id)?;
        require(
            self.state.group == format!("/system.slice/{unit}"),
            "original owner belongs to another backup attempt",
        )?;
        let scope = enzimos_platform::backup_worker_scope::Scope::capture(
            id,
            &self.process,
            self.group.descriptor()?,
        )?;
        require(
            scope.binding()?["worker"]["executable_sha256"] == self.executable_sha256,
            "captured original worker image differs from PID1 admission",
        )?;
        self.recheck()?;
        Ok(scope)
    }
    /// This kernel-only boundary remains observable if the D-Bus provider is lost.
    /// It authorizes resource teardown, never an operation-completion receipt.
    ///
    /// # Errors
    ///
    /// Fails when the process or cgroup cannot be observed.
    pub fn exited_and_empty(&self) -> Result<bool> {
        Ok(self.process.exited()? && self.group.empty()?)
    }
    /// Verify the worker is still in its original cgroup and initial namespaces.
    ///
    /// # Errors
    ///
    /// Fails when the worker moved, its cgroup changed, or it left the initial namespaces.
    pub fn recheck(&self) -> Result<()> {
        self.process.recheck()?;
        let root = PathBuf::from(format!("/proc/{}", self.state.pid));
        let group = files::read_kernel(&root.join("cgroup"), 8192)?;
        require(
            group
                .split(|b| *b == b'\n')
                .filter(|row| !row.is_empty())
                .collect::<Vec<_>>()
                == vec![format!("0::{}", self.state.group).as_bytes()],
            "worker kernel cgroup changed",
        )?;
        for kind in enzimos_policy::namespaces::KINDS {
            require(
                enzimos_policy::namespaces::identity(self.state.pid, kind)?
                    == enzimos_policy::namespaces::identity(2, kind)?,
                "worker left initial kernel namespace",
            )?;
        }
        // An equal cgroup pathname does not retain the original kernel group.
        // A live measured worker must still populate this retained group; a
        // deleted or replaced equal-name group cannot authorize more work.
        require(
            !self.group.empty()?,
            "live worker left its original retained cgroup",
        )?;
        self.process.recheck()
    }
}
fn installed(definition: &contract::Definition) -> Result<(File, files::FileIdentity, String)> {
    let parent = files::directory(
        Path::new(definition.executable)
            .parent()
            .ok_or_else(|| Error("missing parent".into()))?,
        Some(0),
    )?;
    let file = files::open_relative(
        &parent,
        Path::new(
            Path::new(definition.executable)
                .file_name()
                .ok_or_else(|| Error("missing filename".into()))?,
        ),
    )?;
    let metadata = file.metadata()?;
    require(
        metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
            && metadata.nlink() == 1,
        "worker installation authority refused",
    )?;
    let bytes = files::read_file(&file, 32 * 1024 * 1024, Some(0), true)?;
    require(bytes.starts_with(b"\x7fELF"), "native worker ELF required")?;
    Ok((file, files::identity(&metadata), json::sha256(&bytes)))
}
/// Current state of the update worker unit for job `id`, or `None` when it is not loaded.
///
/// # Errors
///
/// Fails unless `id` is valid, or when systemd cannot be queried.
pub async fn snapshot(manager: &Manager, id: &str) -> Result<Option<contract::Snapshot>> {
    snapshot_for(manager, &contract::Definition::updater(id)?).await
}
/// Reads the current state of the worker unit for `definition`, or `None` when no such unit is loaded.
///
/// # Errors
///
/// Fails when systemd cannot be queried or reports an unexpected unit path.
pub async fn snapshot_for(
    manager: &Manager,
    definition: &contract::Definition,
) -> Result<Option<contract::Snapshot>> {
    let Some(path) = manager.unit(&definition.unit.clone()).await? else {
        return Ok(None);
    };
    require(
        path.as_str().starts_with("/org/freedesktop/systemd1/unit/") && path.as_str().len() <= 512,
        "worker unit object path refused",
    )?;
    for attempt in 0..8 {
        let unit: contract::Properties = manager
            .call(
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &("org.freedesktop.systemd1.Unit",),
            )
            .await?;
        let service: contract::Properties = manager
            .call(
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &("org.freedesktop.systemd1.Service",),
            )
            .await?;
        let after: contract::Properties = manager
            .call(
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &("org.freedesktop.systemd1.Unit",),
            )
            .await?;
        if contract::same_unit_epoch(&unit, &after)? {
            return Ok(Some(contract::validate_for(&after, &service, definition)?));
        }
        require(
            attempt < 7,
            "worker unit state did not stabilize; no mutation replay",
        )?;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Err(Error("worker unit state unavailable".into()))
}
/// Caller must durably checkpoint `starting` before invoking this one-shot method.
/// Admit the already running *current* worker. This never starts, references,
/// restarts or adopts another task by unit name; it is the worker-side gate.
pub(crate) async fn current_for(
    manager: &Manager,
    definition: &contract::Definition,
) -> Result<Owner> {
    enzimos_policy::namespaces::initial()?;
    let state = snapshot_for(manager, definition)
        .await?
        .ok_or_else(|| Error("current native worker unit unavailable".into()))?;
    require(
        state.active == "active" && state.pid == std::process::id(),
        "current process is not the registered active native MainPID",
    )?;
    let (executable, identity, executable_sha256) = installed(definition)?;
    let body = files::read_kernel(&PathBuf::from(format!("/proc/{}/stat", state.pid)), 8192)?;
    let stat = process_identity::parse_stat(
        std::str::from_utf8(&body).map_err(|_| Error("current worker stat encoding".into()))?,
        state.pid,
    )?;
    let process = process_identity::Retained::open(
        state.pid,
        stat.start_ticks,
        0,
        &[PathBuf::from(definition.executable)],
    )?
    .pin_executable(&executable)?;
    require(
        files::identity(&executable.metadata()?) == identity,
        "current worker installation changed during admission",
    )?;
    let owner = Owner {
        state,
        process,
        executable_sha256,
        group: crate::update_worker_cgroup::Group::observe_for(definition)?,
    };
    recheck_for(manager, definition, &owner).await?;
    Ok(owner)
}
/// Preserve the exact invocation and original kernel task/cgroup while running.
pub(crate) async fn recheck_for(
    manager: &Manager,
    definition: &contract::Definition,
    owner: &Owner,
) -> Result<()> {
    owner.recheck()?;
    let state = snapshot_for(manager, definition)
        .await?
        .ok_or_else(|| Error("original native worker service lost".into()))?;
    require(
        state.active == "active"
            && state.pid == owner.state.pid
            && state.invocation == owner.state.invocation
            && state.group == owner.state.group,
        "original native worker invocation changed",
    )?;
    owner.recheck()
}
/// Start the update worker unit for job `id` and retain it.
///
/// # Errors
///
/// Fails unless `id` is valid, or when the unit cannot be started exactly as defined and retained.
pub async fn start(manager: &Manager, id: &str) -> Result<Owner> {
    start_for(manager, &contract::Definition::updater(id)?).await
}
/// Starts the worker unit for `definition` as a transient unit and returns its retained owner.
///
/// # Errors
///
/// Fails when the unit already exists or cannot be started exactly as defined and retained.
pub async fn start_for(manager: &Manager, definition: &contract::Definition) -> Result<Owner> {
    let (executable, identity, executable_sha256) = installed(definition)?;
    require(
        manager.unit(&definition.unit.clone()).await?.is_none(),
        "worker unit already exists; no adoption or restart",
    )?;
    let properties = contract::properties_for(definition)?;
    let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
    let job: OwnedObjectPath = manager
        .call(
            PATH,
            MANAGER,
            "StartTransientUnit",
            &(definition.unit.clone(), "fail", properties, auxiliary),
        )
        .await?;
    require(
        job.as_str().starts_with("/org/freedesktop/systemd1/job/") && job.as_str().len() <= 128,
        "worker start outcome uncertain; no retry",
    )?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let state = snapshot_for(manager, definition)
            .await?
            .ok_or_else(|| Error("worker disappeared before handoff; no retry".into()))?;
        if state.active == "active" {
            let body =
                files::read_kernel(&PathBuf::from(format!("/proc/{}/stat", state.pid)), 8192)?;
            let stat = process_identity::parse_stat(
                std::str::from_utf8(&body).map_err(|_| Error("worker stat encoding".into()))?,
                state.pid,
            )?;
            let process = process_identity::Retained::open(
                state.pid,
                stat.start_ticks,
                0,
                &[PathBuf::from(definition.executable)],
            )?
            .pin_executable(&executable)?;
            require(
                files::identity(&executable.metadata()?) == identity,
                "worker executable changed during admission",
            )?;
            let owner = Owner {
                state,
                process,
                executable_sha256,
                group: crate::update_worker_cgroup::Group::observe_for(definition)?,
            };
            owner.recheck()?;
            // This reference retains observability; caller/worker pidfds govern lifetime.
            manager
                .call::<_, ()>(PATH, MANAGER, "RefUnit", &(definition.unit.clone(),))
                .await?;
            owner.recheck()?;
            return Ok(owner);
        }
        require(
            state.active == "activating" && tokio::time::Instant::now() < deadline,
            "worker start not confirmed; no retry",
        )?;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
/// Stop only the exact retained invocation. Unit name alone grants no authority.
///
/// # Errors
///
/// Fails unless `id` is valid, or when `retained` no longer matches the unit or the stop fails.
pub async fn stop(manager: &Manager, id: &str, retained: &Owner) -> Result<()> {
    stop_for(manager, &contract::Definition::updater(id)?, retained).await
}
/// Stops the worker unit for `definition` that `retained` still owns.
///
/// # Errors
///
/// Fails when `retained` no longer matches the unit or the stop fails.
pub async fn stop_for(
    manager: &Manager,
    definition: &contract::Definition,
    retained: &Owner,
) -> Result<()> {
    require(
        retained.state.group == format!("/system.slice/{}", definition.unit),
        "worker ownership belongs to a different native role or attempt",
    )?;
    let owner = &retained.state;
    // PID1 unloads only an inactive or failed unit; with the worker's own
    // process and cgroup proven gone, an unloaded unit is terminal too.
    let collected =
        || -> Result<bool> { Ok(retained.process.exited()? && retained.group.empty()?) };
    let Some(state) = snapshot_for(manager, definition).await? else {
        require(collected()?, "worker stop outcome unavailable")?;
        return Ok(());
    };
    require(
        contract::retained_or_terminal(&state, owner),
        "worker owner changed before stop",
    )?;
    if matches!(state.active.as_str(), "inactive" | "failed")
        && state.pid == 0
        && retained.process.exited()?
        && retained.group.empty()?
    {
        return Ok(());
    }
    // A cleared ID cannot authorize StopUnit, even when its name is unchanged.
    require(
        state.invocation == owner.invocation,
        "cleared worker invocation without original kernel closure",
    )?;
    let _: OwnedObjectPath = manager
        .call(
            PATH,
            MANAGER,
            "StopUnit",
            &(definition.unit.clone(), "fail"),
        )
        .await?;
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(definition.stop_seconds + 10);
    loop {
        let Some(state) = snapshot_for(manager, definition).await? else {
            require(
                collected()?,
                "worker stop receipt unavailable; inspect owned unit",
            )?;
            return Ok(());
        };
        require(
            contract::retained_or_terminal(&state, owner),
            "worker owner changed during stop",
        )?;
        if matches!(state.active.as_str(), "inactive" | "failed")
            && state.pid == 0
            && retained.process.exited()?
            && retained.group.empty()?
        {
            return Ok(());
        }
        require(
            tokio::time::Instant::now() < deadline,
            "worker stop unconfirmed; retain transaction resources",
        )?;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
