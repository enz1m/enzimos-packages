// SPDX-License-Identifier: MIT
//! Exact PID1-owned worker configuration is required before descriptor handoff.
use enzimos_platform::{Error, Result, require};
use enzimos_policy::update_worker_record as record;
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Value};
pub type Properties = HashMap<String, OwnedValue>;
pub type Exec = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
pub const INSTALLER_EXECUTABLE: &str =
    "/usr/lib/enzimos-installer/enzimos-installer-package-worker";
pub const INSTALLER_RUNTIME_SECONDS: u64 = 1800;
pub const INSTALLER_STOP_SECONDS: u64 = 10;
pub const BACKUP_EXECUTABLE: &str = "/usr/lib/enzimos-backend/enzimos-backup-worker";
/// Backup worker unit lifetime (RuntimeMaxSec, and the caller deadlines that
/// add 20 s to it): the longest worker job, the 25 h NAS copy workflow (12 h
/// copy plus a 12 h check), plus 30 min for handoff and summary. It also
/// covers the 12 h `restic backup` and the 12 h adopt/credential checks.
/// Stalls are caught earlier by the restic no-output watchdog and the 3 s
/// checkpoint receive.
pub const BACKUP_RUNTIME_SECONDS: u64 = 25 * 3600 + 1800;
/// Closed registry of native workers, never arbitrary frontend executable input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Definition {
    pub(crate) unit: String,
    pub(crate) executable: &'static str,
    pub(crate) arguments: Vec<String>,
    pub(crate) runtime_seconds: u64,
    pub(crate) stop_seconds: u64,
}
impl Definition {
    pub fn backup(id: &str) -> Result<Self> {
        require(
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "native backup worker identifier",
        )?;
        Ok(Self {
            unit: format!("enzimos-backup-local-{id}.service"),
            executable: BACKUP_EXECUTABLE,
            arguments: vec![BACKUP_EXECUTABLE.into(), "serve".into(), id.into()],
            runtime_seconds: BACKUP_RUNTIME_SECONDS,
            stop_seconds: 10,
        })
    }
    pub fn updater(id: &str) -> Result<Self> {
        Ok(Self {
            unit: record::unit(id)?,
            executable: record::EXECUTABLE,
            arguments: record::arguments(id)?,
            runtime_seconds: record::RUNTIME_SECONDS,
            stop_seconds: record::STOP_SECONDS,
        })
    }
    pub fn installer(id: &str) -> Result<Self> {
        require(
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "native installer worker identifier",
        )?;
        Ok(Self {
            unit: format!("enzimos-install-package-{id}.service"),
            executable: INSTALLER_EXECUTABLE,
            arguments: vec![INSTALLER_EXECUTABLE.into(), "serve".into(), id.into()],
            runtime_seconds: INSTALLER_RUNTIME_SECONDS,
            stop_seconds: INSTALLER_STOP_SECONDS,
        })
    }
    pub fn unit(&self) -> &str {
        &self.unit
    }
    pub fn executable(&self) -> &'static str {
        self.executable
    }
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
    pub fn runtime_seconds(&self) -> u64 {
        self.runtime_seconds
    }
    pub fn stop_seconds(&self) -> u64 {
        self.stop_seconds
    }
}
pub fn properties(id: &str) -> Result<Vec<(&'static str, Value<'static>)>> {
    properties_for(&Definition::updater(id)?)
}
pub fn properties_for(definition: &Definition) -> Result<Vec<(&'static str, Value<'static>)>> {
    let starts = vec![(
        definition.executable.to_owned(),
        definition.arguments.clone(),
        false,
    )];
    let mut properties = vec![
        (
            "Description",
            Value::from("enzimOS native package transaction"),
        ),
        ("Type", Value::from("exec")),
        ("ExitType", Value::from("main")),
        ("User", Value::from("0")),
        ("Group", Value::from("0")),
        ("KillMode", Value::from("control-group")),
        ("Restart", Value::from("no")),
        ("SendSIGKILL", Value::from(true)),
        ("RemainAfterExit", Value::from(false)),
        ("Delegate", Value::from(false)),
        (
            "RuntimeMaxUSec",
            Value::from(definition.runtime_seconds * 1_000_000),
        ),
        (
            "TimeoutStopUSec",
            Value::from(definition.stop_seconds * 1_000_000),
        ),
        ("ExecStart", Value::from(starts)),
    ];
    if matches!(
        definition.executable,
        INSTALLER_EXECUTABLE | BACKUP_EXECUTABLE
    ) {
        properties.extend([
            ("RootDirectory", Value::from("")),
            ("RootImage", Value::from("")),
            ("PrivateMounts", Value::from(false)),
            ("PrivateUsers", Value::from(false)),
            ("PrivateNetwork", Value::from(false)),
            ("PrivateTmp", Value::from(false)),
            ("DynamicUser", Value::from(false)),
            ("UMask", Value::from(0o077u32)),
            ("LimitCORE", Value::from(0u64)),
            ("LimitCORESoft", Value::from(0u64)),
            ("LimitNOFILE", Value::from(4096u64)),
            ("LimitNOFILESoft", Value::from(4096u64)),
        ]);
    }
    if definition.executable == BACKUP_EXECUTABLE {
        properties.extend([
            ("MemoryMax", Value::from(1024 * 1024 * 1024u64)),
            ("TasksMax", Value::from(64u64)),
        ]);
    }
    Ok(properties)
}
fn field<T: TryFrom<OwnedValue>>(properties: &Properties, key: &str) -> Result<T> {
    T::try_from(
        properties
            .get(key)
            .ok_or_else(|| Error("worker unit property missing".into()))?
            .try_clone()
            .map_err(|_| Error("worker unit property type".into()))?,
    )
    .map_err(|_| Error("worker unit property type".into()))
}
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub active: String,
    pub pid: u32,
    pub invocation: Vec<u8>,
    pub group: String,
}
/// GetAll spans two interfaces. Bracket the service sample with Unit state
/// reads so an observed transition is retried without replaying a mutation.
pub fn same_unit_epoch(before: &Properties, after: &Properties) -> Result<bool> {
    Ok(
        field::<String>(before, "ActiveState")? == field::<String>(after, "ActiveState")?
            && field::<Vec<u8>>(before, "InvocationID")?
                == field::<Vec<u8>>(after, "InvocationID")?,
    )
}
/// An empty invocation is PID1's null ID, never authority to stop a task.
/// Terminal retirement still requires the caller's original pidfd and cgroup.
pub fn retained_or_terminal(state: &Snapshot, original: &Snapshot) -> bool {
    let terminal = matches!(state.active.as_str(), "inactive" | "failed") && state.pid == 0;
    original.invocation.len() == 16
        && original.invocation.iter().any(|b| *b != 0)
        && (state.pid == original.pid || state.pid == 0)
        && (state.invocation == original.invocation || (terminal && state.invocation.is_empty()))
}
pub fn validate(unit: &Properties, service: &Properties, id: &str) -> Result<Snapshot> {
    validate_for(unit, service, &Definition::updater(id)?)
}
pub fn validate_for(
    unit: &Properties,
    service: &Properties,
    definition: &Definition,
) -> Result<Snapshot> {
    let name = &definition.unit;
    require(
        unit.len() <= 512 && service.len() <= 512,
        "worker property count bound",
    )?;
    let starts: Vec<Exec> = field(service, "ExecStart")?;
    require(
        field::<String>(unit, "Id")? == *name
            && field::<bool>(unit, "Transient")?
            && field::<String>(unit, "FragmentPath")? == format!("/run/systemd/transient/{name}")
            && field::<Vec<String>>(unit, "DropInPaths")?.is_empty()
            && field::<String>(service, "User")? == "0"
            && field::<String>(service, "Group")? == "0"
            && field::<String>(service, "Type")? == "exec"
            && field::<String>(service, "ExitType")? == "main"
            && field::<String>(service, "KillMode")? == "control-group"
            && field::<String>(service, "Restart")? == "no"
            && field::<bool>(service, "SendSIGKILL")?
            && !field::<bool>(service, "RemainAfterExit")?
            && !field::<bool>(service, "Delegate")?
            && field::<u64>(service, "RuntimeMaxUSec")? == definition.runtime_seconds * 1_000_000
            && field::<u64>(service, "TimeoutStopUSec")? == definition.stop_seconds * 1_000_000
            && starts.len() == 1
            && starts[0].0 == definition.executable
            && starts[0].1 == definition.arguments
            && !starts[0].2,
        "worker unit ownership or lifecycle configuration changed",
    )?;
    let active: String = field(unit, "ActiveState")?;
    if matches!(
        definition.executable,
        INSTALLER_EXECUTABLE | BACKUP_EXECUTABLE
    ) {
        require(
            field::<String>(service, "RootDirectory")?.is_empty()
                && field::<String>(service, "RootImage")?.is_empty()
                && !field::<bool>(service, "PrivateMounts")?
                && !field::<bool>(service, "PrivateUsers")?
                && !field::<bool>(service, "PrivateNetwork")?
                && !field::<bool>(service, "PrivateTmp")?
                && !field::<bool>(service, "DynamicUser")?
                && field::<u32>(service, "UMask")? == 0o077
                && field::<u64>(service, "LimitCORE")? == 0
                && field::<u64>(service, "LimitCORESoft")? == 0
                && field::<u64>(service, "LimitNOFILE")? == 4096
                && field::<u64>(service, "LimitNOFILESoft")? == 4096,
            "installer worker must retain the initial live namespace and disable core dumps",
        )?;
    }
    if definition.executable == BACKUP_EXECUTABLE {
        require(
            field::<u64>(service, "MemoryMax")? == 1024 * 1024 * 1024
                && field::<u64>(service, "TasksMax")? == 64,
            "backup worker memory/task bound changed",
        )?;
    }
    let pid: u32 = field(service, "MainPID")?;
    let invocation: Vec<u8> = field(unit, "InvocationID")?;
    let group: String = field(service, "ControlGroup")?;
    require(
        matches!(
            active.as_str(),
            "active" | "activating" | "deactivating" | "inactive" | "failed"
        ) && pid < i32::MAX as u32
            && (invocation.is_empty()
                || (invocation.len() == 16 && invocation.iter().any(|b| *b != 0)))
            && (group == format!("/system.slice/{name}")
                || (group.is_empty()
                    && pid == 0
                    && matches!(active.as_str(), "deactivating" | "inactive" | "failed"))),
        &format!(
            "worker unit state refused: state={active:?} pid={pid} invocation_bytes={} invocation_nonzero={} group_expected={} group_empty={}",
            invocation.len(),
            invocation.iter().any(|b| *b != 0),
            group == format!("/system.slice/{name}"),
            group.is_empty()
        ),
    )?;
    require(
        active != "active" || (pid > 1 && invocation.len() == 16),
        "worker process unavailable",
    )?;
    Ok(Snapshot {
        active,
        pid,
        invocation,
        group,
    })
}
