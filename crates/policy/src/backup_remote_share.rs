// SPDX-License-Identifier: MIT
//! Settings' network-share setup for the NAS copy: set up, test and
//! remove the SMB share under the operation lock.
//!
//! Setup stages the new configuration, share password and repository password
//! as `backup-remote-setup.*` beside the live inputs and checks them against
//! the NAS first: a folder holding an enzimOS repository that the password
//! opens is adopted, an absent repository is created, anything else is
//! refused and the staged files are removed. Only then are the old inputs,
//! pin and SFTP leftovers retired and the staged files moved into place, so a
//! failed setup leaves the previous configuration as it was. Secret bytes go
//! from sealed inputs or the local password file to new files by kernel copy;
//! nothing here prints or logs them.
use super::Runtime;
use crate::{backup_remote_endpoint as endpoint, storage_runtime::Guard};
use enzimos_platform::{
    Error, Result, files, json,
    remote_restic::{self, Task},
    require,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::Path,
};
const ETC: &str = "/etc/enzimos";
/// Live inputs, rotation inputs and SFTP leftovers in `/etc/enzimos`.
const INPUTS: [&str; 9] = [
    "backup-remote.json",
    "backup-remote.password",
    "backup-remote.share-password",
    "backup-remote.identity",
    "backup-remote.hosts",
    "backup-remote-rotation.json",
    "backup-remote-rotation.password",
    "backup-remote-retired.json",
    "backup-remote-retired.password",
];
/// Pin, initialization receipt, rotation record and automatic copy outcome in
/// the control directory.
const RECORDS: [&str; 4] = [
    "backup-remote-pin.json",
    "backup-remote-init.json",
    "backup-remote-rotation.json",
    crate::backup_run_status::REMOTE_COPY,
];
const ATTEMPTS: &str = "backup-remote-initialization";
const STAGED: [&str; 3] = [
    "backup-remote-setup.json",
    "backup-remote-setup.share-password",
    "backup-remote-setup.password",
];
/// Public codes of this module; the backend passes exactly these to callers.
pub const CODES: [&str; 13] = [
    "remote-share-invalid",
    "remote-share-secret-refused",
    "remote-share-not-configured",
    "remote-backup-reconfigure-as-smb",
    "remote-repository-password-required",
    "remote-repository-password-not-expected",
    "remote-share-unreachable",
    "remote-share-sign-in-refused",
    "remote-share-not-found",
    "remote-share-smb3-unsupported",
    "remote-share-unavailable",
    "remote-repository-password-refused",
    "remote-repository-foreign",
];
/// Also public: an unfinished compromise rotation of the current share.
pub const ROTATION_UNFINISHED: &str = "remote-rotation-unfinished";
/// The public code an error carries (`code` or `code: detail`), if any.
pub fn code(error: &Error) -> Option<&'static str> {
    let head = error.0.split(':').next().unwrap_or("");
    CODES
        .iter()
        .chain(std::iter::once(&ROTATION_UNFINISHED))
        .copied()
        .find(|c| *c == head)
}
fn refuse(code: &'static str, detail: &str) -> Error {
    Error(format!("{code}: {detail}"))
}
/// A Settings request: the share fields of `backup-remote.json` (schema 2),
/// without a schema. Returns the configuration document.
///
/// # Errors
/// `remote-share-invalid` for unknown or missing fields or a value outside
/// the closed share syntax.
pub fn selection(v: &Value) -> Result<Value> {
    let fields = if v.get("domain").is_some() {
        "server share folder user domain"
    } else {
        "server share folder user"
    };
    json::fields(v, fields).map_err(|e| refuse("remote-share-invalid", &e.0))?;
    let mut configuration = v.clone();
    configuration["schema"] = value!(2);
    endpoint::validate(&configuration).map_err(|e| refuse("remote-share-invalid", &e.0))?;
    Ok(configuration)
}
/// What one authenticated identity query found in the share folder.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    /// The password opens the repository with this ID.
    Opened(String),
    /// There is no repository in the folder.
    Absent,
    /// A repository is there, but the password does not open it.
    PasswordRefused,
    /// The share stopped answering or Restic failed otherwise.
    Unknown(&'static str),
}
/// Classify a `restic cat config` run (exit codes of Restic 0.17+, with its
/// messages as a fallback).
pub fn probe(code: Option<i32>, signal: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Probe {
    let text = String::from_utf8_lossy(&stderr[..stderr.len().min(65536)]);
    if code == Some(0) {
        return json::decode(stdout, 32768)
            .ok()
            .filter(|d| matches!(d["version"].as_u64(), Some(1 | 2)))
            .and_then(|d| d["id"].as_str().map(str::to_owned))
            .filter(|id| crate::identity::sha(id).is_ok())
            .map_or(Probe::Unknown("remote-share-unavailable"), Probe::Opened);
    }
    if code == Some(12) || text.contains("wrong password or no key found") {
        Probe::PasswordRefused
    } else if code == Some(10)
        || text.contains("unable to open config file")
        || text.contains("repository does not exist")
    {
        Probe::Absent
    } else if signal == Some(libc::SIGALRM) || text.contains("host is down") {
        Probe::Unknown("remote-share-unreachable")
    } else {
        Probe::Unknown("remote-share-unavailable")
    }
}
/// An existing repository is adopted only when every snapshot in it is an
/// enzimOS whole-system backup point (an empty repository qualifies).
///
/// # Errors
/// `remote-repository-foreign` for anything else.
pub fn adoptable(inventory: &Value) -> Result<usize> {
    let rows = crate::backup_remote_points::inventory(inventory)
        .map_err(|e| refuse("remote-repository-foreign", &e.0))?;
    for (id, row) in &rows {
        crate::backup_points::scope(row, id)
            .map_err(|e| refuse("remote-repository-foreign", &e.0))?;
    }
    Ok(rows.len())
}
/// An unfinished rotation of the share in use blocks setup and removal. A
/// rotation recorded with SFTP pins is an SFTP leftover: it can never finish
/// and is retired like the rest.
fn rotation_blocks(control: &Path) -> Result<()> {
    let path = control.join("backup-remote-rotation.json");
    let Some(file) = optional(&path)? else {
        return Ok(());
    };
    let bytes = files::read_file(
        &file,
        crate::backup_remote_record::ROTATION_LIMIT,
        None,
        true,
    )?;
    let record = json::decode(&bytes, crate::backup_remote_record::ROTATION_LIMIT)?;
    let sftp = record["old_identity"]["schema"] == 1
        || record["old_identity"].get("hosts_sha256").is_some();
    require(
        sftp || matches!(record["phase"].as_str(), Some("complete" | "abandoned")),
        ROTATION_UNFINISHED,
    )
}
fn optional(path: &Path) -> Result<Option<File>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => Ok(Some(File::open(path)?)),
        Ok(_) => Err(Error(format!("{} is not a plain file", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn remove(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
/// Remove the NAS inputs (live, rotation and SFTP leftovers), the pin, the
/// initialization receipt and attempts and a finished or SFTP rotation
/// record. Retrieval receipts and everything else stay. The data on the NAS
/// is not touched. Returns the names removed.
///
/// # Errors
/// `remote-rotation-unfinished`, or a file system error part way.
pub fn retire(etc: &Path, control: &Path) -> Result<Vec<String>> {
    rotation_blocks(control)?;
    let mut removed = Vec::new();
    for name in INPUTS {
        if remove(&etc.join(name))? {
            removed.push(name.to_owned());
        }
    }
    for name in RECORDS {
        if remove(&control.join(name))? {
            removed.push(name.to_owned());
        }
    }
    let attempts = control.join(ATTEMPTS);
    if std::fs::symlink_metadata(&attempts).is_ok() {
        std::fs::remove_dir_all(&attempts)?;
        removed.push(ATTEMPTS.to_owned());
    }
    Ok(removed)
}
/// One new Root-only 0600 file.
fn create(path: &Path) -> Result<File> {
    remove(path)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}
/// The repository password: the local backup's own, or a sealed input when
/// there is no local backup yet.
pub enum Repository<'a> {
    /// Copy `/etc/enzimos/backup.password`.
    Local,
    /// A password the person entered.
    Entered(&'a enzimos_platform::secret::Retained),
}
/// Whether the local backup is set up (its configuration and password exist).
pub fn local_backup_configured() -> bool {
    Path::new(crate::backup_configuration::PATH).is_file()
        && Path::new(crate::backup_configuration::PASSWORD).is_file()
}
struct Staged {
    configuration: Value,
    bytes: Vec<u8>,
}
impl Staged {
    fn write(
        configuration: &Value,
        share: &enzimos_platform::secret::Retained,
        repository: &Repository<'_>,
    ) -> Result<Self> {
        let etc = Path::new(ETC);
        let mut bytes = json::canonical(configuration)?;
        bytes.push(b'\n');
        let mut file = create(&etc.join(STAGED[0]))?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
        share
            .copy_into_new(&create(&etc.join(STAGED[1]))?)
            .map_err(|e| refuse("remote-share-secret-refused", &e.0))?;
        let output = create(&etc.join(STAGED[2]))?;
        match repository {
            Repository::Entered(input) => input
                .copy_into_new(&output)
                .map_err(|e| refuse("remote-share-secret-refused", &e.0))?,
            Repository::Local => {
                let mut source = File::open(crate::backup_configuration::PASSWORD)?;
                let m = source.metadata()?;
                require(
                    m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0,
                    "protected local backup password required",
                )?;
                // File-to-file copy runs in the kernel (copy_file_range).
                std::io::copy(&mut source, &mut &output)?;
                output.sync_all()?;
            }
        }
        Ok(Self {
            configuration: configuration.clone(),
            bytes,
        })
    }
    fn file(index: usize) -> Result<File> {
        Ok(File::open(Path::new(ETC).join(STAGED[index]))?)
    }
    fn discard() {
        for name in STAGED {
            let _ = remove(&Path::new(ETC).join(name));
        }
    }
    /// Move the staged files to the live names.
    fn publish(self) -> Result<Value> {
        let etc = Path::new(ETC);
        for (staged, live) in STAGED.iter().zip([
            "backup-remote.json",
            "backup-remote.share-password",
            "backup-remote.password",
        ]) {
            std::fs::rename(etc.join(staged), etc.join(live))?;
        }
        File::open(etc)?.sync_all()?;
        Ok(value!({"configuration_sha256":json::sha256(&self.bytes)}))
    }
}
impl Runtime {
    fn share_query(
        &self,
        attachment: &std::sync::Arc<enzimos_platform::remote_mount_child::Prepared>,
        endpoint: &remote_restic::Endpoint,
        task: Task,
        credential: &File,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<enzimos_platform::process::Output> {
        boundary()?;
        let output = remote_restic::rotation_read(
            attachment,
            endpoint,
            task,
            &"0".repeat(64),
            self.image.descriptor()?,
            credential,
            &self.scratch,
            boundary,
        )?;
        boundary()?;
        self.empty()?;
        Ok(output)
    }
    fn share_probe(
        &self,
        attachment: &std::sync::Arc<enzimos_platform::remote_mount_child::Prepared>,
        endpoint: &remote_restic::Endpoint,
        credential: &File,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Probe> {
        let out = self.share_query(
            attachment,
            endpoint,
            Task::RemoteIdentity,
            credential,
            boundary,
        )?;
        Ok(probe(
            out.status.code(),
            out.status.signal(),
            &out.stdout,
            &out.stderr,
        ))
    }
}
fn probe_failure(probe: &Probe) -> Error {
    match probe {
        Probe::PasswordRefused => refuse(
            "remote-repository-password-refused",
            "the folder holds a repository this password does not open",
        ),
        Probe::Unknown(code) => refuse(code, "the repository could not be read"),
        Probe::Opened(_) | Probe::Absent => refuse("remote-share-unavailable", "unexpected state"),
    }
}
/// Set up the NAS share (see the module documentation).
///
/// # Errors
/// The public [`CODES`] and [`ROTATION_UNFINISHED`]; `service-busy` while
/// other backup work holds the lock.
pub fn setup_locked(
    guard: &Guard,
    lock: &files::Lock,
    request: &Value,
    share: &enzimos_platform::secret::Retained,
    repository: Repository<'_>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    let configuration = selection(request)?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()
    };
    permission()?;
    let control = Path::new(crate::operation::CONTROL);
    rotation_blocks(control)?;
    let local = matches!(repository, Repository::Local);
    Staged::discard();
    let staged =
        Staged::write(&configuration, share, &repository).inspect_err(|_| Staged::discard())?;
    let outcome = (|| {
        let runtime = Runtime::create(&files::random_hex(16)?, &mut permission)?;
        let (attachment, endpoint) = super::remote_share(&staged.configuration, &Staged::file(1)?)?;
        let credential = Staged::file(2)?;
        let mut boundary = || {
            permission()?;
            runtime.recheck()?;
            attachment.recheck()
        };
        let (id, created) =
            match runtime.share_probe(&attachment, &endpoint, &credential, &mut boundary)? {
                Probe::Opened(id) => {
                    let out = runtime.share_query(
                        &attachment,
                        &endpoint,
                        Task::RemoteInventory,
                        &credential,
                        &mut boundary,
                    )?;
                    require(
                        out.status.code() == Some(0),
                        "remote-share-unavailable: snapshot list failed",
                    )?;
                    adoptable(&json::decode(
                        &out.stdout,
                        crate::backup_remote_points::LIMIT,
                    )?)?;
                    (id, false)
                }
                Probe::Absent => {
                    boundary()?;
                    let out = remote_restic::initialize(
                        &attachment,
                        &endpoint,
                        runtime.image.descriptor()?,
                        &credential,
                        &runtime.scratch,
                        &mut boundary,
                    )?;
                    runtime.empty()?;
                    require(
                        out.status.code() == Some(0),
                        "remote-share-unavailable: the repository could not be created",
                    )?;
                    match runtime.share_probe(&attachment, &endpoint, &credential, &mut boundary)? {
                        Probe::Opened(id) => (id, true),
                        other => return Err(probe_failure(&other)),
                    }
                }
                other => return Err(probe_failure(&other)),
            };
        Ok::<_, Error>((id, created))
    })();
    let (id, created) = match outcome {
        Ok(found) => found,
        Err(error) => {
            Staged::discard();
            return Err(error);
        }
    };
    permission()?;
    let removed = retire(Path::new(ETC), control)?;
    let binding = staged.publish()?;
    let pin = crate::backup_remote_record::new_pin(&value!(id), &binding)?;
    let receipt = value!({"schema":1,"configuration_sha256":binding["configuration_sha256"],"created_boot":crate::operation::boot_id()?});
    crate::backup_remote_record::initialization(&receipt)?;
    for (name, body) in [
        ("backup-remote-init.json", &receipt),
        ("backup-remote-pin.json", &pin),
    ] {
        let mut bytes = json::canonical(body)?;
        bytes.push(b'\n');
        files::atomic(&control.join(name), &bytes, 0o600, Some(0), false)?;
    }
    permission()?;
    Ok(
        value!({"schema":1,"status":"remote-share-configured","repository":if created {"created"} else {"adopted"},
        "repository_id":id,"repository_password":if local {"local-backup"} else {"entered"},
        "retired":removed,"scheduler_enabled":false}),
    )
}
/// Test the configured share: whether the NAS answers, accepts the share
/// account, and what the repository folder holds. Failures of the share are
/// results here, not errors.
///
/// # Errors
/// `remote-share-not-configured`, `remote-backup-reconfigure-as-smb`,
/// `service-busy`, or an internal failure.
pub fn test_locked(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    let mut permission = || {
        authorize()?;
        guard.recheck()?;
        lock.recheck()
    };
    permission()?;
    let Some(file) = optional(&Path::new(ETC).join("backup-remote.json"))? else {
        return Err(refuse(
            "remote-share-not-configured",
            "no NAS share is set up",
        ));
    };
    let configuration = json::decode(&files::read_file(&file, 32768, Some(0), true)?, 32768)?;
    require(
        !endpoint::sftp(&configuration),
        "remote-backup-reconfigure-as-smb",
    )?;
    let inputs = crate::backup_remote_inputs::Inputs::observe(guard)
        .map_err(|e| refuse("remote-share-not-configured", &e.0))?;
    let descriptors = inputs.descriptors(guard)?;
    let share = File::from(descriptors[2].try_clone_to_owned()?);
    let credential = File::from(descriptors[1].try_clone_to_owned()?);
    let pin = optional(&Path::new(crate::operation::CONTROL).join("backup-remote-pin.json"))?
        .map(|f| files::read_file(&f, 32768, Some(0), true))
        .transpose()?
        .map(|b| json::decode(&b, 32768))
        .transpose()?;
    let runtime = Runtime::create(&files::random_hex(16)?, &mut permission)?;
    let result = |reachable: bool, signed_in: bool, repository: &str, reason: Option<&str>| {
        value!({"schema":1,"status":"remote-share-tested","reachable":reachable,"signed_in":signed_in,
            "repository":repository,"repository_id":pin.as_ref().map(|p| p["repository_id"].clone()),"reason":reason})
    };
    let (attachment, endpoint) = match super::remote_share(inputs.configuration(guard)?, &share) {
        Ok(found) => found,
        Err(error) => {
            let reason = code(&error).unwrap_or("remote-share-unavailable");
            return Ok(result(false, false, "unknown", Some(reason)));
        }
    };
    let mut boundary = || {
        permission()?;
        runtime.recheck()?;
        inputs.recheck(guard)?;
        attachment.recheck()
    };
    let found = match runtime.share_probe(&attachment, &endpoint, &credential, &mut boundary) {
        Ok(found) => found,
        Err(error) => match code(&error) {
            Some(reason) => {
                let reachable = reason != "remote-share-unreachable";
                return Ok(result(reachable, false, "unknown", Some(reason)));
            }
            None => return Err(error),
        },
    };
    Ok(match found {
        Probe::Opened(id) => match &pin {
            Some(p) if p["repository_id"] == id.as_str() => result(true, true, "ready", None),
            Some(_) => result(
                true,
                true,
                "different-repository",
                Some("remote-repository-foreign"),
            ),
            None => result(true, true, "not-pinned", None),
        },
        Probe::Absent => result(true, true, "absent", None),
        Probe::PasswordRefused => result(
            true,
            true,
            "password-refused",
            Some("remote-repository-password-refused"),
        ),
        Probe::Unknown(reason) => result(
            reason != "remote-share-unreachable",
            true,
            "unknown",
            Some(reason),
        ),
    })
}
/// Remove the share setup; the data on the NAS stays.
///
/// # Errors
/// [`ROTATION_UNFINISHED`], `service-busy`, or a file system failure.
pub fn remove_locked(
    guard: &Guard,
    lock: &files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    authorize()?;
    guard.recheck()?;
    lock.recheck()?;
    Staged::discard();
    let removed = retire(Path::new(ETC), Path::new(crate::operation::CONTROL))?;
    authorize()?;
    Ok(
        value!({"schema":1,"status":"remote-share-removed","retired":removed,"nas_data_deleted":false}),
    )
}
/// Whether a configured SMB share with its passwords and pinned repository is
/// in place, so a new local backup is copied to it. Metadata only.
pub fn copy_ready() -> bool {
    let Ok(Some(bytes)) = enzimos_platform::files::read_optional(
        &Path::new(ETC).join("backup-remote.json"),
        32768,
        Some(0),
        true,
    ) else {
        return false;
    };
    let configured = json::decode(&bytes, 32768).is_ok_and(|v| endpoint::validate(&v).is_ok());
    let ready = readiness(&bytes);
    configured
        && [
            "share_password_ready",
            "repository_password_ready",
            "repository_ready",
        ]
        .iter()
        .all(|key| ready[*key] == true)
}
/// Readiness for status: metadata only, no secret bytes are read.
pub(crate) fn readiness(configuration_bytes: &[u8]) -> Value {
    let secret = |name: &str| {
        std::fs::symlink_metadata(Path::new(ETC).join(name)).is_ok_and(|m| {
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o077 == 0
                && (1..=4096).contains(&m.len())
        })
    };
    let pin = std::fs::read(Path::new(crate::operation::CONTROL).join("backup-remote-pin.json"))
        .ok()
        .and_then(|b| json::decode(&b, 32768).ok())
        .filter(|p| crate::backup_remote_record::pin(p).is_ok());
    let repository_ready = pin
        .as_ref()
        .is_some_and(|p| p["configuration_sha256"] == json::sha256(configuration_bytes));
    value!({"share_password_ready":secret("backup-remote.share-password"),
        "repository_password_ready":secret("backup-remote.password"),
        "repository_ready":repository_ready,
        "repository_id":if repository_ready {pin.map(|p| p["repository_id"].clone())} else {None}})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_repository_password_is_refused_not_overwritten() {
        let wrong = b"Fatal: wrong password or no key found\n";
        assert_eq!(probe(Some(12), None, b"", wrong), Probe::PasswordRefused);
        assert_eq!(probe(Some(1), None, b"", wrong), Probe::PasswordRefused);
        let error = probe_failure(&Probe::PasswordRefused);
        assert_eq!(code(&error), Some("remote-repository-password-refused"));
        // A child ended by the mount alarm is a NAS that stopped answering.
        assert_eq!(
            probe(None, Some(libc::SIGALRM), b"", b""),
            Probe::Unknown("remote-share-unreachable")
        );
    }
    #[test]
    fn live_and_staged_share_inputs_never_enter_a_backup() {
        for name in INPUTS.iter().chain(&STAGED) {
            let path = format!("/backup-source/system/etc/enzimos/{name}");
            assert!(
                enzimos_platform::backup_command::EXCLUDES.contains(&path.as_str()),
                "{path} is backed up"
            );
        }
    }
}
