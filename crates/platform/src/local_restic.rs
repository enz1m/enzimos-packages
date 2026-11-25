// SPDX-License-Identifier: MIT
//! Closed local consumer roles; no caller-supplied command or environment.
use crate::{Result, files, mount_identity, process, require};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    process::Command,
    time::Duration,
};
/// Closed local repository workflow commands run by [`execute`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    /// Create a new repository.
    Initialize,
    /// List keys to prove the password opens the repository.
    Authenticate,
    /// List keys with the input-checking profile.
    AuthenticateInput,
    /// Check repository metadata without reading pack data.
    CheckMetadata,
}
impl Task {
    /// Stable wire name accepted by [`Task::parse`].
    pub fn name(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Authenticate => "authenticate",
            Self::AuthenticateInput => "authenticate-input",
            Self::CheckMetadata => "check-metadata",
        }
    }
    /// Parse a wire name produced by [`Task::name`].
    ///
    /// # Errors
    ///
    /// Fails for any other name.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "initialize" => Ok(Self::Initialize),
            "authenticate" => Ok(Self::Authenticate),
            "authenticate-input" => Ok(Self::AuthenticateInput),
            "check-metadata" => Ok(Self::CheckMetadata),
            _ => Err(crate::Error("closed local Restic task required".into())),
        }
    }
    fn profile(self) -> &'static str {
        if self == Self::AuthenticateInput {
            "enzimos-restic-input-check"
        } else {
            "enzimos-restic-provision"
        }
    }
    fn arguments(self) -> Vec<&'static str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
        ];
        args.extend(match self {
            Self::Initialize => &["init"][..],
            Self::Authenticate | Self::AuthenticateInput => &["--no-lock", "key", "list", "--json"],
            Self::CheckMetadata => &["check"],
        });
        args
    }
    /// Wall-clock bound for the Restic process.
    pub fn timeout(self) -> Duration {
        if self == Self::CheckMetadata {
            CHECK_TIMEOUT
        } else {
            Duration::from_secs(120)
        }
    }
    /// Byte bound on captured standard output.
    pub fn output_limit(self) -> usize {
        if matches!(self, Self::Authenticate | Self::AuthenticateInput) {
            32768
        } else {
            512 * 1024
        }
    }
}
/// Query-only inventory is deliberately absent from the worker task parser.
#[derive(Clone, Copy)]
pub enum CredentialReview {
    /// List repository keys.
    Keys,
    /// Check repository metadata.
    Metadata,
}
impl CredentialReview {
    fn task(self) -> Task {
        match self {
            Self::Keys => Task::Authenticate,
            Self::Metadata => Task::CheckMetadata,
        }
    }
}
/// Closed replacement-repository mutation roles. Not reachable through Task::parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationPrepare {
    /// Create the replacement repository.
    Initialize,
    /// Copy snapshots into the replacement repository.
    Copy,
    /// Verify all pack data of the replacement repository.
    ReadData,
}
impl RotationPrepare {
    fn arguments(self) -> Vec<&'static str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
            "--no-lock",
        ];
        match self {
            Self::Initialize => args.extend([
                "init",
                "--copy-chunker-params",
                "--from-repo",
                "@fd-dir:2",
                "--from-password-file",
                "@fd:3",
            ]),
            Self::Copy => args.extend([
                "copy",
                "--from-repo",
                "@fd-dir:2",
                "--from-password-file",
                "@fd:3",
            ]),
            Self::ReadData => args.extend(["check", "--read-data"]),
        }
        args
    }
}

/// Fixed read-only selected-file queries. This role is absent from Task::parse.
/// Rotation authentication and inventory only; never initialization/copy/forget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationTask {
    /// List repository keys.
    Keys,
    /// List snapshots.
    Points,
}
impl RotationTask {
    fn arguments(self) -> Vec<&'static str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
            "--no-lock",
        ];
        args.extend(match self {
            Self::Keys => &["key", "list", "--json"][..],
            Self::Points => &["snapshots", "--json"][..],
        });
        args
    }
}
/// Read-only queries about one selected home file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectiveTask {
    /// Resolve the selected snapshot.
    Snapshot,
    /// List the selected path.
    Listing,
    /// List the selected directory tree.
    TreeListing,
    /// Stream the selected file's content.
    Dump,
}
/// A full snapshot ID and a canonical path below `/backup-source/home/`.
#[derive(Clone, Debug)]
pub struct SelectedFile {
    snapshot: String,
    path: String,
}
impl SelectedFile {
    /// Validate a selected snapshot and home path.
    ///
    /// # Errors
    ///
    /// Fails unless `snapshot` is a 64-digit lowercase hex ID and `path` is a canonical path below
    /// `/backup-source/home/` with allowed characters.
    pub fn new(snapshot: &str, path: &str) -> Result<Self> {
        require(
            snapshot.len() == 64
                && snapshot
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "full selected snapshot required",
        )?;
        let tail = path
            .strip_prefix("/backup-source/home/")
            .ok_or_else(|| crate::Error("qualified selected home path required".into()))?;
        let parts = tail.split('/').collect::<Vec<_>>();
        require(
            path.len() <= 1024
                && parts.len() >= 2
                && parts.iter().enumerate().all(|(i, p)| {
                    !p.is_empty()
                        && !matches!(*p, "." | ".." | ".snapshots")
                        && p.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || b"_.-".contains(&b) || (i > 0 && b == b' ')
                        })
                }),
            "canonical selected file path required",
        )?;
        Ok(Self {
            snapshot: snapshot.into(),
            path: path.into(),
        })
    }
    fn arguments(&self, task: SelectiveTask) -> Vec<&str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
            "--no-lock",
        ];
        match task {
            SelectiveTask::Snapshot => args.extend(["snapshots", self.snapshot.as_str(), "--json"]),
            SelectiveTask::Listing => {
                args.extend(["ls", "--json", self.snapshot.as_str(), self.path.as_str()]);
            }
            SelectiveTask::TreeListing => args.extend([
                "ls",
                "--json",
                "--recursive",
                self.snapshot.as_str(),
                self.path.as_str(),
            ]),
            SelectiveTask::Dump => {
                args.extend(["dump", self.snapshot.as_str(), self.path.as_str()]);
            }
        }
        args
    }
}
/// Closed system staging command; target is only the independently supplied FD.
#[derive(Clone)]
pub struct RestoreSystem {
    snapshot: String,
}
impl RestoreSystem {
    /// Validate the snapshot to restore.
    ///
    /// # Errors
    ///
    /// Fails unless `snapshot` is a 64-digit lowercase hex ID.
    pub fn new(snapshot: &str) -> Result<Self> {
        require(
            snapshot.len() == 64
                && snapshot
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "full system restore snapshot required",
        )?;
        Ok(Self {
            snapshot: snapshot.into(),
        })
    }
    fn arguments(&self) -> Vec<&str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
            "--no-lock",
            "restore",
            &self.snapshot,
            "--target",
            "@fd-dir:2",
            "--verify",
            "--exclude",
            "/backup-source/home",
        ];
        for pattern in crate::backup_command::EXCLUDES {
            args.extend(["--exclude", *pattern]);
        }
        args
    }
}
/// Closed complete RAM staging command; target is only the independently supplied FD.
#[derive(Clone)]
pub struct RestoreComplete {
    snapshot: String,
}
impl RestoreComplete {
    /// Validate the snapshot to restore.
    ///
    /// # Errors
    ///
    /// Fails unless `snapshot` is a 64-digit lowercase hex ID.
    pub fn new(snapshot: &str) -> Result<Self> {
        require(
            snapshot.len() == 64
                && snapshot
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "full complete restore snapshot required",
        )?;
        Ok(Self {
            snapshot: snapshot.into(),
        })
    }
    fn arguments(&self) -> Vec<&str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
            "--no-lock",
            "restore",
            &self.snapshot,
            "--target",
            "@fd-dir:2",
            "--verify",
        ];
        for pattern in crate::backup_command::EXCLUDES {
            args.extend(["--exclude", *pattern]);
        }
        args
    }
}
/// Remove paths from every enzimOS whole-system point (`restic rewrite
/// --forget`). Only home paths under `/backup-source/home/` written literally.
#[derive(Clone)]
pub struct Rewrite {
    paths: Vec<String>,
}
impl Rewrite {
    /// # Errors
    /// Refuses empty, too many or non-literal home paths.
    pub fn new(paths: &[String]) -> Result<Self> {
        require(
            !paths.is_empty()
                && paths.len() <= 1000
                && paths.iter().all(|p| {
                    p.strip_prefix("/backup-source/home/").is_some_and(|rest| {
                        rest.contains('/') && crate::fsview::relative(Path::new(rest)).is_ok()
                    }) && crate::backup_rules::restic_pattern(p).as_deref() == Some(p.as_str())
                }),
            "closed literal home removal paths required",
        )?;
        Ok(Self {
            paths: paths.to_vec(),
        })
    }
    fn arguments(&self) -> Vec<&str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
            "rewrite",
            "--forget",
            "--host",
            "enzimos",
            "--tag",
            "enzimos-whole-linux",
        ];
        for path in &self.paths {
            args.extend(["--exclude", path.as_str()]);
        }
        args
    }
}
/// Run a removal rewrite under the retention profile.
///
/// # Errors
/// Fails when the role cannot run.
pub fn rewrite(
    rewrite: &Rewrite,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role(
        Consumer::Rewrite(rewrite.clone()),
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Fixed explicit snapshot IDs only; host/tag filters cannot delete mixed-tag points.
#[derive(Clone)]
pub struct Retention {
    identifiers: Vec<String>,
}
impl Retention {
    /// Validate the snapshots to forget.
    ///
    /// # Errors
    ///
    /// Fails unless there are at most 4096 strictly ascending 64-digit lowercase hex IDs.
    pub fn new(identifiers: &[String]) -> Result<Self> {
        require(
            identifiers.len() <= 4096
                && identifiers.windows(2).all(|v| v[0] < v[1])
                && identifiers.iter().all(|id| {
                    id.len() == 64
                        && id
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                }),
            "closed retention snapshot IDs required",
        )?;
        Ok(Self {
            identifiers: identifiers.to_vec(),
        })
    }
    fn arguments(&self) -> Vec<&str> {
        let mut args = vec![
            "--repo",
            "@fd-dir:0",
            "--password-file",
            "@fd:1",
            "--no-cache",
        ];
        if self.identifiers.is_empty() {
            args.push("prune");
        } else {
            args.push("forget");
            args.extend(self.identifiers.iter().map(String::as_str));
            args.push("--prune");
        }
        args
    }
}
#[derive(Clone)]
pub(crate) enum Consumer {
    Remote(crate::remote_restic::Invocation),
    Workflow(Task),
    CredentialReview(CredentialReview),
    CredentialEnroll,
    Retain(Retention),
    Rewrite(Rewrite),
    RestoreSystem(RestoreSystem),
    RestoreComplete(RestoreComplete),
    Points,
    Selective(SelectedFile, SelectiveTask),
    SelectivePlan(SelectedFile, SelectiveTask),
    RotationRead(RotationTask),
    RotationPrepare(RotationPrepare),
    Backup(std::sync::Arc<crate::backup_mount_child::Prepared>),
}
impl Consumer {
    fn profile(&self) -> &'static str {
        match self {
            Self::Remote(task) => task.profile(),
            Self::Workflow(task) => task.profile(),
            Self::CredentialReview(_) => "enzimos-restic-credential-review",
            Self::CredentialEnroll => "enzimos-restic-credential-enroll",
            Self::Retain(_) | Self::Rewrite(_) => "enzimos-restic-retain",
            Self::RestoreSystem(_) => "enzimos-restic-restore-system",
            Self::RestoreComplete(_) => "enzimos-restic-restore-complete",
            Self::Points => "enzimos-restic-points",
            Self::Selective(..) => "enzimos-restic-selective",
            Self::SelectivePlan(..) => "enzimos-restic-selective-plan",
            Self::RotationRead(..) => "enzimos-restic-rotation-read",
            Self::RotationPrepare(..) => "enzimos-restic-native-rotation-prepare",
            Self::Backup(_) => "enzimos-restic-native-backup",
        }
    }
    fn arguments(&self) -> Vec<&str> {
        match self {
            Self::Remote(task) => task.arguments(),
            Self::Workflow(task) => task.arguments(),
            Self::RotationRead(task) => task.arguments(),
            Self::RotationPrepare(task) => task.arguments(),
            Self::Selective(selection, task) | Self::SelectivePlan(selection, task) => {
                selection.arguments(*task)
            }
            Self::CredentialReview(task) => task.task().arguments(),
            Self::Retain(retention) => retention.arguments(),
            Self::Rewrite(rewrite) => rewrite.arguments(),
            Self::RestoreSystem(restore) => restore.arguments(),
            Self::RestoreComplete(restore) => restore.arguments(),
            Self::CredentialEnroll => vec![
                "--repo",
                "@fd-dir:0",
                "--password-file",
                "@fd:1",
                "--no-cache",
                "key",
                "add",
                "--new-password-file",
                "@fd:2",
            ],
            Self::Backup(prepared) => {
                let mut args = vec![
                    "--repo",
                    "@fd-dir:0",
                    "--password-file",
                    "@fd:1",
                    "--no-cache",
                ];
                args.extend(prepared.arguments().iter().map(String::as_str));
                args
            }
            Self::Points => vec![
                "--repo",
                "@fd-dir:0",
                "--password-file",
                "@fd:1",
                "--no-cache",
                "--no-lock",
                "snapshots",
                "--json",
            ],
        }
    }
    fn timeout(&self) -> Duration {
        match self {
            Self::Remote(task) => task.timeout(),
            Self::Workflow(task) => task.timeout(),
            Self::RotationRead(..) => Duration::from_secs(120),
            Self::RotationPrepare(RotationPrepare::Copy | RotationPrepare::ReadData) => {
                BACKUP_TIMEOUT
            }
            Self::RotationPrepare(..) => Duration::from_secs(3000),
            Self::CredentialReview(task) => task.task().timeout(),
            Self::CredentialEnroll => Duration::from_secs(120),
            Self::Retain(_) | Self::Rewrite(_) => Duration::from_secs(86400),
            Self::RestoreSystem(_) | Self::RestoreComplete(_) => Duration::from_secs(86400),
            Self::Points | Self::SelectivePlan(..) => Duration::from_secs(5),
            Self::Selective(_, task) => Duration::from_secs(if *task == SelectiveTask::Dump {
                300
            } else {
                120
            }),
            Self::Backup(_) => BACKUP_TIMEOUT,
        }
    }
    /// Inactivity limit: only roles that print throttled progress while
    /// healthy are watched.
    pub(crate) fn stall_limit(&self) -> Option<Duration> {
        match self {
            Self::Backup(_)
            | Self::RotationPrepare(RotationPrepare::Copy | RotationPrepare::ReadData) => {
                Some(BACKUP_STALL)
            }
            Self::Remote(invocation) => invocation.stall_limit(),
            _ if self.metadata_check() => Some(CHECK_STALL),
            _ => None,
        }
    }
    fn metadata_check(&self) -> bool {
        matches!(
            self,
            Self::Workflow(Task::CheckMetadata)
                | Self::CredentialReview(CredentialReview::Metadata)
        )
    }
    /// Long roles that print throttled progress: the JSON backup, the
    /// repository copies, `check --read-data` and the metadata checks.
    pub(crate) fn progresses(&self) -> bool {
        match self {
            Self::Backup(_)
            | Self::RotationPrepare(RotationPrepare::Copy | RotationPrepare::ReadData) => true,
            Self::Remote(invocation) => invocation.prints_progress(),
            _ => self.metadata_check(),
        }
    }
    fn output_limit(&self) -> usize {
        match self {
            Self::Remote(_) => crate::remote_restic::OUTPUT_LIMIT,
            Self::Workflow(task) => task.output_limit(),
            Self::RotationRead(..) => 4 * 1024 * 1024,
            Self::RotationPrepare(..) => 2 * 1024 * 1024,
            Self::CredentialReview(task) => task.task().output_limit(),
            Self::CredentialEnroll => 512 * 1024,
            Self::Retain(_) | Self::Rewrite(_) => 2 * 1024 * 1024,
            Self::RestoreSystem(_) | Self::RestoreComplete(_) => 2 * 1024 * 1024,
            Self::SelectivePlan(..) => 1024 * 1024,
            Self::Points => 512 * 1024,
            Self::Selective(_, task) => {
                if *task == SelectiveTask::Dump {
                    16 * 1024 * 1024
                } else {
                    1024 * 1024
                }
            }
            Self::Backup(_) => 2 * 1024 * 1024,
        }
    }
}
fn enforce_role(task: &Consumer, bytes: &[u8]) -> Result<()> {
    require(
        bytes.len() <= 1024 * 1024,
        "AppArmor profile inventory bound",
    )?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| crate::Error("AppArmor inventory encoding".into()))?;
    let rows = text
        .lines()
        .filter(|line| {
            line.strip_prefix(task.profile())
                .is_some_and(|suffix| suffix.starts_with(' '))
        })
        .collect::<Vec<_>>();
    require(
        rows == [format!("{} (enforce)", task.profile())],
        "required local Restic profile is not uniquely enforced",
    )
}
pub(crate) fn require_enforced(task: &Consumer) -> Result<()> {
    let bytes = files::read_kernel(
        Path::new("/sys/kernel/security/apparmor/profiles"),
        1024 * 1024,
    )?;
    enforce_role(task, &bytes)
}
/// Only the owned Root consumer calls this, after independently checking its
/// original caller, durable intent and reviewed filesystem. No plaintext reads.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn execute(
    task: Task,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role(
        Consumer::Workflow(task),
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Display-only snapshots use a distinct enforced read-only profile and five-second bound.
/// No caller-provided arguments, initialization, locking, cache or scratch creation.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn points(
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role(
        Consumer::Points,
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Original admitted preparation and fresh caller checks are mandatory; this
/// returns command observations only, never snapshot cleanup or backup receipts.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn backup(
    prepared: &std::sync::Arc<crate::backup_mount_child::Prepared>,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    let mut check = || {
        boundary()?;
        prepared.recheck()
    };
    check()?;
    execute_role(
        Consumer::Backup(std::sync::Arc::clone(prepared)),
        image,
        repository,
        credential,
        scratch,
        &mut check,
    )
}
/// Independent fixed review role. It cannot initialize, add/remove keys or
/// substitute a caller-selected command, profile or credential path.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn credential_review(
    task: CredentialReview,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role(
        Consumer::CredentialReview(task),
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Selected read-only queries retain fixed arguments and a separate mandatory profile.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn selective(
    selection: &SelectedFile,
    task: SelectiveTask,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role(
        Consumer::Selective(selection.clone(), task),
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Read-only plan queries are separately confined and bounded. A dump cannot
/// enter this role, and it never creates a scratch directory or receipt.
///
/// # Errors
///
/// Fails unless `task` is `Snapshot` or `TreeListing`, or as for [`execute`].
pub fn selective_plan(
    selection: &SelectedFile,
    task: SelectiveTask,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    require(
        matches!(task, SelectiveTask::Snapshot | SelectiveTask::TreeListing),
        "closed selected metadata plan task required",
    )?;
    execute_role(
        Consumer::SelectivePlan(selection.clone(), task),
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Fixed read-only rotation queries. Authentication failures retain their actual
/// exit code so only Restic's explicit wrong-password code can prove refusal.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn rotation_read(
    task: RotationTask,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role(
        Consumer::RotationRead(task),
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Forget exactly the snapshots in `retention`.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn retain(
    retention: &Retention,
    image: &File,
    repository: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role(
        Consumer::Retain(retention.clone()),
        image,
        repository,
        credential,
        scratch,
        boundary,
    )
}
/// Restore a system snapshot into the staging directory `target`.
///
/// # Errors
///
/// Fails when `target` is not the private Root staging subvolume, or as for [`execute`].
pub fn restore_system(
    restore: &RestoreSystem,
    image: &File,
    repository: &File,
    credential: &File,
    target: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role_extended(
        Consumer::RestoreSystem(restore.clone()),
        image,
        repository,
        credential,
        None,
        Some(target),
        scratch,
        boundary,
    )
}
/// Restore a complete snapshot into the staging directory `target`.
///
/// # Errors
///
/// Fails when `target` is not the private Root staging subvolume, or as for [`execute`].
pub fn restore_complete(
    restore: &RestoreComplete,
    image: &File,
    repository: &File,
    credential: &File,
    target: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role_extended(
        Consumer::RestoreComplete(restore.clone()),
        image,
        repository,
        credential,
        None,
        Some(target),
        scratch,
        boundary,
    )
}
/// One fixed key addition; never admitted through the generic worker task parser.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
pub fn credential_enroll(
    image: &File,
    repository: &File,
    current: &File,
    next: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    execute_role_extended(
        Consumer::CredentialEnroll,
        image,
        repository,
        current,
        Some(next),
        None,
        scratch,
        boundary,
    )
}
/// Only original protected descriptors supplied by the native Root coordinator.
/// Target/credential and source/credential are distinct; there are no paths,
/// environment secrets, task strings, optional roles or source write commands.
///
/// # Errors
///
/// Fails when a descriptor is not the expected protected Root file, the confining AppArmor profile
/// is not enforced, `boundary` fails, or the process exceeds its time or output bound. A nonzero
/// Restic exit is returned in the output.
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
#[expect(
    clippy::too_many_arguments,
    reason = "Each descriptor fills a distinct, closed Restic role."
)]
pub fn rotation_prepare(
    task: RotationPrepare,
    image: &File,
    target: &File,
    next: &File,
    source: &File,
    current: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    require(
        crate::process_identity::effective_uid() == 0,
        "Root rotation consumer required",
    )?;
    let task = Consumer::RotationPrepare(task);
    let directories = [target, source, scratch];
    let mut directory_shapes = Vec::new();
    let mut directory_mounts = Vec::new();
    for f in directories {
        let m = f.metadata()?;
        require(
            m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
            "original private rotation directory required",
        )?;
        directory_shapes.push((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()));
        directory_mounts.push(mount_identity::id(f.as_fd(), true)?);
    }
    require(
        directory_shapes[0].0 == directory_shapes[1].0
            && directory_mounts[0] == directory_mounts[1]
            && directory_shapes[0] != directory_shapes[1],
        "distinct replacement/source on original backup mount required",
    )?;
    // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `fs` is a writable `libc::statfs` and `scratch` keeps the descriptor open.
        unsafe { libc::fstatfs(scratch.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x01021994,
        "private rotation scratch tmpfs required",
    )?;
    let mut credentials = Vec::new();
    let mut credential_mounts = Vec::new();
    for f in [next, current] {
        let m = f.metadata()?;
        let flags = crate::files::status_flags(&f);
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && matches!(m.mode() & 0o7777, 0o400 | 0o600)
                && m.nlink() == 1
                && (1..=4096).contains(&m.len())
                && flags >= 0
                && flags & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY,
            "original protected rotation password required",
        )?;
        credentials.push(files::identity(&m));
        credential_mounts.push(mount_identity::id(f.as_fd(), true)?);
    }
    require(
        (credentials[0].0, credentials[0].1) != (credentials[1].0, credentials[1].1),
        "rotation passwords alias",
    )?;
    let image_epoch = files::identity(&image.metadata()?);
    let descriptions = [image, target, next, source, current, scratch];
    let flags = descriptions.map(|f| crate::files::status_flags(&f));
    require(
        flags.iter().all(|f| *f >= 0),
        "original rotation description status unavailable",
    )?;
    let mut checkpoint = || {
        for (i, f) in directories.into_iter().enumerate() {
            let m = f.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()) == directory_shapes[i]
                    && mount_identity::id(f.as_fd(), true)? == directory_mounts[i],
                "original rotation directory changed",
            )?;
        }
        for (i, f) in [next, current].into_iter().enumerate() {
            require(
                files::identity(&f.metadata()?) == credentials[i]
                    && mount_identity::id(f.as_fd(), true)? == credential_mounts[i],
                "original rotation password changed",
            )?;
        }
        for (f, flag) in descriptions.into_iter().zip(flags) {
            require(
                crate::files::status_flags(&f) == flag,
                "original rotation shared status changed",
            )?;
        }
        require(
            files::identity(&image.metadata()?) == image_epoch,
            "original rotation image changed",
        )?;
        enforce_role(
            &task,
            &files::read_kernel(
                Path::new("/sys/kernel/security/apparmor/profiles"),
                1024 * 1024,
            )?,
        )?;
        boundary()
    };
    checkpoint()?;
    let descriptors = [
        target.as_fd(),
        next.as_fd(),
        source.as_fd(),
        current.as_fd(),
        scratch.as_fd(),
    ];
    let output = process::local_restic(
        image,
        &task.arguments(),
        task.timeout(),
        task.output_limit(),
        &descriptors,
        task.clone(),
        &mut checkpoint,
    )?;
    checkpoint()?;
    Ok(output)
}

mod execution;
pub(crate) use execution::confine_child;
pub(crate) use execution::environment;
use execution::execute_role;
use execution::execute_role_extended;
pub(crate) use execution::progress_line;

/// Total bound for a plain `restic check` (metadata only).
pub(crate) const CHECK_TIMEOUT: Duration = Duration::from_secs(12 * 3600);
/// No-output limit for a plain `restic check`. Restic 0.19.1 prints progress
/// only while checking snapshots/trees; loading indexes and listing packs are
/// silent (measured: no line for 6 min on a throttled read). The silence limit
/// therefore stays at the old total bound (20 min), so no check that used to
/// pass can trip it, while a long check that keeps printing may now finish.
pub(crate) const CHECK_STALL: Duration = Duration::from_secs(1200);
/// Total bound for one `restic backup`: a first whole-system backup to a USB
/// disk takes hours. Liveness is enforced by `BACKUP_STALL` instead.
pub(crate) const BACKUP_TIMEOUT: Duration = Duration::from_secs(12 * 3600);
/// Abort a backup only after this long without any output. With
/// `PROGRESS_FPS` a live backup prints a status line every 30 s.
pub(crate) const BACKUP_STALL: Duration = Duration::from_secs(15 * 60);
/// Progress rate for the long roles (`backup --json`, `copy`). For copy the
/// variable is what turns progress on at all. With stdout not a terminal
/// Restic 0.19 still
/// emits ~10 JSON status lines per second (measured: ~2.4 KiB/s), so a whole-
/// system backup passed its 2 MiB / 8192-line output bound after about 15
/// minutes. One line per 30 s keeps a 24 h run near 700 KiB. Short roles never
/// get it: for non-JSON commands any rate would *enable* progress text.
pub(crate) const PROGRESS_FPS: &str = "0.0333";
