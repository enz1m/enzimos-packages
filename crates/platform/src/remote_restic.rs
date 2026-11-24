// SPDX-License-Identifier: MIT
//! Closed SMB-share Restic queries, one-snapshot copies and whole-system
//! backups into the share; initialization has its own factory.
//!
//! The NAS repository is a folder on an SMB share. Each Restic child mounts the
//! share with kernel CIFS in its own private mount namespace (see
//! `remote_mount_child`) and uses Restic's local backend on the mounted folder;
//! Restic itself runs without network access. A backup child also attaches the
//! reviewed read-only sources in that namespace (see `backup_mount_child`).
use crate::{Error, Result, files, mount_identity, process, require};
use std::{
    fs::File,
    net::Ipv4Addr,
    os::{fd::AsFd, unix::fs::MetadataExt},
    sync::Arc,
    time::Duration,
};
/// Where the share is mounted inside each Restic child's private namespace.
pub const MOUNT: &str = "/backup-remote";
/// The server: a canonical IPv4 address or a lower-case DNS host name.
///
/// # Errors
/// A value outside this closed syntax.
pub fn server(value: &str) -> Result<()> {
    if value.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let ip = value
            .parse::<Ipv4Addr>()
            .map_err(|_| Error("SMB server: canonical IPv4 address or host name".into()))?;
        return require(
            ip.to_string() == value
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && ip != Ipv4Addr::BROADCAST,
            "SMB server: canonical IPv4 address or host name",
        );
    }
    require(
        (1..=253).contains(&value.len())
            && value.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }),
        "SMB server: canonical IPv4 address or host name",
    )
}
/// A share name as NAS systems offer them, including hidden `name$` shares.
///
/// # Errors
/// A value outside this closed syntax.
pub fn share(value: &str) -> Result<()> {
    require(
        (1..=80).contains(&value.len())
            && !value.starts_with([' ', '.', '-'])
            && !value.ends_with([' ', '.'])
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._$-".contains(&b)),
        "SMB share name",
    )
}
/// The repository folder inside the share: one or more plain components.
///
/// # Errors
/// A value outside this closed syntax.
pub fn folder(value: &str) -> Result<()> {
    let parts = value.split('/').collect::<Vec<_>>();
    require(
        (1..=240).contains(&value.len())
            && parts.len() <= 32
            && parts.iter().all(|p| {
                !p.is_empty()
                    && !p.starts_with(['.', '-'])
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            }),
        "SMB repository folder: relative path of plain names",
    )
}
/// The share account, optionally with its domain or workgroup.
///
/// # Errors
/// A value outside this closed syntax.
pub fn account(user: &str, domain: Option<&str>) -> Result<()> {
    require(
        (1..=64).contains(&user.len())
            && !user.starts_with(['-', '.'])
            && user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b)),
        "SMB user name",
    )?;
    require(
        domain.is_none_or(|d| {
            (1..=64).contains(&d.len())
                && !d.starts_with(['-', '.'])
                && d.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        }),
        "SMB domain or workgroup",
    )
}
/// The NAS share and the repository folder inside it, validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    server: String,
    share: String,
    folder: String,
    user: String,
    domain: Option<String>,
}
impl Endpoint {
    /// # Errors
    /// Any part outside the closed syntax of [`server`], [`share`],
    /// [`folder`] or [`account`].
    pub fn new(
        server_name: &str,
        share_name: &str,
        folder_path: &str,
        user: &str,
        domain: Option<&str>,
    ) -> Result<Self> {
        server(server_name)?;
        share(share_name)?;
        folder(folder_path)?;
        account(user, domain)?;
        Ok(Self {
            server: server_name.into(),
            share: share_name.into(),
            folder: folder_path.into(),
            user: user.into(),
            domain: domain.map(str::to_owned),
        })
    }
    /// The Restic repository inside the child's private share mount.
    pub fn repository(&self) -> String {
        format!("{MOUNT}/{}", self.folder)
    }
    pub(crate) fn server(&self) -> &str {
        &self.server
    }
    /// `//server/share`, the kernel CIFS source.
    pub(crate) fn unc(&self) -> String {
        format!("//{}/{}", self.server, self.share)
    }
    pub(crate) fn user(&self) -> &str {
        &self.user
    }
    pub(crate) fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}
/// What a failed share mount in a remote Restic child means for the person
/// fixing it: a public `remote-share-*` code, then the detail. The kernel's
/// own words stay in the child's mount context.
pub(crate) fn mount_refusal(error: &std::io::Error) -> Error {
    let (code, reason) = match error.raw_os_error() {
        Some(libc::EACCES | libc::EKEYREJECTED) => (
            "remote-share-sign-in-refused",
            "the NAS refused the share user or password",
        ),
        Some(libc::ENOENT | libc::ENXIO) => (
            "remote-share-not-found",
            "the NAS has no share with that name",
        ),
        Some(
            libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::ENETUNREACH
            | libc::ECONNREFUSED
            | libc::ECONNRESET
            | libc::ETIMEDOUT,
        ) => ("remote-share-unreachable", "the NAS did not answer"),
        Some(libc::EOPNOTSUPP | libc::EPROTO | libc::EPROTONOSUPPORT) => (
            "remote-share-smb3-unsupported",
            "the NAS does not offer signed SMB 3",
        ),
        Some(libc::ENODEV) => (
            "remote-share-unavailable",
            "the kernel SMB client is not available",
        ),
        Some(libc::EPERM) => (
            "remote-share-unavailable",
            "the share mount point or its checks changed",
        ),
        _ => ("remote-share-unavailable", "the share could not be mounted"),
    };
    Error(format!("{code}: {reason} ({error})"))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    RemoteInitialize,
    RemoteIdentity,
    RemoteKeys,
    RemoteSelected,
    RemoteInventory,
    RemoteCheck,
    LocalSelected,
    LocalInventory,
    LocalCheck,
    Replicate,
    Retrieve,
    /// A whole-system backup into the share; only [`backup`] runs it.
    Backup,
}
#[derive(Clone)]
pub(crate) struct Invocation {
    pub(crate) attachment: Arc<crate::remote_mount_child::Prepared>,
    /// The read-only sources of a share backup, attached after the share.
    pub(crate) sources: Option<Arc<crate::backup_mount_child::Prepared>>,
    task: Task,
    read_only: bool,
    standalone_check: bool,
    /// Remote `forget --prune` may rewrite many packs on the share.
    long_running: bool,
    args: Vec<String>,
}
impl Invocation {
    fn new(
        attachment: &Arc<crate::remote_mount_child::Prepared>,
        endpoint: &Endpoint,
        task: Task,
        snapshot: &str,
    ) -> Result<Self> {
        let args = arguments(endpoint, task, snapshot)?;
        Ok(Self {
            attachment: Arc::clone(attachment),
            sources: None,
            task,
            read_only: false,
            standalone_check: false,
            long_running: false,
            args,
        })
    }
    pub(crate) fn arguments(&self) -> Vec<&str> {
        self.args.iter().map(String::as_str).collect()
    }
    pub(crate) fn read_only(&self) -> bool {
        self.read_only
    }
    /// Snapshot copies to or from the NAS: long, but always printing.
    pub(crate) fn copies(&self) -> bool {
        copies(self.task)
    }
    /// Metadata checks (workflow and standalone); prune shares the task but
    /// is long_running and stays quiet.
    pub(crate) fn checks(&self) -> bool {
        checks(self.task) && !self.long_running
    }
    pub(crate) fn prints_progress(&self) -> bool {
        self.copies() || self.checks() || self.task == Task::Backup
    }
    /// Copies and backups: 15 min of silence. Checks: their old total bound,
    /// because index loading and pack listing print nothing (see CHECK_STALL).
    pub(crate) fn stall_limit(&self) -> Option<Duration> {
        if self.copies() || self.task == Task::Backup {
            Some(crate::local_restic::BACKUP_STALL)
        } else if self.checks() {
            Some(if self.standalone_check {
                crate::local_restic::CHECK_STALL
            } else {
                TIMEOUT
            })
        } else {
            None
        }
    }
    pub(crate) fn timeout(&self) -> Duration {
        if self.task == Task::Backup {
            crate::local_restic::BACKUP_TIMEOUT
        } else if self.copies() {
            COPY_TIMEOUT
        } else if self.checks() {
            crate::local_restic::CHECK_TIMEOUT
        } else if self.long_running {
            PRUNE_TIMEOUT
        } else if self.read_only {
            Duration::from_secs(120)
        } else {
            TIMEOUT
        }
    }
    pub(crate) fn profile(&self) -> &'static str {
        if self.task == Task::Backup {
            "enzimos-restic-native-remote-backup"
        } else if self.standalone_check {
            "enzimos-restic-native-remote-check"
        } else if self.task == Task::RemoteInitialize {
            "enzimos-restic-native-remote-initialize"
        } else if self.read_only {
            "enzimos-restic-native-remote-rotation-read"
        } else if matches!(self.task, Task::Retrieve | Task::LocalCheck) {
            "enzimos-restic-native-retrieve"
        } else {
            "enzimos-restic-native-replicate"
        }
    }
}
fn arguments(endpoint: &Endpoint, task: Task, snapshot: &str) -> Result<Vec<String>> {
    require(
        snapshot.len() == 64
            && snapshot
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "full remote copy snapshot required",
    )?;
    let local = matches!(
        task,
        Task::LocalSelected | Task::LocalInventory | Task::LocalCheck | Task::Retrieve
    );
    let mut args = vec![
        "--repo".into(),
        if local {
            "@fd-dir:0".into()
        } else {
            endpoint.repository()
        },
        "--password-file".into(),
        if local {
            "@fd:1".into()
        } else {
            "@fd:2".into()
        },
        "--no-cache".into(),
    ];
    // Copies and checks print their progress (throttled by
    // RESTIC_PROGRESS_FPS) so the no-output watchdog can tell a slow run
    // from a stalled one; every other role stays quiet.
    if !copies(task) && !checks(task) {
        args.push("--quiet".into());
    }
    match task {
        Task::RemoteInitialize | Task::Backup => {
            return Err(crate::Error(
                "exclusive remote initialization or backup factory required".into(),
            ));
        }
        Task::RemoteKeys => args.extend(["--no-lock", "key", "list", "--json"].map(String::from)),
        Task::RemoteIdentity => args.extend(["--no-lock", "cat", "config"].map(String::from)),
        Task::RemoteSelected | Task::LocalSelected => {
            args.extend(["--no-lock", "snapshots", snapshot, "--json"].map(String::from));
        }
        Task::RemoteInventory | Task::LocalInventory => {
            args.extend(["--no-lock", "snapshots", "--json"].map(String::from));
        }
        Task::RemoteCheck | Task::LocalCheck => args.push("check".into()),
        Task::Replicate => args.extend(
            [
                "copy",
                "--from-repo",
                "@fd-dir:0",
                "--from-password-file",
                "@fd:1",
                snapshot,
            ]
            .map(String::from),
        ),
        Task::Retrieve => args.extend([
            "copy".into(),
            "--from-repo".into(),
            endpoint.repository(),
            "--from-password-file".into(),
            "@fd:2".into(),
            snapshot.into(),
        ]),
    }
    Ok(args)
}
/// Only observations are returned. The policy receiver still independently
/// admits Root sender OFDs, original pin/intent and the whole worker scope.
pub fn execute(
    attachment: &Arc<crate::remote_mount_child::Prepared>,
    endpoint: &Endpoint,
    task: Task,
    snapshot: &str,
    image: &File,
    repository: &File,
    local_password: &File,
    remote_password: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    let invocation = Invocation::new(attachment, endpoint, task, snapshot)?;
    execute_invocation(
        invocation,
        image,
        repository,
        local_password,
        remote_password,
        scratch,
        boundary,
    )
}
fn rotation_task(task: Task) -> Result<()> {
    require(
        matches!(
            task,
            Task::RemoteIdentity | Task::RemoteKeys | Task::RemoteInventory | Task::RemoteSelected
        ),
        "closed readonly remote rotation task required",
    )
}
fn readonly_arguments(endpoint: &Endpoint, task: Task, snapshot: &str) -> Result<Vec<String>> {
    rotation_task(task)?;
    let mut args = arguments(endpoint, task, snapshot)?;
    require(
        args[2] == "--password-file" && args[3] == "@fd:2",
        "fixed remote query credential index",
    )?;
    args[3] = "@fd:0".into();
    Ok(args)
}
fn initialization_arguments(endpoint: &Endpoint) -> Vec<String> {
    vec![
        "--repo".into(),
        endpoint.repository(),
        "--password-file".into(),
        "@fd:0".into(),
        "--no-cache".into(),
        "--quiet".into(),
        "init".into(),
    ]
}
/// Separate exact remote initializer; local repository and password roles are
/// absent. The policy caller must retain its actual original entered receipt.
pub fn initialize(
    attachment: &Arc<crate::remote_mount_child::Prepared>,
    endpoint: &Endpoint,
    image: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    let args = initialization_arguments(endpoint);
    let invocation = Invocation {
        attachment: Arc::clone(attachment),
        sources: None,
        task: Task::RemoteInitialize,
        read_only: true,
        standalone_check: false,
        long_running: false,
        args,
    };
    execute_invocation(
        invocation, image, scratch, credential, credential, scratch, boundary,
    )
}
fn check_arguments(endpoint: &Endpoint) -> Result<Vec<String>> {
    let mut args = initialization_arguments(endpoint);
    require(
        args.pop().as_deref() == Some("init"),
        "closed remote-only argument prefix required",
    )?;
    // A standalone check prints progress like the workflow check.
    args.retain(|arg| arg != "--quiet");
    args.push("check".into());
    Ok(args)
}
/// Standalone metadata check has only remote credential and scratch descriptors.
/// It cannot acquire local copy repository/password roles through its factory.
pub fn check(
    attachment: &Arc<crate::remote_mount_child::Prepared>,
    endpoint: &Endpoint,
    image: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    let args = check_arguments(endpoint)?;
    let invocation = Invocation {
        attachment: Arc::clone(attachment),
        sources: None,
        task: Task::RemoteCheck,
        read_only: true,
        standalone_check: true,
        long_running: false,
        args,
    };
    execute_invocation(
        invocation, image, scratch, credential, credential, scratch, boundary,
    )
}
/// `--repo` on the share folder, the remote password at descriptor 0, then the
/// reviewed closed archive arguments of the prepared sources.
fn backup_arguments(endpoint: &Endpoint, sources: &[String]) -> Result<Vec<String>> {
    require(
        sources.first().map(String::as_str) == Some("backup"),
        "closed reviewed backup arguments required",
    )?;
    let mut args = initialization_arguments(endpoint);
    require(
        args.pop().as_deref() == Some("init") && args.pop().as_deref() == Some("--quiet"),
        "closed remote-only argument prefix required",
    )?;
    args.extend(sources.iter().cloned());
    Ok(args)
}
/// One whole-system backup into the share repository: the child mounts the
/// share, attaches the prepared read-only sources beside it, leaves the
/// network namespace and runs the reviewed `restic backup --json` under its
/// own mandatory profile. Only the remote password and scratch are mapped.
///
/// # Errors
/// A share that cannot be mounted (public `remote-share-*` codes), changed
/// descriptors or attachments, the backup timeout or no-output watchdog.
pub fn backup(
    attachment: &Arc<crate::remote_mount_child::Prepared>,
    endpoint: &Endpoint,
    sources: &Arc<crate::backup_mount_child::Prepared>,
    image: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    let args = backup_arguments(endpoint, sources.arguments())?;
    let invocation = Invocation {
        attachment: Arc::clone(attachment),
        sources: Some(Arc::clone(sources)),
        task: Task::Backup,
        read_only: true,
        standalone_check: false,
        long_running: false,
        args,
    };
    let mut check = || {
        boundary()?;
        sources.recheck()
    };
    execute_invocation(
        invocation, image, scratch, credential, credential, scratch, &mut check,
    )
}
fn prune_arguments(endpoint: &Endpoint, snapshots: &[String]) -> Result<Vec<String>> {
    require(
        !snapshots.is_empty() && snapshots.len() <= 4096,
        "remote retention batch bound",
    )?;
    let mut unique = std::collections::BTreeSet::new();
    for id in snapshots {
        require(
            id.len() == 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && unique.insert(id),
            "full distinct remote snapshot IDs required",
        )?;
    }
    let mut args = initialization_arguments(endpoint);
    require(
        args.pop().as_deref() == Some("init"),
        "closed remote-only argument prefix required",
    )?;
    args.push("forget".into());
    args.extend(snapshots.iter().cloned());
    args.push("--prune".into());
    Ok(args)
}
/// Forget exact remote snapshot IDs and prune. Like the standalone check it has
/// only remote credential and scratch descriptors, and runs under the same
/// remote-only confinement (no local repository or password roles).
pub fn prune(
    attachment: &Arc<crate::remote_mount_child::Prepared>,
    endpoint: &Endpoint,
    snapshots: &[String],
    image: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    let args = prune_arguments(endpoint, snapshots)?;
    let invocation = Invocation {
        attachment: Arc::clone(attachment),
        sources: None,
        task: Task::RemoteCheck,
        read_only: true,
        standalone_check: true,
        long_running: true,
        args,
    };
    execute_invocation(
        invocation, image, scratch, credential, credential, scratch, boundary,
    )
}
/// Only fixed remote identity/key/inventory/selected queries. No copy/check/init.
pub fn rotation_read(
    attachment: &Arc<crate::remote_mount_child::Prepared>,
    endpoint: &Endpoint,
    task: Task,
    snapshot: &str,
    image: &File,
    credential: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    rotation_task(task)?;
    let mut invocation = Invocation::new(attachment, endpoint, task, snapshot)?;
    invocation.read_only = true;
    invocation.args = readonly_arguments(endpoint, task, snapshot)?;
    execute_invocation(
        invocation, image, scratch, credential, credential, scratch, boundary,
    )
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fcntl, fstatfs, fstatvfs, geteuid and others)."
)]
fn execute_invocation(
    invocation: Invocation,
    image: &File,
    repository: &File,
    local_password: &File,
    remote_password: &File,
    scratch: &File,
    boundary: &mut dyn FnMut() -> Result<()>,
) -> Result<process::Output> {
    require(
        unsafe { libc::geteuid() == 0 && libc::getuid() == 0 },
        "Root remote consumer required",
    )?;
    let attachment = &invocation.attachment;
    let original = files::identity(&scratch.metadata()?);
    let mount = mount_identity::id(scratch.as_fd(), true)?;
    let m = scratch.metadata()?;
    let mut status: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && unsafe { libc::fstatfs(std::os::fd::AsRawFd::as_raw_fd(scratch), &mut status) } == 0
            && status.f_type as u64 == 0x01021994,
        "original private tmpfs remote scratch",
    )?;
    let mut space: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatvfs(std::os::fd::AsRawFd::as_raw_fd(scratch), &mut space) } == 0
            && u128::from(space.f_bavail) * u128::from(space.f_frsize) >= 256 * 1024 * 1024,
        "remote scratch reserve",
    )?;
    let mut immutable = Vec::new();
    for (index, file) in [image, local_password, remote_password]
        .into_iter()
        .enumerate()
    {
        let m = file.metadata()?;
        let flags = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(file), libc::F_GETFL) };
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && (index == 0 || m.mode() & 0o077 == 0)
                && m.len() > 0
                && m.len()
                    <= if index == 0 {
                        process::executable_limit("/usr/bin/restic")
                    } else {
                        4096
                    }
                && flags >= 0
                && flags & libc::O_ACCMODE == libc::O_RDONLY
                && flags & libc::O_PATH == 0,
            "original protected remote image and credentials",
        )?;
        immutable.push((
            file,
            files::identity(&m),
            mount_identity::id(file.as_fd(), true)?,
        ));
    }
    let repository_epoch = repository.metadata()?;
    require(
        repository_epoch.is_dir()
            && repository_epoch.uid() == 0
            && repository_epoch.gid() == 0
            && repository_epoch.mode() & 0o022 == 0,
        "original Root local copy repository",
    )?;
    let repository_shape = (
        repository_epoch.dev(),
        repository_epoch.ino(),
        repository_epoch.mode(),
        repository_epoch.uid(),
        repository_epoch.gid(),
    );
    let repository_mount = mount_identity::id(repository.as_fd(), true)?;
    let consumer = crate::local_restic::Consumer::Remote(invocation.clone());
    let mut check = || {
        boundary()?;
        attachment.recheck()?;
        crate::local_restic::require_enforced(&consumer)?;
        for (file, epoch, mount) in &immutable {
            require(
                files::identity(&file.metadata()?) == *epoch
                    && mount_identity::id(file.as_fd(), true)? == *mount,
                "original remote executable or credential changed",
            )?;
        }
        let r = repository.metadata()?;
        require(
            (r.dev(), r.ino(), r.mode(), r.uid(), r.gid()) == repository_shape
                && mount_identity::id(repository.as_fd(), true)? == repository_mount,
            "original remote local repository changed",
        )?;
        let mut available: libc::statvfs = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::fstatvfs(std::os::fd::AsRawFd::as_raw_fd(scratch), &mut available) }
                == 0
                && u128::from(available.f_bavail) * u128::from(available.f_frsize)
                    >= 256 * 1024 * 1024,
            "remote scratch reserve lost",
        )?;
        let now = scratch.metadata()?;
        // Only child scratch entries may change directory mtime/ctime/size.
        require(
            (
                now.dev(),
                now.ino(),
                now.mode(),
                now.uid(),
                now.gid(),
                now.nlink(),
            ) == (
                original.0,
                original.1,
                original.7,
                original.8,
                original.9,
                original.10,
            ) && mount_identity::id(scratch.as_fd(), true)? == mount,
            "original remote scratch changed",
        )
    };
    check()?;
    crate::local_restic::require_enforced(&consumer)?;
    let args = invocation.arguments();
    let descriptors = if invocation.read_only {
        vec![remote_password.as_fd(), scratch.as_fd()]
    } else {
        vec![
            repository.as_fd(),
            local_password.as_fd(),
            remote_password.as_fd(),
            scratch.as_fd(),
        ]
    };
    let output = process::remote_restic(image, &args, &descriptors, consumer.clone(), &mut check)?;
    check()?;
    Ok(output)
}
fn copies(task: Task) -> bool {
    matches!(task, Task::Replicate | Task::Retrieve)
}
fn checks(task: Task) -> bool {
    matches!(task, Task::RemoteCheck | Task::LocalCheck)
}
pub(crate) const TIMEOUT: Duration = Duration::from_secs(1800);
/// One snapshot copy to or from the NAS: a first copy of a whole-system
/// backup over the network takes hours. Liveness is the no-output watchdog.
pub const COPY_TIMEOUT: Duration = Duration::from_secs(12 * 3600);
/// The whole replicate/retrieve workflow: the copy (12 h), the metadata
/// check after it (12 h) and short identity/inventory queries.
pub const WORKFLOW_TIMEOUT: Duration = Duration::from_secs(25 * 3600);
/// Same bound as a local retention prune.
pub(crate) const PRUNE_TIMEOUT: Duration = Duration::from_secs(86400);
pub(crate) const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_roles_bind_exact_source_destination_credentials_and_one_full_id() {
        let endpoint =
            Endpoint::new("nas.local", "backups", "enzimos/laptop", "ann", None).unwrap();
        let id = "a".repeat(64);
        for (task, repo, password, from_repo, from_password) in [
            (
                Task::Replicate,
                endpoint.repository(),
                "@fd:2",
                "@fd-dir:0".to_owned(),
                "@fd:1",
            ),
            (
                Task::Retrieve,
                "@fd-dir:0".to_owned(),
                "@fd:1",
                endpoint.repository(),
                "@fd:2",
            ),
        ] {
            let args = arguments(&endpoint, task, &id).unwrap();
            assert_eq!(args[0], "--repo");
            assert_eq!(args[1], repo);
            assert_eq!(args[2], "--password-file");
            assert_eq!(args[3], password);
            assert_eq!(
                &args[args.len() - 6..],
                &[
                    "copy",
                    "--from-repo",
                    &from_repo,
                    "--from-password-file",
                    from_password,
                    &id
                ]
            );
            assert!(!args.contains(&"--no-lock".into()));
            for bad in ["a", "latest", "a;exec", ""] {
                assert!(arguments(&endpoint, task, bad).is_err());
            }
        }
        for task in [
            Task::RemoteIdentity,
            Task::RemoteSelected,
            Task::RemoteInventory,
            Task::LocalInventory,
        ] {
            let args = arguments(&endpoint, task, &id).unwrap();
            assert!(args.contains(&"--no-lock".into()));
            assert!(
                !args.contains(&"copy".into())
                    && !args.contains(&"init".into())
                    && !args.contains(&"forget".into())
            );
        }
    }
    #[test]
    fn a_share_backup_writes_only_the_share_repository_with_the_reviewed_archive_arguments() {
        let endpoint =
            Endpoint::new("nas.local", "backups", "enzimos/laptop", "ann", None).unwrap();
        let reviewed = crate::backup_command::arguments(
            &["system", "home", "boot", "inventory"]
                .map(|t| format!("/backup-source/{t}"))
                .into_iter()
                .collect(),
        )
        .unwrap();
        let args = backup_arguments(&endpoint, &reviewed).unwrap();
        assert_eq!(
            args[..5],
            [
                "--repo",
                "/backup-remote/enzimos/laptop",
                "--password-file",
                "@fd:0",
                "--no-cache"
            ]
        );
        assert_eq!(args[5..], reviewed[..]);
        assert!(
            !args
                .iter()
                .any(|a| a.starts_with("@fd-dir") || a == "--quiet")
        );
        assert!(backup_arguments(&endpoint, &["copy".into()]).is_err());
        assert!(arguments(&endpoint, Task::Backup, &"a".repeat(64)).is_err());
    }
    #[test]
    fn share_endpoint_admits_plain_names_and_refuses_option_or_path_injection() {
        let e = Endpoint::new(
            "192.0.2.4",
            "backup$",
            "enzimos/host-one",
            "ann",
            Some("HOME"),
        )
        .unwrap();
        assert_eq!(e.repository(), "/backup-remote/enzimos/host-one");
        assert_eq!(e.unc(), "//192.0.2.4/backup$");
        Endpoint::new("nas-1.lan", "Family Backups", "pc.2026", "ann@home", None).unwrap();
        for (server, share, folder, user, domain) in [
            ("192.000.2.4", "b", "f", "u", None),
            ("0.0.0.0", "b", "f", "u", None),
            ("NAS.local", "b", "f", "u", None),
            ("nas.local.", "b", "f", "u", None),
            ("-oip=1.2.3.4", "b", "f", "u", None),
            ("nas", "b,ip=10.0.0.1", "f", "u", None),
            ("nas", "../c", "f", "u", None),
            ("nas", "b/c", "f", "u", None),
            ("nas", "b", "/abs", "u", None),
            ("nas", "b", "a/../c", "u", None),
            ("nas", "b", "a//c", "u", None),
            ("nas", "b", ".hidden", "u", None),
            ("nas", "b", "", "u", None),
            ("nas", "b", "f", "u,uid=0", None),
            ("nas", "b", "f", "-u", None),
            ("nas", "b", "f", "dom\\u", None),
            ("nas", "b", "f", "u", Some("a,b")),
            ("nas", "b", "f", "u", Some("")),
        ] {
            assert!(
                Endpoint::new(server, share, folder, user, domain).is_err(),
                "{server} {share} {folder} {user} {domain:?}"
            );
        }
    }
}
