// SPDX-License-Identifier: MIT
//! Fixed local Restic consumer with original image and per-job private tmpfs.
use crate::settings_command::Command;
use enzimos_platform::{
    Result, files,
    local_restic::{self, Task},
    mount_identity, require,
};
use serde_json::Value;
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original private backup runtime required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
/// Observed command completion, never repository pinning, enrollment, recovery
/// export, schedule admission or completion of the owning setup transaction.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Observed {
    Initialized,
    Authenticated(String),
    IncorrectPassword,
    MetadataChecked,
}
/// The worker retains the original public header until the report is sent.
pub struct WorkflowObservation {
    value: Value,
    header: Option<(crate::backup_repository_header::Header, File)>,
}
impl WorkflowObservation {
    /// Descriptor of the retained repository header, if the workflow read one.
    ///
    /// # Errors
    ///
    /// Fails when the header changed.
    pub fn header_descriptor(&self) -> Result<Option<&File>> {
        self.value()?;
        Ok(self.header.as_ref().map(|(header, _)| header.descriptor()))
    }
    /// The workflow report.
    ///
    /// # Errors
    ///
    /// Fails when the retained header changed.
    pub fn value(&self) -> Result<&Value> {
        if let Some((header, repository)) = &self.header {
            header.recheck(repository)?;
        }
        Ok(&self.value)
    }
}
fn observed(task: Task, code: Option<i32>, stdout: &[u8]) -> Result<Observed> {
    require(
        stdout.len() <= task.output_limit(),
        "local Restic output exceeded role bound",
    )?;
    if matches!(task, Task::Authenticate | Task::AuthenticateInput) {
        if code == Some(12) {
            return Ok(Observed::IncorrectPassword);
        }
        let keys = crate::backup_restic_result::keys(code, stdout)?;
        let current = keys
            .into_iter()
            .find(|(_, current)| *current)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .0;
        return Ok(Observed::Authenticated(current));
    }
    require(
        code == Some(0),
        "local repository command failed or uncertain; no replay",
    )?;
    Ok(if task == Task::Initialize {
        Observed::Initialized
    } else {
        Observed::MetadataChecked
    })
}
/// A private tmpfs job directory with the pinned Restic image for one backup job.
pub struct Runtime {
    image: Command,
    path: PathBuf,
    scratch: File,
    shape: Shape,
    mount: u64,
}
/// Actual bounded consumer outcome, without worker or source cleanup authority.
pub struct BackupObservation {
    snapshot: String,
    stdout: File,
    stdout_sha256: String,
}
impl BackupObservation {
    pub(crate) fn stdout(&self) -> Result<&File> {
        let bytes = enzimos_platform::memfile::read_sealed(&self.stdout, 2 * 1024 * 1024, 0)?;
        require(
            enzimos_platform::json::sha256(&bytes) == self.stdout_sha256
                && crate::backup_restic_result::backup(Some(0), &bytes)? == self.snapshot,
            "original bounded sealed Restic output changed",
        )?;
        Ok(&self.stdout)
    }
    pub(crate) fn stdout_sha256(&self) -> Result<&str> {
        self.stdout()?;
        Ok(&self.stdout_sha256)
    }
    pub(crate) fn value(&self) -> Value {
        serde_json::json!({"status":"backup-observed","snapshot_id":self.snapshot,
            "transfer_complete":true,"worker_scope_closed":false,
            "source_cleanup_complete":false,"backup_complete":false})
    }
}
/// Original fixed vendor image retained by the producer before service start.
pub struct Image {
    command: Command,
}
impl Image {
    /// Open and pin the installed Restic image.
    ///
    /// # Errors
    ///
    /// Fails when the executable is missing or unsafe.
    pub fn open() -> Result<Self> {
        crate::namespaces::initial()?;
        Ok(Self {
            command: Command::open("/usr/bin/restic")?,
        })
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.command.evidence()
    }
    /// The pinned image file.
    ///
    /// # Errors
    ///
    /// Fails when the image changed.
    pub fn descriptor(&self) -> Result<&File> {
        self.command.descriptor()
    }
}
impl Runtime {
    pub(crate) fn backup_prepared(
        &self,
        prepared: &std::sync::Arc<enzimos_platform::backup_mount_child::Prepared>,
        handoff: &crate::backup_transfer_handoff::Handoff,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<BackupObservation> {
        self.recheck()?;
        self.empty()?;
        boundary()?;
        require(
            self.image_evidence()? == handoff.request()?["context"]["restic"],
            "original transfer consumer image differs from admitted image",
        )?;
        let mut ongoing = || {
            self.recheck()?;
            handoff.recheck()?;
            prepared.recheck()?;
            boundary()
        };
        let output = if let Some((configuration, share_password, credential)) = handoff.share()? {
            self.backup_share(
                prepared,
                handoff,
                configuration,
                share_password,
                credential,
                &mut ongoing,
            )?
        } else {
            local_restic::backup(
                prepared,
                handoff.consumer_descriptor()?,
                handoff.repository_descriptor()?,
                handoff.credential_descriptor()?,
                &self.scratch,
                &mut ongoing,
            )?
        };
        ongoing()?;
        self.empty()?;
        let snapshot = crate::backup_restic_result::backup(output.status.code(), &output.stdout)?;
        // Path-bearing raw output stays private to the sealed Root control handoff.
        // Public observation/status fields retain their existing bounded shape.
        let stdout_sha256 = enzimos_platform::json::sha256(&output.stdout);
        let stdout = enzimos_platform::memfile::sealed("backup-observed-output", &output.stdout)?;
        Ok(BackupObservation {
            snapshot,
            stdout,
            stdout_sha256,
        })
    }
    /// `restic backup` into the pinned share repository, between two
    /// authenticated identity queries that must both match the share pin, so
    /// a replaced or foreign repository in the share folder never receives
    /// the backup or completes it.
    fn backup_share(
        &self,
        prepared: &std::sync::Arc<enzimos_platform::backup_mount_child::Prepared>,
        handoff: &crate::backup_transfer_handoff::Handoff,
        configuration: &Value,
        share_password: &File,
        credential: &File,
        ongoing: &mut dyn FnMut() -> Result<()>,
    ) -> Result<enzimos_platform::process::Output> {
        use enzimos_platform::remote_restic::{self, Task};
        let pin = handoff.request()?["context"]["share"]["pin"].clone();
        let (attachment, endpoint) = remote_share(configuration, share_password)?;
        let image = handoff.consumer_descriptor()?;
        let identity = |ongoing: &mut dyn FnMut() -> Result<()>| -> Result<Value> {
            ongoing()?;
            let output = remote_restic::rotation_read(
                &attachment,
                &endpoint,
                Task::RemoteIdentity,
                &"0".repeat(64),
                image,
                credential,
                &self.scratch,
                ongoing,
            )?;
            ongoing()?;
            self.empty()?;
            crate::backup_remote_observation::identity_data(
                output.status.code(),
                &output.stdout,
                &pin,
            )
        };
        let first = identity(ongoing)?;
        let mut check = || {
            ongoing()?;
            attachment.recheck()
        };
        let output = remote_restic::backup(
            &attachment,
            &endpoint,
            prepared,
            image,
            credential,
            &self.scratch,
            &mut check,
        )?;
        require(
            identity(ongoing)? == first,
            "share repository identity changed during the backup",
        )?;
        Ok(output)
    }
    /// Selected repository output only; original whole-worker closure and private
    /// filesystem publication remain with the caller. No historical metadata is applied.
    ///
    /// # Errors
    ///
    /// Fails when an input or the consumer image differs from the original handoff, `boundary`
    /// fails, or a Restic command fails or is uncertain. Commands are never replayed.
    pub fn selective_export(
        &self,
        handoff: &crate::backup_selective_handoff::Handoff,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::backup_selective_observation::Observed> {
        use local_restic::{SelectedFile, SelectiveTask};
        self.recheck()?;
        self.empty()?;
        handoff.recheck()?;
        let request = handoff.request()?.clone();
        let selected = &request["context"]["selection"];
        let snapshot = enzimos_platform::json::string(&selected["snapshot"])?;
        let path = enzimos_platform::json::string(&selected["path"])?;
        let selection = SelectedFile::new(snapshot, path)?;
        require(
            self.image_evidence()? == request["context"]["restic"],
            "original selective consumer image differs",
        )?;
        let mut ongoing = || {
            self.recheck()?;
            handoff.recheck()?;
            boundary()
        };
        let mut run = |task| {
            ongoing()?;
            let output = local_restic::selective(
                &selection,
                task,
                handoff.consumer_descriptor()?,
                handoff.repository_descriptor()?,
                handoff.current_descriptor()?,
                &self.scratch,
                &mut ongoing,
            )?;
            ongoing()?;
            self.empty()?;
            require(
                output.status.code() == Some(0),
                "selected query failed or uncertain; no replay",
            )?;
            Ok::<_, enzimos_platform::Error>(output.stdout)
        };
        let snapshots = run(SelectiveTask::Snapshot)?;
        crate::backup_selective_result::snapshot_scope(Some(0), &snapshots, snapshot)?;
        let tree = request["kind"] == "selective-tree-export";
        let task = if tree {
            SelectiveTask::TreeListing
        } else {
            SelectiveTask::Listing
        };
        let before = run(task)?;
        let data = run(SelectiveTask::Dump)?;
        let after = run(task)?;
        let details = if tree {
            let before = crate::backup_tree_result::metadata(Some(0), &before, snapshot, path)?;
            let after = crate::backup_tree_result::metadata(Some(0), &after, snapshot, path)?;
            require(
                before.details == after.details,
                "selected tree changed across dump",
            )?;
            crate::backup_tree_result::verify_tar(&data, path, &before)?;
            let mut details = before.details;
            details["content_bytes"] = details["size"].clone();
            details["size"] = serde_json::json!(data.len());
            details
        } else {
            let before =
                crate::backup_selective_result::metadata(Some(0), &before, snapshot, path)?;
            let after = crate::backup_selective_result::metadata(Some(0), &after, snapshot, path)?;
            require(
                before == after && before["size"].as_u64() == Some(data.len() as u64),
                "selected file metadata or authenticated dump length changed",
            )?;
            before
        };
        ongoing()?;
        let observed =
            crate::backup_selective_observation::Observed::seal(&request, &details, &data)?;
        observed.recheck()?;
        ongoing()?;
        Ok(observed)
    }
    /// Five fixed commands, admitted original handoff and fresh checkpoints.
    /// This observes keys and metadata without completing the enrollment.
    ///
    /// # Errors
    ///
    /// Fails when an input or the consumer image differs from the original handoff, `boundary`
    /// fails, or a Restic command fails or is uncertain. Commands are never replayed.
    pub fn credential_review(
        &self,
        handoff: &crate::backup_credential_handoff::Handoff,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::backup_credential_observation::Observed> {
        use local_restic::CredentialReview;
        self.recheck()?;
        self.empty()?;
        handoff.recheck()?;
        require(
            self.image_evidence()? == handoff.request()?["context"]["restic"],
            "original credential review consumer image differs",
        )?;
        let mut ongoing = || {
            self.recheck()?;
            handoff.recheck()?;
            boundary()
        };
        let mut run = |task, credential| {
            ongoing()?;
            let output = local_restic::credential_review(
                task,
                handoff.consumer_descriptor()?,
                handoff.repository_descriptor()?,
                credential,
                &self.scratch,
                &mut ongoing,
            )?;
            ongoing()?;
            self.empty()?;
            require(
                output.status.code() == Some(0),
                "credential review command failed or uncertain; no replay",
            )?;
            Ok::<_, enzimos_platform::Error>(output.stdout)
        };
        let current_first = run(CredentialReview::Keys, handoff.current_descriptor()?)?;
        let candidate_first = run(CredentialReview::Keys, handoff.candidate_descriptor()?)?;
        run(CredentialReview::Metadata, handoff.candidate_descriptor()?)?;
        let current_last = run(CredentialReview::Keys, handoff.current_descriptor()?)?;
        let candidate_last = run(CredentialReview::Keys, handoff.candidate_descriptor()?)?;
        ongoing()?;
        let enrollment = handoff.enrollment_record()?;
        let result = crate::backup_credential_observation::Observed::seal(
            handoff.request()?,
            &enrollment,
            [
                &current_first,
                &candidate_first,
                &current_last,
                &candidate_last,
            ],
        )?;
        ongoing()?;
        result.recheck()?;
        Ok(result)
    }
    /// Called after original starting intent and fresh caller approval; existing
    /// attempt directories cannot be adopted.
    /// Fixed original remote worker only. A successful copy/check remains an
    /// observation until the caller closes the actual whole kernel scope.
    pub(crate) fn initialize_remote<'h>(
        &'h self,
        entered: &'h crate::backup_remote_initialize::Entered<'h>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<RemoteInitialized<'h>> {
        self.recheck()?;
        self.empty()?;
        entered.start(self, authorize)?;
        let descriptors = entered.descriptors()?;
        let (attachment, endpoint) = remote_share(
            entered.configuration()?,
            &File::from(descriptors[2].try_clone_to_owned()?),
        )?;
        let credential = File::from(descriptors[1].try_clone_to_owned()?);
        let mut boundary = || {
            self.recheck()?;
            entered.recheck(authorize)?;
            attachment.recheck()
        };
        let output = enzimos_platform::remote_restic::initialize(
            &attachment,
            &endpoint,
            self.image.descriptor()?,
            &credential,
            &self.scratch,
            &mut boundary,
        )?;
        require(
            output.status.code() == Some(0),
            "remote initialization failed/unknown; entered receipt retained, no replay",
        )?;
        self.empty()?;
        boundary()?;
        let identity = enzimos_platform::remote_restic::rotation_read(
            &attachment,
            &endpoint,
            enzimos_platform::remote_restic::Task::RemoteIdentity,
            &"0".repeat(64),
            self.image.descriptor()?,
            &credential,
            &self.scratch,
            &mut boundary,
        )?;
        require(
            identity.status.code() == Some(0),
            "remote initialized identity query failed; no pin adoption",
        )?;
        let data = enzimos_platform::json::decode(&identity.stdout, 32768)?;
        require(
            data.is_object() && matches!(data["version"].as_u64(), Some(1 | 2)),
            "authenticated initialized remote version required",
        )?;
        crate::identity::sha(data["id"].as_str().unwrap_or(""))?;
        let pin = crate::backup_remote_record::new_pin(&data["id"], entered.binding()?)?;
        self.empty()?;
        boundary()?;
        Ok(RemoteInitialized {
            entered,
            runtime: self,
            pin,
        })
    }
    /// Copy a snapshot between the local repository and the network share as the handoff describes.
    ///
    /// # Errors
    ///
    /// Fails when an input or the consumer image differs from the original handoff, `boundary`
    /// fails, or a Restic command fails or is uncertain. Commands are never replayed.
    pub fn remote_copy<'h>(
        &self,
        handoff: &'h crate::backup_remote_handoff::Handoff<'_>,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::backup_remote_observation::Observed<'h>> {
        use enzimos_platform::remote_restic::{Task, execute};
        self.recheck()?;
        self.empty()?;
        handoff.recheck()?;
        let request = handoff.request()?.clone();
        let ctx = &request["context"];
        require(
            self.image_evidence()? == ctx["remote"]["restic"],
            "remote runtime original vendor image differs",
        )?;
        let files = handoff.descriptors()?;
        let (attachment, endpoint) = remote_share(
            &ctx["remote"]["inputs"]["configuration"],
            files["remote-share-password"],
        )?;
        let snapshot = enzimos_platform::json::string(&ctx["snapshot"])?;
        // The copy itself is bounded by COPY_TIMEOUT and a no-output watchdog.
        let deadline =
            std::time::Instant::now() + enzimos_platform::remote_restic::WORKFLOW_TIMEOUT;
        let ongoing = std::cell::RefCell::new(|| {
            require(
                std::time::Instant::now() < deadline,
                "remote copy workflow deadline; no replay",
            )?;
            self.recheck()?;
            handoff.recheck()?;
            boundary()
        });
        let run = |task| {
            (ongoing.borrow_mut())()?;
            let output = execute(
                &attachment,
                &endpoint,
                task,
                snapshot,
                files["restic"],
                files["local-repository"],
                files["local-credential"],
                files["remote-password"],
                &self.scratch,
                &mut || (ongoing.borrow_mut())(),
            )?;
            (ongoing.borrow_mut())()?;
            self.empty()?;
            require(
                output.status.code() == Some(0),
                "remote copy command failed or uncertain; no replay",
            )?;
            Ok::<_, enzimos_platform::Error>(output.stdout)
        };
        let pin = &ctx["remote"]["pin"];
        let remote_first = crate::backup_remote_observation::identity_data(
            Some(0),
            &run(Task::RemoteIdentity)?,
            pin,
        )?;
        let replicate = ctx["direction"] == "replicate";
        let selected = if replicate {
            Task::LocalSelected
        } else {
            Task::RemoteSelected
        };
        let source_first =
            enzimos_platform::json::decode(&run(selected)?, crate::backup_remote_points::LIMIT)?;
        crate::backup_remote_points::selected(&source_first, snapshot)?;
        let destination_before = if replicate {
            Value::Null
        } else {
            let before = enzimos_platform::json::decode(
                &run(Task::LocalInventory)?,
                crate::backup_remote_points::LIMIT,
            )?;
            crate::backup_remote_points::retrieval_admission(&source_first, snapshot, &before)?;
            before
        };
        let intent = if replicate {
            None
        } else {
            Some(crate::backup_remote_receipt::Intent::enter(
                handoff,
                &source_first,
                &destination_before,
                &mut || (ongoing.borrow_mut())(),
            )?)
        };
        run(if replicate {
            Task::Replicate
        } else {
            Task::Retrieve
        })?;
        let destination_after = enzimos_platform::json::decode(
            &run(if replicate {
                Task::RemoteInventory
            } else {
                Task::LocalInventory
            })?,
            crate::backup_remote_points::LIMIT,
        )?;
        if replicate {
            crate::backup_remote_points::replicated(&source_first, snapshot, &destination_after)?;
        } else {
            crate::backup_remote_points::retrieved(
                &source_first,
                snapshot,
                &destination_before,
                &destination_after,
            )?;
        }
        run(if replicate {
            Task::RemoteCheck
        } else {
            Task::LocalCheck
        })?;
        let source_last =
            enzimos_platform::json::decode(&run(selected)?, crate::backup_remote_points::LIMIT)?;
        let remote_last = crate::backup_remote_observation::identity_data(
            Some(0),
            &run(Task::RemoteIdentity)?,
            pin,
        )?;
        (ongoing.borrow_mut())()?;
        crate::backup_remote_observation::Observed::seal(
            handoff,
            source_first,
            source_last,
            destination_before,
            destination_after,
            remote_first,
            remote_last,
            intent,
        )
    }
    /// Create the private job directory for job `id` on the original tmpfs.
    ///
    /// # Errors
    ///
    /// Fails when `preflight` fails, the directories are not on the original tmpfs, or the job
    /// directory exists.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    pub fn create(id: &str, preflight: &mut dyn FnMut() -> Result<()>) -> Result<Self> {
        crate::namespaces::initial()?;
        crate::backup_worker_request::id(id)?;
        preflight()?;
        let run = files::directory(Path::new("/run/enzimos"), Some(0))?;
        shape(&run)?;
        // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `fs` is a writable `libc::statfs` and `run` keeps the descriptor open.
            unsafe { libc::fstatfs(run.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x01021994,
            "native backup runtime must start on original tmpfs",
        )?;
        let mount = mount_identity::id(run.as_fd(), true)?;
        preflight()?;
        let base = files::ensure_directory_relative(&run, Path::new("backup-native"), 0o700, 0)?;
        shape(&base)?;
        require(
            mount_identity::id(base.as_fd(), true)? == mount,
            "backup runtime left original tmpfs",
        )?;
        preflight()?;
        let jobs = files::ensure_directory_relative(&base, Path::new("jobs"), 0o700, 0)?;
        shape(&jobs)?;
        require(
            mount_identity::id(jobs.as_fd(), true)? == mount,
            "backup jobs left original tmpfs",
        )?;
        preflight()?;
        let job_path = Path::new("/run/enzimos/backup-native/jobs").join(id);
        let job = files::create_directory(&job_path, 0o700, 0)?;
        shape(&job)?;
        preflight()?;
        let scratch = files::create_directory(&job_path.join("scratch"), 0o700, 0)?;
        let fresh = shape(&scratch)?;
        require(
            mount_identity::id(scratch.as_fd(), true)? == mount,
            "fresh scratch left original tmpfs",
        )?;
        preflight()?;
        let this = Self::open(id)?;
        require(
            this.shape == fresh && this.mount == mount,
            "fresh original scratch replaced before admission",
        )?;
        preflight()?;
        Ok(this)
    }
    /// The fresh worker's creator must have durably recorded intent before
    /// making this fixed scratch directory. Existing partial scratch is refused.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
    pub(crate) fn open(id: &str) -> Result<Self> {
        crate::namespaces::initial()?;
        require(
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "native backup runtime identifier",
        )?;
        let path = Path::new("/run/enzimos/backup-native/jobs")
            .join(id)
            .join("scratch");
        let scratch = files::directory(&path, Some(0))?;
        let shape = shape(&scratch)?;
        // SAFETY: `libc::statfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `fs` is a writable `libc::statfs` and `scratch` keeps the descriptor open.
            unsafe { libc::fstatfs(scratch.as_raw_fd(), &mut fs) } == 0 && fs.f_type == 0x01021994,
            "backup scratch must be original tmpfs",
        )?;
        let mount = mount_identity::id(scratch.as_fd(), true)?;
        let this = Self {
            image: Command::open("/usr/bin/restic")?,
            path,
            scratch,
            shape,
            mount,
        };
        this.empty()?;
        this.recheck()?;
        Ok(this)
    }
    fn empty(&self) -> Result<()> {
        require(
            files::directory_is_empty(&self.scratch)?,
            "backup scratch contains an unknown outcome; no adoption",
        )
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.image.recheck()?;
        let named = files::directory(&self.path, Some(0))?;
        require(
            shape(&named)? == self.shape
                && shape(&self.scratch)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.scratch.as_fd(), true)? == self.mount,
            "original native backup scratch changed",
        )
    }
    /// JSON evidence for the pinned Restic image.
    ///
    /// # Errors
    ///
    /// Fails when the image changed.
    pub fn image_evidence(&self) -> Result<Value> {
        self.recheck()?;
        self.image.evidence()
    }
    /// One original service performs all fixed provision steps. The original
    /// encrypted header is retained across child boundaries and idle intervals.
    ///
    /// # Errors
    ///
    /// Fails when an input or the consumer image differs from the original handoff, `boundary`
    /// fails, or a Restic command fails or is uncertain. Commands are never replayed.
    pub fn workflow(
        &self,
        work: crate::backup_worker_task::Work,
        repository: &File,
        credential: &File,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<WorkflowObservation> {
        use crate::backup_worker_task::Work;
        if let Work::Single(task) = work {
            let value = match self.run(task, repository, credential, boundary)? {
                Observed::Initialized => serde_json::json!({"status":"initialized"}),
                Observed::Authenticated(key) => {
                    serde_json::json!({"status":"authenticated","key_id":key})
                }
                Observed::IncorrectPassword => serde_json::json!({"status":"incorrect-password"}),
                Observed::MetadataChecked => serde_json::json!({"status":"metadata-checked"}),
            };
            return Ok(WorkflowObservation {
                value,
                header: None,
            });
        }
        let initializing = work == Work::ProvisionInitialize;
        if initializing {
            require(
                self.run(Task::Initialize, repository, credential, boundary)?
                    == Observed::Initialized,
                "initial provision did not initialize original empty repository",
            )?;
        }
        let header = crate::backup_repository_header::Header::observe(repository)?;
        let mut ongoing = || {
            header.recheck(repository)?;
            boundary()
        };
        let Observed::Authenticated(key) =
            self.run(Task::Authenticate, repository, credential, &mut ongoing)?
        else {
            return Err(enzimos_platform::Error(
                "stored provision credential did not authenticate; original attempt retained"
                    .into(),
            ));
        };
        require(
            self.run(Task::CheckMetadata, repository, credential, &mut ongoing)?
                == Observed::MetadataChecked,
            "original repository metadata check incomplete",
        )?;
        ongoing()?;
        let value = serde_json::json!({"status":"provisioned","mode":if initializing {"initialize"} else {"adopt"},
            "key_id":key,"metadata_checked":true,"header":header.evidence(repository)?});
        let repository = repository.try_clone()?;
        Ok(WorkflowObservation {
            value,
            header: Some((header, repository)),
        })
    }
    /// Only the native worker uses this after verifying its actual PID1 MainPID,
    /// original sender/caller pidfd, durable request and owned mount scope.
    /// The boundary is sampled throughout child execution, including idle time.
    pub(crate) fn run(
        &self,
        task: Task,
        repository: &File,
        credential: &File,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Observed> {
        self.recheck()?;
        self.empty()?;
        boundary()?;
        let mount = mount_identity::id(repository.as_fd(), true)?;
        let header = Header::observe(repository, task, mount, 0)?;
        let mut ongoing = || {
            self.recheck()?;
            if let Some(header) = &header {
                header.recheck(repository)?;
            }
            boundary()
        };
        let output = local_restic::execute(
            task,
            self.image.descriptor()?,
            repository,
            credential,
            &self.scratch,
            &mut ongoing,
        )?;
        self.recheck()?;
        boundary()?;
        self.empty()?;
        if let Some(header) = &header {
            header.recheck(repository)?;
        }
        let result = observed(task, output.status.code(), &output.stdout)?;
        if result == Observed::Initialized {
            Header::observe(repository, Task::CheckMetadata, mount, 0)?;
        }
        Ok(result)
    }
}
pub(crate) struct RemoteInitialized<'a> {
    entered: &'a crate::backup_remote_initialize::Entered<'a>,
    runtime: &'a Runtime,
    pin: Value,
}
impl RemoteInitialized<'_> {
    pub(crate) fn require_original(
        &self,
        entered: &crate::backup_remote_initialize::Entered<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.entered, entered),
            "remote observation belongs to another original initialization actor",
        )?;
        self.entered.recheck(authorize)?;
        self.runtime.recheck()?;
        self.runtime.empty()?;
        crate::backup_remote_record::pin(&self.pin)
    }
    pub(crate) fn pin(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.require_original(self.entered, authorize)?;
        Ok(&self.pin)
    }
}
struct Header {
    file: File,
    identity: files::FileIdentity,
    mount: u64,
    owner: u32,
    bytes: Vec<u8>,
}
impl Header {
    fn observe(repository: &File, task: Task, mount: u64, owner: u32) -> Result<Option<Self>> {
        if task == Task::Initialize {
            require(
                files::directory_is_empty(repository)?,
                "repository initialization requires an originally empty directory",
            )?;
            return Ok(None);
        }
        let file = files::open_relative(repository, Path::new("config"))?;
        let m = file.metadata()?;
        require(
            m.uid() == owner
                && m.mode() & 0o022 == 0
                && m.nlink() == 1
                && (1..=1024 * 1024).contains(&m.len())
                && mount_identity::id(file.as_fd(), true)? == mount,
            "original protected encrypted repository header required",
        )?;
        let this = Self {
            identity: files::identity(&m),
            bytes: files::read_file(&file, 1024 * 1024, Some(owner), true)?,
            file,
            mount,
            owner,
        };
        this.recheck(repository)?;
        Ok(Some(this))
    }
    fn recheck(&self, repository: &File) -> Result<()> {
        let named = files::open_relative(repository, Path::new("config"))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && files::read_file(&self.file, 1024 * 1024, Some(self.owner), true)? == self.bytes,
            "original encrypted repository header changed or replaced",
        )
    }
}
// Drop only retires descriptors. Unknown scratch is never swept on later entry.
/// The NAS share for one remote workflow: its endpoint and the prepared
/// attachment every remote Restic child of the workflow mounts privately.
///
/// # Errors
/// An invalid configuration, an unprotected share password, or a server
/// that cannot be found or does not answer.
pub(crate) fn remote_share(
    configuration: &Value,
    share_password: &File,
) -> Result<(
    std::sync::Arc<enzimos_platform::remote_mount_child::Prepared>,
    enzimos_platform::remote_restic::Endpoint,
)> {
    let endpoint = crate::backup_remote_endpoint::endpoint(configuration)?;
    let attachment = std::sync::Arc::new(enzimos_platform::remote_mount_child::Prepared::prepare(
        &endpoint,
        share_password,
    )?);
    Ok((attachment, endpoint))
}

#[path = "backup_credential_enroll.rs"]
pub mod enrollment;

#[path = "backup_remote_check.rs"]
pub mod remote_check;

#[path = "backup_retention_runtime.rs"]
pub mod retention;

#[path = "backup_recovery_export.rs"]
pub mod recovery_export;

#[path = "backup_remote_share.rs"]
pub mod remote_share;

#[path = "backup_remote_retention.rs"]
pub mod remote_retention;

#[path = "backup_system_restore.rs"]
pub mod system_restore;

mod rotation_prepare;
