// SPDX-License-Identifier: MIT
//! Admission of the actual original transfer descriptions; no consumer execution.
use crate::{
    backup_transfer_request as wire,
    backup_worker_handoff::{identity, readonly},
    control_record::Observation,
};
use enzimos_platform::{
    Result,
    backup_worker_scope::Scope,
    fd_packet::Message,
    files, json, memfile, mount_identity,
    process_identity::{self, Retained},
    require, stream_copy,
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
const BACKEND: &str = "/usr/lib/enzimos-backend/enzimos-system-backend";
const WORKER: &str = "/usr/lib/enzimos-backend/enzimos-backup-worker";
const FOLDER: &str = "backup-transfer-workers";
fn named(path: &str) -> Result<File> {
    let path = Path::new(path);
    let parent = files::directory(path.parent().unwrap(), Some(0))?;
    files::open_relative(&parent, Path::new(path.file_name().unwrap()))
}
/// What the worker independently re-observes for the destination role.
#[allow(
    clippy::large_enum_variant,
    reason = "One value per transfer, never moved in bulk."
)]
enum Admitted {
    Drive {
        configuration: crate::backup_configuration::Configuration,
        header: crate::backup_repository_header::Header,
    },
    Share(ShareInputs),
}
struct ShareInputs {
    remote: crate::backup_remote_inputs::Inputs,
    pin: Observation,
    rotation: Option<Observation>,
    restic: crate::backup_restic_runtime::Image,
}
pub struct Handoff {
    request: Value,
    frame: Value,
    files: Vec<File>,
    numbers: Vec<u32>,
    original: Vec<Option<files::FileIdentity>>,
    caller: Retained,
    worker: Retained,
    source: crate::storage_runtime::Guard,
    admitted: Admitted,
}
impl Handoff {
    pub fn receive(message: Message, scope: &Scope) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let binding = scope.binding()?;
        require(
            binding["worker"]["pid"] == std::process::id()
                && message.files.len() == wire::DESCRIPTORS,
            "transfer receiver must be actual original worker with exact descriptors",
        )?;
        let files = message
            .files
            .into_iter()
            .map(File::from)
            .collect::<Vec<_>>();
        let request = json::decode(
            &memfile::read_sealed(&files[0], wire::LIMIT, 0)?,
            wire::LIMIT,
        )?;
        let frame = json::decode(&message.body, wire::LIMIT)?;
        let numbers = wire::frame(&frame, &request, &message.sender)?;
        require(
            request["worker"] == *binding,
            "transfer request differs from actual worker scope",
        )?;
        let actor = &request["context"]["caller"];
        let caller = Retained::open(
            actor["pid"].as_u64().unwrap() as u32,
            actor["start_ticks"].as_u64().unwrap(),
            0,
            &[PathBuf::from(BACKEND)],
        )?
        .pin_executable(&files[2])?;
        identity(&files[2], &actor["image_epoch"])?;
        require(
            stream_copy::hash_borrowed(&files[2], 32 * 1024 * 1024, Some(0))?.1
                == actor["executable_sha256"],
            "transfer original backend image bytes differ",
        )?;
        let image = named(WORKER)?;
        let worker = Retained::open(
            std::process::id(),
            binding["worker"]["start_ticks"].as_u64().unwrap(),
            0,
            &[PathBuf::from(WORKER)],
        )?
        .pin_executable(&image)?;
        require(
            stream_copy::hash_borrowed(&image, 32 * 1024 * 1024, Some(0))?.1
                == binding["worker"]["executable_sha256"],
            "actual current transfer worker image differs",
        )?;
        let share = wire::share(&request["context"]);
        // Directories (root, repository, Root control) and the pidfd have no
        // stable file epoch; their identities are checked by role instead.
        let original = files
            .iter()
            .enumerate()
            .map(|(i, file)| {
                if i == 1 || i == 3 || (i == 4 && !share) {
                    Ok(None)
                } else {
                    Ok(Some(files::identity(&file.metadata()?)))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let source = crate::storage_runtime::Guard::observe()?;
        let admitted = if share {
            Admitted::Share(ShareInputs {
                remote: crate::backup_remote_inputs::Inputs::observe(&source)?,
                pin: Observation::open(
                    source.control(),
                    Path::new("backup-remote-pin.json"),
                    32768,
                    source.control_mount_id(),
                )?,
                rotation: Observation::optional(
                    source.control(),
                    Path::new("backup-remote-rotation.json"),
                    crate::backup_remote_record::ROTATION_LIMIT,
                    source.control_mount_id(),
                )?,
                restic: crate::backup_restic_runtime::Image::open()?,
            })
        } else {
            Admitted::Drive {
                configuration: crate::backup_configuration::Configuration::open()?,
                header: crate::backup_repository_header::Header::observe(&files[4])?,
            }
        };
        let this = Self {
            request,
            frame,
            files,
            numbers,
            original,
            caller,
            worker,
            source,
            admitted,
        };
        this.recheck()?;
        crate::backup_worker_handoff::command(&this.files[6], &this.request["context"]["restic"])?;
        this.recheck()?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
    pub fn recheck(&self) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        self.caller.recheck()?;
        self.worker.recheck()?;
        require(
            self.worker.stat.pid == std::process::id(),
            "transfer handoff belongs to original worker",
        )?;
        for kind in crate::namespaces::KINDS {
            require(
                crate::namespaces::identity(self.caller.stat.pid, kind)?
                    == crate::namespaces::identity(2, kind)?,
                "original transfer caller left initial namespace",
            )?;
        }
        for ((file, number), epoch) in self.files.iter().zip(&self.numbers).zip(&self.original) {
            self.caller.require_description(file.as_fd(), *number)?;
            if let Some(epoch) = epoch {
                require(
                    files::identity(&file.metadata()?) == *epoch,
                    "original transfer description epoch changed",
                )?;
            }
        }
        require(
            process_identity::pidfd_target(self.files[1].as_fd())? == self.caller.stat.pid
                && json::decode(
                    &memfile::read_sealed(&self.files[0], wire::LIMIT, 0)?,
                    wire::LIMIT,
                )? == self.request,
            "original transfer caller pidfd or sealed request changed",
        )?;
        let context = &self.request["context"];
        self.source.recheck()?;
        require(
            self.source.backup_root_binding()? == context["source"],
            "transfer original source changed",
        )?;
        match &self.admitted {
            Admitted::Drive {
                configuration,
                header,
            } => self.recheck_drive(configuration, header)?,
            Admitted::Share(share) => self.recheck_share(
                &share.remote,
                &share.pin,
                share.rotation.as_ref(),
                &share.restic,
            )?,
        }
        for (i, metadata) in [
            (2, &context["caller"]["image_epoch"]),
            (6, &context["restic"]["inode"]),
            (9, &context["operation_lock"]["inode"]),
            (10, &self.frame["intent"]["file"]),
        ] {
            identity(&self.files[i], metadata)?;
            if i != 9 {
                readonly(&self.files[i])?;
            }
        }
        require(
            mount_identity::id(self.files[6].as_fd(), true)? == context["restic"]["mount"],
            "original transfer public document or vendor mount changed",
        )?;
        let restic = named("/usr/bin/restic")?;
        identity(&restic, &context["restic"]["inode"])?;
        require(
            mount_identity::id(restic.as_fd(), true)? == context["restic"]["mount"],
            "named original Restic mount changed",
        )?;
        let lock = named("/run/enzimos/operation.lock")?;
        identity(&lock, &context["operation_lock"]["inode"])?;
        require(
            mount_identity::id(lock.as_fd(), true)? == context["operation_lock"]["mount"],
            "named original lock mount changed",
        )?;
        require(
            mount_identity::id(self.files[9].as_fd(), true)? == context["operation_lock"]["mount"],
            "original transfer lock mount changed",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.files[9])?;
        let rival = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        let error = std::io::Error::last_os_error();
        require(
            rival == -1 && error.raw_os_error() == Some(libc::EWOULDBLOCK),
            "original transfer lock exclusion unavailable",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.files[9])?;
        let registry =
            files::directory_relative(self.source.control(), Path::new(FOLDER), Some(0))?;
        let m = registry.metadata()?;
        let proof = &self.frame["intent"];
        require(
            serde_json::json!([m.dev(), m.ino(), m.mode(), m.uid(), m.gid()]) == proof["parent"]
                && mount_identity::id(registry.as_fd(), true)? == proof["mount"]
                && proof["mount"] == self.source.control_mount_id(),
            "original transfer intent registry changed",
        )?;
        let record = files::open_relative(
            &registry,
            Path::new(&format!("{}.json", self.request["id"].as_str().unwrap())),
        )?;
        identity(&record, &proof["file"])?;
        require(
            mount_identity::id(record.as_fd(), true)? == proof["mount"],
            "named original transfer intent mount changed",
        )?;
        require(
            mount_identity::id(self.files[10].as_fd(), true)? == proof["mount"],
            "original transfer intent mount changed",
        )?;
        let bytes = files::read_file(&self.files[10], wire::LIMIT, Some(0), true)?;
        require(
            json::sha256(&bytes) == proof["bytes_sha256"],
            "original transfer intent bytes changed",
        )?;
        let intent = json::decode(&bytes, wire::LIMIT)?;
        json::fields(
            &intent,
            "schema id phase request_sha256 worker receiver_accepted transfer_complete backup_complete",
        )?;
        require(
            intent["schema"] == 1
                && intent["id"] == self.request["id"]
                && intent["phase"] == "send-entered"
                && intent["request_sha256"] == json::fingerprint(&self.request)?
                && intent["worker"] == self.request["worker"]
                && intent["receiver_accepted"] == false
                && intent["transfer_complete"] == false
                && intent["backup_complete"] == false,
            "transfer must retain actual original send intent, without receipt adoption",
        )
    }
    /// The borrowed drive destination, its pin, configuration, credential and
    /// encrypted header, each against an independent observation.
    fn recheck_drive(
        &self,
        configuration: &crate::backup_configuration::Configuration,
        header: &crate::backup_repository_header::Header,
    ) -> Result<()> {
        let context = &self.request["context"];
        require(
            configuration.evidence()? == context["configuration"],
            "transfer original source or configuration changed",
        )?;
        let destination =
            crate::backup_destination::Destination::open(configuration, &self.source)?;
        destination.require_free_space()?;
        require(
            destination.evidence()? == context["destination"]
                && crate::backup_worker_scope::directory(&self.files[3])?
                    == context["root_directory"]
                && crate::backup_worker_scope::directory(destination.root_descriptor()?)?
                    == context["root_directory"]
                && crate::backup_worker_scope::directory(&self.files[4])?
                    == context["repository_directory"],
            "actual borrowed transfer destination differs from original",
        )?;
        let repository = crate::backup_admission::Repository::open(&destination)?;
        require(
            repository.evidence()? == context["pin"],
            "transfer original stored pin changed",
        )?;
        for (i, metadata) in [
            (5, &context["credential"]["inode"]),
            (7, &context["configuration"]["inode"]),
            (8, &context["pin"]["inode"]),
        ] {
            identity(&self.files[i], metadata)?;
            readonly(&self.files[i])?;
        }
        let credential = named(crate::backup_configuration::PASSWORD)?;
        identity(&credential, &context["credential"]["inode"])?;
        require(
            mount_identity::id(credential.as_fd(), true)? == context["credential"]["mount"],
            "named original credential mount changed",
        )?;
        require(
            mount_identity::id(self.files[5].as_fd(), true)? == context["credential"]["mount"]
                && context["credential"]["mount"] == self.source.root_mount_id(),
            "original transfer credential left configured Root mount",
        )?;
        for (i, expected) in [(7, &context["configuration"]), (8, &context["pin"])] {
            require(
                mount_identity::id(self.files[i].as_fd(), true)? == expected["mount"],
                "original transfer public document or vendor mount changed",
            )?;
        }
        header.recheck(&self.files[4])?;
        require(
            header.evidence(&self.files[4])? == context["header"],
            "original transfer header changed",
        )
    }
    /// The share configuration, both passwords and the share pin, each the
    /// same description as an independent observation of the live names; an
    /// unfinished share rotation is refused.
    fn recheck_share(
        &self,
        remote: &crate::backup_remote_inputs::Inputs,
        pin: &Observation,
        rotation: Option<&Observation>,
        restic: &crate::backup_restic_runtime::Image,
    ) -> Result<()> {
        let context = &self.request["context"];
        let share = &context["share"];
        require(
            crate::backup_worker_scope::directory(&self.files[3])? == context["root_control"]
                && crate::backup_worker_scope::directory(self.source.control())?
                    == context["root_control"],
            "borrowed Root control differs from independently held control",
        )?;
        require(
            remote.evidence(&self.source)? == share["inputs"],
            "share input epochs or public bytes differ from independent admission",
        )?;
        pin.recheck()?;
        crate::backup_remote_record::pin(pin.value()?)?;
        require(
            pin.value()? == &share["pin"] && pin.evidence()? == share["pin_epoch"],
            "share pin bytes or epoch differ",
        )?;
        if let Some(rotation) = rotation {
            rotation.recheck()?;
            crate::backup_remote_record::rotation(rotation.value()?)?;
            require(
                matches!(
                    rotation.value()?["phase"].as_str(),
                    Some("complete" | "abandoned")
                ) && rotation.evidence()? == share["rotation_epoch"],
                "share rotation is unfinished or changed",
            )?;
        } else {
            require(
                share["rotation_epoch"].is_null()
                    && Observation::optional(
                        self.source.control(),
                        Path::new("backup-remote-rotation.json"),
                        crate::backup_remote_record::ROTATION_LIMIT,
                        self.source.control_mount_id(),
                    )?
                    .is_none(),
                "share rotation appeared at original absent name",
            )?;
        }
        require(
            restic.evidence()? == context["restic"],
            "share transfer vendor image differs from independent image admission",
        )?;
        let inputs = remote.descriptors(&self.source)?;
        for (j, i) in [(0, 4), (1, 5), (2, 7)] {
            let actual = File::from(inputs[j].try_clone_to_owned()?);
            identity(&self.files[i], &share["inputs"]["original_epochs"][j])?;
            readonly(&self.files[i])?;
            require(
                files::identity(&actual.metadata()?) == files::identity(&self.files[i].metadata()?)
                    && mount_identity::id(actual.as_fd(), true)?
                        == mount_identity::id(self.files[i].as_fd(), true)?,
                "share input descriptor differs from independent original",
            )?;
        }
        identity(&self.files[8], &share["pin_epoch"]["epoch"])?;
        readonly(&self.files[8])?;
        require(
            mount_identity::id(self.files[8].as_fd(), true)? == share["pin_epoch"]["mount"]
                && files::identity(&pin.descriptor()?.metadata()?)
                    == files::identity(&self.files[8].metadata()?),
            "share pin descriptor differs from independent original",
        )
    }
    pub fn request(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.request)
    }
    pub(crate) fn original_caller(&self) -> Result<&Retained> {
        self.recheck()?;
        Ok(&self.caller)
    }
    pub(crate) fn original_source(&self) -> Result<&crate::storage_runtime::Guard> {
        self.recheck()?;
        Ok(&self.source)
    }
    pub(crate) fn require_original_caller_image(&self, image: &File) -> Result<()> {
        self.recheck()?;
        require(
            files::identity(&image.metadata()?) == files::identity(&self.files[2].metadata()?)
                && mount_identity::id(image.as_fd(), true)?
                    == mount_identity::id(self.files[2].as_fd(), true)?,
            "source offer image differs from original transfer caller",
        )
    }
    fn drive(&self) -> Result<()> {
        self.recheck()?;
        require(
            matches!(self.admitted, Admitted::Drive { .. }),
            "drive repository role of a share transfer",
        )
    }
    pub fn repository_descriptor(&self) -> Result<&File> {
        self.drive()?;
        Ok(&self.files[4])
    }
    pub fn credential_descriptor(&self) -> Result<&File> {
        self.drive()?;
        Ok(&self.files[5])
    }
    /// The share configuration, share password and repository password of a
    /// transfer into the NAS share, or `None` for a drive transfer.
    pub fn share(&self) -> Result<Option<(&Value, &File, &File)>> {
        self.recheck()?;
        Ok(match &self.admitted {
            Admitted::Drive { .. } => None,
            Admitted::Share(_) => Some((
                &self.request["context"]["share"]["inputs"]["configuration"],
                &self.files[7],
                &self.files[5],
            )),
        })
    }
    pub fn consumer_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.files[6])
    }
}
