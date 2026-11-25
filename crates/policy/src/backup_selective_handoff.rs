// SPDX-License-Identifier: MIT
//! Admission of actual original selective export descriptions; no consumer execution.
use crate::{
    backup_selective_request as wire,
    backup_worker_handoff::{identity, readonly},
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
const FOLDER: &str = "selective-export-workers";
fn named(path: &str) -> Result<File> {
    let path = Path::new(path);
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(0),
    )?;
    files::open_relative(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        ),
    )
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
    configuration: crate::backup_configuration::Configuration,
    header: crate::backup_repository_header::Header,
}
impl Handoff {
    pub fn receive(message: Message, scope: &Scope) -> Result<Self> {
        Self::receive_original(message, || scope)
    }
    fn receive_original<'s>(
        message: Message,
        original: impl FnOnce() -> &'s Scope,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let scope = original();
        let binding = scope.binding()?;
        require(
            binding["worker"]["pid"] == std::process::id()
                && message.files.len() == wire::DESCRIPTORS,
            "selective export receiver must be actual original worker with exact descriptors",
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
            "selective export request differs from actual worker scope",
        )?;
        let actor = &request["context"]["caller"];
        let caller = Retained::open(
            enzimos_platform::json::unsigned(&actor["pid"])? as u32,
            enzimos_platform::json::unsigned(&actor["start_ticks"])?,
            0,
            &[PathBuf::from(BACKEND)],
        )?
        .pin_executable(&files[2])?;
        identity(&files[2], &actor["image_epoch"])?;
        require(
            stream_copy::hash_borrowed(&files[2], 32 * 1024 * 1024, Some(0))?.1
                == actor["executable_sha256"],
            "selective export original backend image bytes differ",
        )?;
        let image = named(WORKER)?;
        let worker = Retained::open(
            std::process::id(),
            enzimos_platform::json::unsigned(&binding["worker"]["start_ticks"])?,
            0,
            &[PathBuf::from(WORKER)],
        )?
        .pin_executable(&image)?;
        require(
            stream_copy::hash_borrowed(&image, 32 * 1024 * 1024, Some(0))?.1
                == binding["worker"]["executable_sha256"],
            "actual current selective export worker image differs",
        )?;
        let original = files
            .iter()
            .enumerate()
            .map(|(i, file)| {
                if matches!(i, 1 | 3 | 4) {
                    Ok(None)
                } else {
                    Ok(Some(files::identity(&file.metadata()?)))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let source = crate::storage_runtime::Guard::observe()?;
        let configuration = crate::backup_configuration::Configuration::open()?;
        let header = crate::backup_repository_header::Header::observe(&files[4])?;
        let this = Self {
            request,
            frame,
            files,
            numbers,
            original,
            caller,
            worker,
            source,
            configuration,
            header,
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
            "selective export handoff belongs to original worker",
        )?;
        for kind in crate::namespaces::KINDS {
            require(
                crate::namespaces::identity(self.caller.stat.pid, kind)?
                    == crate::namespaces::identity(2, kind)?,
                "original selective export caller left initial namespace",
            )?;
        }
        for ((file, number), epoch) in self.files.iter().zip(&self.numbers).zip(&self.original) {
            self.caller.require_description(file.as_fd(), *number)?;
            if let Some(epoch) = epoch {
                require(
                    files::identity(&file.metadata()?) == *epoch,
                    "original selective export description epoch changed",
                )?;
            }
        }
        require(
            process_identity::pidfd_target(self.files[1].as_fd())? == self.caller.stat.pid
                && json::decode(
                    &memfile::read_sealed(&self.files[0], wire::LIMIT, 0)?,
                    wire::LIMIT,
                )? == self.request,
            "original selective export caller pidfd or sealed request changed",
        )?;
        let context = &self.request["context"];
        self.source.recheck()?;
        require(
            self.source.backup_root_binding()? == context["source"]
                && self.configuration.evidence()? == context["configuration"],
            "selective export original source or configuration changed",
        )?;
        let destination =
            crate::backup_destination::Destination::open(&self.configuration, &self.source)?;
        destination.require_writable()?;
        require(
            destination.evidence()? == context["destination"]
                && crate::backup_worker_scope::directory(&self.files[3])?
                    == context["root_directory"]
                && crate::backup_worker_scope::directory(destination.root_descriptor()?)?
                    == context["root_directory"]
                && crate::backup_worker_scope::directory(&self.files[4])?
                    == context["repository_directory"],
            "actual borrowed selective export destination differs from original",
        )?;
        let repository = crate::backup_admission::Repository::open(&destination)?;
        require(
            repository.evidence()? == context["pin"],
            "selective export original stored pin changed",
        )?;
        for (i, metadata) in [
            (2, &context["caller"]["image_epoch"]),
            (5, &context["credential"]["inode"]),
            (6, &context["restic"]["inode"]),
            (7, &context["configuration"]["inode"]),
            (8, &context["pin"]["inode"]),
            (9, &context["operation_lock"]["inode"]),
            (10, &self.frame["intent"]["file"]),
        ] {
            identity(&self.files[i], metadata)?;
            if i != 9 {
                readonly(&self.files[i])?;
            }
        }
        let credential = named(crate::backup_configuration::PASSWORD)?;
        identity(&credential, &context["credential"]["inode"])?;
        require(
            mount_identity::id(credential.as_fd(), true)? == context["credential"]["mount"],
            "named original selective credential mount changed",
        )?;
        require(
            mount_identity::id(self.files[5].as_fd(), true)? == context["credential"]["mount"]
                && context["credential"]["mount"] == self.source.root_mount_id(),
            "original selective export credential left configured Root mount",
        )?;
        for (i, expected) in [
            (6, &context["restic"]),
            (7, &context["configuration"]),
            (8, &context["pin"]),
        ] {
            require(
                mount_identity::id(self.files[i].as_fd(), true)? == expected["mount"],
                "original selective export public document or vendor mount changed",
            )?;
        }
        let restic = named("/usr/bin/restic")?;
        identity(&restic, &context["restic"]["inode"])?;
        require(
            mount_identity::id(restic.as_fd(), true)? == context["restic"]["mount"],
            "named original Restic mount changed",
        )?;
        self.header.recheck(&self.files[4])?;
        require(
            self.header.evidence(&self.files[4])? == context["header"],
            "original selective export header changed",
        )?;
        let lock = named("/run/enzimos/operation.lock")?;
        identity(&lock, &context["operation_lock"]["inode"])?;
        require(
            mount_identity::id(lock.as_fd(), true)? == context["operation_lock"]["mount"],
            "named original lock mount changed",
        )?;
        require(
            mount_identity::id(self.files[9].as_fd(), true)? == context["operation_lock"]["mount"],
            "original selective export lock mount changed",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.files[9])?;
        let rival = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        let error = std::io::Error::last_os_error();
        require(
            rival == -1 && error.raw_os_error() == Some(libc::EWOULDBLOCK),
            "original selective export lock exclusion unavailable",
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
            "original selective export intent registry changed",
        )?;
        let record = files::open_relative(
            &registry,
            Path::new(&format!(
                "{}.json",
                enzimos_platform::json::string(&self.request["id"])?
            )),
        )?;
        identity(&record, &proof["file"])?;
        require(
            mount_identity::id(record.as_fd(), true)? == proof["mount"],
            "named original selective export intent mount changed",
        )?;
        require(
            mount_identity::id(self.files[10].as_fd(), true)? == proof["mount"],
            "original selective export intent mount changed",
        )?;
        let bytes = files::read_file(&self.files[10], wire::LIMIT, Some(0), true)?;
        require(
            json::sha256(&bytes) == proof["bytes_sha256"],
            "original selective export intent bytes changed",
        )?;
        let intent = json::decode(&bytes, wire::LIMIT)?;
        json::fields(
            &intent,
            "schema id phase request_sha256 worker receiver_accepted export_complete live_home_written",
        )?;
        require(
            intent["schema"] == 1
                && intent["id"] == self.request["id"]
                && intent["phase"] == "send-entered"
                && intent["request_sha256"] == json::fingerprint(&self.request)?
                && intent["worker"] == self.request["worker"]
                && intent["receiver_accepted"] == false
                && intent["export_complete"] == false
                && intent["live_home_written"] == false,
            "selective export must retain actual original send intent, without receipt adoption",
        )
    }
    pub fn request(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.request)
    }
    /// The original caller process, for liveness while awaiting its answer.
    pub(crate) fn original_caller(&self) -> Result<&Retained> {
        self.recheck()?;
        Ok(&self.caller)
    }
    pub fn repository_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.files[4])
    }
    pub(crate) fn current_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.files[5])
    }
    pub fn consumer_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.files[6])
    }
}
