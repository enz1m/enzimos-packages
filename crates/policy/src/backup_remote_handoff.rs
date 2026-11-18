// SPDX-License-Identifier: MIT
//! Independent admission of sixteen actual original descriptions by Root worker.
use crate::{
    backup_remote_request as wire,
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
const FOLDER: &str = "backup-remote-workers";
fn named(path: &str) -> Result<File> {
    let path = Path::new(path);
    let parent = files::directory(path.parent().unwrap(), Some(0))?;
    files::open_relative(&parent, Path::new(path.file_name().unwrap()))
}
pub struct Handoff<'s> {
    scope: &'s Scope,
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
    remote: crate::backup_remote_inputs::Inputs,
    pin: Observation,
    rotation: Option<Observation>,
    restic: crate::backup_restic_runtime::Image,
}
impl<'s> Handoff<'s> {
    pub fn receive(message: Message, scope: &'s Scope) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let binding = scope.binding()?;
        require(
            binding["worker"]["pid"] == std::process::id()
                && message.files.len() == wire::DESCRIPTORS,
            "remote receiver must be original actual Root worker with sixteen descriptors",
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
            "remote request differs from actual original worker scope",
        )?;
        let actor = &request["context"]["remote"]["caller"];
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
            "remote original backend image bytes differ",
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
            "remote current original worker image differs",
        )?;
        let original = files
            .iter()
            .enumerate()
            .map(|(i, file)| {
                if matches!(i, 1 | 3 | 4 | 5) {
                    Ok(None)
                } else {
                    Ok(Some(files::identity(&file.metadata()?)))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let source = crate::storage_runtime::Guard::observe()?;
        let remote = crate::backup_remote_inputs::Inputs::observe(&source)?;
        let pin = Observation::open(
            source.control(),
            Path::new("backup-remote-pin.json"),
            32768,
            source.control_mount_id(),
        )?;
        let rotation = Observation::optional(
            source.control(),
            Path::new("backup-remote-rotation.json"),
            crate::backup_remote_record::ROTATION_LIMIT,
            source.control_mount_id(),
        )?;
        let this = Self {
            scope,
            request,
            frame,
            original,
            numbers,
            caller,
            worker,
            configuration: crate::backup_configuration::Configuration::open()?,
            header: crate::backup_repository_header::Header::observe(&files[5])?,
            files,
            remote,
            pin,
            rotation,
            restic: crate::backup_restic_runtime::Image::open()?,
            source,
        };
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
            self.scope.binding()? == &self.request["worker"],
            "remote actual original worker cgroup/scope changed",
        )?;
        require(
            self.worker.stat.pid == std::process::id(),
            "remote handoff belongs to actual original worker",
        )?;
        for kind in crate::namespaces::KINDS {
            require(
                crate::namespaces::identity(self.caller.stat.pid, kind)?
                    == crate::namespaces::identity(2, kind)?,
                "remote Root sender left initial namespaces",
            )?;
        }
        for ((file, number), epoch) in self.files.iter().zip(&self.numbers).zip(&self.original) {
            self.caller.require_description(file.as_fd(), *number)?;
            if let Some(epoch) = epoch {
                require(
                    files::identity(&file.metadata()?) == *epoch,
                    "remote original description epoch changed",
                )?;
            }
        }
        require(
            process_identity::pidfd_target(self.files[1].as_fd())? == self.caller.stat.pid
                && json::decode(
                    &memfile::read_sealed(&self.files[0], wire::LIMIT, 0)?,
                    wire::LIMIT,
                )? == self.request,
            "remote original caller pidfd or sealed request differs",
        )?;
        let context = &self.request["context"];
        let remote = &context["remote"];
        self.source.recheck()?;
        require(
            self.source.backup_root_binding()? == context["source"]
                && self.configuration.evidence()? == context["local_configuration"],
            "remote original source or local configuration changed",
        )?;
        let destination =
            crate::backup_destination::Destination::open(&self.configuration, &self.source)?;
        destination.require_free_space()?;
        require(
            destination.evidence()? == context["destination"]
                && crate::backup_worker_scope::directory(&self.files[4])? == context["local_root"]
                && crate::backup_worker_scope::directory(destination.root_descriptor()?)?
                    == context["local_root"]
                && crate::backup_worker_scope::directory(&self.files[5])?
                    == context["local_repository"]
                && crate::backup_worker_scope::directory(&File::from(
                    destination.repository_descriptor()?.try_clone_to_owned()?,
                ))? == context["local_repository"],
            "actual local remote-copy repository differs from original",
        )?;
        let local_pin = crate::backup_admission::Repository::open(&destination)?;
        require(
            local_pin.evidence()? == context["local_pin"],
            "remote original local pin changed",
        )?;
        require(
            crate::backup_worker_scope::directory(&self.files[3])?
                == crate::backup_worker_scope::directory(self.source.control())?,
            "remote borrowed Root control differs from independently held control",
        )?;
        self.header.recheck(&self.files[5])?;
        require(
            self.header.evidence(&self.files[5])? == context["local_header"],
            "remote original local encrypted header changed",
        )?;
        require(
            self.remote.evidence(&self.source)? == remote["inputs"],
            "remote original input epochs/public bytes differ from independent admission",
        )?;
        self.pin.recheck()?;
        crate::backup_remote_record::pin(self.pin.value()?)?;
        require(
            self.pin.value()? == &remote["pin"] && self.pin.evidence()? == remote["pin_epoch"],
            "remote original pin bytes or epoch differ",
        )?;
        if let Some(rotation) = &self.rotation {
            rotation.recheck()?;
            crate::backup_remote_record::rotation(rotation.value()?)?;
            require(
                matches!(
                    rotation.value()?["phase"].as_str(),
                    Some("complete" | "abandoned")
                ) && rotation.evidence()? == remote["rotation_epoch"],
                "remote original rotation is unfinished or changed",
            )?;
        } else {
            require(
                remote["rotation_epoch"].is_null()
                    && Observation::optional(
                        self.source.control(),
                        Path::new("backup-remote-rotation.json"),
                        crate::backup_remote_record::ROTATION_LIMIT,
                        self.source.control_mount_id(),
                    )?
                    .is_none(),
                "remote rotation appeared at original absent name",
            )?;
        }
        require(
            self.restic.evidence()? == remote["restic"],
            "remote original vendor image differs from independent image admission",
        )?;
        for (i, epoch, mount) in [
            (2, &remote["caller"]["image_epoch"], None),
            (
                6,
                &context["local_credential"]["inode"],
                Some(&context["local_credential"]["mount"]),
            ),
            (
                7,
                &context["local_configuration"]["inode"],
                Some(&context["local_configuration"]["mount"]),
            ),
            (
                8,
                &context["local_pin"]["inode"],
                Some(&context["local_pin"]["mount"]),
            ),
            (
                9,
                &remote["restic"]["inode"],
                Some(&remote["restic"]["mount"]),
            ),
            (
                13,
                &remote["pin_epoch"]["epoch"],
                Some(&remote["pin_epoch"]["mount"]),
            ),
            (
                14,
                &context["operation_lock"]["inode"],
                Some(&context["operation_lock"]["mount"]),
            ),
            (
                15,
                &self.frame["intent"]["file"],
                Some(&self.frame["intent"]["mount"]),
            ),
        ] {
            identity(&self.files[i], epoch)?;
            if i != 14 {
                readonly(&self.files[i])?;
            }
            if let Some(mount) = mount {
                require(
                    mount_identity::id(self.files[i].as_fd(), true)? == *mount,
                    "remote original file mount changed",
                )?;
            }
        }
        let inputs = self.remote.descriptors(&self.source)?;
        for (j, fd) in inputs.iter().enumerate() {
            let actual = File::from(fd.try_clone_to_owned()?);
            identity(&self.files[10 + j], &remote["inputs"]["original_epochs"][j])?;
            readonly(&self.files[10 + j])?;
            require(
                files::identity(&actual.metadata()?)
                    == files::identity(&self.files[10 + j].metadata()?)
                    && mount_identity::id(actual.as_fd(), true)?
                        == mount_identity::id(self.files[10 + j].as_fd(), true)?,
                "remote original private/public input descriptor differs from independent original",
            )?;
        }
        let credential = named(crate::backup_configuration::PASSWORD)?;
        identity(&credential, &context["local_credential"]["inode"])?;
        require(
            mount_identity::id(credential.as_fd(), true)? == context["local_credential"]["mount"]
                && context["local_credential"]["mount"] == self.source.root_mount_id(),
            "remote original local credential left configured Root",
        )?;
        for (actual, i) in [
            (self.configuration.descriptor()?, 7),
            (local_pin.descriptor()?, 8),
            (self.restic.descriptor()?, 9),
            (self.pin.descriptor()?, 13),
        ] {
            require(
                files::identity(&actual.metadata()?) == files::identity(&self.files[i].metadata()?)
                    && mount_identity::id(actual.as_fd(), true)?
                        == mount_identity::id(self.files[i].as_fd(), true)?,
                "remote original document/vendor does not match independently held description",
            )?;
        }
        let lock = named("/run/enzimos/operation.lock")?;
        identity(&lock, &context["operation_lock"]["inode"])?;
        require(
            mount_identity::id(lock.as_fd(), true)? == context["operation_lock"]["mount"],
            "remote named original lock mount changed",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.files[14])?;
        let rival = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        let error = std::io::Error::last_os_error();
        require(
            rival == -1 && error.raw_os_error() == Some(libc::EWOULDBLOCK),
            "remote original lock exclusion unavailable",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.files[14])?;
        let registry =
            files::directory_relative(self.source.control(), Path::new(FOLDER), Some(0))?;
        let m = registry.metadata()?;
        let proof = &self.frame["intent"];
        require(
            serde_json::json!([m.dev(), m.ino(), m.mode(), m.uid(), m.gid()]) == proof["parent"]
                && mount_identity::id(registry.as_fd(), true)? == proof["mount"]
                && proof["mount"] == self.source.control_mount_id(),
            "remote original intent registry changed",
        )?;
        let record = files::open_relative(
            &registry,
            Path::new(&format!("{}.json", self.request["id"].as_str().unwrap())),
        )?;
        identity(&record, &proof["file"])?;
        require(
            mount_identity::id(record.as_fd(), true)? == proof["mount"],
            "remote named original intent mount changed",
        )?;
        let bytes = files::read_file(&self.files[15], wire::LIMIT, Some(0), true)?;
        require(
            json::sha256(&bytes) == proof["bytes_sha256"],
            "remote original send intent bytes changed",
        )?;
        let intent = json::decode(&bytes, wire::LIMIT)?;
        json::fields(
            &intent,
            "schema id phase request_sha256 worker receiver_accepted copy_complete receipt_complete",
        )?;
        require(
            intent["schema"] == 1
                && intent["id"] == self.request["id"]
                && intent["phase"] == "send-entered"
                && intent["request_sha256"] == json::fingerprint(&self.request)?
                && intent["worker"] == self.request["worker"]
                && intent["receiver_accepted"] == false
                && intent["copy_complete"] == false
                && intent["receipt_complete"] == false,
            "remote must retain actual original one-use send intent without adoption",
        )
    }
    pub(crate) fn guard(&self) -> Result<&crate::storage_runtime::Guard> {
        self.recheck()?;
        Ok(&self.source)
    }
    pub(crate) fn legacy_binding(&self) -> Result<Value> {
        self.recheck()?;
        crate::backup_destination::legacy_binding(
            &self.request["context"]["destination"],
            &self.source,
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
    /// Only independently admitted original descriptions, still requiring this
    /// live Root worker and original sender at every consumer checkpoint.
    pub fn descriptors(&self) -> Result<std::collections::BTreeMap<&'static str, &File>> {
        self.recheck()?;
        Ok(wire::ROLES
            .iter()
            .enumerate()
            .map(|(i, role)| (*role, &self.files[i + 1]))
            .collect())
    }
}
