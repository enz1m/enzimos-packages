// SPDX-License-Identifier: MIT
//! Original descriptor admission; this is not a launch or completion authority.
use enzimos_platform::{
    Result, fd_packet, files, json, memfile, mount_identity, process_identity, require, secret,
    stream_copy,
};
use serde_json::Value;
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
const IMAGE: &str = "/usr/lib/enzimos-backend/enzimos-system-backend";
/// Descriptors received from the backend for one worker request.
pub struct Handoff {
    request: Value,
    worker: Value,
    files: Vec<File>,
    numbers: Vec<u32>,
    original: Vec<Option<files::FileIdentity>>,
    caller: process_identity::Retained,
    source: crate::storage_runtime::Guard,
    header: Option<crate::backup_repository_header::Header>,
}
pub(crate) fn identity(file: &File, expected: &Value) -> Result<()> {
    require(
        serde_json::to_value(files::identity(&file.metadata()?))? == *expected,
        "worker original file identity differs from request",
    )
}
fn named(path: &Path) -> Result<File> {
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
pub(crate) fn readonly(file: &File) -> Result<()> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "worker borrowed authority must be read-only",
    )
}
pub(crate) fn command(file: &File, evidence: &Value) -> Result<()> {
    crate::settings_command::validate(evidence)?;
    readonly(file)?;
    identity(file, &evidence["inode"])?;
    require(
        mount_identity::id(file.as_fd(), true)? == evidence["mount"],
        "worker vendor mount changed",
    )?;
    let path = Path::new(enzimos_platform::json::string(&evidence["path"])?);
    let parent = files::directory(
        path.parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?,
        Some(0),
    )?;
    let named = files::open_relative(
        &parent,
        Path::new(
            path.file_name()
                .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?,
        ),
    )?;
    identity(&named, &evidence["inode"])?;
    require(
        mount_identity::id(named.as_fd(), true)? == evidence["mount"]
            && stream_copy::hash_borrowed(
                file,
                enzimos_platform::process::executable_limit(
                    path.to_str()
                        .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
                ),
                Some(0),
            )?
            .1 == evidence["sha256"],
        "worker original vendor image changed",
    )?;
    identity(file, &evidence["inode"])
}
impl Handoff {
    /// The owning service must separately prove its registered PID1 MainPID,
    /// invocation and original cgroup before using these borrowed descriptors.
    /// This constructor never creates scratch files, consumes a password or runs a child.
    ///
    /// # Errors
    ///
    /// Fails when the sender is not the captured worker or the descriptor count differs.
    pub fn receive(
        message: fd_packet::Message,
        scope: &enzimos_platform::backup_worker_scope::Scope,
    ) -> Result<Self> {
        crate::namespaces::initial()?;
        let worker = scope.binding()?.clone();
        require(
            worker["worker"]["pid"] == std::process::id(),
            "handoff receiver is not captured original worker",
        )?;
        require(
            (9..=11).contains(&message.files.len()),
            "native backup handoff descriptor count",
        )?;
        let files = message
            .files
            .into_iter()
            .map(File::from)
            .collect::<Vec<_>>();
        let request = json::decode(
            &memfile::read_sealed(&files[0], crate::backup_worker_request::LIMIT, 0)?,
            crate::backup_worker_request::LIMIT,
        )?;
        let frame = json::decode(&message.body, crate::backup_worker_request::LIMIT)?;
        let numbers = crate::backup_worker_request::frame(&frame, &request, &message.sender)?;
        require(
            numbers.len() == files.len(),
            "native backup SCM descriptor count changed",
        )?;
        let actor = &request["caller"];
        let caller = process_identity::Retained::open(
            enzimos_platform::json::unsigned(&actor["pid"])? as u32,
            enzimos_platform::json::unsigned(&actor["start_ticks"])?,
            0,
            &[PathBuf::from(IMAGE)],
        )?
        .pin_executable(&files[4])?;
        require(
            stream_copy::hash_borrowed(&files[4], 32 * 1024 * 1024, Some(0))?.1
                == actor["executable_sha256"],
            "worker caller image differs from original plan",
        )?;
        let source = crate::storage_runtime::Guard::observe()?;
        let original = files
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if (3..=3).contains(&i) || (5..=6).contains(&i) {
                    Ok(None)
                } else {
                    Ok(Some(files::identity(&f.metadata()?)))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let mut this = Self {
            request,
            worker,
            files,
            numbers,
            original,
            caller,
            source,
            header: None,
        };
        this.recheck()?;
        if !this.request["header"].is_null() {
            let header = crate::backup_repository_header::Header::observe(&this.files[6])?;
            require(
                header.evidence(&this.files[6])? == this.request["header"],
                "worker original encrypted header differs from admitted request",
            )?;
            this.header = Some(header);
        }
        this.recheck()?;
        Ok(this)
    }
    fn original_files(&self) -> Result<()> {
        for (file, expected) in self.files.iter().zip(&self.original) {
            if let Some(expected) = expected {
                require(
                    files::identity(&file.metadata()?) == *expected,
                    "worker admitted original metadata changed",
                )?;
            }
        }
        Ok(())
    }
    /// The received request.
    ///
    /// # Errors
    ///
    /// Fails when the handoff changed.
    pub fn request(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.request)
    }
    /// The original caller process, for liveness while awaiting its answer.
    pub(crate) fn original_caller(&self) -> Result<&process_identity::Retained> {
        self.recheck()?;
        Ok(&self.caller)
    }
    /// Only after current PID1 admission and a fresh caller checkpoint may the
    /// worker pass this original descriptor to the closed Restic consumer.
    ///
    /// # Errors
    ///
    /// Fails when the request has no consumer input or the handoff changed.
    pub fn consumer_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(if self.request["consumer_input"].is_null() {
            &self.files[7]
        } else {
            self.files
                .last()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
        })
    }
    /// The received repository descriptor.
    ///
    /// # Errors
    ///
    /// Fails when the handoff changed.
    pub fn repository_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.files[6])
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (flock).")]
    pub(crate) fn recheck(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.original_files()?;
        self.caller.recheck()?;
        for kind in crate::namespaces::KINDS {
            require(
                crate::namespaces::identity(self.caller.stat.pid, kind)?
                    == crate::namespaces::identity(2, kind)?,
                "worker caller left initial namespace",
            )?;
        }
        for (file, number) in self.files.iter().zip(&self.numbers) {
            self.caller.require_description(file.as_fd(), *number)?;
        }
        require(
            process_identity::pidfd_target(self.files[3].as_fd())? == self.caller.stat.pid,
            "worker original caller pidfd target changed",
        )?;
        require(
            json::decode(
                &memfile::read_sealed(&self.files[0], crate::backup_worker_request::LIMIT, 0)?,
                crate::backup_worker_request::LIMIT,
            )? == self.request,
            "worker immutable request changed",
        )?;
        let id = enzimos_platform::json::string(&self.request["id"])?;
        let intent = json::decode(
            &files::read_file(&self.files[1], 128 * 1024, Some(0), true)?,
            128 * 1024,
        )?;
        crate::backup_worker_intent::validate(&intent, id)?;
        require(
            intent["phase"] == "starting"
                && intent["request"] == self.request
                && intent["worker"] == self.worker,
            "worker must receive exact original starting intent",
        )?;
        readonly(&self.files[1])?;
        let directory = files::directory_relative(
            self.source.control(),
            Path::new("backup-native-workers"),
            Some(0),
        )?;
        let dm = directory.metadata()?;
        let jm = self.files[1].metadata()?;
        require(
            dm.uid() == 0
                && dm.gid() == 0
                && dm.mode() & 0o7777 == 0o700
                && mount_identity::id(directory.as_fd(), true)? == self.source.control_mount_id()
                && jm.uid() == 0
                && jm.gid() == 0
                && jm.mode() & 0o7777 == 0o600
                && jm.nlink() == 1,
            "worker starting journal must remain Root-private on original control mount",
        )?;
        let journal = files::open_relative(&directory, Path::new(&format!("{id}.json")))?;
        require(
            files::identity(&journal.metadata()?) == files::identity(&self.files[1].metadata()?)
                && mount_identity::id(self.files[1].as_fd(), true)?
                    == self.source.control_mount_id(),
            "worker original starting intent replaced or remounted",
        )?;
        let lock = named(Path::new("/run/enzimos/operation.lock"))?;
        let lock_identity = files::identity(&self.files[2].metadata()?);
        require(
            files::identity(&lock.metadata()?) == lock_identity
                && lock_identity.2 == 0
                && lock_identity.7 & 0o7777 == 0o600
                && lock_identity.8 == 0
                && lock_identity.9 == 0
                && lock_identity.10 == 1,
            "worker original operation lock replaced or unsafe",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.files[2])?;
        // SAFETY: flock takes no pointers and `lock` keeps the descriptor open.
        let rival = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        let error = std::io::Error::last_os_error();
        require(
            rival == -1 && error.raw_os_error() == Some(libc::EWOULDBLOCK),
            "worker original lock exclusion unavailable",
        )?;
        enzimos_platform::flock_identity::exclusive(&self.files[2])?;
        crate::backup_worker_scope::recheck(
            &self.request,
            &self.source,
            &self.files[5],
            &self.files[6],
        )?;
        if let Some(header) = &self.header {
            require(
                header.evidence(&self.files[6])? == self.request["header"],
                "worker original encrypted header changed",
            )?;
        }
        identity(&self.files[7], &self.request["credential"]["identity"])?;
        if self.request["credential"]["kind"] == "sealed-caller-input" {
            secret::retain(
                self.files[7].as_fd(),
                enzimos_platform::json::unsigned(&self.request["plan"]["owner_uid"])? as u32,
            )?
            .recheck()?;
            let reader = crate::settings_command::Command::open(
                "/usr/lib/enzimos-backend/enzimos-secret-validator",
            )?;
            require(
                reader.evidence()? == self.request["reader"],
                "worker original input validator changed",
            )?;
        } else {
            readonly(&self.files[7])?;
            let named = named(Path::new("/etc/enzimos/backup.password"))?;
            identity(&named, &self.request["credential"]["identity"])?;
            require(
                mount_identity::id(self.files[7].as_fd(), true)? == self.source.root_mount_id(),
                "worker stored credential left original source mount",
            )?;
        }
        command(&self.files[8], &self.request["restic"])?;
        if !self.request["consumer_input"].is_null() {
            crate::backup_auth_input::borrowed(
                &self.request["consumer_input"],
                id,
                enzimos_platform::json::unsigned(&self.request["credential"]["identity"][2])?,
                self.files
                    .last()
                    .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
            )?;
        }
        for (index, key, path) in [
            (9, "outer", "backup-initial-setup.json"),
            (10, "configuration", "/etc/enzimos/backup.json"),
        ] {
            let expected = &self.request[key];
            if expected.is_null() {
                continue;
            }
            readonly(&self.files[index])?;
            identity(&self.files[index], &expected["identity"])?;
            let named = if key == "outer" {
                files::open_relative(self.source.control(), Path::new(path))?
            } else {
                named(Path::new(path))?
            };
            identity(&named, &expected["identity"])?;
            let body = files::read_file(&self.files[index], 65536, Some(0), true)?;
            require(
                json::sha256(&body) == expected["sha256"],
                "worker original public document changed",
            )?;
            if key == "outer" {
                let outer = json::decode(&body, 65536)?;
                crate::backup_setup_context::validate(&outer)?;
                require(
                    outer["plan"] == self.request["plan"],
                    "worker outer intent differs from original setup plan",
                )?;
                require(
                    mount_identity::id(self.files[index].as_fd(), true)?
                        == self.source.control_mount_id(),
                    "worker outer left control mount",
                )?;
            }
            if key == "configuration" {
                require(
                    json::decode(&body, 65536)? == expected["value"],
                    "worker public configuration differs",
                )?;
            }
        }
        self.source.recheck()?;
        self.original_files()?;
        self.caller.recheck()
    }
}
