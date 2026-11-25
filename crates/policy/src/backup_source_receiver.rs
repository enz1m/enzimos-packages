// SPDX-License-Identifier: MIT
//! Admission of original readonly descriptions; no namespace or cleanup grant.
use crate::{
    backup_source_offer_wire as wire, backup_transfer_handoff::Handoff, control_record::Retained,
};
use enzimos_platform::{
    Result,
    backup_worker_scope::Scope,
    fd_packet::{Message, Packet},
    files, json, memfile, mount_identity, process_identity, require, stream_copy,
};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
const FOLDER: &str = "backup-source-receivers";
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "protected original source receiver registry",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
fn tree(file: &File, expected: &Value) -> Result<()> {
    crate::backup_worker_handoff::readonly(file)?;
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7022 == 0,
        "protected original source directory required",
    )?;
    crate::backup_worker_handoff::identity(file, &expected["inode"])?;
    require(
        mount_identity::id(file.as_fd(), true)? == expected["detached_mount"],
        "actual original source mount identity differs",
    )?;
    mount_protections(file)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
fn mount_protections(file: &File) -> Result<()> {
    // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
    let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    require(
        // SAFETY: `status` is a writable `libc::statvfs` and `file` keeps the descriptor open.
        unsafe { libc::fstatvfs(file.as_raw_fd(), &mut status) } == 0
            && status.f_flag & required == required,
        "actual original source readonly mount protections differ",
    )
}

struct Chunk {
    files: Vec<File>,
    numbers: Vec<u32>,
}
pub struct Received<'a> {
    handoff: &'a Handoff,
    scope: &'a Scope,
    request: Value,
    chunks: Vec<Chunk>,
    trees: BTreeMap<String, (usize, usize)>,
    registry: File,
    registry_shape: Shape,
    record: Retained,
    value: Value,
}
/// Borrowed original admission actor, never reconstructed from a receipt.
pub struct PreparedChild<'a, 'b> {
    received: &'a mut Received<'b>,
    attachment: std::sync::Arc<enzimos_platform::backup_mount_child::Prepared>,
}
impl PreparedChild<'_, '_> {
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
        self.received.recheck_partial()?;
        require(
            self.received.value["phase"] == "child-prepared",
            "original source child preparation changed",
        )?;
        self.attachment.recheck()
    }
    /// Consume this one-use preparation. Intent precedes child spawn; failures
    /// retain it. No retry or cleanup actor can be manufactured from the output.
    pub fn run(
        self,
        runtime: &crate::backup_restic_runtime::Runtime,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::backup_restic_runtime::BackupObservation> {
        self.recheck(authorize)?;
        let mut next = self.received.value.clone();
        next["phase"] = value!("consumer-entered");
        self.received.record.replace(&next)?;
        self.received.value = next;
        let mut boundary = || {
            authorize()?;
            self.received.recheck_partial()?;
            require(
                self.received.value["phase"] == "consumer-entered",
                "original transfer execution intent changed",
            )?;
            self.attachment.recheck()
        };
        boundary()?;
        let observed =
            runtime.backup_prepared(&self.attachment, self.received.handoff, &mut boundary)?;
        boundary()?;
        let mut next = self.received.value.clone();
        next["phase"] = value!("consumer-observed");
        next["consumer"] = observed.value();
        self.received.record.replace(&next)?;
        self.received.value = next;
        self.received.recheck_partial()?;
        authorize()?;
        self.received.recheck_partial()?;
        Ok(observed)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            value!({"receipt":self.received.value,"record":self.received.record.evidence()?,
            "receiver_accepted":true,"attachment_prepared":true,"source_mounts_admitted":false,
            "transfer_complete":false,"backup_complete":false}),
        )
    }
}
impl<'a> Received<'a> {
    /// Persist the one-shot intent before preparing any child attachment. Failure
    /// retains that intent; neither dropping the borrow nor receipts permit retry.
    pub fn prepare_child(
        &mut self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PreparedChild<'_, 'a>> {
        authorize()?;
        self.recheck()?;
        let mut next = self.value.clone();
        next["phase"] = value!("child-preparation-entered");
        self.record.replace(&next)?;
        self.value = next;
        authorize()?;
        self.recheck_partial()?;
        let sources = self
            .trees
            .iter()
            .map(|(target, (chunk, index))| (target.as_str(), &self.chunks[*chunk].files[*index]))
            .collect();
        let arguments = self.request["arguments"]
            .as_array()
            .ok_or_else(|| enzimos_platform::Error("original reviewed arguments missing".into()))?
            .iter()
            .map(|s| {
                s.as_str().map(str::to_owned).ok_or_else(|| {
                    enzimos_platform::Error("original reviewed argument type".into())
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let attachment = std::sync::Arc::new(
            enzimos_platform::backup_mount_child::Prepared::prepare_reviewed(sources, &arguments)?,
        );
        authorize()?;
        self.recheck_partial()?;
        attachment.recheck()?;
        let mut next = self.value.clone();
        next["phase"] = value!("child-prepared");
        self.record.replace(&next)?;
        self.value = next;
        let prepared = PreparedChild {
            received: self,
            attachment,
        };
        prepared.recheck(authorize)?;
        Ok(prepared)
    }
    fn actors(handoff: &Handoff, scope: &Scope, channel: &Packet) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let caller = handoff.original_caller()?;
        let worker = scope.binding()?;
        let peer = channel.peer_credentials()?;
        require(
            worker["worker"]["pid"] == std::process::id()
                && peer.pid == caller.stat.pid
                && peer.uid == 0
                && peer.gid == 0,
            "source channel original caller or current worker changed",
        )
    }
    fn admit(handoff: &Handoff, request: &Value, index: usize, message: Message) -> Result<Chunk> {
        let frame = json::decode(&message.body, wire::LIMIT)?;
        let numbers = wire::frame(&frame, request, index, &message.sender)?;
        require(
            numbers.len() == message.files.len(),
            "source packet actual descriptor count differs",
        )?;
        let chunk = Chunk {
            files: message.files.into_iter().map(File::from).collect(),
            numbers,
        };
        let caller = handoff.original_caller()?;
        for (file, number) in chunk.files.iter().zip(&chunk.numbers) {
            caller.require_description(file.as_fd(), *number)?;
        }
        require(
            json::decode(
                &memfile::read_sealed(&chunk.files[0], wire::LIMIT, 0)?,
                wire::LIMIT,
            )? == *request
                && process_identity::pidfd_target(chunk.files[1].as_fd())? == caller.stat.pid,
            "source sealed request or original caller pidfd changed",
        )?;
        handoff.require_original_caller_image(&chunk.files[2])?;
        crate::backup_worker_handoff::readonly(&chunk.files[2])?;
        crate::backup_worker_handoff::identity(&chunk.files[2], &request["caller"]["image_epoch"])?;
        require(
            stream_copy::hash_borrowed(&chunk.files[2], 32 * 1024 * 1024, Some(0))?.1
                == request["caller"]["executable_sha256"],
            "source original caller executable bytes differ",
        )?;
        let targets = wire::targets(request)?;
        for (target, file) in targets
            .iter()
            .skip(index * wire::CHUNK)
            .take(wire::CHUNK)
            .zip(chunk.files.iter().skip(wire::BASE_FILES))
        {
            tree(file, &request["sources"][target])?;
        }
        Ok(chunk)
    }
    /// All chunks are admitted before any source may be borrowed. An interrupted
    /// durable intent is retained and cannot be reopened as an admission actor.
    pub fn receive(
        handoff: &'a Handoff,
        scope: &'a Scope,
        channel: &Packet,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        Self::actors(handoff, scope, channel)?;
        channel.wait_ready(
            handoff.original_caller()?,
            crate::backup_worker_checkpoint::CALLER_WINDOW,
            &mut || Self::actors(handoff, scope, channel),
        )?;
        let first =
            channel.receive_counts(wire::LIMIT, &[7, 8, 9, 10, 11, 12], Duration::from_secs(2))?;
        let sealed = File::from(first.files[0].try_clone()?);
        let request = json::decode(&memfile::read_sealed(&sealed, wire::LIMIT, 0)?, wire::LIMIT)?;
        wire::request(&request)?;
        let caller = handoff.original_caller()?;
        require(
            request["worker"] == *scope.binding()?
                && request["id"] == handoff.request()?["id"]
                && request["boot_id"] == crate::operation::boot_id()?
                && request["caller"]["pid"] == caller.stat.pid
                && request["caller"]["start_ticks"] == caller.stat.start_ticks
                && request["caller"]["executable_sha256"]
                    == handoff.request()?["context"]["caller"]["executable_sha256"],
            "source offer differs from actual original handoff actors",
        )?;
        require(
            request["input_sha256"] == handoff.request()?["context"]["input_sha256"]
                && request["arguments"] == handoff.request()?["context"]["arguments"],
            "source offer differs from original captured transfer context",
        )?;
        let chunk = Self::admit(handoff, &request, 0, first)?;
        authorize()?;
        Self::actors(handoff, scope, channel)?;
        let guard = handoff.original_source()?;
        let registry =
            files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let registry_shape = shape(&registry)?;
        require(
            registry_shape.5 == guard.control_mount_id()
                && files::directory_names(&registry, 256)?.len() < 256,
            "source receiver registry mount or capacity",
        )?;
        let mut body = value!({"schema":1,"id":request["id"],"phase":"entered","request_sha256":json::sha256(&json::canonical(&request)?),"nonce":request["nonce"],"worker":scope.binding()?,"received_chunks":1,"source_mounts_admitted":false,"transfer_complete":false,"backup_complete":false});
        let record = Retained::create(
            &registry,
            Path::new(&format!(
                "{}.json",
                enzimos_platform::json::string(&request["id"])?
            )),
            &body,
            wire::LIMIT,
            registry_shape.5,
        )?;
        let mut this = Self {
            handoff,
            scope,
            request,
            chunks: vec![chunk],
            trees: BTreeMap::new(),
            registry,
            registry_shape,
            record,
            value: body.clone(),
        };
        let targets = wire::targets(&this.request)?;
        for index in 1..targets.len().div_ceil(wire::CHUNK) {
            authorize()?;
            this.recheck_partial()?;
            Self::actors(handoff, scope, channel)?;
            let count = wire::BASE_FILES + (targets.len() - index * wire::CHUNK).min(wire::CHUNK);
            // Guarded sender preparation can exceed a ready-packet deadline.
            // Waiting consumes no descriptions and retains the exact live caller;
            // fresh authorization and normal packet admission still surround it.
            channel.wait_ready(
                handoff.original_caller()?,
                crate::backup_worker_checkpoint::CALLER_WINDOW,
                &mut || Self::actors(handoff, scope, channel),
            )?;
            let message = channel.receive(wire::LIMIT, count, Duration::from_secs(2))?;
            let chunk = Self::admit(handoff, &this.request, index, message)?;
            // Common descriptors must remain the same producer descriptions.
            require(
                chunk.numbers[..wire::BASE_FILES] == this.chunks[0].numbers[..wire::BASE_FILES],
                "source chunk common descriptions changed",
            )?;
            authorize()?;
            Self::actors(handoff, scope, channel)?;
            this.chunks.push(chunk);
            body["received_chunks"] = value!(this.chunks.len());
            this.record.replace(&body)?;
            this.value = body.clone();
            this.recheck_partial()?;
        }
        for (i, target) in targets.into_iter().enumerate() {
            this.trees.insert(
                target,
                (i / wire::CHUNK, wire::BASE_FILES + i % wire::CHUNK),
            );
        }
        authorize()?;
        this.recheck_partial()?;
        body["phase"] = value!("descriptors-admitted");
        this.record.replace(&body)?;
        this.value = body;
        this.recheck()?;
        authorize()?;
        this.recheck()?;
        Ok(this)
    }
    fn recheck_partial(&self) -> Result<()> {
        crate::namespaces::initial()?;
        self.handoff.recheck()?;
        require(
            *self.scope.binding()? == self.request["worker"]
                && self.request["boot_id"] == crate::operation::boot_id()?,
            "original source receiver worker or boot changed",
        )?;
        let guard = self.handoff.original_source()?;
        let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&self.registry)? == self.registry_shape
                && shape(&named)? == self.registry_shape
                && self.registry_shape.5 == guard.control_mount_id()
                && *self.record.value()? == self.value,
            "original source receiver intent or registry changed",
        )?;
        let caller = self.handoff.original_caller()?;
        let targets = wire::targets(&self.request)?;
        for (index, chunk) in self.chunks.iter().enumerate() {
            for (file, number) in chunk.files.iter().zip(&chunk.numbers) {
                caller.require_description(file.as_fd(), *number)?;
            }
            require(
                json::decode(
                    &memfile::read_sealed(&chunk.files[0], wire::LIMIT, 0)?,
                    wire::LIMIT,
                )? == self.request
                    && process_identity::pidfd_target(chunk.files[1].as_fd())? == caller.stat.pid,
                "admitted original source request or pidfd changed",
            )?;
            self.handoff
                .require_original_caller_image(&chunk.files[2])?;
            crate::backup_worker_handoff::identity(
                &chunk.files[2],
                &self.request["caller"]["image_epoch"],
            )?;
            for (target, file) in targets
                .iter()
                .skip(index * wire::CHUNK)
                .take(wire::CHUNK)
                .zip(chunk.files.iter().skip(wire::BASE_FILES))
            {
                tree(file, &self.request["sources"][target])?;
            }
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<()> {
        self.recheck_partial()?;
        require(
            self.value["phase"] == "descriptors-admitted"
                && self.trees.len() == wire::targets(&self.request)?.len(),
            "incomplete source receiver cannot lend descriptions",
        )
    }
    pub fn directories(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<BTreeMap<&str, &File>> {
        authorize()?;
        self.recheck()?;
        Ok(self
            .trees
            .iter()
            .map(|(target, (chunk, index))| (target.as_str(), &self.chunks[*chunk].files[*index]))
            .collect())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"receipt":self.value,"record":self.record.evidence()?,"receiver_accepted":true,"source_mounts_admitted":false,"transfer_complete":false,"backup_complete":false}),
        )
    }
}
