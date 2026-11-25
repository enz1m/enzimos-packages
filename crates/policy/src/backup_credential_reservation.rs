// SPDX-License-Identifier: MIT
//! One original credential review request/send, never a reconstructed actor.
//! The extra retained operation-lock OFD keeps uncertainty fenced if a caller
//! must retain this actor until actual original whole-worker closure.
use crate::{
    backup_credential_context::Context, backup_credential_request as wire, control_record::Retained,
};
use enzimos_platform::{
    Result, backup_worker_scope::Scope, fd_packet::Packet, files, json, memfile, mount_identity,
    require,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
const FOLDER: &str = "credential-review-workers";
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original protected credential review request registry",
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
/// A durable credential review request reserved for one worker scope.
pub struct Reserved<'r, 'a, 'g> {
    context: &'r Context<'a, 'g>,
    scope: Scope,
    request: Value,
    sealed: File,
    lock_retained: File,
    registry: File,
    shape: Shape,
    record: Retained,
    value: Value,
    sent: bool,
    delivered: bool,
}
impl<'r, 'a, 'g> Reserved<'r, 'a, 'g> {
    /// Reserve the review request for the worker in `scope`.
    ///
    /// # Errors
    ///
    /// Fails when the worker or context changed, the request registry is full, or `authorize`
    /// fails.
    pub fn enter(
        context: &'r Context<'a, 'g>,
        scope: Scope,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        context.recheck(authorize)?;
        let original = context.evidence(authorize)?;
        let worker = scope.binding()?.clone();
        require(
            worker["id"] == original["id"],
            "original credential review worker attempt differs",
        )?;
        let request = value!({"schema":1,"kind":"credential-review","id":original["id"],
            "boot_id":original["boot_id"],"worker":worker,"context":original});
        wire::request(&request)?;
        let sealed = memfile::sealed("credential-review", &json::canonical(&request)?)?;
        context.recheck(authorize)?;
        require(
            *scope.binding()? == request["worker"],
            "original worker changed before request intent",
        )?;
        let guard = context.guard();
        let registry =
            files::ensure_directory_relative(guard.control(), Path::new(FOLDER), 0o700, 0)?;
        let directory_shape = shape(&registry)?;
        require(
            directory_shape.5 == guard.control_mount_id()
                && files::directory_names(&registry, 256)?.len() < 256,
            "credential review request registry mount/capacity",
        )?;
        context.recheck(authorize)?;
        let value = value!({"schema":1,"id":request["id"],"phase":"prepared",
            "request_sha256":json::fingerprint(&request)?,"worker":request["worker"],
            "receiver_accepted":false,"review_complete":false,"enrollment_complete":false});
        let record = Retained::create(
            &registry,
            Path::new(&format!(
                "{}.json",
                enzimos_platform::json::string(&request["id"])?
            )),
            &value,
            wire::LIMIT,
            directory_shape.5,
        )?;
        let map = context.descriptors(authorize)?;
        let lock_retained = File::from(map["operation-lock"].try_clone_to_owned()?);
        enzimos_platform::flock_identity::exclusive(&lock_retained)?;
        let this = Self {
            context,
            scope,
            request,
            sealed,
            lock_retained,
            registry,
            shape: directory_shape,
            record,
            value,
            sent: false,
            delivered: false,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.components(authorize)?;
        require(
            *self.scope.binding()? == self.request["worker"],
            "original live credential review worker changed",
        )
    }
    fn components(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.context.recheck(authorize)?;
        enzimos_platform::flock_identity::exclusive(&self.lock_retained)?;
        let guard = self.context.guard();
        let named = files::directory_relative(guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&named)? == self.shape
                && shape(&self.registry)? == self.shape
                && *self.record.value()? == self.value
                && *self.scope.original_binding()? == self.request["worker"]
                && *self.context.evidence(authorize)? == self.request["context"]
                && json::decode(
                    &memfile::read_sealed(&self.sealed, wire::LIMIT, 0)?,
                    wire::LIMIT,
                )? == self.request,
            "original credential review request actor, receipt, scope or sealed bytes changed",
        )
    }
    /// Only actual original pidfd death and original empty cgroup can close
    /// this request. Closure supplies no key observation or enrollment completion.
    ///
    /// # Errors
    ///
    /// Fails when the closed scope is not the reserved worker's, or the record cannot be updated.
    pub fn close(self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<ClosedRequest<'g>> {
        self.components(authorize)?;
        let closed = self.scope.close()?;
        require(
            *closed.binding()? == self.request["worker"],
            "closed credential review worker differs from original request",
        )?;
        self.context.recheck(authorize)?;
        let mut record = self.record;
        let mut next = self.value;
        next["phase"] = value!("worker-kernel-closed");
        next["worker_kernel_closed"] = value!(closed.binding()?);
        record.replace(&next)?;
        closed.recheck()?;
        let this = ClosedRequest {
            guard: self.context.guard(),
            registry: self.registry,
            shape: self.shape,
            closed,
            record,
            value: next,
            request: self.request,
            sealed: self.sealed,
        };
        this.recheck()?;
        Ok(this)
    }
    fn descriptions(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Vec<BorrowedFd<'_>>> {
        self.recheck(authorize)?;
        let map = self.context.descriptors(authorize)?;
        let mut files = vec![self.sealed.as_fd()];
        for role in wire::ROLES {
            files.push(*map.get(role).ok_or_else(|| {
                enzimos_platform::Error("original credential review descriptor role missing".into())
            })?);
        }
        files.push(self.record.descriptor()?.as_fd());
        for file in &files {
            self.context
                .require_description(*file, file.as_raw_fd() as u32)?;
        }
        Ok(files)
    }
    pub(crate) fn request(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.request)
    }
    pub(crate) fn enrollment_record(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<&Value> {
        self.recheck(authorize)?;
        self.context.enrollment_record(authorize)
    }
    pub(crate) fn enrollment_actor(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<std::sync::Arc<()>> {
        self.recheck(authorize)?;
        self.context.enrollment_actor(authorize)
    }
    pub(crate) fn kernel_scope(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Scope> {
        self.components(authorize)?;
        Ok(&self.scope)
    }
    /// Send the request to the reserved worker over `channel`.
    ///
    /// # Errors
    ///
    /// Fails when the request was already sent, the peer is another process, or the send fails.
    /// Sends are never retried.
    pub fn send(
        &mut self,
        channel: &Packet,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            !self.sent,
            "credential review request already sent or uncertain; no replay",
        )?;
        let peer = channel.peer_credentials()?;
        require(
            peer.uid == 0
                && peer.gid == 0
                && u64::from(peer.pid)
                    == enzimos_platform::json::unsigned(&self.request["worker"]["worker"]["pid"])?,
            "credential review request peer is not original reserved worker",
        )?;
        self.sent = true;
        let mut next = self.value.clone();
        next["phase"] = value!("send-entered");
        self.record.replace(&next)?;
        self.value = next;
        let files = self.descriptions(authorize)?;
        let numbers = files
            .iter()
            .map(|f| f.as_raw_fd() as u32)
            .collect::<Vec<_>>();
        let frame = value!({"schema":1,"kind":"credential-review","id":self.request["id"],
            "request_sha256":json::fingerprint(&self.request)?,"descriptor_numbers":numbers,"intent":self.record.evidence()?});
        wire::frame(
            &frame,
            &self.request,
            &enzimos_platform::fd_packet::Credentials {
                pid: std::process::id(),
                uid: 0,
                gid: 0,
            },
        )?;
        channel.send(&json::canonical(&frame)?, &files, Duration::from_secs(2))?;
        self.recheck(authorize)?;
        // Keep the original send-entered inode stable until the whole worker
        // closes. Delivery alone cannot advance the intent observed by the child.
        self.delivered = true;
        self.recheck(authorize)
    }
    /// JSON evidence for the reservation and its progress.
    ///
    /// # Errors
    ///
    /// Fails when the reservation changed or `authorize` fails.
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            value!({"receipt":self.value,"record":self.record.evidence()?,"packet_delivered":self.delivered,"receiver_accepted":false,
            "review_complete":false,"enrollment_complete":false}),
        )
    }
}
/// Original process/cgroup closure, never reconstructed from metadata.
pub struct ClosedRequest<'g> {
    guard: &'g crate::storage_runtime::Guard,
    registry: File,
    shape: Shape,
    closed: enzimos_platform::backup_worker_scope::Closed,
    record: Retained,
    value: Value,
    request: Value,
    sealed: File,
}
impl ClosedRequest<'_> {
    pub(crate) fn require_request(&self, request: &Value) -> Result<()> {
        self.recheck()?;
        require(
            self.request == *request,
            "closed credential worker belongs to another original request",
        )
    }
    /// The closed request's record.
    ///
    /// # Errors
    ///
    /// Fails when the closed request changed.
    pub fn binding(&self) -> Result<&Value> {
        self.recheck()?;
        self.closed.binding()
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let named = files::directory_relative(self.guard.control(), Path::new(FOLDER), Some(0))?;
        require(
            shape(&self.registry)? == self.shape
                && shape(&named)? == self.shape
                && self.shape.5 == self.guard.control_mount_id(),
            "original closed credential review registry replaced/covered",
        )?;
        self.closed.recheck()?;
        require(
            *self.record.value()? == self.value
                && self.value["phase"] == "worker-kernel-closed"
                && self.value["worker_kernel_closed"] == *self.closed.binding()?
                && self.request["worker"] == *self.closed.binding()?
                && self.value["request_sha256"] == json::fingerprint(&self.request)?
                && json::decode(
                    &memfile::read_sealed(&self.sealed, wire::LIMIT, 0)?,
                    wire::LIMIT,
                )? == self.request,
            "original closed credential review request or receipt changed",
        )
    }
    /// JSON evidence for the closed request.
    ///
    /// # Errors
    ///
    /// Fails when the closed request changed.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"receipt":self.value,"record":self.record.evidence()?,
            "credential_exported":false,"review_complete":false,
            "old_access_revoked":false,"enrollment_complete":false}),
        )
    }
}
