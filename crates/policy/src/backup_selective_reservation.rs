// SPDX-License-Identifier: MIT
//! One original selective export request/send, never a reconstructed actor.
//! The extra retained operation-lock OFD keeps uncertainty fenced if a caller
//! must retain this actor until actual original whole-worker closure.
use crate::{
    backup_selective_context::Context, backup_selective_request as wire, control_record::Retained,
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
const FOLDER: &str = "selective-export-workers";
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original protected selective export request registry",
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
            "original selective export worker attempt differs",
        )?;
        let request = value!({"schema":1,"kind":context.kind().request(),"id":original["id"],
            "boot_id":original["boot_id"],"worker":worker,"context":original});
        wire::request(&request)?;
        let sealed = memfile::sealed("selective-file-export", &json::canonical(&request)?)?;
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
            "selective export request registry mount/capacity",
        )?;
        context.recheck(authorize)?;
        let value = value!({"schema":1,"id":request["id"],"phase":"prepared",
            "request_sha256":json::fingerprint(&request)?,"worker":request["worker"],
            "receiver_accepted":false,"export_complete":false,"live_home_written":false});
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
            "original live selective export worker changed",
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
            "original selective export request actor, receipt, scope or sealed bytes changed",
        )
    }
    /// Only actual original pidfd death and original empty cgroup can close
    /// this request. Closure supplies no file observation or export publication.
    pub fn close(self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<ClosedRequest<'g>> {
        self.components(authorize)?;
        let closed = self.scope.close()?;
        require(
            *closed.binding()? == self.request["worker"],
            "closed selective export worker differs from original request",
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
            context_actor: self.context.actor_identity(),
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
                enzimos_platform::Error("original selective export descriptor role missing".into())
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
    pub(crate) fn kernel_scope(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Scope> {
        self.components(authorize)?;
        Ok(&self.scope)
    }
    pub fn send(
        &mut self,
        channel: &Packet,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(authorize)?;
        require(
            !self.sent,
            "selective export request already sent or uncertain; no replay",
        )?;
        let peer = channel.peer_credentials()?;
        require(
            peer.uid == 0
                && peer.gid == 0
                && u64::from(peer.pid)
                    == enzimos_platform::json::unsigned(&self.request["worker"]["worker"]["pid"])?,
            "selective export request peer is not original reserved worker",
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
        let frame = value!({"schema":1,"kind":self.context.kind().request(),"id":self.request["id"],
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
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            value!({"receipt":self.value,"record":self.record.evidence()?,"packet_delivered":self.delivered,"receiver_accepted":false,
            "export_complete":false,"live_home_written":false}),
        )
    }
}
/// Original process/cgroup closure, never reconstructed from metadata.
pub struct ClosedRequest<'g> {
    context_actor: std::sync::Arc<()>,
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
    pub(crate) fn require_context_actor(&self, context: &Context<'_, '_>) -> Result<()> {
        self.recheck()?;
        require(
            std::sync::Arc::ptr_eq(&self.context_actor, &context.actor_identity()),
            "closed selected worker requires original context actor; no reopening",
        )
    }
    pub(crate) fn require_guard(&self, guard: &crate::storage_runtime::Guard) -> Result<()> {
        self.recheck()?;
        require(
            std::ptr::eq(self.guard, guard),
            "closed selected worker requires original storage actor",
        )
    }
    pub(crate) fn require_request(&self, request: &Value) -> Result<()> {
        self.recheck()?;
        require(
            self.request == *request,
            "closed selective worker belongs to another original request",
        )
    }
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
            "original closed selective export registry replaced/covered",
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
            "original closed selective export request or receipt changed",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"receipt":self.value,"record":self.record.evidence()?,
            "export_complete":false,
            "live_home_written":false,"metadata_restored":false,"per_user_authorized":false}),
        )
    }
}
