// SPDX-License-Identifier: MIT
//! One original transfer request and packet send. No receipt can reopen an actor.
use crate::{
    backup_transfer_context::Context, backup_transfer_request as wire, control_record::Retained,
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
const FOLDER: &str = "backup-transfer-workers";
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "original protected transfer request registry",
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
pub struct Reserved<'r, 'a, 'b, 'c, 's, 'cfg, 'g> {
    context: &'r Context<'a, 'b, 'c, 's, 'cfg, 'g>,
    scope: Scope,
    request: Value,
    sealed: File,
    registry: File,
    shape: Shape,
    record: Retained,
    value: Value,
    sent: bool,
    delivered: bool,
}
impl<'r, 'a, 'b, 'c, 's, 'cfg, 'g> Reserved<'r, 'a, 'b, 'c, 's, 'cfg, 'g> {
    pub fn enter(
        context: &'r Context<'a, 'b, 'c, 's, 'cfg, 'g>,
        scope: Scope,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        // evidence() performs the complete fresh context check itself.
        let original = context.evidence(authorize)?;
        let worker = scope.binding()?.clone();
        require(
            worker["id"] == original["id"],
            "original transfer worker attempt differs",
        )?;
        let request = value!({"schema":1,"kind":"captured-backup-transfer","id":original["id"],
            "boot_id":original["boot_id"],"worker":worker,"context":original});
        wire::request(&request)?;
        let sealed = memfile::sealed("captured-backup-transfer", &json::canonical(&request)?)?;
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
            "transfer request registry mount/capacity",
        )?;
        context.recheck(authorize)?;
        let value = value!({"schema":1,"id":request["id"],"phase":"prepared",
            "request_sha256":json::fingerprint(&request)?,"worker":request["worker"],
            "receiver_accepted":false,"transfer_complete":false,"backup_complete":false});
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
        let this = Self {
            context,
            scope,
            request,
            sealed,
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
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.components(authorize)?;
        require(
            *self.scope.binding()? == self.request["worker"],
            "original live transfer worker changed",
        )
    }
    fn components(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        authorize()?;
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
            "original transfer request actor, receipt, scope or sealed bytes changed",
        )
    }
    /// Only the owned original kernel scope may authorize intent retirement.
    /// This consumes the live actor; it does not release source descriptions,
    /// delete captures/staging or assert a completed transfer.
    pub fn close(self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<ClosedRequest> {
        self.components(authorize)?;
        let closed = self.scope.close()?;
        require(
            *closed.binding()? == self.request["worker"],
            "closed transfer worker differs from original request",
        )?;
        self.context.recheck(authorize)?;
        let mut record = self.record;
        let mut next = self.value;
        next["phase"] = value!("worker-kernel-closed");
        next["worker_kernel_closed"] = value!(closed.binding()?);
        record.replace(&next)?;
        closed.recheck()?;
        let this = ClosedRequest {
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
        for role in wire::roles(&self.request["context"]) {
            files.push(*map.get(role).ok_or_else(|| {
                enzimos_platform::Error("original transfer descriptor role missing".into())
            })?);
        }
        files.push(self.record.descriptor()?.as_fd());
        for file in &files {
            self.context
                .require_description(*file, file.as_raw_fd() as u32)?;
        }
        Ok(files)
    }
    /// Immutable comparison data only. Reading it grants no acknowledgement,
    /// descriptor or consumer authority; control replies still call recheck().
    pub(crate) fn original_request(&self) -> &Value {
        &self.request
    }
    /// The actual retained scope for sender/sequence parsing only. Its kernel
    /// checks remain active; acknowledgement still requires the complete actor.
    pub(crate) fn control_scope(&self) -> &Scope {
        &self.scope
    }
    pub fn request(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Value> {
        self.recheck(authorize)?;
        Ok(&self.request)
    }
    pub fn kernel_scope(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<&Scope> {
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
            "transfer request already sent or uncertain; no replay",
        )?;
        let peer = channel.peer_credentials()?;
        require(
            peer.uid == 0
                && peer.gid == 0
                && u64::from(peer.pid)
                    == enzimos_platform::json::unsigned(&self.request["worker"]["worker"]["pid"])?,
            "transfer request peer is not original reserved worker",
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
        let frame = value!({"schema":1,"kind":"captured-backup-transfer","id":self.request["id"],
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
        // Keep the original send-entered inode stable until the whole worker
        // closes. Delivery alone cannot advance the intent observed by the child.
        self.delivered = true;
        self.recheck(authorize)
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            value!({"receipt":self.value,"record":self.record.evidence()?,"packet_delivered":self.delivered,"receiver_accepted":false,
            "transfer_complete":false,"backup_complete":false}),
        )
    }
}
/// Original process/cgroup closure, never reconstructed from metadata.
pub struct ClosedRequest {
    closed: enzimos_platform::backup_worker_scope::Closed,
    record: Retained,
    value: Value,
    request: Value,
    sealed: File,
}
impl ClosedRequest {
    pub(crate) fn binding(&self) -> Result<&Value> {
        self.recheck()?;
        self.closed.binding()
    }
    pub fn recheck(&self) -> Result<()> {
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
            "original closed transfer request or receipt changed",
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"receipt":self.value,"record":self.record.evidence()?,
            "source_descriptions_released":false,"transfer_complete":false,
            "cleanup_complete":false,"backup_complete":false}),
        )
    }
}
