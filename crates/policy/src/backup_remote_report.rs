// SPDX-License-Identifier: MIT
//! Original Root SCM report plus actual whole-kernel closure; no JSON actor constructor.
use crate::{
    backup_remote_observation as observation,
    backup_remote_receipt::Intent,
    backup_remote_reservation::{ClosedRequest, Reserved},
    storage_runtime::Guard,
};
use enzimos_platform::{
    Result,
    fd_packet::{Message, Packet},
    json, memfile, require,
};
use serde_json::{Value, json as value};
use std::{fs::File, os::fd::AsFd, sync::Arc, time::Duration};
pub struct Reported<'g> {
    guard: &'g Guard,
    request: Value,
    report: Value,
    output: File,
    intent: Option<Intent>,
    actor: Arc<()>,
}
pub enum Incoming<'g> {
    Challenge(Message),
    Observed(Reported<'g>),
}
pub(crate) fn sender(message: &Message, worker: u32) -> Result<()> {
    require(
        message.files.is_empty()
            && message.sender.pid == worker
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "remote challenge is not original Root worker",
    )
}
fn report(body: &Value, request: &Value, sequence: u64) -> Result<()> {
    json::fields(
        body,
        "schema kind id request_sha256 sequence nonce result worker_scope_closed stdout_descriptor_number stdout_sha256 receipt_descriptor_number receipt_epoch",
    )?;
    require(
        body["schema"].as_u64() == Some(1)
            && body["kind"] == "remote-copy"
            && body["id"] == request["id"]
            && body["request_sha256"] == json::fingerprint(request)?
            && sequence > 0
            && body["sequence"].as_u64() == Some(sequence)
            && body["worker_scope_closed"] == false
            && body["stdout_descriptor_number"]
                .as_u64()
                .is_some_and(|n| (3..1048576).contains(&n)),
        "remote report differs from original request/approval",
    )?;
    crate::backup_worker_request::id(body["nonce"].as_str().unwrap_or(""))?;
    crate::identity::sha(body["stdout_sha256"].as_str().unwrap_or(""))?;
    crate::backup_remote_checkpoint::outcome(&body["result"])?;
    if request["context"]["direction"] == "retrieve" {
        require(
            body["receipt_descriptor_number"]
                .as_u64()
                .is_some_and(|n| (3..1048576).contains(&n))
                && body["receipt_descriptor_number"] != body["stdout_descriptor_number"],
            "retrieval requires distinct original receipt descriptor",
        )?;
        crate::backup_existing_repository_wire::intent(
            &body["receipt_epoch"],
            crate::backup_remote_receipt::LIMIT,
        )?;
    } else {
        require(
            body["receipt_descriptor_number"].is_null() && body["receipt_epoch"].is_null(),
            "replication cannot attach a retrieval receipt",
        )?;
    }
    Ok(())
}
pub fn receive<'g>(
    channel: &Packet,
    reserved: &Reserved<'_, '_, 'g>,
    sequence: u64,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Incoming<'g>> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    reserved.recheck(authorize)?;
    let request = reserved.request(authorize)?.clone();
    let scope = reserved.kernel_scope(authorize)?;
    let pid = enzimos_platform::json::unsigned(&scope.binding()?["worker"]["pid"])? as u32;
    let peer = channel.peer_credentials()?;
    require(
        peer.pid == pid && peer.uid == 0 && peer.gid == 0,
        "remote report peer is not original live worker",
    )?;
    let mut message = channel.receive_counts(4096, &[0, 1, 2], Duration::from_secs(3))?;
    require(
        message.sender.pid == pid && message.sender.uid == 0 && message.sender.gid == 0,
        "remote report kernel sender changed",
    )?;
    let body = json::decode(&message.body, 4096)?;
    if body.get("result").is_none() {
        require(
            message.files.is_empty(),
            "remote challenge cannot supply descriptors",
        )?;
        return Ok(Incoming::Challenge(message));
    }
    report(&body, &request, sequence)?;
    let retrieve = request["context"]["direction"] == "retrieve";
    require(
        message.files.len() == if retrieve { 2 } else { 1 },
        "exact remote observation/receipt descriptor count",
    )?;
    let receipt = if retrieve {
        let file = File::from(
            message
                .files
                .pop()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
        );
        scope.require_description(
            file.as_fd(),
            enzimos_platform::json::unsigned(&body["receipt_descriptor_number"])? as u32,
        )?;
        Some(file)
    } else {
        None
    };
    let output = File::from(
        message
            .files
            .pop()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
    );
    scope.require_description(
        output.as_fd(),
        enzimos_platform::json::unsigned(&body["stdout_descriptor_number"])? as u32,
    )?;
    let guard = reserved.guard(authorize)?;
    let intent = receipt
        .map(|file| {
            Intent::admit(
                guard,
                enzimos_platform::json::string(&request["context"]["receipt_id"])?,
                file,
            )
        })
        .transpose()?;
    let this = Reported {
        guard,
        request,
        report: body,
        output,
        intent,
        actor: reserved.actor_identity(authorize)?,
    };
    this.recheck()?;
    reserved.recheck(authorize)?;
    Ok(Incoming::Observed(this))
}
impl<'g> Reported<'g> {
    fn body(&self) -> Result<Value> {
        let bytes = memfile::read_sealed(&self.output, observation::LIMIT, 0)?;
        require(
            json::sha256(&bytes) == self.report["stdout_sha256"],
            "original remote sealed output digest changed",
        )?;
        json::decode(&bytes, observation::LIMIT)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        report(
            &self.report,
            &self.request,
            self.report["sequence"].as_u64().unwrap_or(0),
        )?;
        let body = self.body()?;
        require(
            observation::measured(&body, &self.request)? == self.report["result"],
            "original remote sealed result differs from reported observation",
        )?;
        if let Some(intent) = &self.intent {
            intent.recheck(self.guard)?;
            require(
                intent.evidence(self.guard)? == self.report["receipt_epoch"]
                    && intent.value(self.guard)? == &body["retrieval_intent"],
                "original retrieval SCM receipt differs from sealed report",
            )?;
        }
        Ok(())
    }
    pub fn report(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.report)
    }
    pub fn close(self, closed: ClosedRequest) -> Result<Closed<'g>> {
        self.recheck()?;
        closed.require_request(&self.request, &self.actor)?;
        let this = Closed {
            original: self,
            closed,
        };
        this.recheck()?;
        Ok(this)
    }
}
pub struct Closed<'g> {
    original: Reported<'g>,
    closed: ClosedRequest,
}
impl Closed<'_> {
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()?;
        self.closed
            .require_request(&self.original.request, &self.original.actor)
    }
    pub fn require_context(
        &self,
        context: &crate::backup_remote_copy_context::Context<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck()?;
        self.closed.require_context(context, authorize)?;
        if let Some(intent) = &self.original.intent {
            require(
                intent.value(self.original.guard)?["local_binding"]
                    == context.legacy_binding(authorize)?,
                "closed retrieval original local binding changed",
            )?;
        }
        Ok(())
    }
    /// Explicitly consume the original admitted receipt only after the actual
    /// whole kernel scope closes. Its metadata cannot recreate this actor.
    pub fn complete_retrieval(
        mut self,
        context: &crate::backup_remote_copy_context::Context<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.require_context(context, authorize)?;
        let result = self.result()?;
        require(
            result["direction"] == "retrieve"
                && context.evidence(authorize)?["direction"] == "retrieve",
            "retrieval completion requires original closed retrieval",
        )?;
        let intent = self.original.intent.take().ok_or_else(|| {
            enzimos_platform::Error("original retrieval receipt actor missing".into())
        })?;
        let expected = intent.value(self.original.guard)?.clone();
        let mut check = || {
            self.closed.require_context(context, authorize)?;
            self.closed
                .require_request(&self.original.request, &self.original.actor)?;
            self.original.guard.recheck()?;
            require(
                observation::measured(&self.original.body()?, &self.original.request)?
                    == self.original.report["result"]
                    && expected["local_binding"] == context.legacy_binding(authorize)?,
                "original retrieval observation or held destination changed during completion",
            )
        };
        check()?;
        let receipt = intent.finish(
            self.original.guard,
            enzimos_platform::json::string(&result["copied_snapshot"])?,
            &mut check,
        )?;
        check()?;
        Ok(
            value!({"status":"remote-point-retrieved-to-local","id":receipt["id"],"remote_snapshot":receipt["remote_snapshot"],"local_snapshot":receipt["local_snapshot"],"local_restore_available":true,"live_home_written":false,"scheduler_enabled":false,"automatic_retry":false}),
        )
    }
    pub fn result(&self) -> Result<Value> {
        self.recheck()?;
        let mut result = self.original.report["result"].clone();
        result["worker_scope_closed"] = value!(true);
        Ok(result)
    }
}
