// SPDX-License-Identifier: MIT
//! Original kernel-stamped report and owned whole-worker closure, without replay.
use crate::{
    backup_selective_observation,
    backup_selective_reservation::{ClosedRequest, Reserved},
};
use enzimos_platform::{
    Result,
    fd_packet::{Message, Packet},
    json, require,
};
use serde_json::{Value, json as value};
use std::{fs::File, os::fd::AsFd, time::Duration};
pub struct Reported {
    request: Value,
    report: Value,
    output: File,
}
pub enum Incoming {
    Challenge(Message),
    Observed(Reported),
}
pub(crate) fn sender(message: &Message, worker: u32) -> Result<()> {
    require(
        message.files.is_empty()
            && message.sender.pid == worker
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "selective challenge is not original Root worker",
    )
}
fn report(body: &Value, request: &Value, sequence: u64) -> Result<()> {
    json::fields(
        body,
        "schema kind id request_sha256 sequence nonce result worker_scope_closed stdout_descriptor_number stdout_sha256",
    )?;
    require(
        body["schema"] == 1
            && body["kind"] == request["kind"]
            && body["id"] == request["id"]
            && body["request_sha256"] == json::fingerprint(request)?
            && sequence > 0
            && body["sequence"].as_u64() == Some(sequence)
            && body["worker_scope_closed"] == false
            && body["stdout_descriptor_number"]
                .as_u64()
                .is_some_and(|n| (3..=1048576).contains(&n)),
        "selective report differs from original request and approval",
    )?;
    crate::backup_worker_request::id(body["nonce"].as_str().unwrap_or(""))?;
    crate::identity::sha(body["stdout_sha256"].as_str().unwrap_or(""))?;
    crate::backup_selective_checkpoint::outcome(&body["result"])
}
pub fn receive(
    channel: &Packet,
    reserved: &Reserved<'_, '_, '_>,
    sequence: u64,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Incoming> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    reserved.recheck(authorize)?;
    let request = reserved.request(authorize)?.clone();
    let scope = reserved.kernel_scope(authorize)?;
    let binding = scope.binding()?;
    require(
        *binding == request["worker"],
        "selective report requires original live scope",
    )?;
    let pid = enzimos_platform::json::unsigned(&binding["worker"]["pid"])? as u32;
    let peer = channel.peer_credentials()?;
    require(
        peer.pid == pid && peer.uid == 0 && peer.gid == 0,
        "selective report peer is not original worker",
    )?;
    let mut message = channel.receive_counts(4096, &[0, 1], Duration::from_secs(3))?;
    require(
        message.sender.pid == pid && message.sender.uid == 0 && message.sender.gid == 0,
        "selective report kernel sender changed",
    )?;
    let body = json::decode(&message.body, 4096)?;
    if body.get("result").is_none() {
        sender(&message, pid)?;
        return Ok(Incoming::Challenge(message));
    }
    report(&body, &request, sequence)?;
    require(
        message.files.len() == 1,
        "selective report requires one original sealed observation",
    )?;
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
    let observed = Reported {
        request,
        report: body,
        output,
    };
    observed.recheck()?;
    reserved.recheck(authorize)?;
    Ok(Incoming::Observed(observed))
}
impl Reported {
    pub fn report(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.report)
    }
    fn recheck(&self) -> Result<()> {
        report(
            &self.report,
            &self.request,
            self.report["sequence"].as_u64().unwrap_or(0),
        )?;
        let bytes = enzimos_platform::memfile::read_sealed(
            &self.output,
            backup_selective_observation::LIMIT,
            0,
        )?;
        require(
            json::sha256(&bytes) == self.report["stdout_sha256"],
            "original selective sealed report digest changed",
        )?;
        let (header, _) = backup_selective_observation::decode(&bytes, &self.request)?;
        require(
            backup_selective_observation::outcome(&header) == self.report["result"],
            "original sealed selected outcome differs from request or reported metadata",
        )
    }

    pub fn close<'g>(self, closed: ClosedRequest<'g>) -> Result<Closed<'g>> {
        self.recheck()?;
        closed.require_request(&self.request)?;
        let this = Closed {
            original: self,
            closed,
        };
        this.recheck()?;
        Ok(this)
    }
}
/// The original output and original kernel closure survive until completion.
/// There is no constructor from a receipt, key ID, digest or copied JSON.
pub struct Closed<'g> {
    original: Reported,
    closed: ClosedRequest<'g>,
}
impl Closed<'_> {
    pub(crate) fn require_context(
        &self,
        context: &crate::backup_selective_context::Context<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck()?;
        self.closed.require_guard(context.guard())?;
        self.closed.require_context_actor(context)?;
        require(
            *context.evidence(authorize)? == self.original.request["context"],
            "export publication differs from original selected context",
        )
    }

    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()?;
        self.closed.require_request(&self.original.request)
    }
    /// Only the original closed worker observation may satisfy the reviewed tree.
    pub fn require_tree(&self, expected: &Value) -> Result<()> {
        self.recheck()?;
        require(
            self.original.request["kind"] == "selective-tree-export",
            "tree review requires original tree worker",
        )?;
        let (header, _) = self.observed_data()?;
        let observed = &header["file"];
        require(
            observed["path"] == expected["path"]
                && observed["node_sha256"] == expected["node_sha256"]
                && observed["entries"] == expected["entries"]
                && observed["content_bytes"] == expected["size"],
            "closed tree observation differs from authenticated review",
        )?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"result":self.original.report["result"],"report_sha256":json::fingerprint(&self.original.report)?,
            "closed_request":self.closed.evidence()?,"worker_kernel_closed":true,
            "export_complete":false,"live_home_written":false,"metadata_restored":false,"per_user_authorized":false}),
        )
    }
    /// Borrow actual original immutable output only after original kernel closure.
    /// These bytes alone cannot create an export completion actor.
    pub(crate) fn observed_data(&self) -> Result<(Value, Vec<u8>)> {
        self.recheck()?;
        let bytes = enzimos_platform::memfile::read_sealed(
            &self.original.output,
            backup_selective_observation::LIMIT,
            0,
        )?;
        let (header, data) = backup_selective_observation::decode(&bytes, &self.original.request)?;
        let result = (header, data.to_vec());
        self.recheck()?;
        Ok(result)
    }
}
