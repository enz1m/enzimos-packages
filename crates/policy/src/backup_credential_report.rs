// SPDX-License-Identifier: MIT
//! Original kernel-stamped report and owned whole-worker closure, without replay.
use crate::{
    backup_credential_observation,
    backup_credential_reservation::{ClosedRequest, Reserved},
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
    enrollment: Value,
    enrollment_actor: std::sync::Arc<()>,
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
        "credential challenge is not original Root worker",
    )
}
fn report(body: &Value, request: &Value, sequence: u64) -> Result<()> {
    json::fields(
        body,
        "schema kind id request_sha256 sequence nonce result worker_scope_closed stdout_descriptor_number stdout_sha256",
    )?;
    require(
        body["schema"] == 1
            && body["kind"] == "credential-review"
            && body["id"] == request["id"]
            && body["request_sha256"] == json::fingerprint(request)?
            && sequence > 0
            && body["sequence"].as_u64() == Some(sequence)
            && body["worker_scope_closed"] == false
            && body["stdout_descriptor_number"]
                .as_u64()
                .is_some_and(|n| (3..=1048576).contains(&n)),
        "credential report differs from original request and approval",
    )?;
    crate::backup_worker_request::id(body["nonce"].as_str().unwrap_or(""))?;
    crate::identity::sha(body["stdout_sha256"].as_str().unwrap_or(""))?;
    crate::backup_credential_checkpoint::outcome(&body["result"])
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
        "credential report requires original live scope",
    )?;
    let pid = binding["worker"]["pid"].as_u64().unwrap() as u32;
    let peer = channel.peer_credentials()?;
    require(
        peer.pid == pid && peer.uid == 0 && peer.gid == 0,
        "credential report peer is not original worker",
    )?;
    let mut message = channel.receive_counts(4096, &[0, 1], Duration::from_secs(3))?;
    require(
        message.sender.pid == pid && message.sender.uid == 0 && message.sender.gid == 0,
        "credential report kernel sender changed",
    )?;
    let body = json::decode(&message.body, 4096)?;
    if body.get("result").is_none() {
        sender(&message, pid)?;
        return Ok(Incoming::Challenge(message));
    }
    report(&body, &request, sequence)?;
    require(
        message.files.len() == 1,
        "credential report requires one original sealed observation",
    )?;
    let output = File::from(message.files.pop().unwrap());
    scope.require_description(
        output.as_fd(),
        body["stdout_descriptor_number"].as_u64().unwrap() as u32,
    )?;
    let enrollment = reserved.enrollment_record(authorize)?.clone();
    let observed = Reported {
        request,
        report: body,
        output,
        enrollment,
        enrollment_actor: reserved.enrollment_actor(authorize)?,
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
            backup_credential_observation::LIMIT,
            0,
        )?;
        require(
            json::sha256(&bytes) == self.report["stdout_sha256"],
            "original credential sealed report digest changed",
        )?;
        let body = json::decode(&bytes, backup_credential_observation::LIMIT)?;
        require(
            body["request_sha256"] == json::fingerprint(&self.request)?
                && backup_credential_observation::measured(&body, &self.enrollment)?
                    == self.report["result"]["new_key"],
            "original sealed credential outcome differs from request or reported key",
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
fn legacy_material(enrollment: &Value, input: &Value, boot: &Value, body: &Value) -> Result<Value> {
    let keys =
        |field: &str| crate::backup_restic_result::keys(Some(0), &json::canonical(&body[field])?);
    Ok(value!({"enrollment":enrollment,
        "repository_binding":crate::backup_credential_record::stable_binding(&enrollment["repository_binding"])? ,
        "keys":keys("current_first")?,"candidate_keys":keys("candidate_first")?,
        "input_identity":input,"review_boot":boot}))
}
impl Closed<'_> {
    /// Exact historical review digest material; it is data, not execution or
    /// completion authority. Completion still consumes the original typed actors.
    pub fn review_sha256(&self) -> Result<String> {
        self.recheck()?;
        let bytes = enzimos_platform::memfile::read_sealed(
            &self.original.output,
            backup_credential_observation::LIMIT,
            0,
        )?;
        let body = json::decode(&bytes, backup_credential_observation::LIMIT)?;
        let material = legacy_material(
            &self.original.enrollment,
            &self.original.request["context"]["input_identity"],
            &self.original.request["boot_id"],
            &body,
        )?;
        self.recheck()?;
        json::fingerprint(&material)
    }
    pub fn result(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"enrollment":self.original.enrollment["id"],"review_sha256":self.review_sha256()?,
            "new_key":self.original.report["result"]["new_key"],"receipt_completed":false,
            "key_creation_replayed":false,"old_access_revoked":false}),
        )
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()?;
        self.closed.require_request(&self.original.request)
    }
    pub(crate) fn require_enrollment(
        &self,
        enrollment: &crate::backup_credential_journal::Enrollment<'_>,
        candidate: &crate::backup_credential_candidate::Candidate<'_>,
    ) -> Result<String> {
        self.recheck()?;
        require(
            std::sync::Arc::ptr_eq(
                &self.original.enrollment_actor,
                &enrollment.actor_identity()?,
            ),
            "completion requires original retained enrollment actor; no reopening or receipt adoption",
        )?;
        enrollment.require_input(candidate)?;
        let evidence = enrollment.evidence()?;
        let context = &self.original.request["context"];
        let expected = &context["enrollment"];
        require(
            *enrollment.record()? == self.original.enrollment
                && evidence["bytes_sha256"] == expected["bytes_sha256"]
                && evidence["file"] == expected["file"]
                && evidence["directory"] == expected["directory"]
                && evidence["mount"] == expected["mount"]
                && enrollment.record()?["id"] == expected["id"],
            "closed review differs from original enrollment actor",
        )?;
        let candidate = candidate.evidence()?;
        require(
            candidate["root"] == context["source"]
                && candidate["next_mount"] == context["next_credential"]["mount"]
                && candidate["current_file"] == context["current_credential"]["inode"]
                && candidate["next_file"] == context["next_credential"]["inode"]
                && candidate["input_identity"] == context["input_identity"],
            "closed review differs from original credential inputs",
        )?;
        self.recheck()?;
        Ok(self.original.report["result"]["new_key"]
            .as_str()
            .unwrap()
            .into())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"result":self.original.report["result"],"report_sha256":json::fingerprint(&self.original.report)?,
            "closed_request":self.closed.evidence()?,"worker_kernel_closed":true,
            "enrollment_complete":false,"credential_exported":false,"old_access_revoked":false}),
        )
    }
}
