// SPDX-License-Identifier: MIT
//! Fresh nonce-bound caller approval; a failed exchange is never replayed.
use crate::backup_credential_handoff::Handoff;
use enzimos_platform::{
    Result,
    fd_packet::{Message, Packet},
    files, json, require,
};
use serde_json::{Value, json as value};
use std::{
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};
/// The credential review worker side of the checkpoint exchange.
pub struct Checkpoint {
    channel: Packet,
    sequence: u64,
    failed: bool,
}
fn acknowledgement(message: &Message, challenge: &Value, caller: u32) -> Result<()> {
    require(
        message.files.is_empty()
            && message.sender.pid == caller
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "credential review acknowledgement is not original Root caller",
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(
        &body,
        "schema kind id request_sha256 sequence nonce allowed",
    )?;
    require(
        body["schema"] == 1
            && body["kind"] == "credential-review"
            && body["allowed"] == true
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|key| body[*key] == challenge[*key]),
        "credential review approval changed, stale or revoked; no replay",
    )
}
impl Checkpoint {
    /// Start the exchange on `channel`.
    pub fn new(channel: Packet) -> Self {
        Self {
            channel,
            sequence: 0,
            failed: false,
        }
    }
    /// Ask the caller to approve continuing.
    ///
    /// # Errors
    ///
    /// Fails after the checkpoint loop ended or exceeded its bound, or when the caller does not
    /// approve.
    pub fn recheck(&mut self, handoff: &Handoff) -> Result<()> {
        require(
            !self.failed && self.sequence < 10000,
            "original credential review checkpoint retired or bounded out",
        )?;
        self.failed = true;
        let request = handoff.request()?;
        self.sequence += 1;
        let challenge = value!({"schema":1,"kind":"credential-review","id":request["id"],
            "request_sha256":json::fingerprint(request)?,"sequence":self.sequence,"nonce":files::random_hex(16)?});
        let caller = enzimos_platform::json::unsigned(&request["context"]["caller"]["pid"])? as u32;
        self.channel
            .send(&json::canonical(&challenge)?, &[], Duration::from_secs(2))?;
        self.channel.wait_ready(
            handoff.original_caller()?,
            crate::backup_worker_checkpoint::CALLER_WINDOW,
            &mut || handoff.recheck(),
        )?;
        let response = self.channel.receive(4096, 0, Duration::from_secs(2))?;
        acknowledgement(&response, &challenge, caller)?;
        handoff.recheck()?;
        self.failed = false;
        Ok(())
    }
    /// Report review only. Original worker retirement and enrollment completion
    /// remain with the caller; a failed report exchange cannot resend the report.
    ///
    /// # Errors
    ///
    /// Fails without a fresh approval or when the report cannot be sent.
    pub fn report(
        &mut self,
        handoff: &Handoff,
        observation: &crate::backup_credential_observation::Observed,
    ) -> Result<()> {
        require(
            !self.failed && self.sequence > 0,
            "credential review report requires fresh original approval",
        )?;
        self.failed = true;
        let request = handoff.request()?;
        observation.require_request(request)?;
        let result = observation.value()?;
        outcome(&result)?;
        let stdout = observation.descriptor()?;
        let report = value!({"schema":1,"kind":"credential-review","id":request["id"],
            "request_sha256":json::fingerprint(request)?,"sequence":self.sequence,"nonce":files::random_hex(16)?,
            "result":result,"worker_scope_closed":false,
            "stdout_descriptor_number":stdout.as_raw_fd(),"stdout_sha256":observation.digest()?});
        self.channel.send(
            &json::canonical(&report)?,
            &[stdout.as_fd()],
            Duration::from_secs(2),
        )?;
        self.channel.wait_ready(
            handoff.original_caller()?,
            crate::backup_worker_checkpoint::CALLER_WINDOW,
            &mut || handoff.recheck(),
        )?;
        let response = self.channel.receive(4096, 0, Duration::from_secs(3))?;
        report_ack(
            &response,
            &report,
            enzimos_platform::json::unsigned(&request["context"]["caller"]["pid"])? as u32,
        )?;
        handoff.recheck()
    }
}
pub(crate) fn outcome(body: &Value) -> Result<()> {
    json::fields(
        body,
        "status new_key metadata_checked worker_scope_closed enrollment_complete credential_exported old_access_revoked",
    )?;
    require(
        body["status"] == "credential-reviewed"
            && body["metadata_checked"] == true
            && body["worker_scope_closed"] == false
            && body["enrollment_complete"] == false
            && body["credential_exported"] == false
            && body["old_access_revoked"] == false,
        "credential observation cannot assert closure, completion, export or revocation",
    )?;
    crate::identity::sha(body["new_key"].as_str().unwrap_or("")).map(|_| ())
}
fn report_ack(message: &Message, report: &Value, caller: u32) -> Result<()> {
    require(
        message.files.is_empty()
            && message.sender.pid == caller
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "credential review report receipt is not original Root caller",
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(
        &body,
        "schema kind id request_sha256 sequence nonce report_sha256 received",
    )?;
    require(
        body["schema"] == report["schema"]
            && report["schema"] == 1
            && body["kind"] == "credential-review"
            && body["received"] == true
            && body["report_sha256"] == json::fingerprint(report)?
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|key| body[*key] == report[*key]),
        "original credential review report receipt changed, stale or revoked",
    )
}
