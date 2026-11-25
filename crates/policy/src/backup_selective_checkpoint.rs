// SPDX-License-Identifier: MIT
//! Fresh nonce-bound caller approval; a failed exchange is never replayed.
use crate::backup_selective_handoff::Handoff;
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
/// The selective export worker side of the checkpoint exchange.
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
        "selective export acknowledgement is not original Root caller",
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(
        &body,
        "schema kind id request_sha256 sequence nonce allowed",
    )?;
    require(
        body["schema"] == 1
            && body["kind"] == challenge["kind"]
            && body["allowed"] == true
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|key| body[*key] == challenge[*key]),
        "selective export approval changed, stale or revoked; no replay",
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
            "original selective export checkpoint retired or bounded out",
        )?;
        self.failed = true;
        let request = handoff.request()?;
        self.sequence += 1;
        let challenge = value!({"schema":1,"kind":request["kind"],"id":request["id"],
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
    /// Report observation only. Original worker retirement and export publication
    /// remain with the caller; a failed report exchange cannot resend the report.
    ///
    /// # Errors
    ///
    /// Fails without a fresh approval or when the report cannot be sent.
    pub fn report(
        &mut self,
        handoff: &Handoff,
        observation: &crate::backup_selective_observation::Observed,
    ) -> Result<()> {
        require(
            !self.failed && self.sequence > 0,
            "selective export report requires fresh original approval",
        )?;
        self.failed = true;
        let request = handoff.request()?;
        observation.require_request(request)?;
        let result = observation.value()?;
        outcome(&result)?;
        let stdout = observation.descriptor()?;
        let report = value!({"schema":1,"kind":request["kind"],"id":request["id"],
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
        "status snapshot file sha256 worker_scope_closed export_complete live_home_written metadata_restored per_user_authorized",
    )?;
    require(
        matches!(
            body["status"].as_str(),
            Some("selected-file-observed" | "selected-tree-observed")
        ) && [
            "worker_scope_closed",
            "export_complete",
            "live_home_written",
            "metadata_restored",
            "per_user_authorized",
        ]
        .iter()
        .all(|key| body[*key] == false),
        "selected observation cannot assert closure, export or live-home mutation",
    )?;
    for digest in [&body["snapshot"], &body["sha256"]] {
        crate::identity::sha(digest.as_str().unwrap_or(""))?;
    }
    json::fields(
        &body["file"],
        if body["status"] == "selected-tree-observed" {
            "path size node_sha256 entries content_bytes"
        } else {
            "path size node_sha256"
        },
    )?;
    if body["status"] == "selected-tree-observed" {
        require(
            body["file"]["entries"]
                .as_u64()
                .is_some_and(|n| (1..=crate::backup_tree_result::MAX_ENTRIES as u64).contains(&n))
                && body["file"]["content_bytes"]
                    .as_u64()
                    .is_some_and(|n| n <= crate::backup_selective_result::MAX_FILE),
            "tree observation count/content bound",
        )?;
    }
    crate::backup_selective_result::file_path(body["file"]["path"].as_str().unwrap_or(""))?;
    crate::identity::sha(body["file"]["node_sha256"].as_str().unwrap_or(""))?;
    require(
        body["file"]["size"]
            .as_u64()
            .is_some_and(|n| n <= crate::backup_selective_result::MAX_FILE),
        "selected observation size bound",
    )
}
fn report_ack(message: &Message, report: &Value, caller: u32) -> Result<()> {
    require(
        message.files.is_empty()
            && message.sender.pid == caller
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "selective export report receipt is not original Root caller",
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(
        &body,
        "schema kind id request_sha256 sequence nonce report_sha256 received",
    )?;
    require(
        body["schema"] == report["schema"]
            && report["schema"] == 1
            && body["kind"] == report["kind"]
            && body["received"] == true
            && body["report_sha256"] == json::fingerprint(report)?
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|key| body[*key] == report[*key]),
        "original selective export report receipt changed, stale or revoked",
    )
}
