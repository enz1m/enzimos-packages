// SPDX-License-Identifier: MIT
//! Fresh nonce-bound caller approval; a failed exchange is never replayed.
use crate::backup_transfer_handoff::Handoff;
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
        "transfer acknowledgement is not original Root caller",
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(
        &body,
        "schema kind id request_sha256 sequence nonce allowed",
    )?;
    require(
        body["schema"] == 1
            && body["kind"] == "captured-backup-transfer"
            && body["allowed"] == true
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|key| body[*key] == challenge[*key]),
        "transfer approval changed, stale or revoked; no replay",
    )
}
impl Checkpoint {
    pub fn new(channel: Packet) -> Self {
        Self {
            channel,
            sequence: 0,
            failed: false,
        }
    }
    pub fn recheck(&mut self, handoff: &Handoff) -> Result<()> {
        require(
            !self.failed && self.sequence < 10000,
            "original transfer checkpoint retired or bounded out",
        )?;
        self.failed = true;
        let request = handoff.request()?;
        self.sequence += 1;
        let challenge = value!({"schema":1,"kind":"captured-backup-transfer","id":request["id"],
            "request_sha256":json::fingerprint(request)?,"sequence":self.sequence,"nonce":files::random_hex(16)?});
        let caller = request["context"]["caller"]["pid"].as_u64().unwrap() as u32;
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
    /// Observe data transfer only. Original worker retirement and source cleanup
    /// remain with the caller; a failed report exchange cannot resend the report.
    pub fn report(
        &mut self,
        handoff: &Handoff,
        observation: &crate::backup_restic_runtime::BackupObservation,
    ) -> Result<()> {
        require(
            !self.failed && self.sequence > 0,
            "transfer report requires fresh original approval",
        )?;
        self.failed = true;
        let request = handoff.request()?;
        let result = observation.value();
        outcome(&result)?;
        let stdout = observation.stdout()?;
        let report = value!({"schema":2,"kind":"captured-backup-transfer","id":request["id"],
            "request_sha256":json::fingerprint(request)?,"sequence":self.sequence,"nonce":files::random_hex(16)?,
            "result":result,"worker_scope_closed":false,
            "stdout_descriptor_number":stdout.as_raw_fd(),"stdout_sha256":observation.stdout_sha256()?});
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
            request["context"]["caller"]["pid"].as_u64().unwrap() as u32,
        )?;
        handoff.recheck()
    }
}
pub(crate) fn outcome(body: &Value) -> Result<()> {
    json::fields(
        body,
        "status snapshot_id transfer_complete worker_scope_closed source_cleanup_complete backup_complete",
    )?;
    require(
        body["status"] == "backup-observed"
            && body["transfer_complete"] == true
            && body["worker_scope_closed"] == false
            && body["source_cleanup_complete"] == false
            && body["backup_complete"] == false,
        "consumer outcome cannot assert worker/source/backup completion",
    )?;
    crate::identity::sha(body["snapshot_id"].as_str().unwrap_or("")).map(|_| ())
}
fn report_ack(message: &Message, report: &Value, caller: u32) -> Result<()> {
    require(
        message.files.is_empty()
            && message.sender.pid == caller
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "transfer report receipt is not original Root caller",
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(
        &body,
        "schema kind id request_sha256 sequence nonce report_sha256 received",
    )?;
    require(
        body["schema"] == report["schema"]
            && matches!(report["schema"].as_u64(), Some(1 | 2))
            && body["kind"] == "captured-backup-transfer"
            && body["received"] == true
            && body["report_sha256"] == json::fingerprint(report)?
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|key| body[*key] == report[*key]),
        "original transfer report receipt changed, stale or revoked",
    )
}
