// SPDX-License-Identifier: MIT
//! Caller-side one-use control loop tied to the actual original reservation.
use crate::{
    backup_transfer_observation::{self, Incoming, Observation},
    backup_transfer_reservation::Reserved,
};
use enzimos_platform::{
    Result,
    fd_packet::{Message, Packet},
    json, require,
};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, time::Duration};
pub struct State {
    sequence: u64,
    nonces: BTreeSet<String>,
    failed: bool,
    finished: bool,
}
pub enum Event {
    Checkpoint,
    Observed(Observation),
}
fn challenge(message: &Message, request: &Value, sequence: u64) -> Result<Value> {
    backup_transfer_observation::sender(
        message,
        request["worker"]["worker"]["pid"].as_u64().unwrap() as u32,
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(&body, "schema kind id request_sha256 sequence nonce")?;
    require(
        body["schema"] == 1
            && body["kind"] == "captured-backup-transfer"
            && body["id"] == request["id"]
            && body["request_sha256"] == json::fingerprint(request)?
            && body["sequence"].as_u64() == Some(sequence),
        "transfer challenge differs from original request/sequence",
    )?;
    crate::backup_worker_request::id(body["nonce"].as_str().unwrap_or(""))?;
    Ok(body)
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            nonces: BTreeSet::new(),
            failed: false,
            finished: false,
        }
    }
    pub fn receive(
        &mut self,
        reserved: &Reserved<'_, '_, '_, '_, '_, '_, '_>,
        channel: &Packet,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Event> {
        require(
            !self.failed && !self.finished && self.sequence < 10000 && self.nonces.len() < 10001,
            "original caller transfer control retired or bounded out",
        )?;
        self.failed = true;
        // Parsing needs only immutable request data and the actual kernel scope.
        // The full fresh authorization/context check remains before every ACK.
        let request = reserved.original_request().clone();
        let incoming = backup_transfer_observation::receive(
            channel,
            reserved.control_scope(),
            &request,
            self.sequence,
        )?;
        match incoming {
            Incoming::Challenge(message) => {
                let next = self.sequence + 1;
                let challenge = challenge(&message, &request, next)?;
                require(
                    self.nonces
                        .insert(challenge["nonce"].as_str().unwrap().to_owned()),
                    "transfer nonce reused",
                )?;
                // Fresh caller permission and all original actors precede every
                // acknowledgement. Revocation retains intent and retires this loop.
                reserved.recheck(authorize)?;
                let mut reply = challenge;
                reply["allowed"] = value!(true);
                authorize()?;
                channel.send(&json::canonical(&reply)?, &[], Duration::from_secs(2))?;
                reserved.recheck(authorize)?;
                self.sequence = next;
                self.failed = false;
                Ok(Event::Checkpoint)
            }
            Incoming::Observed(observed) => {
                let report = observed.report();
                require(
                    self.nonces
                        .insert(report["nonce"].as_str().unwrap().to_owned()),
                    "transfer report nonce reused",
                )?;
                reserved.recheck(authorize)?;
                let reply = value!({"schema":report["schema"],"kind":"captured-backup-transfer","id":report["id"],
                    "request_sha256":report["request_sha256"],"sequence":report["sequence"],"nonce":report["nonce"],
                    "report_sha256":json::fingerprint(report)?,"received":true});
                authorize()?;
                channel.send(&json::canonical(&reply)?, &[], Duration::from_secs(2))?;
                // The worker may naturally exit immediately after this receipt.
                // Original context/intent and kernel scope remain retained; no
                // complete-backup or source-cleanup authority is published here.
                self.finished = true;
                Ok(Event::Observed(observed))
            }
        }
    }
}
