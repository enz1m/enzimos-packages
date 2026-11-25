// SPDX-License-Identifier: MIT
//! Caller-side one-use control loop tied to the actual original reservation.
use crate::{
    backup_credential_report::{self, Incoming, Reported},
    backup_credential_reservation::Reserved,
};
use enzimos_platform::{
    Result,
    fd_packet::{Message, Packet},
    json, require,
};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, time::Duration};
/// Caller-side state of one worker control loop: sequence, used nonces and outcome.
pub struct State {
    sequence: u64,
    nonces: BTreeSet<String>,
    failed: bool,
    finished: bool,
}
/// A packet received from the worker.
pub enum Event {
    /// A checkpoint challenge was answered.
    Checkpoint,
    /// The worker reported.
    Observed(Reported),
}
fn challenge(message: &Message, request: &Value, sequence: u64) -> Result<Value> {
    backup_credential_report::sender(
        message,
        enzimos_platform::json::unsigned(&request["worker"]["worker"]["pid"])? as u32,
    )?;
    let body = json::decode(&message.body, 4096)?;
    json::fields(&body, "schema kind id request_sha256 sequence nonce")?;
    require(
        body["schema"] == 1
            && body["kind"] == "credential-review"
            && body["id"] == request["id"]
            && body["request_sha256"] == json::fingerprint(request)?
            && body["sequence"].as_u64() == Some(sequence),
        "credential review challenge differs from original request/sequence",
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
    /// A loop at sequence zero with no nonces used.
    pub fn new() -> Self {
        Self {
            sequence: 0,
            nonces: BTreeSet::new(),
            failed: false,
            finished: false,
        }
    }
    /// Receive the next packet from the reserved worker and answer a checkpoint challenge.
    ///
    /// # Errors
    ///
    /// Fails after the loop ended or exceeded its bound, on a reused nonce or bad sequence, when
    /// the sender is not the reserved worker, or when `authorize` fails.
    pub fn receive(
        &mut self,
        reserved: &Reserved<'_, '_, '_>,
        channel: &Packet,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Event> {
        require(
            !self.failed && !self.finished && self.sequence < 10000 && self.nonces.len() < 10001,
            "original caller credential review control retired or bounded out",
        )?;
        self.failed = true;
        reserved.recheck(authorize)?;
        let request = reserved.request(authorize)?.clone();
        let incoming =
            backup_credential_report::receive(channel, reserved, self.sequence, authorize)?;
        match incoming {
            Incoming::Challenge(message) => {
                let next = self.sequence + 1;
                let challenge = challenge(&message, &request, next)?;
                require(
                    self.nonces
                        .insert(enzimos_platform::json::string(&challenge["nonce"])?.to_owned()),
                    "credential review nonce reused",
                )?;
                // Fresh caller permission and all original actors precede every
                // acknowledgement. Revocation retains intent and retires this loop.
                reserved.recheck(authorize)?;
                let mut reply = challenge;
                reply["allowed"] = value!(true);
                channel.send(&json::canonical(&reply)?, &[], Duration::from_secs(2))?;
                reserved.recheck(authorize)?;
                self.sequence = next;
                self.failed = false;
                Ok(Event::Checkpoint)
            }
            Incoming::Observed(observed) => {
                let report = observed.report()?;
                require(
                    self.nonces
                        .insert(enzimos_platform::json::string(&report["nonce"])?.to_owned()),
                    "credential review report nonce reused",
                )?;
                reserved.recheck(authorize)?;
                let reply = value!({"schema":report["schema"],"kind":"credential-review","id":report["id"],
                    "request_sha256":report["request_sha256"],"sequence":report["sequence"],"nonce":report["nonce"],
                    "report_sha256":json::fingerprint(report)?,"received":true});
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
