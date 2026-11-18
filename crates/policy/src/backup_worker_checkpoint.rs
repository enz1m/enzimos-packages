// SPDX-License-Identifier: MIT
//! Fresh acknowledgement at every child boundary; never authorization by cached JSON.
use enzimos_platform::{
    Result,
    fd_packet::{Message, Packet},
    files, json, require,
};
use serde_json::{Value, json as value};
use std::{fs::File, os::fd::AsFd, time::Duration};
/// How long a worker waits for its original caller to acknowledge one
/// checkpoint or report. The caller validates its whole authority chain
/// (approval, journals, mount scope, device inventory) before it answers; the
/// adoption provision pass also revalidates both credential witnesses. That
/// can take longer than a packet deadline, so the worker waits while the
/// caller process is alive (pidfd) and its handoff stays valid, exactly like a
/// captured backup transfer. A dead caller still ends the wait immediately.
pub const CALLER_WINDOW: Duration = Duration::from_secs(120);
pub struct Checkpoint {
    channel: Packet,
    sequence: u64,
    failed: bool,
}
fn acknowledgement(reply: &Message, challenge: &Value, caller: u32) -> Result<()> {
    require(
        reply.files.is_empty()
            && reply.sender.pid == caller
            && reply.sender.uid == 0
            && reply.sender.gid == 0,
        "backup checkpoint sender is not original Root caller",
    )?;
    let v = json::decode(&reply.body, 4096)?;
    json::fields(&v, "schema id request_sha256 sequence nonce authorized")?;
    require(
        v["schema"] == 1
            && v["authorized"] == true
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|key| v[*key] == challenge[*key]),
        "backup checkpoint revoked, replayed or changed",
    )
}
impl Checkpoint {
    /// Only the receiver of a fully checked original handoff supplies the connected
    /// channel. Any failure permanently retires it; no reconnection or resend.
    pub fn new(channel: Packet) -> Self {
        Self {
            channel,
            sequence: 0,
            failed: false,
        }
    }
    pub fn recheck(&mut self, handoff: &crate::backup_worker_handoff::Handoff) -> Result<()> {
        require(
            !self.failed && self.sequence < 10000,
            "backup checkpoint retired or boundary bound reached",
        )?;
        // Latch before sampling/sending. A failed partial exchange is not replayable.
        self.failed = true;
        let request = handoff.request()?;
        self.sequence += 1;
        let challenge = value!({"schema":1,"id":request["id"],"request_sha256":json::fingerprint(request)?,
            "sequence":self.sequence,"nonce":files::random_hex(16)?});
        let caller = request["caller"]["pid"].as_u64().unwrap() as u32;
        self.channel
            .send(&json::canonical(&challenge)?, &[], Duration::from_secs(2))?;
        self.channel.wait_ready(
            handoff.original_caller()?,
            crate::backup_worker_checkpoint::CALLER_WINDOW,
            &mut || handoff.recheck(),
        )?;
        let reply = self.channel.receive(4096, 0, Duration::from_secs(2))?;
        acknowledgement(&reply, &challenge, caller)?;
        handoff.recheck()?;
        self.failed = false;
        Ok(())
    }
    pub fn report(
        &mut self,
        handoff: &crate::backup_worker_handoff::Handoff,
        result: &Value,
        header: Option<&File>,
    ) -> Result<()> {
        require(
            !self.failed && self.sequence > 0,
            "worker result requires successful fresh checkpoint",
        )?;
        self.failed = true;
        let request = handoff.request()?;
        let task = request["task"].as_str().unwrap();
        crate::backup_worker_result::for_request(result, request)?;
        require(
            header.is_some() == (result["status"] == "provisioned"),
            "provision report requires original encrypted header descriptor",
        )?;
        if let Some(header) = header {
            require(
                serde_json::to_value(files::identity(&header.metadata()?))?
                    == result["header"]["identity"],
                "reported encrypted header differs from original descriptor",
            )?;
        }
        let v = value!({"schema":2,"id":request["id"],"request_sha256":json::fingerprint(request)?,
            "sequence":self.sequence,"task":task,"result":result,"worker_scope_closed":false,
            "nonce":files::random_hex(16)?,"header_number":header.map(std::os::fd::AsRawFd::as_raw_fd)});
        let descriptors = header.map(|f| vec![f.as_fd()]).unwrap_or_default();
        self.channel
            .send(&json::canonical(&v)?, &descriptors, Duration::from_secs(2))?;
        self.channel.wait_ready(
            handoff.original_caller()?,
            crate::backup_worker_checkpoint::CALLER_WINDOW,
            &mut || handoff.recheck(),
        )?;
        let reply = self.channel.receive(4096, 0, Duration::from_secs(3))?;
        report_acknowledgement(
            &reply,
            &v,
            request["caller"]["pid"].as_u64().unwrap() as u32,
        )?;
        handoff.recheck()
    }
}
fn report_acknowledgement(reply: &Message, report: &Value, caller: u32) -> Result<()> {
    require(
        reply.files.is_empty()
            && reply.sender.pid == caller
            && reply.sender.uid == 0
            && reply.sender.gid == 0,
        "report receipt is not original Root caller",
    )?;
    let v = json::decode(&reply.body, 4096)?;
    json::fields(
        &v,
        "schema id request_sha256 sequence nonce report_sha256 received",
    )?;
    require(
        v["schema"] == 2
            && v["received"] == true
            && v["report_sha256"] == json::fingerprint(report)?
            && ["id", "request_sha256", "sequence", "nonce"]
                .iter()
                .all(|k| v[*k] == report[*k]),
        "report receipt changed, stale or revoked; no resend",
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn actual_packet_credentials_cannot_be_replaced_by_body_claims() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (sender, receiver) = Packet::pair().unwrap();
        let challenge = value!({"schema":1,"id":"1".repeat(32),"request_sha256":"a".repeat(64),"sequence":1,"nonce":"b".repeat(32)});
        let mut reply = challenge.clone();
        reply["authorized"] = value!(true);
        sender
            .send(
                &json::canonical(&reply).unwrap(),
                &[],
                Duration::from_secs(1),
            )
            .unwrap();
        let message = receiver.receive(4096, 0, Duration::from_secs(1)).unwrap();
        assert_eq!(message.sender.uid, unsafe { libc::geteuid() });
        assert!(acknowledgement(&message, &challenge, std::process::id()).is_err());
    }
}
