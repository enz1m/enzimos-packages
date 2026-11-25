// SPDX-License-Identifier: MIT
//! One original source reservation, sealed offer and non-replayable packet send.
//! Recipient acceptance and private namespace attachment are separate operations.
use crate::{
    backup_readonly_trees::Reserved, backup_source_offer_wire as wire,
    backup_transfer_caller::Caller,
};
use enzimos_platform::{
    Result,
    fd_packet::{Credentials, Packet},
    files, json, memfile, require,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    time::Duration,
};
pub struct Offer<'o, 'a, 'b, 'c, 's, 'cfg, 'g> {
    reserved: Reserved<'a, 'b, 'c, 's, 'cfg, 'g>,
    caller: &'o Caller,
    sealed: File,
    request: Value,
    sha256: String,
    sent: bool,
    next: usize,
    failed: bool,
}
impl<'o, 'a, 'b, 'c, 's, 'cfg, 'g> Offer<'o, 'a, 'b, 'c, 's, 'cfg, 'g> {
    pub fn enter(
        mut reserved: Reserved<'a, 'b, 'c, 's, 'cfg, 'g>,
        caller: &'o Caller,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        caller.verify_image_bytes()?;
        reserved.recheck()?;
        let evidence = reserved.evidence()?;
        let nonce = files::random_hex(16)?;
        let request = value!({"schema":1,"kind":"readonly-source-offer","id":evidence["receipt"]["id"],
            "boot_id":evidence["receipt"]["boot_id"],"nonce":nonce,"caller":caller.evidence()?,
            "worker":reserved.worker_binding()?,"input_sha256":evidence["receipt"]["input_sha256"],
            "sources":evidence["receipt"]["trees"],"arguments":reserved.arguments()?});
        wire::request(&request)?;
        let bytes = json::canonical(&request)?;
        require(bytes.len() <= wire::LIMIT, "bounded original source offer")?;
        let sha256 = json::sha256(&bytes);
        let sealed = memfile::sealed("readonly-source-offer", &bytes)?;
        authorize()?;
        caller.recheck()?;
        reserved.enter_offer(&nonce, &sha256)?;
        let this = Self {
            reserved,
            caller,
            sealed,
            request,
            sha256,
            sent: false,
            next: 0,
            failed: false,
        };
        this.recheck()?;
        authorize()?;
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.caller.recheck()?;
        self.reserved.recheck()?;
        require(
            json::decode(
                &memfile::read_sealed(&self.sealed, wire::LIMIT, 0)?,
                wire::LIMIT,
            )? == self.request
                && self.request["caller"] == self.caller.evidence()?
                && self.request["worker"] == *self.reserved.worker_binding()?
                && self.sha256 == json::sha256(&json::canonical(&self.request)?),
            "original sealed source offer changed",
        )?;
        let evidence = self.reserved.evidence()?;
        require(
            self.request["sources"] == evidence["receipt"]["trees"]
                && self.request["input_sha256"] == evidence["receipt"]["input_sha256"]
                && evidence["receipt"]["offer"]
                    == value!({"nonce":self.request["nonce"],"request_sha256":self.sha256}),
            "source offer differs from actual original reservation",
        )
    }
    fn peer(&self, channel: &Packet) -> Result<()> {
        self.recheck()?;
        let peer = channel.peer_credentials()?;
        require(
            peer.uid == 0
                && peer.gid == 0
                && u64::from(peer.pid)
                    == enzimos_platform::json::unsigned(&self.request["worker"]["worker"]["pid"])?,
            "source channel does not belong to original reserved worker",
        )
    }
    /// Original intent is durable before the first packet. Any partial send is
    /// uncertain and never replayed, including on this same still-live actor.
    pub fn send(
        &mut self,
        channel: &Packet,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        while !self.send_next(channel, authorize)? {}
        Ok(())
    }
    /// Send exactly one original chunk, allowing the owning caller to service
    /// fresh worker checkpoints between chunks. Partial sends retire this actor.
    pub fn send_next(
        &mut self,
        channel: &Packet,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<bool> {
        require(!self.failed, "original source offer failed; no replay")?;
        self.failed = true;
        authorize()?;
        self.peer(channel)?;
        let targets = wire::targets(&self.request)?;
        let chunks = targets.chunks(wire::CHUNK).collect::<Vec<_>>();
        require(
            self.next < chunks.len(),
            "original source offer already delivered; no replay",
        )?;
        if !self.sent {
            self.sent = true;
            self.reserved.enter_send(
                enzimos_platform::json::string(&self.request["nonce"])?,
                &self.sha256,
            )?;
        }
        let index = self.next;
        let chunk = chunks[index];
        let sender = Credentials {
            pid: std::process::id(),
            uid: 0,
            gid: 0,
        };
        authorize()?;
        self.peer(channel)?;
        let trees = self.reserved.descriptors(authorize)?;
        let mut descriptions: Vec<BorrowedFd<'_>> = vec![
            self.sealed.as_fd(),
            self.caller.pidfd()?,
            self.caller.image()?.as_fd(),
        ];
        for target in chunk {
            descriptions.push(
                *trees
                    .get(target.as_str())
                    .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
            );
        }
        let numbers = descriptions
            .iter()
            .map(|fd| fd.as_raw_fd() as u32)
            .collect::<Vec<_>>();
        for (fd, number) in descriptions.iter().zip(&numbers) {
            self.caller.require_description(*fd, *number)?;
        }
        let frame = value!({"schema":1,"kind":"readonly-source-chunk","id":self.request["id"],
                "nonce":self.request["nonce"],"request_sha256":self.sha256,"index":index,
                "start":index*wire::CHUNK,"targets":chunk,"fd_numbers":numbers});
        wire::frame(&frame, &self.request, index, &sender)?;
        authorize()?;
        self.peer(channel)?;
        channel.send(
            &json::canonical(&frame)?,
            &descriptions,
            Duration::from_secs(2),
        )?;
        authorize()?;
        self.peer(channel)?;
        self.next += 1;
        self.recheck()?;
        self.failed = false;
        Ok(self.next == chunks.len())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"request":self.request,"request_sha256":self.sha256,"send_entered":self.sent,
            "receiver_accepted":false,"source_mounts_admitted":false,"transfer_complete":false,"backup_complete":false}),
        )
    }
    pub fn close(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::backup_readonly_trees::ReleasedDescriptors> {
        authorize()?;
        self.caller.recheck()?;
        self.reserved.close(authorize)
    }
}
