// SPDX-License-Identifier: MIT
//! Typed observation received from the original worker's actual kernel-stamped packet.
use enzimos_platform::{
    Result,
    backup_worker_scope::{Closed, Scope},
    fd_packet::{Message, Packet},
    json, require,
};
use serde_json::Value;
use std::{fs::File, os::fd::AsFd, path::Path, time::Duration};
pub struct Observation {
    request_sha256: String,
    worker: Value,
    result: Value,
    report: Value,
    header: Option<File>,
}
pub enum Incoming {
    Challenge(Message),
    Observation(Observation),
}
pub fn receive(
    channel: &Packet,
    scope: &Scope,
    request: &Value,
    sequence: u64,
) -> Result<Incoming> {
    crate::namespaces::initial()?;
    crate::backup_worker_request::executable(request)?;
    let worker = scope.original_binding()?;
    require(
        worker["id"] == request["id"],
        "observed worker belongs to another original request",
    )?;
    let mut message = channel.receive_counts(4096, &[0, 1], Duration::from_secs(3))?;
    require(
        u64::from(message.sender.pid)
            == enzimos_platform::json::unsigned(&worker["worker"]["pid"])?
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "observation packet sender is not original Root worker",
    )?;
    let body = json::decode(&message.body, 4096)?;
    if body.get("result").is_none() {
        require(
            message.files.is_empty(),
            "checkpoint cannot carry a repository descriptor",
        )?;
        return Ok(Incoming::Challenge(message));
    }
    report(&body, request, sequence)?;
    require(
        message.files.len() == usize::from(body["result"]["status"] == "provisioned"),
        "report encrypted-header descriptor count differs from fixed workflow",
    )?;
    let header = if let Some(file) = message.files.pop() {
        let file = File::from(file);
        scope.require_description(
            file.as_fd(),
            enzimos_platform::json::unsigned(&body["header_number"])? as u32,
        )?;
        crate::backup_worker_handoff::readonly(&file)?;
        crate::backup_worker_handoff::identity(&file, &body["result"]["header"]["identity"])?;
        Some(file)
    } else {
        None
    };
    Ok(Incoming::Observation(Observation {
        request_sha256: json::fingerprint(request)?,
        worker: worker.clone(),
        result: body["result"].clone(),
        report: body,
        header,
    }))
}
fn report(body: &Value, request: &Value, sequence: u64) -> Result<()> {
    json::fields(
        body,
        "schema id request_sha256 sequence task result worker_scope_closed nonce header_number",
    )?;
    require(
        body["schema"] == 2
            && body["id"] == request["id"]
            && body["request_sha256"] == json::fingerprint(request)?
            && body["sequence"].as_u64() == Some(sequence)
            && sequence > 0
            && body["task"] == request["task"]
            && body["worker_scope_closed"] == false,
        "worker report differs from last acknowledged original request",
    )?;
    crate::backup_worker_request::id(body["nonce"].as_str().unwrap_or(""))?;
    if body["result"]["status"] == "provisioned" {
        require(
            body["header_number"]
                .as_u64()
                .is_some_and(|n| n <= i32::MAX as u64),
            "original header descriptor number required",
        )?;
    } else {
        require(
            body["header_number"].is_null(),
            "non-provision report cannot advertise repository authority",
        )?;
    }
    crate::backup_worker_result::for_request(&body["result"], request)
}
impl Observation {
    pub(crate) fn original_header(&self) -> Result<&File> {
        self.header.as_ref().ok_or_else(|| {
            enzimos_platform::Error("original reported header descriptor required".into())
        })
    }
    pub fn nonce(&self) -> &str {
        self.report["nonce"]
            .as_str()
            .expect("reports are admitted only with a valid nonce")
    }
    pub fn receipt(&self) -> Result<Value> {
        Ok(
            serde_json::json!({"schema":2,"id":self.report["id"],"request_sha256":self.report["request_sha256"],
            "sequence":self.report["sequence"],"nonce":self.report["nonce"],
            "report_sha256":json::fingerprint(&self.report)?,"received":true}),
        )
    }
    /// Closing this original public descriptor grants no pin/enrollment authority.
    /// It must precede normal unmount; the completed worker/mount proofs remain
    /// separately required for durable completion.
    pub fn retire_header(
        &mut self,
        request: &Value,
        closed: &Closed,
        owned: &crate::backup_setup_mount::Scope<'_, '_, '_>,
    ) -> Result<()> {
        self.observed_closed(request, closed)?;
        require(
            self.result["status"] != "provisioned" || self.header.is_some(),
            "original report header already retired; no repeated cleanup",
        )?;
        owned.recheck()?;
        require(
            owned.evidence()? == request["mount"],
            "header retirement differs from original owned mount",
        )?;
        if let Some(file) = &self.header {
            crate::backup_worker_handoff::identity(file, &self.result["header"]["identity"])?;
            let root = File::from(owned.descriptor()?.try_clone_to_owned()?);
            let repo =
                enzimos_platform::files::directory_relative(&root, Path::new("restic"), Some(0))?;
            let header = crate::backup_repository_header::Header::observe(&repo)?;
            require(
                header.evidence(&repo)? == self.result["header"],
                "reported original header changed before retirement",
            )?;
            require(
                enzimos_platform::json::sha256(&enzimos_platform::files::read_file(
                    file,
                    1024 * 1024,
                    Some(0),
                    true,
                )?) == self.result["header"]["sha256"],
                "held reported header bytes changed",
            )?;
        }
        owned.recheck()?;
        drop(self.header.take());
        Ok(())
    }
    /// Caller may display an observation; this is not a completion receipt.
    pub fn result(&self) -> &Value {
        &self.result
    }
    pub(crate) fn completed(&self, request: &Value, closed: &Closed) -> Result<Value> {
        require(
            self.header.is_none(),
            "reported repository descriptor must retire before normal mount completion",
        )?;
        self.observed_closed(request, closed)
    }
    pub(crate) fn observed_closed(&self, request: &Value, closed: &Closed) -> Result<Value> {
        require(
            json::fingerprint(request)? == self.request_sha256 && closed.binding()? == &self.worker,
            "observed consumer differs from original closed worker/request",
        )?;
        crate::backup_worker_result::for_request(&self.result, request)?;
        closed.recheck()?;
        Ok(self.result.clone())
    }
}
