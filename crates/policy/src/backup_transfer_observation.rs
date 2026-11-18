// SPDX-License-Identifier: MIT
//! Kernel-stamped original worker observation, never a reconstructed cleanup actor.
use enzimos_platform::{
    Result,
    backup_worker_scope::Scope,
    fd_packet::{Message, Packet},
    json, require,
};
use serde_json::{Value, json as value};
use std::{fs::File, os::fd::AsFd, time::Duration};
pub struct Observation {
    request: Value,
    report: Value,
    worker: Value,
    output: Option<File>,
}
pub enum Incoming {
    Challenge(Message),
    Observed(Observation),
}
pub fn receive(
    channel: &Packet,
    scope: &Scope,
    request: &Value,
    sequence: u64,
) -> Result<Incoming> {
    crate::backup_transfer_request::request(request)?;
    let worker = scope.original_binding()?;
    require(
        *worker == request["worker"],
        "transfer report belongs to another original worker",
    )?;
    let peer = channel.peer_credentials()?;
    require(
        peer.uid == 0
            && peer.gid == 0
            && u64::from(peer.pid) == worker["worker"]["pid"].as_u64().unwrap(),
        "transfer control peer is not original worker",
    )?;
    let mut message = channel.receive_counts(4096, &[0, 1], Duration::from_secs(3))?;
    require(
        message.sender.pid == worker["worker"]["pid"].as_u64().unwrap() as u32
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "original transfer kernel sender differs",
    )?;
    let body = json::decode(&message.body, 4096)?;
    if body.get("result").is_none() {
        sender(&message, worker["worker"]["pid"].as_u64().unwrap() as u32)?;
        return Ok(Incoming::Challenge(message));
    }
    report(&body, request, sequence)?;
    let output = if body["schema"] == 2 {
        require(
            message.files.len() == 1,
            "version2 transfer report requires one actual sealed output",
        )?;
        let file = File::from(message.files.pop().unwrap());
        scope.require_description(
            file.as_fd(),
            body["stdout_descriptor_number"].as_u64().unwrap() as u32,
        )?;
        output(&file, &body)?;
        Some(file)
    } else {
        require(
            message.files.is_empty(),
            "legacy report cannot acquire output authority",
        )?;
        None
    };
    Ok(Incoming::Observed(Observation {
        request: request.clone(),
        report: body,
        worker: worker.clone(),
        output,
    }))
}
pub(crate) fn sender(message: &Message, worker: u32) -> Result<()> {
    require(
        message.files.is_empty()
            && message.sender.pid == worker
            && message.sender.uid == 0
            && message.sender.gid == 0,
        "transfer message is not original Root worker",
    )
}
fn report(body: &Value, request: &Value, sequence: u64) -> Result<()> {
    json::fields(
        body,
        if body["schema"] == 2 {
            "schema kind id request_sha256 sequence nonce result worker_scope_closed stdout_descriptor_number stdout_sha256"
        } else {
            "schema kind id request_sha256 sequence nonce result worker_scope_closed"
        },
    )?;
    if body["schema"] == 2 {
        crate::identity::sha(body["stdout_sha256"].as_str().unwrap_or(""))?;
        require(
            body["stdout_descriptor_number"]
                .as_u64()
                .is_some_and(|n| (3..=1048576).contains(&n)),
            "original stdout descriptor number bound",
        )?;
    }
    require(
        matches!(body["schema"].as_u64(), Some(1 | 2))
            && body["kind"] == "captured-backup-transfer"
            && body["id"] == request["id"]
            && body["request_sha256"] == json::fingerprint(request)?
            && body["sequence"].as_u64() == Some(sequence)
            && sequence > 0
            && body["worker_scope_closed"] == false,
        "transfer report differs from original request/approval",
    )?;
    crate::backup_worker_request::id(body["nonce"].as_str().unwrap_or(""))?;
    crate::backup_transfer_checkpoint::outcome(&body["result"])
}
fn output(file: &File, report: &Value) -> Result<(Vec<u8>, Value)> {
    let bytes = enzimos_platform::memfile::read_sealed(file, 2 * 1024 * 1024, 0)?;
    require(
        json::sha256(&bytes) == report["stdout_sha256"].as_str().unwrap_or(""),
        "original sealed output digest differs from measured worker report",
    )?;
    let summary = crate::backup_restic_result::backup_summary(Some(0), &bytes)?;
    require(
        summary["snapshot_id"] == report["result"]["snapshot_id"],
        "original terminal summary snapshot differs",
    )?;
    Ok((bytes, summary))
}
impl Observation {
    pub fn value(&self) -> &Value {
        &self.report["result"]
    }
    pub fn report(&self) -> &Value {
        &self.report
    }
    /// Legacy reports intentionally have no stdout/publication authority.
    fn output(&self) -> Result<(Vec<u8>, Value)> {
        require(
            self.report["schema"] == 2,
            "legacy transfer report lacks original summary/log artifact",
        )?;
        output(
            self.output.as_ref().ok_or_else(|| {
                enzimos_platform::Error("original sealed report output unavailable".into())
            })?,
            &self.report,
        )
    }
    pub fn require_closed(
        &self,
        request: &crate::backup_transfer_reservation::ClosedRequest,
        sources: &crate::backup_readonly_trees::ReleasedDescriptors,
    ) -> Result<()> {
        require(
            *request.binding()? == self.worker,
            "closed request differs from observed worker",
        )?;
        sources.require_transfer(
            &self.worker,
            &self.request["id"],
            &self.request["context"]["input_sha256"],
        )
    }
    /// Review with the retained actual closed actors, without copying authority.
    pub fn closed_evidence(
        &self,
        request: &crate::backup_transfer_reservation::ClosedRequest,
        sources: &crate::backup_readonly_trees::ReleasedDescriptors,
    ) -> Result<Value> {
        self.require_closed(request, sources)?;
        Ok(
            value!({"observation":self.report,"worker_scope_closed":true,
            "source_descriptors_released":true,"source_cleanup_complete":false,"backup_complete":false}),
        )
    }
    /// Combine two actual retirement actors. Neither transfer observation nor a
    /// copied closure receipt can retire original source descriptions.
    pub fn close<'a>(
        self,
        request: &'a crate::backup_transfer_reservation::ClosedRequest,
        sources: &'a crate::backup_readonly_trees::ReleasedDescriptors,
    ) -> Result<ClosedObservation<'a>> {
        require(
            *request.binding()? == self.worker,
            "closed request differs from observed transfer worker",
        )?;
        sources.require_transfer(
            &self.worker,
            &self.request["id"],
            &self.request["context"]["input_sha256"],
        )?;
        Ok(ClosedObservation {
            original: self,
            request,
            sources,
        })
    }
}
/// Observation only: actual source snapshot and stage cleanup is still required.
pub struct ClosedObservation<'a> {
    original: Observation,
    request: &'a crate::backup_transfer_reservation::ClosedRequest,
    sources: &'a crate::backup_readonly_trees::ReleasedDescriptors,
}
impl ClosedObservation<'_> {
    /// Actual source file epoch/mount must match the original retired offer.
    pub(crate) fn require_boot(
        &self,
        boot: &crate::backup_boot_capture::Captured<'_, '_>,
    ) -> Result<()> {
        self.recheck()?;
        boot.recheck()?;
        let sources = self.sources.evidence()?;
        let tree = &sources["receipt"]["trees"]["/backup-source/boot"];
        let file = boot.descriptor()?;
        require(
            tree["inode"] == value!(enzimos_platform::files::identity(&file.metadata()?))
                && tree["source_mount"]
                    == enzimos_platform::mount_identity::id(file.as_fd(), true)?
                && boot.original_root()? == self.original.request["context"]["source"],
            "original boot tree differs from actual transferred source",
        )
    }
    pub(crate) fn require_inventory_stage(
        &self,
        stage: &crate::backup_inventory_stage::Staged<'_, '_, '_, '_>,
    ) -> Result<()> {
        self.recheck()?;
        stage.recheck()?;
        let sources = self.sources.evidence()?;
        let tree = &sources["receipt"]["trees"]["/backup-source/inventory"];
        let file = stage.original_directory()?;
        require(
            tree["inode"] == value!(enzimos_platform::files::identity(&file.metadata()?))
                && tree["source_mount"]
                    == enzimos_platform::mount_identity::id(file.as_fd(), true)?
                && stage.original_root()? == self.original.request["context"]["source"]
                && stage.evidence()?["receipt"]["id"] == self.original.request["id"],
            "original inventory stage differs from actual transferred source",
        )
    }
    pub(crate) fn require_snapshot(
        &self,
        capture: &crate::backup_snapshot_creation::Captured<'_, '_>,
    ) -> Result<()> {
        self.recheck()?;
        capture.recheck()?;
        let dataset = capture.dataset()?;
        let target = format!("/backup-source/{}", dataset.archive);
        let sources = self.sources.evidence()?;
        let tree = &sources["receipt"]["trees"][&target];
        let file = capture.snapshot()?.descriptor()?;
        // Snapshot's owned File supplies the full epoch; no path or JSON ctor.
        require(
            tree["inode"] == capture.original_epoch()?
                && tree["source_mount"] == enzimos_platform::mount_identity::id(file, true)?,
            "cleanup snapshot differs from original transferred source description",
        )?;
        require(
            capture.original_root()? == self.original.request["context"]["source"],
            "cleanup snapshot does not retain original transfer source root",
        )
    }

    pub fn recheck(&self) -> Result<()> {
        require(
            *self.request.binding()? == self.original.worker,
            "original observed closure changed",
        )?;
        self.sources.require_transfer(
            &self.original.worker,
            &self.original.request["id"],
            &self.original.request["context"]["input_sha256"],
        )
    }
    pub fn original_summary(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.original.output()?.1)
    }
    pub fn original_log(&self) -> Result<Vec<u8>> {
        self.recheck()?;
        Ok(self.original.output()?.0)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"request_sha256":json::fingerprint(&self.original.request)?,
        "worker":self.original.worker,"consumer":self.original.report["result"],"source_descriptions_released":true,
        "source_cleanup_complete":false,"backup_complete":false}),
        )
    }
}
