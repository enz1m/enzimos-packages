// SPDX-License-Identifier: MIT
//! Actual immutable remote worker observations, without receipt/closure authority.
use enzimos_platform::{Result, json, memfile, require};
use serde_json::{Value, json as value};
use std::fs::File;
pub const LIMIT: usize = 16 * 1024 * 1024;
pub fn identity_data(code: Option<i32>, bytes: &[u8], pin: &Value) -> Result<Value> {
    require(
        code == Some(0),
        "remote repository identity query failed; no replay",
    )?;
    crate::backup_remote_record::pin(pin)?;
    let data = json::decode(bytes, crate::backup_remote_points::LIMIT)?;
    require(
        data.is_object() && matches!(data["version"].as_u64(), Some(1 | 2)),
        "authenticated remote repository version",
    )?;
    crate::identity::sha(data["id"].as_str().unwrap_or(""))?;
    require(
        data["id"] == pin["repository_id"],
        "authenticated remote repository ID differs from original pin",
    )?;
    Ok(pin.clone())
}
pub(crate) fn measured(body: &Value, request: &Value) -> Result<Value> {
    crate::backup_remote_request::request(request)?;
    json::fields(
        body,
        "schema kind request_sha256 source_first source_last destination_before destination_after remote_first remote_last metadata_checked worker_scope_closed receipt_complete retrieval_intent",
    )?;
    let ctx = &request["context"];
    let source = ctx["snapshot"].as_str().unwrap();
    require(
        body["schema"].as_u64() == Some(1)
            && body["kind"] == "remote-copy-observed"
            && body["request_sha256"] == json::fingerprint(request)?
            && body["metadata_checked"] == true
            && body["worker_scope_closed"] == false
            && body["receipt_complete"] == false,
        "remote observation differs or asserts receipt/closure",
    )?;
    require(
        body["source_first"] == body["source_last"]
            && body["remote_first"] == ctx["remote"]["pin"]
            && body["remote_last"] == ctx["remote"]["pin"],
        "remote source or pinned identity changed across copy/check",
    )?;
    let copied = if ctx["direction"] == "replicate" {
        require(
            body["retrieval_intent"].is_null(),
            "replication cannot attach a retrieval receipt",
        )?;
        require(
            body["destination_before"].is_null(),
            "replication cannot substitute a retrieval inventory",
        )?;
        crate::backup_remote_points::replicated(
            &body["source_first"],
            source,
            &body["destination_after"],
        )?
    } else {
        crate::backup_remote_receipt::record(&body["retrieval_intent"])?;
        let intent = &body["retrieval_intent"];
        let selected = crate::backup_remote_points::selected(&body["source_first"], source)?;
        require(
            intent["id"] == ctx["receipt_id"]
                && intent["phase"] == "copying"
                && intent["remote_snapshot"] == source
                && intent["original"] == *selected.get("original").unwrap_or(&selected["id"])
                && intent["remote_repository"] == ctx["remote"]["pin"]
                && intent["boot_id"] == request["boot_id"],
            "remote observation retrieval intent differs from original copy",
        )?;
        crate::backup_remote_points::retrieved(
            &body["source_first"],
            source,
            &body["destination_before"],
            &body["destination_after"],
        )?
    };
    Ok(
        value!({"status":"remote-copy-observed","direction":ctx["direction"],"snapshot":source,"copied_snapshot":copied,"repository_id":ctx["remote"]["pin"]["repository_id"],"metadata_checked":true,"worker_scope_closed":false,"receipt_complete":false,"live_home_written":false,"scheduler_enabled":false,"automatic_retry":false}),
    )
}
pub struct Observed<'h> {
    guard: &'h crate::storage_runtime::Guard,
    intent: Option<crate::backup_remote_receipt::Intent>,
    output: File,
    digest: String,
    request: Value,
}
impl<'h> Observed<'h> {
    pub(crate) fn seal(
        handoff: &'h crate::backup_remote_handoff::Handoff<'_>,
        source_first: Value,
        source_last: Value,
        destination_before: Value,
        destination_after: Value,
        remote_first: Value,
        remote_last: Value,
        intent: Option<crate::backup_remote_receipt::Intent>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let request = handoff.request()?.clone();
        let guard = handoff.guard()?;
        let retrieval_intent = intent
            .as_ref()
            .map(|record| record.value(guard).cloned())
            .transpose()?;
        let body = value!({"retrieval_intent":retrieval_intent,"schema":1,"kind":"remote-copy-observed","request_sha256":json::fingerprint(&request)?,"source_first":source_first,"source_last":source_last,"destination_before":destination_before,"destination_after":destination_after,"remote_first":remote_first,"remote_last":remote_last,"metadata_checked":true,"worker_scope_closed":false,"receipt_complete":false});
        measured(&body, &request)?;
        let bytes = json::canonical(&body)?;
        require(bytes.len() <= LIMIT, "bounded immutable remote copy output")?;
        let this = Self {
            guard,
            intent,
            output: memfile::sealed("remote-copy-observed", &bytes)?,
            digest: json::sha256(&bytes),
            request,
        };
        this.recheck()?;
        handoff.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        if let Some(intent) = &self.intent {
            intent.recheck(self.guard)?;
        }
        let bytes = memfile::read_sealed(&self.output, LIMIT, 0)?;
        require(
            json::sha256(&bytes) == self.digest,
            "original immutable remote observation changed",
        )?;
        let body = json::decode(&bytes, LIMIT)?;
        measured(&body, &self.request)?;
        if let Some(intent) = &self.intent {
            require(
                intent.value(self.guard)? == &body["retrieval_intent"],
                "original retrieval intent differs from sealed observation",
            )?;
        }
        Ok(())
    }
    pub(crate) fn receipt_descriptor(&self) -> Result<Option<&File>> {
        self.recheck()?;
        self.intent
            .as_ref()
            .map(|intent| intent.descriptor(self.guard))
            .transpose()
    }
    pub(crate) fn receipt_evidence(&self) -> Result<Option<Value>> {
        self.recheck()?;
        self.intent
            .as_ref()
            .map(|intent| intent.evidence(self.guard))
            .transpose()
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.output)
    }
    pub fn digest(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.digest)
    }
    pub fn value(&self) -> Result<Value> {
        self.recheck()?;
        measured(
            &json::decode(&memfile::read_sealed(&self.output, LIMIT, 0)?, LIMIT)?,
            &self.request,
        )
    }
    pub(crate) fn require_request(&self, request: &Value) -> Result<()> {
        self.recheck()?;
        require(
            &self.request == request,
            "remote observation belongs to another original request",
        )
    }
}
