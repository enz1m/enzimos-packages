// SPDX-License-Identifier: MIT
//! Actual sealed worker observations, without enrollment completion authority.
use enzimos_platform::{Result, json, memfile, require};
use serde_json::{Value, json as value};
use std::fs::File;
pub const LIMIT: usize = 192 * 1024;
pub(crate) fn measured(body: &Value, enrollment: &Value) -> Result<String> {
    json::fields(
        body,
        "schema kind request_sha256 current_first candidate_first current_last candidate_last metadata_checked worker_scope_closed enrollment_complete",
    )?;
    require(
        body["schema"] == 1
            && body["kind"] == "credential-review-observed"
            && body["metadata_checked"] == true
            && body["worker_scope_closed"] == false
            && body["enrollment_complete"] == false,
        "credential observation cannot claim worker closure or enrollment completion",
    )?;
    crate::identity::sha(
        body["request_sha256"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("credential request digest required".into()))?,
    )?;
    let keys = |field| -> Result<_> {
        let bytes = json::canonical(&body[field])?;
        require(
            bytes.len() <= 32768,
            "individual credential key output bound",
        )?;
        crate::backup_restic_result::keys(Some(0), &bytes)
    };
    let current = keys("current_first")?;
    let candidate = keys("candidate_first")?;
    require(
        current == keys("current_last")? && candidate == keys("candidate_last")?,
        "credential key inventories changed across metadata check; no completion",
    )?;
    crate::backup_credential_record::sole_added_key(enrollment, &current, &candidate)
}
pub struct Observed {
    output: File,
    digest: String,
    request_sha256: String,
    enrollment: Value,
    key: String,
}
impl Observed {
    // Only the fixed actual runtime constructs this after five successful
    // commands. Decoded data cannot construct this actor or close its worker.
    pub(crate) fn seal(request: &Value, enrollment: &Value, outputs: [&[u8]; 4]) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let request_sha256 = json::fingerprint(request)?;
        let fields = [
            "current_first",
            "candidate_first",
            "current_last",
            "candidate_last",
        ];
        let mut body = value!({"schema":1,"kind":"credential-review-observed",
            "request_sha256":request_sha256,"metadata_checked":true,
            "worker_scope_closed":false,"enrollment_complete":false});
        for (field, bytes) in fields.into_iter().zip(outputs) {
            body[field] = json::decode(bytes, 32768)?;
        }
        let key = measured(&body, enrollment)?;
        let bytes = json::canonical(&body)?;
        require(
            bytes.len() <= LIMIT,
            "credential review sealed observation bound",
        )?;
        let this = Self {
            output: memfile::sealed("credential-review-observed", &bytes)?,
            digest: json::sha256(&bytes),
            request_sha256,
            enrollment: enrollment.clone(),
            key,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        let bytes = memfile::read_sealed(&self.output, LIMIT, 0)?;
        require(
            json::sha256(&bytes) == self.digest,
            "original sealed credential observation changed",
        )?;
        let body = json::decode(&bytes, LIMIT)?;
        require(
            body["request_sha256"] == self.request_sha256
                && measured(&body, &self.enrollment)? == self.key,
            "original credential review request or observed key changed",
        )
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.output)
    }
    pub(crate) fn require_request(&self, request: &Value) -> Result<()> {
        self.recheck()?;
        require(
            self.request_sha256 == json::fingerprint(request)?,
            "credential observation belongs to another original request",
        )
    }
    pub fn digest(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.digest)
    }
    pub fn value(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"status":"credential-reviewed","new_key":self.key,"metadata_checked":true,
            "worker_scope_closed":false,"enrollment_complete":false,
            "credential_exported":false,"old_access_revoked":false}),
        )
    }
}
