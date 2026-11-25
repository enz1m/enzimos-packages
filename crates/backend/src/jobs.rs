// SPDX-License-Identifier: MIT
//! Legacy history rows keep their exact schema with original retained epochs.
use crate::operation_store::Store;
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
use std::path::Path;

pub(crate) fn identifier(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn validate(record: &Value, id: &str) -> Result<()> {
    json::fields(
        record,
        "schema request_id owner_uid operation state snapshot",
    )?;
    require(
        record["schema"].as_u64() == Some(1)
            && record["request_id"] == id
            && identifier(id)
            && record["owner_uid"]
                .as_u64()
                .is_some_and(|n| n < u64::from(u32::MAX))
            && record["operation"] == "home-history-create",
        "job-record-invalid",
    )?;
    require(
        matches!(
            record["state"].as_str(),
            Some("prepared" | "running" | "completed" | "uncertain")
        ),
        "job-record-invalid",
    )?;
    require(
        if record["state"] == "completed" {
            record["snapshot"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < (1u64 << 63))
        } else {
            record["snapshot"].is_null()
        },
        "job-record-invalid",
    )
}
pub(crate) fn transition(before: &Value, after: &Value) -> Result<()> {
    let id = before["request_id"]
        .as_str()
        .ok_or_else(|| Error("job-record-invalid".into()))?;
    validate(before, id)?;
    validate(after, id)?;
    for key in ["schema", "request_id", "owner_uid", "operation"] {
        require(before[key] == after[key], "job-plan-changed")?;
    }
    require(
        matches!(
            (before["state"].as_str(), after["state"].as_str()),
            (Some("prepared"), Some("running" | "uncertain"))
                | (Some("running"), Some("completed" | "uncertain"))
        ),
        "job-transition-refused",
    )
}
pub(crate) fn public(record: &Value) -> Result<Value> {
    let id = record["request_id"]
        .as_str()
        .ok_or_else(|| Error("job-record-invalid".into()))?;
    validate(record, id)?;
    Ok(
        value!({"schema":2,"operation":record["operation"],"request_id":id,"state":record["state"],"snapshot":record["snapshot"]}),
    )
}
pub(crate) struct JobStore<G> {
    store: Store<G>,
}
impl<G: Fn() -> Result<()>> JobStore<G> {
    pub(crate) fn open(path: &Path, guard: G) -> Result<Self> {
        Self::open_owned(path, 0, guard)
    }
    pub(crate) fn open_owned(path: &Path, owner: u32, guard: G) -> Result<Self> {
        Ok(Self {
            store: Store::open_history(path, owner, guard)?,
        })
    }
    pub(crate) fn status(&self, id: &str, uid: u32) -> Result<Value> {
        self.store.status(id, uid)
    }
    /// true means a fresh durable attempt; a completed row never calls a provider.
    pub(crate) fn prepare(&mut self, id: &str, uid: u32) -> Result<(Value, bool)> {
        match self.status(id, uid) {
            Ok(body) => {
                require(
                    body["state"] == "completed",
                    "job-result-uncertain-no-replay",
                )?;
                return Ok((body, false));
            }
            Err(e) if e.0 == "job-not-found" => (),
            Err(e) => return Err(e),
        }
        let row = value!({"schema":1,"request_id":id,"owner_uid":uid,"operation":"home-history-create","state":"prepared","snapshot":null});
        self.store.publish(id, row.clone())?;
        Ok((row, true))
    }
    pub(crate) fn phase(
        &mut self,
        id: &str,
        uid: u32,
        state: &str,
        snapshot: Option<u64>,
    ) -> Result<Value> {
        let mut row = self.status(id, uid)?;
        row["state"] = value!(state);
        row["snapshot"] = value!(snapshot);
        self.store.publish(id, row.clone())?;
        Ok(row)
    }
}
