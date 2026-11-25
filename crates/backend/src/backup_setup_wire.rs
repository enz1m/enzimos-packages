// SPDX-License-Identifier: MIT
//! Existing setup control/input JSON. No client plan, pathname or command.
use enzimos_platform::{Result, require};
use serde_json::Value;
pub(crate) struct Request {
    body: Value,
    pub action: &'static str,
}
impl Request {
    pub(crate) fn decode(bytes: &[u8], input: bool) -> Result<Self> {
        let body = super::system_wire::decode(bytes, 1024)?;
        super::system_wire::fields(
            &body,
            if input {
                "schema request_id plan_sha256 allow_interaction"
            } else {
                "schema request_id plan_sha256 allow_interaction action selection_id mode"
            },
        )?;
        require(body["schema"].as_u64() == Some(1), "request-version")?;
        require(
            super::system_wire::hex(body["request_id"].as_str().unwrap_or(""), 32),
            "job-request-invalid",
        )?;
        require(body["allow_interaction"].is_boolean(), "interaction-type")?;
        let action = if input {
            "submit"
        } else {
            match body["action"].as_str() {
                Some("plan") => "plan",
                Some("status") => "status",
                Some("cancel") => "cancel",
                _ => return Err(enzimos_platform::Error("operation-unavailable".into())),
            }
        };
        require(
            if matches!(action, "cancel" | "submit") {
                super::system_wire::hex(body["plan_sha256"].as_str().unwrap_or(""), 64)
            } else {
                body["plan_sha256"].is_null()
            },
            "job-plan-invalid",
        )?;
        if !input {
            if action == "plan" {
                require(
                    super::system_wire::hex(body["selection_id"].as_str().unwrap_or(""), 64)
                        && matches!(body["mode"].as_str(), Some("initialize" | "adopt")),
                    "job-plan-invalid",
                )?;
            } else {
                require(
                    body["selection_id"].is_null() && body["mode"].is_null(),
                    "job-plan-invalid",
                )?;
                require(body["allow_interaction"] == false, "interaction-type")?;
            }
        }
        Ok(Self { body, action })
    }
    pub(crate) fn body(&self) -> &Value {
        &self.body
    }
}
