// SPDX-License-Identifier: MIT
//! A consumer observation never claims the worker, mount or setup has closed.
use enzimos_platform::{Result, json, require};
use serde_json::Value;
pub fn for_request(result: &Value, request: &Value) -> Result<()> {
    validate(result, request["task"].as_str().unwrap_or(""))?;
    if result["status"] == "provisioned" {
        require(
            result["header"]["identity"][0] == request["repository"]["device"],
            "provision header left original repository filesystem",
        )?;
        if request["plan"]["mode"] == "adopt" {
            require(
                result["header"] == request["header"],
                "provision observation changed original adopted header",
            )?;
        }
    }
    Ok(())
}
pub fn validate(result: &Value, task: &str) -> Result<()> {
    match result["status"].as_str() {
        Some("provisioned") => {
            json::fields(result, "status mode key_id metadata_checked header")?;
            require(
                result["metadata_checked"] == true
                    && matches!(
                        (task, result["mode"].as_str()),
                        ("provision-initialize", Some("initialize"))
                            | ("provision-adopt", Some("adopt"))
                    ),
                "provision observation differs from fixed workflow/mode",
            )?;
            crate::identity::sha(result["key_id"].as_str().unwrap_or(""))?;
            crate::backup_repository_header::validate(&result["header"])
        }
        Some("authenticated") => {
            json::fields(result, "status key_id")?;
            require(
                matches!(task, "authenticate" | "authenticate-input"),
                "authentication result for wrong task",
            )?;
            crate::identity::sha(
                result["key_id"]
                    .as_str()
                    .ok_or_else(|| enzimos_platform::Error("observed key ID required".into()))?,
            )
            .map(|_| ())
        }
        Some(status) => {
            json::fields(result, "status")?;
            require(
                matches!(
                    (task, status),
                    ("initialize", "initialized")
                        | ("check-metadata", "metadata-checked")
                        | ("authenticate" | "authenticate-input", "incorrect-password")
                ),
                "worker observation differs from fixed task",
            )
        }
        None => Err(enzimos_platform::Error(
            "worker observation status required".into(),
        )),
    }
}
