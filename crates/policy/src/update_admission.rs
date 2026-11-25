// SPDX-License-Identifier: MIT
//! The unchanged cohort publication journal has only preparation and completion.
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
/// Validate an update admission journal record.
///
/// # Errors
///
/// Fails when a field is missing or invalid.
pub fn validate(body: &Value) -> Result<()> {
    json::fields(
        body,
        "schema phase cohort admission_sha256 retained_previous",
    )?;
    require(
        body["schema"] == 1 && matches!(body["phase"].as_str(), Some("prepared" | "complete")),
        "update admission journal schema or phase",
    )?;
    let cohort = body["cohort"]
        .as_str()
        .ok_or_else(|| Error("admission cohort name type".into()))?;
    let sequence = cohort
        .strip_prefix("cohort-main-")
        .or_else(|| cohort.strip_prefix("cohort-testing-"))
        .ok_or_else(|| Error("admission cohort outside fixed channels".into()))?;
    let number = sequence
        .parse::<u64>()
        .map_err(|_| Error("admission sequence encoding".into()))?;
    require(
        number > 0 && number.to_string() == sequence,
        "admission cohort canonical sequence",
    )?;
    crate::identity::sha(
        body["admission_sha256"]
            .as_str()
            .ok_or_else(|| Error("admission digest type".into()))?,
    )?;
    if !body["retained_previous"].is_null() {
        let suffix = body["retained_previous"]
            .as_str()
            .and_then(|s| s.strip_prefix(".enzimos-cohort-"))
            .ok_or_else(|| Error("admission retained previous name type".into()))?;
        require(
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "admission retained previous cannot escape the owned sibling",
        )?;
    }
    Ok(())
}
/// Require that `after` is a valid successor of `before`.
///
/// # Errors
///
/// Fails when the transition replays or skips completion, or changes the cohort.
pub fn transition(before: Option<&Value>, after: &Value) -> Result<()> {
    validate(after)?;
    if let Some(before) = before {
        validate(before)?;
        require(
            before["phase"] == "prepared" && after["phase"] == "complete",
            "unfinished admission cannot replay or skip completion",
        )?;
        for field in ["cohort", "admission_sha256", "retained_previous"] {
            require(
                before[field] == after[field],
                "admission immutable intent changed",
            )?;
        }
        Ok(())
    } else {
        require(
            after["phase"] == "prepared",
            "admission intent must precede publication",
        )
    }
}
