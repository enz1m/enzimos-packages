// SPDX-License-Identifier: MIT
//! Loader-only recovery publication binds immutable intent; artifacts never replay.
use crate::{boot_entries, recovery_image, recovery_records};
use enzimos_platform::{Result, json, require};
use serde_json::Value;
pub(crate) fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(v, "schema record bios_before default_before journal_sha256")?;
    require(
        v["schema"].as_u64() == Some(1),
        "invalid recovery publication journal schema",
    )?;
    recovery_image::validate(&v["record"], id)?;
    require(
        v["record"]["phase"] == "intent"
            && enzimos_platform::json::object(&v["record"]["observations"])?.is_empty(),
        "publication journal must bind unconfirmed intent",
    )?;
    let bios = recovery_records::text(v, "bios_before")?;
    let defaults = recovery_records::text(v, "default_before")?;
    require(
        bios.len() <= boot_entries::MAX_TEXT && defaults.len() <= boot_entries::MAX_TEXT,
        "recovery publication metadata byte bound",
    )?;
    let menu = boot_entries::menu(bios)?;
    let (_, title) = recovery_image::entry_names(id)?;
    require(
        menu.entries.iter().all(|entry| entry.title != title),
        "publication cannot adopt existing BIOS entry",
    )?;
    boot_entries::fields(defaults, false)?;
    recovery_records::digest(v, "journal_sha256")
}
pub(crate) fn expected_record(journal: &Value, current: &Value) -> Result<()> {
    let id = recovery_records::text(&journal["record"], "id")?;
    validate(journal, id)?;
    recovery_image::validate(current, id)?;
    require(
        matches!(current["phase"].as_str(), Some("artifacts" | "ready")),
        "artifact creation incomplete; no replay or adoption",
    )?;
    let mut normalized = current.clone();
    normalized["phase"] = serde_json::json!("intent");
    normalized["observations"] = serde_json::json!({});
    require(
        normalized == journal["record"],
        "image record differs from publication intent",
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Before,
    After,
}
pub(crate) fn classify(actual: &Value, before: &Value, after: &Value) -> Result<State> {
    if actual == after {
        return Ok(State::After);
    }
    require(
        actual == before,
        "recovery publication metadata drift; no overwrite permitted",
    )?;
    Ok(State::Before)
}
