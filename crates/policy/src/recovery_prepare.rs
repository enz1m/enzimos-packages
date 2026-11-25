// SPDX-License-Identifier: MIT
//! System1 recovery preparation previews original receipts and never selects defaults.
use crate::{identity, operation, recovery_plan::Review};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{os::unix::fs::MetadataExt, path::Path};
fn selection(body: &Value) -> Result<(&str, &str)> {
    json::fields(body, "birth generation")?;
    let text = |key| {
        body[key]
            .as_str()
            .ok_or_else(|| Error("recovery selection text required".into()))
    };
    Ok((
        identity::safe_id(text("birth")?)?,
        identity::safe_id(text("generation")?)?,
    ))
}
pub fn observation(body: &Value) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    let (birth, generation) = selection(body)?;
    let guard = crate::storage_runtime::Guard::observe()?;
    let directory =
        files::directory_relative(guard.control(), Path::new("generation-registry"), Some(0))?;
    let original = crate::control_record::Retained::open(
        &directory,
        Path::new("catalog.json"),
        crate::catalog::MAX_CATALOG,
        guard.control_mount_id(),
    )?;
    // Preview requires the initialized lock. It cannot create a registry or catalog.
    let lock = files::open_relative(&directory, Path::new("lock"))?;
    let m = lock.metadata()?;
    require(
        m.is_file() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o7777 == 0o600,
        "existing private catalog lock required",
    )?;
    let review = Review::open(birth, generation)?;
    let view = review.view()?;
    require(
        view["catalog_epoch"]["record"] == original.evidence()?,
        "original preview catalog changed during locking",
    )?;
    require(
        view["catalog_epoch"]["lock"] == value!(files::identity(&m))
            && files::identity(&lock.metadata()?) == files::identity(&m),
        "original preview catalog lock changed during acquisition",
    )?;
    guard.recheck()?;
    original.recheck()?;
    Ok(view)
}
pub fn prepare<F: FnMut() -> Result<()>>(
    body: &Value,
    request_id: &str,
    expected: &Value,
    authorize: &mut F,
) -> Result<Value> {
    let (birth, generation) = selection(body)?;
    require(
        request_id.len() == 32
            && request_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "recovery request identity required",
    )?;
    // Run the first native plan verification before holding the catalog transaction lock.
    authorize()?;
    let lock = operation::lock()?;
    let id = format!("api-{request_id}");
    let result =
        crate::recovery_plan::prepare_reviewed(&id, birth, generation, &lock, expected, authorize)?;
    lock.recheck()?;
    require(
        result["id"] == id
            && result["status"] == "recovery-plan-prepared"
            && result["activation_available"] == false
            && result["retirement_enabled"] == false,
        "original recovery preparation reply differs",
    )?;
    completion(
        request_id,
        result["plan_sha256"]
            .as_str()
            .ok_or_else(|| Error("recovery plan digest required".into()))?,
    )
}
/// Closed reply data alone grants no preparation or activation authority.
pub(crate) fn completion(request_id: &str, digest: &str) -> Result<Value> {
    require(
        request_id.len() == 32
            && request_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "recovery request identity required",
    )?;
    identity::sha(digest)?;
    Ok(
        value!({"recovery_id":format!("api-{request_id}"),"plan_sha256":digest,"activation_available":false}),
    )
}
