// SPDX-License-Identifier: MIT
//! Pure historical restored filename; no account or filesystem authority.
use crate::{Result, json, require};
use serde_json::json as value;
pub fn restored(path: &str, id: &str) -> Result<String> {
    let base = path
        .rsplit('/')
        .next()
        .ok_or_else(|| crate::Error("job-plan-invalid".into()))?;
    let split = base
        .rfind('.')
        .filter(|i| base[..*i].bytes().any(|b| b != b'.'))
        .unwrap_or(base.len());
    let mut bytes = json::canonical(&value!({"id":id}))?;
    bytes.push(b'\n');
    let digest = json::sha256(&bytes);
    let name = format!(
        "{} (restored {}){}",
        &base[..split],
        &digest[..12],
        &base[split..]
    );
    require(
        !base.is_empty()
            && !name.is_empty()
            && name.len() <= 255
            && !matches!(name.as_str(), "." | "..")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_. ()-".contains(&b)),
        "job-plan-invalid",
    )?;
    Ok(name)
}
