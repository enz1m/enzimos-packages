// SPDX-License-Identifier: MIT
//! Pure historical restored filename; no account or filesystem authority.
use crate::{Result, json, require};
use serde_json::json as value;
/// File name for a restored copy of `path`, tagged with a digest of `id` before the extension.
///
/// # Errors
///
/// Fails when the name is empty, too long, or contains other characters than ASCII letters, digits
/// and `_. ()-`.
pub fn restored(path: &str, id: &str) -> Result<String> {
    let base = path
        .rsplit('/')
        .next()
        .ok_or_else(|| crate::Error("job-plan-invalid".into()))?;
    let (stem, extension) = match base.rsplit_once('.') {
        Some((stem, extension)) if stem.bytes().any(|b| b != b'.') => (stem, Some(extension)),
        _ => (base, None),
    };
    let mut bytes = json::canonical(&value!({"id":id}))?;
    bytes.push(b'\n');
    let digest = json::sha256(&bytes);
    let short = digest.get(..12).unwrap_or(&digest);
    let name = match extension {
        Some(extension) => format!("{stem} (restored {short}).{extension}"),
        None => format!("{stem} (restored {short})"),
    };
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
