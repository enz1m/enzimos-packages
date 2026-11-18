// SPDX-License-Identifier: MIT
//! Legacy-compatible authority identity, exported from a private public-material copy.
use crate::{authority, authority_build, authority_mount::Authority, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, path::Path};
pub fn ownertrust_digest(body: &[u8]) -> Result<String> {
    let body =
        std::str::from_utf8(body).map_err(|_| Error("authority ownertrust encoding".into()))?;
    authority::trusted_local(body, &BTreeSet::new())?;
    let mut rows = body
        .lines()
        .filter(|row| !row.is_empty() && !row.starts_with('#'))
        .collect::<Vec<_>>();
    rows.sort_unstable();
    Ok(json::sha256(rows.join("\n").as_bytes()))
}
pub fn observe(guard: &Guard) -> Result<Value> {
    let mounted = Authority::observe(guard)?;
    let source = mounted.files()?;
    let base = Path::new("/run/enzimos/rebind-authority-views");
    files::ensure_directory(base, 0o700, 0)?;
    let home = base.join(files::random_hex(16)?);
    let directory = files::create_directory(&home, 0o700, 0)?;
    for (name, body) in &source {
        files::atomic(
            &home.join(name),
            body,
            if name == "gpg.conf" { 0o644 } else { 0o600 },
            Some(0),
            false,
        )?;
    }
    directory.sync_all()?;
    mounted.recheck(guard)?;
    let exported = authority_build::gpg(&home, &["--export-ownertrust"], &[])?;
    let mut result = value!({"ownertrust":ownertrust_digest(&exported)?});
    for name in ["pubring.gpg", "gpg.conf", "approved.trust"] {
        result[name] = value!(json::sha256(&source[name]));
    }
    mounted.recheck(guard)?;
    require(
        mounted.files()? == source,
        "authority changed while measuring exported trust",
    )?;
    guard.recheck()?;
    Ok(result)
}
