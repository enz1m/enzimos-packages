// SPDX-License-Identifier: MIT
use crate::{filesystem, identity, operation};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::Value;
use std::{
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
    time::Duration,
};
pub fn validate(v: &Value) -> Result<()> {
    require(v.is_object(), "storage configuration object required")?;
    let mut names = std::collections::BTreeSet::new();
    for key in [
        "root_subvol",
        "home_subvol",
        "authority_subvol",
        "control_subvol",
    ] {
        let s = v[key].as_str().ok_or_else(|| {
            Error("explicit independent storage subvolume configuration required".into())
        })?;
        identity::safe_id(s)?;
        require(
            names.insert(s),
            "control/root/home/authority must be independent",
        )?;
    }
    identity::uuid(
        v["filesystem_uuid"]
            .as_str()
            .ok_or_else(|| Error("configured filesystem UUID required".into()))?,
    )?;
    Ok(())
}
pub fn config() -> Result<Value> {
    let bytes = files::read(
        Path::new("/etc/enzimos/storage.json"),
        2 * 1024 * 1024,
        Some(0),
        true,
    )?;
    let v = json::decode(&bytes, 2 * 1024 * 1024)?;
    validate(&v)?;
    Ok(v)
}
pub fn storage_guard() -> Result<Value> {
    operation::root_only()?;
    require(
        std::fs::read_link("/proc/self/ns/mnt")? == std::fs::read_link("/proc/1/ns/mnt")?,
        "initial system mount namespace required",
    )?;
    let c = config()?;
    let directory = files::directory(Path::new(operation::CONTROL), Some(0))?;
    let before = directory.metadata()?;
    require(
        before.uid() == 0 && before.mode() & 0o077 == 0,
        "unsafe private control storage",
    )?;
    let mounted = operation::query(
        "/usr/bin/findmnt",
        &[
            "-n",
            "-o",
            "UUID,FSROOT,FSTYPE",
            "--mountpoint",
            operation::CONTROL,
        ],
        Duration::from_secs(30),
        4096,
        &[0],
    )?;
    let text = std::str::from_utf8(&mounted).map_err(|_| Error("control mount encoding".into()))?;
    let expected_root = format!("/{}", enzimos_platform::json::string(&c["control_subvol"])?);
    require(
        text.split_whitespace().collect::<Vec<_>>()
            == vec![
                enzimos_platform::json::string(&c["filesystem_uuid"])?,
                &expected_root,
                "btrfs",
            ],
        "independent control mount identity mismatch",
    )?;
    let root = operation::query(
        "/usr/bin/findmnt",
        &["-n", "-o", "UUID", "--mountpoint", "/"],
        Duration::from_secs(30),
        4096,
        &[0],
    )?;
    require(
        std::str::from_utf8(&root).map(str::trim).ok() == c["filesystem_uuid"].as_str(),
        "live root filesystem identity mismatch",
    )?;
    require(
        filesystem::observe(directory.as_fd())?["filesystem_uuid"] == c["filesystem_uuid"],
        "held control descriptor filesystem changed",
    )?;
    let after = files::directory(Path::new(operation::CONTROL), Some(0))?.metadata()?;
    require(
        (before.dev(), before.ino()) == (after.dev(), after.ino()),
        "control directory changed during observation",
    )?;
    require(
        config()? == c,
        "storage configuration changed during observation",
    )?;
    Ok(c)
}
