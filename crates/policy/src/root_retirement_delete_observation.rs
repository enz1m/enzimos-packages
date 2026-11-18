// SPDX-License-Identifier: MIT
//! Strict comparisons for actual Btrfs unlink observations. Comparisons do not
//! construct syscall-success, ownership, progress or cold replay witnesses.
use enzimos_platform::{Error, Result, files, require};
use serde_json::Value;
/// Btrfs unlink_subvol reduces the parent size by twice the literal disk name
/// length, updates its mtime/ctime and preserves its remaining identity fields.
/// Parent subvolume ID/UUID and filesystem joins remain separate requirements.
pub fn parent_delta(
    before: files::FileIdentity,
    after: files::FileIdentity,
    name: &str,
) -> Result<()> {
    require(
        !name.is_empty()
            && name.len() <= 255
            && name.is_ascii()
            && !name.contains('/')
            && !name.as_bytes().contains(&0)
            && !matches!(name, "." | ".."),
        "literal original Btrfs unlink name required",
    )?;
    let expected = before
        .2
        .checked_sub((name.len() as u64) * 2)
        .ok_or_else(|| Error("original Btrfs unlink parent size underflow".into()))?;
    require(
        (before.0, before.1, before.7, before.8, before.9, before.10)
            == (after.0, after.1, after.7, after.8, after.9, after.10)
            && after.2 == expected
            && (after.3, after.4) >= (before.3, before.4)
            && (after.5, after.6) >= (before.5, before.6),
        "Btrfs unlink parent changed beyond the exact owned name removal",
    )
}
/// Current Btrfs releases the dead root's anonymous device number. An actual
/// retained FD may therefore report st_dev=0 after a successful deletion. Name
/// absence and complete kernel-tree removal must be proved independently.
pub fn held_dead_root(before: files::FileIdentity, after: files::FileIdentity) -> Result<()> {
    require(
        after.0 == 0
            && before.0 != 0
            && before.1 == 256
            && (
                before.1, before.2, before.3, before.4, before.7, before.8, before.9, before.10,
            ) == (
                after.1, after.2, after.3, after.4, after.7, after.8, after.9, after.10,
            )
            && (after.5, after.6) >= (before.5, before.6),
        "original dead Btrfs root descriptor changed beyond owned kernel retirement",
    )
}
pub fn inventory_delta(
    before: &crate::birth_runtime::Records,
    after: &crate::birth_runtime::Records,
    target: &Value,
) -> Result<()> {
    let path = target["path"]
        .as_str()
        .ok_or_else(|| Error("original removed inventory path".into()))?;
    let mut identity = target
        .as_object()
        .ok_or_else(|| Error("original removed inventory identity".into()))?
        .clone();
    identity.remove("role");
    require(
        before.get(path) == Some(&Value::Object(identity)),
        "original removed root differs from complete before-inventory",
    )?;
    require(
        !before
            .keys()
            .any(|name| name.starts_with(&format!("{path}/"))),
        "original removed root retains nested subvolumes",
    )?;
    let mut expected = before.clone();
    expected.remove(path);
    require(
        after == &expected,
        "kernel inventory changed beyond exactly one original removed root",
    )
}
