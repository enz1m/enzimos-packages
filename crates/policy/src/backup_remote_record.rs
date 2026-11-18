// SPDX-License-Identifier: MIT
//! Closed public remote receipts; none supplies an execution actor.
use crate::{identity, recovery_records as records};
use enzimos_platform::{Result, json, require};
use serde_json::Value;
pub const ROTATION_LIMIT: usize = 2 * 1024 * 1024;
/// The remote repository pinned at its first initialization: its Restic ID
/// and the share configuration it was made with. A share whose repository has
/// another ID is refused. Schema 1 pins came from the SFTP transport, whose
/// host key they bound; such a NAS backup has to be set up again.
pub fn pin(v: &Value) -> Result<()> {
    require(
        !(v["schema"] == 1 || v.get("hosts_sha256").is_some()),
        crate::backup_remote_endpoint::RECONFIGURE,
    )?;
    json::fields(v, "schema repository_id configuration_sha256")?;
    require(
        v["schema"].as_u64() == Some(2),
        "remote repository pin schema",
    )?;
    for key in ["repository_id", "configuration_sha256"] {
        identity::sha(records::text(v, key)?)?;
    }
    Ok(())
}
/// A new pin for the repository `id` made with the configuration `binding`.
///
/// # Errors
/// `id` or the binding's configuration digest is not a full SHA-256 hex ID.
pub fn new_pin(id: &Value, binding: &Value) -> Result<Value> {
    let pin = serde_json::json!({"schema":2,"repository_id":id,"configuration_sha256":binding["configuration_sha256"]});
    self::pin(&pin)?;
    Ok(pin)
}
pub fn initialization(v: &Value) -> Result<()> {
    json::fields(v, "schema configuration_sha256 created_boot")?;
    require(
        v["schema"].as_u64() == Some(1),
        "remote initialization schema",
    )?;
    identity::sha(records::text(v, "configuration_sha256")?)?;
    identity::uuid(records::text(v, "created_boot")?).map(|_| ())
}
pub fn copied(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema source_snapshot remote_snapshot repository_id boot_id",
    )?;
    require(
        v["schema"].as_u64() == Some(1),
        "remote copy receipt schema",
    )?;
    for key in ["source_snapshot", "remote_snapshot", "repository_id"] {
        identity::sha(records::text(v, key)?)?;
    }
    identity::uuid(records::text(v, "boot_id")?).map(|_| ())
}
pub fn rotation(v: &Value) -> Result<()> {
    let metadata = v["schema"].as_u64() == Some(2);
    json::fields(
        v,
        if metadata {
            "schema phase created_boot old_identity new_identity old_config_sha256 new_config_sha256 old_password_identity new_password_identity points credential_identity_kind"
        } else {
            "schema phase created_boot old_identity new_identity old_config_sha256 new_config_sha256 old_password_sha256 new_password_sha256 points"
        },
    )?;
    require(
        matches!(v["schema"].as_u64(), Some(1 | 2)),
        "remote rotation schema",
    )?;
    if metadata {
        require(
            v["credential_identity_kind"] == "metadata-v2",
            "remote rotation credential identity kind",
        )?;
        for key in ["old_password_identity", "new_password_identity"] {
            crate::backup_rotation_record::credential_identity(&v[key])?;
        }
        require(
            v["old_password_identity"] != v["new_password_identity"],
            "remote rotation credential aliases old material",
        )?;
        for key in ["filesystem_uuid", "root_uuid", "root_id", "root_path"] {
            require(
                v["old_password_identity"][key] == v["new_password_identity"][key],
                "remote rotation credentials cross configured root",
            )?;
        }
        require(
            v["old_password_identity"]["inode"] != v["new_password_identity"]["inode"],
            "remote rotation credentials alias inode",
        )?;
    } else {
        for key in ["old_password_sha256", "new_password_sha256"] {
            identity::sha(records::text(v, key)?)?;
        }
        require(
            v["old_password_sha256"] != v["new_password_sha256"],
            "remote rotation aliases old password digest",
        )?;
    }
    let phase = records::text(v, "phase")?;
    require(
        matches!(
            phase,
            "initializing"
                | "copying"
                | "copied"
                | "switching"
                | "switched"
                | "complete"
                | "abandoned"
        ) || (metadata && phase == "discarding"),
        "remote rotation phase",
    )?;
    identity::uuid(records::text(v, "created_boot")?)?;
    pin(&v["old_identity"])?;
    for key in ["old_config_sha256", "new_config_sha256"] {
        identity::sha(records::text(v, key)?)?;
    }
    require(
        v["old_config_sha256"] != v["new_config_sha256"],
        "remote rotation aliases old configuration",
    )?;
    require(
        v["old_identity"]["configuration_sha256"] == v["old_config_sha256"],
        "remote rotation original pin configuration differs",
    )?;
    if !v["new_identity"].is_null() {
        pin(&v["new_identity"])?;
        require(
            v["new_identity"]["configuration_sha256"] == v["new_config_sha256"]
                && v["new_identity"]["repository_id"] != v["old_identity"]["repository_id"],
            "remote rotation new pin must bind a separate repository",
        )?;
    }
    if let Some(points) = v["points"].as_object() {
        require(
            (1..=10000).contains(&points.len()),
            "remote rotation point mapping bound",
        )?;
        let mut targets = std::collections::BTreeSet::new();
        for (source, target) in points {
            identity::sha(source)?;
            let target = target.as_str().unwrap_or("");
            identity::sha(target)?;
            require(targets.insert(target), "remote rotation duplicate target")?;
        }
    } else {
        require(
            v["points"].is_null(),
            "remote rotation copy mapping required",
        )?;
    }
    require(
        !matches!(
            phase,
            "copied" | "switching" | "switched" | "discarding" | "complete"
        ) || (!v["new_identity"].is_null() && !v["points"].is_null()),
        "remote rotation advanced without authenticated new identity/copies",
    )
}
