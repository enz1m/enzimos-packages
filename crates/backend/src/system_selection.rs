// SPDX-License-Identifier: MIT
//! Per-version selection registry preserves the existing System1 API.
use super::system_wire::{hex, id, text, uuid};
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
/// Backup retention tiers (see enzimos_policy::backup_retention).
pub(crate) const RETENTION_TIERS: [&str; 5] = ["last", "daily", "weekly", "monthly", "yearly"];
fn fields(v: &Value, names: &str) -> Result<()> {
    json::fields(v, names).map_err(|_| Error("job-plan-invalid".into()))
}
fn exit(v: &Value) -> bool {
    matches!(v.as_str(), Some("reboot" | "poweroff"))
}
fn rotation(v: &Value) -> bool {
    matches!(v.as_str(), Some("abandon" | "switch" | "discard"))
}
fn image(v: &Value) -> bool {
    v.as_str()
        .and_then(|s| s.strip_prefix("ri-"))
        .is_some_and(|s| hex(s, 64))
}
fn safe(v: &Value, max: usize) -> bool {
    v.as_str().is_some_and(|s| id(s, max))
}
fn sha(v: &Value) -> bool {
    v.as_str().is_some_and(|s| hex(s, 64))
}
fn restore_path(v: &Value) -> bool {
    let Some(s) = v.as_str() else {
        return false;
    };
    let Some(tail) = s.strip_prefix("/backup-source/home/") else {
        return false;
    };
    let rows = tail.split('/').collect::<Vec<_>>();
    s.chars().count() <= 1024
        && rows.len() >= 2
        && rows.iter().enumerate().all(|(i, part)| {
            !part.is_empty()
                && !matches!(*part, "." | ".." | ".snapshots")
                && part.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b"_.-".contains(&b) || (i > 0 && b == b' ')
                })
        })
}
pub(crate) fn validate(schema: u64, v: &Value) -> Result<()> {
    let valid = match schema {
        // backup-create and update-apply take no selection; the server
        // measures everything it plans.
        3 | 5 => v.is_null(),
        4 => {
            fields(v, "birth generation")?;
            safe(&v["birth"], 81) && safe(&v["generation"], 81)
        }
        6 | 7 | 8 | 10 | 11 => {
            fields(
                v,
                match schema {
                    6 => "id grant_sha256",
                    8 => "id review_sha256",
                    11 => "id review_sha256 action",
                    _ => "id",
                },
            )?;
            safe(&v["id"], 81)
                && (schema != 6 || sha(&v["grant_sha256"]))
                && (!matches!(schema, 8 | 11) || sha(&v["review_sha256"]))
                && (schema != 11 || rotation(&v["action"]))
        }
        9 => {
            fields(v, "generation plan_sha256")?;
            safe(&v["generation"], 81) && sha(&v["plan_sha256"])
        }
        12 => {
            fields(v, "root_uuid plan_sha256")?;
            uuid(text(v, "root_uuid")?) && sha(&v["plan_sha256"])
        }
        13 | 14 => {
            fields(v, if schema == 13 { "id image exit" } else { "id" })?;
            text(v, "id")?
                .strip_prefix("root-")
                .is_some_and(|s| hex(s, 32))
                && (schema != 13 || image(&v["image"]) && exit(&v["exit"]))
        }
        15 | 16 => {
            fields(
                v,
                if schema == 16 {
                    "rotation review_sha256 action"
                } else {
                    "rotation"
                },
            )?;
            v["rotation"] == "remote"
                && (schema != 16 || sha(&v["review_sha256"]) && rotation(&v["action"]))
        }
        17 | 18 => {
            fields(
                v,
                if schema == 17 {
                    "id plan_sha256 image flavor exit"
                } else {
                    "id"
                },
            )?;
            safe(&v["id"], 48)
                && (schema != 17
                    || sha(&v["plan_sha256"])
                        && image(&v["image"])
                        && matches!(v["flavor"].as_str(), Some("linux" | "linux-lts"))
                        && exit(&v["exit"]))
        }
        19 | 20 | 21 | 24 | 29 => {
            fields(
                v,
                match schema {
                    20 => "id export uid",
                    21 => "id grant_sha256",
                    _ => "id snapshot path",
                },
            )?;
            safe(&v["id"], 81)
                && match schema {
                    20 => {
                        safe(&v["export"], 81)
                            && v["uid"]
                                .as_u64()
                                .is_some_and(|n| (1000..(1 << 31)).contains(&n))
                    }
                    21 => sha(&v["grant_sha256"]),
                    _ => sha(&v["snapshot"]) && restore_path(&v["path"]),
                }
        }
        22 | 23 => {
            fields(
                v,
                if schema == 22 {
                    "snapshot"
                } else {
                    "id snapshot"
                },
            )?;
            sha(&v["snapshot"]) && (schema != 23 || safe(&v["id"], 81))
        }
        25 => {
            fields(v, "connection trusted")?;
            uuid(text(v, "connection")?) && v["trusted"].is_boolean()
        }
        26 | 27 => {
            fields(v, "enabled")?;
            v["enabled"].is_boolean()
        }
        28 => {
            fields(v, "action risk_acknowledged")?;
            let action = text(v, "action")?;
            matches!(
                action,
                "auto" | "suspend" | "hibernate" | "power-off" | "ignore"
            ) && v["risk_acknowledged"].as_bool() == Some(matches!(action, "suspend" | "ignore"))
        }
        30 => {
            fields(v, "hourly daily weekly monthly yearly manual")?;
            let rows = v.as_object().unwrap();
            rows.values().all(|v| v.as_u64().is_some_and(|n| n <= 1000))
                && v["manual"].as_u64().is_some_and(|n| n > 0)
                && (1..=1000).contains(
                    &rows
                        .iter()
                        .filter(|(k, _)| k.as_str() != "manual")
                        .map(|(_, v)| v.as_u64().unwrap_or(1001))
                        .sum::<u64>(),
                )
        }
        31 => {
            // Mirrors enzimos_policy::backup_retention::validate; this crate is
            // also built without the policy crate.
            fields(v, "automatic last daily weekly monthly yearly")?;
            v["automatic"].is_boolean()
                && RETENTION_TIERS
                    .iter()
                    .all(|tier| v[*tier].is_u64() && v[*tier].as_u64().is_some_and(|n| n <= 1000))
                && v["last"].as_u64().is_some_and(|n| n >= 1)
        }
        32 => {
            fields(v, "mode risk_acknowledged")?;
            let mode = text(v, "mode")?;
            matches!(mode, "balanced" | "responsive" | "off")
                && v["risk_acknowledged"].as_bool() == Some(mode == "off")
        }
        _ => false,
    };
    require(valid, "job-plan-invalid")
}
