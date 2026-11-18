// SPDX-License-Identifier: MIT
//! System1 backup status preserves the legacy redacted fields and pinned PID1 timer.
use enzimos_platform::{Error, Result, require};
use enzimos_policy::{backup_status::Status, storage_runtime::Guard};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zbus::zvariant::OwnedValue;
const TIMER: &str = "enzimos-backup.timer";
const TIMER_PATH: &str = "/org/freedesktop/systemd1/unit/enzimos_2dbackup_2etimer";

pub(crate) fn query(guard: &Guard) -> Result<Value> {
    let receipts = crate::backup_status_records::Snapshot::observe(guard)?;
    let status = Status::observe(guard)?;
    let enabled = status.schedule_enabled()?;
    let next = if enabled {
        tokio::runtime::Handle::try_current()
            .map_err(|_| Error("backup status timer runtime unavailable".into()))?
            .block_on(next_run())?
    } else {
        None
    };
    let last = match receipts.latest()? {
        Some(receipt) => {
            json!({"time":enzimos_policy::backup_status::timestamp(receipt.seconds,receipt.nanoseconds)?,
            "state":receipt.state,"point":receipt.point})
        }
        None => Value::Null,
    };
    let result = status.report(last, next)?;
    require(
        result["schedule_enabled"] == enabled,
        "backup status schedule changed during query",
    )?;
    receipts.recheck()?;
    status.recheck()?;
    Ok(result)
}
async fn next_run() -> Result<Option<String>> {
    let Ok(manager) = crate::system_manager::Manager::new().await else {
        return Ok(None);
    };
    let Ok(Some(path)) = manager.unit(TIMER).await else {
        return Ok(None);
    };
    require(
        path.as_str() == TIMER_PATH,
        "backup status timer object differs",
    )?;
    let Ok(unit): Result<BTreeMap<String, OwnedValue>> = manager
        .call(
            path.as_str(),
            "org.freedesktop.DBus.Properties",
            "GetAll",
            &("org.freedesktop.systemd1.Unit",),
        )
        .await
    else {
        return Ok(None);
    };
    let active = unit
        .get("ActiveState")
        .and_then(|value| <&str>::try_from(value).ok())
        .ok_or_else(|| Error("backup status timer active state type".into()))?;
    if active != "active" {
        return Ok(None);
    }
    let Ok(timer): Result<BTreeMap<String, OwnedValue>> = manager
        .call(
            path.as_str(),
            "org.freedesktop.DBus.Properties",
            "GetAll",
            &("org.freedesktop.systemd1.Timer",),
        )
        .await
    else {
        return Ok(None);
    };
    let micros = timer
        .get("NextElapseUSecRealtime")
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| Error("backup status timer date type".into()))?;
    let result = timer_date(micros)?;
    manager.recheck().await?;
    Ok(result)
}
fn timer_date(micros: u64) -> Result<Option<String>> {
    if matches!(micros, 0 | u64::MAX) {
        return Ok(None);
    }
    require(
        micros / 1_000_000 < 253402300799,
        "backup status timer date bound",
    )?;
    Ok(Some(enzimos_policy::backup_status::timestamp(
        (micros / 1_000_000) as i64,
        (micros % 1_000_000 * 1000) as i64,
    )?))
}
