// SPDX-License-Identifier: MIT
//! Bounded same-real-UID journal metadata; no core, environment or command-line access.
use enzimos_platform::{Error, Result, json, process, require};
use serde_json::{Value, json as value};
use std::time::Duration;
const MESSAGE: &str = "fc2e22bc6ee647b6b90729ab34a250b1";
const LIMIT: usize = 256 * 1024;
fn text(v: &Value, n: usize) -> String {
    use unicode_general_category::{GeneralCategory as C, get_general_category};
    v.as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| {
            *c == ' '
                || !matches!(
                    get_general_category(*c),
                    C::Control
                        | C::Format
                        | C::Surrogate
                        | C::PrivateUse
                        | C::Unassigned
                        | C::LineSeparator
                        | C::ParagraphSeparator
                        | C::SpaceSeparator
                )
        })
        .take(n)
        .collect()
}
pub fn reports(body: &[u8], uid: u32) -> Result<Value> {
    require(body.len() <= LIMIT, "journal response exceeds bound")?;
    let body =
        std::str::from_utf8(body).map_err(|_| Error("invalid journal response text".into()))?;
    let mut reports = Vec::new();
    let uid = uid.to_string();
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = json::decode(line.as_bytes(), LIMIT)?;
        if !row.is_object()
            || row["MESSAGE_ID"].as_str() != Some(MESSAGE)
            || row["COREDUMP_UID"].as_str() != Some(&uid)
        {
            continue;
        }
        let Some(ts) = row["__REALTIME_TIMESTAMP"].as_str() else {
            continue;
        };
        if ts.is_empty() || ts.len() > 20 || !ts.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(micros) = ts.parse::<i64>() else {
            continue;
        };
        let Some(when) = chrono::DateTime::from_timestamp(
            micros / 1_000_000,
            (micros % 1_000_000) as u32 * 1000,
        ) else {
            continue;
        };
        if when.format("%Y").to_string().len() != 4 {
            continue;
        }
        let when = when.to_rfc3339_opts(
            if micros % 1_000_000 == 0 {
                chrono::SecondsFormat::Secs
            } else {
                chrono::SecondsFormat::Micros
            },
            false,
        );
        let unit = if row["COREDUMP_USER_UNIT"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        {
            &row["COREDUMP_USER_UNIT"]
        } else {
            &row["COREDUMP_UNIT"]
        };
        reports.push(value!({"timestamp":when,"executable":text(&row["COREDUMP_EXE"],512),"name":text(&row["COREDUMP_COMM"],128),"signal":text(&row["COREDUMP_SIGNAL_NAME"],32),"pid":text(&row["COREDUMP_PID"],20),"unit":text(unit,128)}));
        if reports.len() == 64 {
            break;
        }
    }
    Ok(value!({"schema":1,"reports":reports,"raw_core_access":false}))
}
pub fn read() -> Result<Value> {
    let uid = enzimos_platform::process_identity::real_uid();
    require(
        uid == enzimos_platform::process_identity::effective_uid(),
        "unprivileged real UID journal query required",
    )?;
    let user = format!("COREDUMP_UID={uid}");
    let message = format!("MESSAGE_ID={MESSAGE}");
    let output = process::run(
        "/usr/bin/journalctl",
        &[
            "--quiet",
            "--no-pager",
            "--output=json",
            "--output-fields=MESSAGE_ID,COREDUMP_UID,COREDUMP_EXE,COREDUMP_COMM,COREDUMP_SIGNAL_NAME,COREDUMP_PID,COREDUMP_USER_UNIT,COREDUMP_UNIT",
            "--since=-1days",
            "-n",
            "64",
            &message,
            &user,
        ],
        &[],
        Duration::from_secs(10),
        LIMIT,
    )?;
    require(output.status.success(), "journal metadata unavailable")?;
    reports(&output.stdout, uid)
}
