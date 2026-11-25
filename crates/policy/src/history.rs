// SPDX-License-Identifier: MIT
use enzimos_platform::{Result, json, require};
use serde_json::Value;
pub const HOME_KEYS: &[(&str, &str)] = &[
    ("hourly", "TIMELINE_LIMIT_HOURLY"),
    ("daily", "TIMELINE_LIMIT_DAILY"),
    ("weekly", "TIMELINE_LIMIT_WEEKLY"),
    ("monthly", "TIMELINE_LIMIT_MONTHLY"),
    ("yearly", "TIMELINE_LIMIT_YEARLY"),
    ("manual", "NUMBER_LIMIT"),
];
pub fn validate_home(v: &Value) -> Result<()> {
    json::fields(v, "hourly daily weekly monthly yearly manual")?;
    let mut sum = 0;
    for (label, _) in HOME_KEYS {
        let n = v[label]
            .as_u64()
            .filter(|n| *n <= 1000)
            .ok_or_else(|| enzimos_platform::Error("invalid home retention bounds".into()))?;
        if *label == "manual" {
            require(n >= 1, "manual retention minimum")?;
        } else {
            sum += n;
        }
    }
    require(
        (1..=1000).contains(&sum),
        "empty or excessive timeline retention",
    )
}
pub fn validate_backup(v: &Value) -> Result<()> {
    crate::backup_retention::validate(v)
}
pub fn home_arguments(v: &Value) -> Result<Vec<String>> {
    validate_home(v)?;
    let mut args = vec![
        "--no-dbus".into(),
        "-c".into(),
        "home".into(),
        "set-config".into(),
    ];
    for (label, key) in HOME_KEYS {
        args.push(format!(
            "{key}={}",
            enzimos_platform::json::unsigned(&v[label])?
        ));
    }
    args.push(format!(
        "NUMBER_LIMIT_IMPORTANT={}",
        enzimos_platform::json::unsigned(&v["manual"])?
    ));
    Ok(args)
}
