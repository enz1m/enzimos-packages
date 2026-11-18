// SPDX-License-Identifier: MIT
//! Future home limits change without invoking cleanup or touching snapshots.
use crate::{
    home_history_source::{self, Source},
    operation,
};
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
const KEYS: [(&str, &str); 6] = [
    ("hourly", "TIMELINE_LIMIT_HOURLY"),
    ("daily", "TIMELINE_LIMIT_DAILY"),
    ("weekly", "TIMELINE_LIMIT_WEEKLY"),
    ("monthly", "TIMELINE_LIMIT_MONTHLY"),
    ("yearly", "TIMELINE_LIMIT_YEARLY"),
    ("manual", "NUMBER_LIMIT"),
];
pub fn validate(policy: &Value) -> Result<()> {
    json::fields(policy, "hourly daily weekly monthly yearly manual")?;
    require(
        policy
            .as_object()
            .unwrap()
            .values()
            .all(|n| n.as_u64().is_some_and(|n| n <= 1000)),
        "home retention bounds",
    )?;
    let timeline = KEYS
        .iter()
        .filter(|(k, _)| *k != "manual")
        .map(|(k, _)| policy[*k].as_u64().unwrap())
        .sum::<u64>();
    require(
        policy["manual"].as_u64().unwrap() > 0 && (1..=1000).contains(&timeline),
        "home retention timeline or manual bounds",
    )
}
pub fn policy(bytes: &[u8]) -> Result<Value> {
    home_history_source::configuration(bytes)?;
    let mut policy = serde_json::Map::new();
    for line in std::str::from_utf8(bytes)
        .map_err(|_| Error("home retention encoding".into()))?
        .lines()
    {
        let Some((key, contents)) = line.trim().split_once('=') else {
            continue;
        };
        if let Some((label, _)) = KEYS.iter().find(|(_, expected)| *expected == key) {
            let contents = &contents[1..contents.len() - 1];
            require(
                !contents.is_empty()
                    && contents.len() <= 5
                    && contents.bytes().all(|n| n.is_ascii_digit()),
                "home retention decimal limit unavailable",
            )?;
            let number: u64 = contents
                .parse()
                .map_err(|_| Error("home retention decimal limit".into()))?;
            policy.insert((*label).into(), value!(number));
        }
    }
    let policy = Value::Object(policy);
    json::fields(&policy, "hourly daily weekly monthly yearly manual")?;
    Ok(policy)
}
pub fn replacement(bytes: &[u8], next: &Value) -> Result<Vec<u8>> {
    validate(next)?;
    policy(bytes)?;
    let before = std::str::from_utf8(bytes).map_err(|_| Error("home retention encoding".into()))?;
    let mut out = String::with_capacity(before.len() + 64);
    let mut important = false;
    for line in before.split_inclusive('\n') {
        let key = line.trim().split_once('=').map(|(key, _)| key);
        let chosen = KEYS
            .iter()
            .find(|(_, expected)| Some(*expected) == key)
            .map(|(label, _)| *label)
            .or_else(|| {
                if key == Some("NUMBER_LIMIT_IMPORTANT") {
                    important = true;
                    Some("manual")
                } else {
                    None
                }
            });
        if let Some(label) = chosen {
            let prefix = &line[..line.len() - line.trim_start().len()];
            let end = if line.ends_with("\r\n") {
                "\r\n"
            } else if line.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}{}=\"{}\"{end}",
                key.unwrap(),
                next[label].as_u64().unwrap()
            ));
        } else {
            out.push_str(line);
        }
    }
    if !important {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!(
            "NUMBER_LIMIT_IMPORTANT=\"{}\"\n",
            next["manual"].as_u64().unwrap()
        ));
    }
    home_history_source::configuration(out.as_bytes())?;
    require(
        policy(out.as_bytes())? == *next,
        "home retention rendered outcome differs",
    )?;
    Ok(out.into_bytes())
}
pub fn observation() -> Result<Value> {
    let source = Source::observe()?;
    let policy = policy(source.configuration_bytes()?)?;
    Ok(
        value!({"source":source.evidence()?,"configuration_parent":source.configuration_context()?,"policy":policy}),
    )
}
pub fn set<F: FnMut() -> Result<()>>(
    selection: &Value,
    expected: &Value,
    mut authorize: F,
) -> Result<Value> {
    validate(selection)?;
    let lock = operation::lock()?;
    let mut source = Source::observe()?;
    let before = value!({"source":source.evidence()?,"configuration_parent":source.configuration_context()?,"policy":policy(source.configuration_bytes()?)?});
    require(before == *expected, "home retention plan changed")?;
    let bytes = replacement(source.configuration_bytes()?, selection)?;
    authorize()?;
    source.recheck()?;
    lock.recheck()?;
    source.publish_configuration(&bytes)?;
    require(
        policy(source.configuration_bytes()?)? == *selection,
        "home retention outcome differs; no automatic replay",
    )?;
    source.recheck()?;
    lock.recheck()?;
    Ok(value!({"policy":selection,"existing_history_removed":false,"cleanup_started":false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    const BEFORE: &str = "# retained comment\nSUBVOLUME=\"/home\"\nFSTYPE=\"btrfs\"\nTIMELINE_CLEANUP=\"yes\"\nALLOW_USERS=\"\"\nTIMELINE_LIMIT_HOURLY=\"10\"\nTIMELINE_LIMIT_DAILY=\"10\"\nTIMELINE_LIMIT_WEEKLY=\"0\"\nTIMELINE_LIMIT_MONTHLY=\"10\"\nTIMELINE_LIMIT_YEARLY=\"10\"\nNUMBER_LIMIT=\"50\"\nNUMBER_LIMIT_IMPORTANT=\"10\"\n";
    fn next() -> Value {
        value!({"hourly":24,"daily":7,"weekly":4,"monthly":12,"yearly":1,"manual":20})
    }
    #[test]
    fn risk_of_excessive_or_empty_retention_and_ambiguous_configuration_is_refused() {
        for (key, value) in [
            ("manual", value!(0)),
            ("hourly", value!(1001)),
            ("daily", value!(true)),
        ] {
            let mut wrong = next();
            wrong[key] = value;
            assert!(replacement(BEFORE.as_bytes(), &wrong).is_err());
        }
        let empty = value!({"hourly":0,"daily":0,"weekly":0,"monthly":0,"yearly":0,"manual":1});
        assert!(validate(&empty).is_err());
        assert!(policy(format!("{BEFORE}NUMBER_LIMIT=\"50\"\n").as_bytes()).is_err());
        assert!(
            policy(
                BEFORE
                    .replace("NUMBER_LIMIT=\"50\"", "NUMBER_LIMIT=\"0-50\"")
                    .as_bytes()
            )
            .is_err()
        );
    }
}
