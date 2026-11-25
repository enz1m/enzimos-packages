// SPDX-License-Identifier: MIT
//! Bounded libalpm records: empty optional values may add blank separator lines.
use crate::{Error, Result, require};
use std::collections::BTreeMap;

/// Parse one `desc`/`files` record into its `%NAME%` sections and their lines.
///
/// # Errors
/// An empty, oversized or non-UTF-8 record, a control byte, or a malformed or
/// repeated section name.
pub fn parse(bytes: &[u8]) -> Result<BTreeMap<&str, Vec<&str>>> {
    require(
        !bytes.is_empty() && bytes.len() <= 512 * 1024,
        "ALPM record byte bound",
    )?;
    let text = std::str::from_utf8(bytes).map_err(|_| Error("ALPM record encoding".into()))?;
    require(!text.contains(['\r', '\0']), "ALPM record control byte")?;
    let mut lines = text.split('\n').peekable();
    let mut fields = BTreeMap::new();
    while lines.peek().is_some() {
        while lines.peek() == Some(&"") {
            lines.next();
        }
        let Some(name) = lines.next() else { break };
        require(
            name.len() >= 3
                && name.len() <= 128
                && name.starts_with('%')
                && name.ends_with('%')
                && name
                    .bytes()
                    .skip(1)
                    .take(name.len() - 2)
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && fields.len() < 128
                && !fields.contains_key(name),
            "ALPM record section ambiguity",
        )?;
        let mut values = Vec::new();
        while let Some(&line) = lines.peek() {
            if line.is_empty() {
                break;
            }
            values.push(line);
            lines.next();
        }
        fields.insert(name, values);
    }
    require(!fields.is_empty(), "ALPM record has no sections")?;
    Ok(fields)
}
