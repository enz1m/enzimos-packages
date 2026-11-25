// SPDX-License-Identifier: MIT
//! Bounded PE/UKI section reader. Does not extract or execute image content.
use enzimos_platform::{Error, Result, require};
use std::collections::BTreeMap;
fn word(body: &[u8], p: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        body.get(p..p + 2)
            .ok_or_else(|| Error("truncated PE header".into()))?
            .try_into()
            .map_err(|_| enzimos_platform::Error("value out of range".into()))?,
    ))
}
fn dword(body: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        body.get(p..p + 4)
            .ok_or_else(|| Error("truncated PE header".into()))?
            .try_into()
            .map_err(|_| enzimos_platform::Error("value out of range".into()))?,
    ))
}
pub(crate) fn sections(body: &[u8]) -> Result<BTreeMap<String, &[u8]>> {
    require(
        body.len() >= 64 && body.len() <= 256 * 1024 * 1024 && body.starts_with(b"MZ"),
        "UKI DOS header or bound",
    )?;
    let offset = dword(body, 60)? as usize;
    require(
        offset.checked_add(24).is_some_and(|n| n <= body.len())
            && body.get(offset..offset + 4) == Some(b"PE\0\0"),
        "UKI PE header",
    )?;
    let count = word(body, offset + 6)? as usize;
    let optional = word(body, offset + 20)? as usize;
    let start = offset + 24 + optional;
    require(
        (1..=64).contains(&count)
            && start
                .checked_add(count * 40)
                .is_some_and(|n| n <= body.len()),
        "PE section bound",
    )?;
    let mut result = BTreeMap::new();
    for i in 0..count {
        let p = start + i * 40;
        let name = &body[p..p + 8];
        let end = name.iter().position(|b| *b == 0).unwrap_or(8);
        require(
            name[end..].iter().all(|b| *b == 0),
            "invalid PE section name",
        )?;
        let name = std::str::from_utf8(&name[..end])
            .map_err(|_| Error("PE section name encoding".into()))?;
        require(
            !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_graphic())
                && !result.contains_key(name),
            "invalid duplicate PE section",
        )?;
        let size = dword(body, p + 8)? as usize;
        let raw_size = dword(body, p + 16)? as usize;
        let raw_offset = dword(body, p + 20)? as usize;
        require(
            raw_offset
                .checked_add(raw_size)
                .is_some_and(|n| n <= body.len()),
            "PE section range",
        )?;
        if matches!(name, ".linux" | ".initrd" | ".cmdline") {
            require(size <= raw_size, "truncated UKI payload")?;
        }
        result.insert(
            name.to_owned(),
            &body[raw_offset..raw_offset + size.min(raw_size)],
        );
    }
    Ok(result)
}
