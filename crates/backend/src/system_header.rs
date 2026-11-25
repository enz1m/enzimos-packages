// SPDX-License-Identifier: MIT
//! Preserve the original header signature, including structure parentheses.
use enzimos_platform::{Error, Result, require};
// zvariant's parsed Signature merges a top-level argument list and a single
// structure. Read the bounded header's original signature text before comparing
// this closed service contract. The body remains deserialized by zbus.
pub(crate) fn signature(data: &zbus::zvariant::serialized::Data<'_, '_>) -> Result<String> {
    let bytes = data.bytes();
    let bad = || Error("wire-signature".into());
    require(
        bytes.len() >= 16 && matches!(bytes[0], b'l' | b'B'),
        "wire-signature",
    )?;
    let number = |at: usize| -> Result<usize> {
        let row: [u8; 4] = bytes
            .get(at..at + 4)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        Ok(if bytes[0] == b'l' {
            u32::from_le_bytes(row)
        } else {
            u32::from_be_bytes(row)
        } as usize)
    };
    let length = number(12)?;
    require(
        length <= 65536 && length <= bytes.len() - 16,
        "wire-signature",
    )?;
    let end = 16 + length;
    let mut at = 16;
    let mut seen = [false; 256];
    let mut signature = None;
    while at < end {
        at = (at + 7) & !7;
        require(at < end, "wire-signature")?;
        let code = bytes[at] as usize;
        require(code != 0 && !seen[code], "wire-signature")?;
        seen[code] = true;
        if code == 8 {
            require(
                at + 4 < end && bytes[at + 1..at + 4] == [1, b'g', 0],
                "wire-signature",
            )?;
            at += 4;
            require(at < end, "wire-signature")?;
            let n = bytes[at] as usize;
            at += 1;
            require(at + n < end && bytes[at + n] == 0, "wire-signature")?;
            signature = Some(
                std::str::from_utf8(&bytes[at..at + n])
                    .map_err(|_| bad())?
                    .to_owned(),
            );
            at += n + 1;
        } else {
            // D-Bus requires ignoring unfamiliar header fields. Keep parsing
            // their bounded variant with the library, including nested types
            // and any actual descriptor table, without interpreting the value.
            require(at + 1 < end, "wire-signature")?;
            let (_, used) = data
                .slice(at + 1..end)
                .deserialize::<zbus::zvariant::OwnedValue>()
                .map_err(|_| bad())?;
            require(used > 0 && used < end - at, "wire-signature")?;
            at += 1 + used;
        }
    }
    require(at == end, "wire-signature")?;
    Ok(signature.unwrap_or_default())
}
