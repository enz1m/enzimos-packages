// SPDX-License-Identifier: MIT
use enzimos_platform::{Result, require};
pub fn safe_id(s: &str) -> Result<&str> {
    require(
        !s.is_empty()
            && s.len() <= 81
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid generation identifier",
    )?;
    Ok(s)
}
pub fn uuid(s: &str) -> Result<&str> {
    require(
        s.len() == 36
            && s.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            }),
        "invalid UUID",
    )?;
    Ok(s)
}
pub fn sha(s: &str) -> Result<&str> {
    require(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA256",
    )?;
    Ok(s)
}
