// SPDX-License-Identifier: MIT
//! Validation of identifiers, UUIDs and digests used in records.
use enzimos_platform::{Result, require};
/// Require a safe identifier: ASCII alphanumerics, `.`, `_` and `-` within a length bound.
///
/// # Errors
///
/// Fails for any other form.
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
/// Require a lowercase hyphenated UUID.
///
/// # Errors
///
/// Fails for any other form.
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
/// Require a lowercase hex SHA-256.
///
/// # Errors
///
/// Fails for any other form.
pub fn sha(s: &str) -> Result<&str> {
    require(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA256",
    )?;
    Ok(s)
}
