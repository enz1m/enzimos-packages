// SPDX-License-Identifier: MIT
//! Strict JSON decoding and the canonical encoding used for digests.
use crate::{Result, require};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt::{self, Write as _};

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate properties")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<Strict>()? {
                    out.push(v.0);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate JSON property"));
                    }
                    out.insert(k, a.next_value::<Strict>()?.0);
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(StrictVisitor)
    }
}

/// Decode one JSON document of at most `limit` bytes, refusing duplicate object keys.
///
/// # Errors
///
/// Fails when the input exceeds `limit`, is malformed, has duplicate keys or trailing data.
pub fn decode(bytes: &[u8], limit: usize) -> Result<Value> {
    require(bytes.len() <= limit, "JSON size limit exceeded")?;
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = Strict::deserialize(&mut d)?.0;
    d.end()?;
    Ok(value)
}

/// Wire dispatchers need refusal classes without receiving parser diagnostics
/// or the input/property text. General callers retain the existing decode API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeFailure {
    /// Input exceeds the byte limit.
    Bound,
    /// An object repeats a key.
    Duplicate,
    /// Input is not one well-formed JSON document.
    Malformed,
}
/// [`decode`] with a refusal class instead of parser diagnostics.
///
/// # Errors
///
/// Returns the [`DecodeFailure`] class of the refusal.
pub fn decode_classified(bytes: &[u8], limit: usize) -> std::result::Result<Value, DecodeFailure> {
    if bytes.len() > limit {
        return Err(DecodeFailure::Bound);
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = Strict::deserialize(&mut d)
        .map_err(|e| {
            if e.to_string().starts_with("duplicate JSON property") {
                DecodeFailure::Duplicate
            } else {
                DecodeFailure::Malformed
            }
        })?
        .0;
    d.end().map_err(|_| DecodeFailure::Malformed)?;
    Ok(value)
}

// Python's previous canonical encoder escapes non-ASCII. Keep existing plan and
// receipt digests stable across the language transition, including surrogate pairs.
/// Compact JSON with sorted object keys and non-ASCII escaped as UTF-16 `\uXXXX`.
///
/// # Errors
///
/// Fails when `value` cannot be serialized.
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let text = serde_json::to_string(value)?;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            for u in c.encode_utf16(&mut [0; 2]) {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{u:04x}");
            }
        }
    }
    Ok(out.into_bytes())
}
/// Lowercase hex SHA-256 of [`canonical`].
///
/// # Errors
///
/// Fails as [`canonical`] does.
pub fn fingerprint(value: &Value) -> Result<String> {
    Ok(sha256(&canonical(value)?))
}
/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn typed<T>(value: Option<T>) -> Result<T> {
    value.ok_or_else(|| crate::Error("unexpected JSON value type".into()))
}
/// String content of `value`.
///
/// # Errors
///
/// Fails when `value` is not a string.
pub fn string(value: &Value) -> Result<&str> {
    typed(value.as_str())
}
/// Unsigned integer content of `value`.
///
/// # Errors
///
/// Fails when `value` is not an unsigned integer that fits `u64`.
pub fn unsigned(value: &Value) -> Result<u64> {
    typed(value.as_u64())
}
/// Signed integer content of `value`.
///
/// # Errors
///
/// Fails when `value` is not an integer that fits `i64`.
pub fn signed(value: &Value) -> Result<i64> {
    typed(value.as_i64())
}
/// Boolean content of `value`.
///
/// # Errors
///
/// Fails when `value` is not a boolean.
pub fn boolean(value: &Value) -> Result<bool> {
    typed(value.as_bool())
}
/// Members of an object `value`.
///
/// # Errors
///
/// Fails when `value` is not an object.
pub fn object(value: &Value) -> Result<&Map<String, Value>> {
    typed(value.as_object())
}
/// Mutable members of an object `value`.
///
/// # Errors
///
/// Fails when `value` is not an object.
pub fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>> {
    typed(value.as_object_mut())
}
/// Elements of an array `value`.
///
/// # Errors
///
/// Fails when `value` is not an array.
pub fn array(value: &Value) -> Result<&Vec<Value>> {
    typed(value.as_array())
}
/// Mutable elements of an array `value`.
///
/// # Errors
///
/// Fails when `value` is not an array.
pub fn array_mut(value: &mut Value) -> Result<&mut Vec<Value>> {
    typed(value.as_array_mut())
}
/// Require `value` to be an object with exactly the space-separated field `names`.
///
/// # Errors
///
/// Fails when `value` is not an object or its keys differ.
pub fn fields(value: &Value, names: &str) -> Result<()> {
    let expected: std::collections::BTreeSet<_> = names.split_whitespace().collect();
    let Some(object) = value.as_object() else {
        return require(false, "expected JSON object");
    };
    require(
        object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == expected,
        "missing or unexpected fields",
    )
}
