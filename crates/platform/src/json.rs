// SPDX-License-Identifier: MIT
use crate::{Result, require};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

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
    Bound,
    Duplicate,
    Malformed,
}
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
pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    let text = serde_json::to_string(value)?;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            for u in c.encode_utf16(&mut [0; 2]) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    Ok(out.into_bytes())
}
pub fn fingerprint(value: &Value) -> Result<String> {
    Ok(sha256(&canonical(value)?))
}
pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
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
