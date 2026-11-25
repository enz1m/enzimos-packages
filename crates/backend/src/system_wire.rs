// SPDX-License-Identifier: MIT
//! Closed System1 wire contracts; caller identity never comes from JSON.
use enzimos_platform::{Error, Result, json, require};
use serde_json::Value;
/// Well-known bus name of the system service.
pub const BUS: &str = "org.enzimos.System1";
/// Object path of the system service.
pub const PATH: &str = "/org/enzimos/System1";
pub(crate) const MAX_REQUEST: usize = 4096;
/// Operation names in their stable wire order.
pub const OPERATIONS: [&str; 31] = enzimos_platform::system_contract::OPERATIONS;
pub(crate) const QUERIES: [&str; 10] = [
    "system",
    "history",
    "backups",
    "network-trust",
    "power-policy",
    "snapshots",
    "backup-points",
    "backup-candidates",
    "memory-policy",
    "tmp-storage",
];
fn error(code: &str) -> Error {
    Error(code.into())
}
pub(crate) fn fields(body: &Value, keys: &str) -> Result<()> {
    json::fields(body, keys).map_err(|_| error("request-fields"))
}
pub(crate) fn text<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    body[key].as_str().ok_or_else(|| error("job-plan-invalid"))
}
pub(crate) fn hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn id(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub(crate) fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn nonfinite(bytes: &[u8]) -> bool {
    let (mut quoted, mut escaped, mut i) = (false, false, 0);
    while i < bytes.len() {
        let b = bytes[i];
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            quoted = true;
            i += 1;
            continue;
        }
        if b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            if matches!(&bytes[start..i], b"NaN" | b"Infinity") {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}
/// Decode one strict JSON request of at most `limit` bytes.
///
/// # Errors
///
/// Fails with a public code when the request is too large, malformed, has duplicate fields or
/// non-finite numbers.
pub fn decode(bytes: &[u8], limit: usize) -> Result<Value> {
    require(bytes.len() <= limit, "request-bound")?;
    require(!nonfinite(bytes), "nonfinite-value")?;
    json::decode_classified(bytes, limit).map_err(|e| {
        error(match e {
            json::DecodeFailure::Bound => "request-bound",
            json::DecodeFailure::Duplicate => "duplicate-field",
            json::DecodeFailure::Malformed => "malformed-request",
        })
    })
}
/// Require a unique system bus sender name (`:N.M`).
///
/// # Errors
///
/// Fails for well-known or malformed names.
pub fn sender(value: &str) -> Result<()> {
    let valid = value
        .strip_prefix(':')
        .and_then(|s| s.split_once('.'))
        .is_some_and(|(a, b)| {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|n| n.is_ascii_digit())
                && b.bytes().all(|n| n.is_ascii_digit())
        });
    require(
        value.len() <= 255 && valid,
        "unique-system-bus-sender-required",
    )
}
/// Admit a method call by path, interface, member, signature and reply expectation.
///
/// # Errors
///
/// Fails for unknown methods, a wrong signature, a no-reply call, or a non-unique sender.
pub fn call(
    path: &str,
    interface: &str,
    member: &str,
    signature: &str,
    no_reply: bool,
    peer: &str,
) -> Result<()> {
    let expected = match member {
        "GetCapabilities" => "",
        "Execute"
        | "Job"
        | "Operation"
        | "Query"
        | "InspectBackgroundBroker"
        | "BackupSetupControl"
        | "BackupRecoveryExport"
        | "BackupRecoveryConfirm"
        | "BackupRemoteShare" => "s",
        "BackupSetupInput" | "LoginAppearance" => "sh",
        "BackupRemoteShareSetup" => "sah",
        _ => return Err(error("wire-method-unavailable")),
    };
    require(path == PATH && interface == BUS, "wire-method-unavailable")?;
    require(signature == expected, "wire-signature")?;
    require(!no_reply, "wire-reply-required")?;
    sender(peer)
}
/// Decode an `Execute` request body.
///
/// # Errors
///
/// Fails when the body is malformed, has unexpected fields or version, or names an unavailable
/// operation.
pub fn execute(bytes: &[u8]) -> Result<Value> {
    let body = decode(bytes, MAX_REQUEST)?;
    fields(&body, "schema operation allow_interaction")?;
    require(body["schema"].as_u64() == Some(1), "request-version")?;
    require(
        body["operation"] == "home-history-create",
        "operation-unavailable",
    )?;
    require(body["allow_interaction"].is_boolean(), "interaction-type")?;
    Ok(body)
}
pub(crate) fn job(bytes: &[u8]) -> Result<Value> {
    let body = decode(bytes, MAX_REQUEST)?;
    fields(
        &body,
        "schema operation action request_id allow_interaction",
    )?;
    require(body["schema"].as_u64() == Some(2), "request-version")?;
    require(
        body["operation"] == "home-history-create"
            && matches!(body["action"].as_str(), Some("submit" | "status")),
        "operation-unavailable",
    )?;
    require(
        body["request_id"].as_str().is_some_and(|s| hex(s, 32)),
        "job-request-invalid",
    )?;
    require(body["allow_interaction"].is_boolean(), "interaction-type")?;
    Ok(body)
}
pub(crate) fn query(bytes: &[u8]) -> Result<Value> {
    let body = decode(bytes, MAX_REQUEST)?;
    fields(&body, "schema query")?;
    require(body["schema"].as_u64() == Some(1), "request-version")?;
    require(
        body["query"].as_str().is_some_and(|s| QUERIES.contains(&s)),
        "operation-unavailable",
    )?;
    Ok(body)
}
/// `BackupRecoveryExport` / `BackupRecoveryConfirm` request. Confirmation names
/// the export ticket and the fixed statement the user made.
pub(crate) fn recovery(bytes: &[u8], confirm: bool) -> Result<Value> {
    let body = decode(bytes, 1024)?;
    fields(
        &body,
        if confirm {
            "schema allow_interaction ticket assertion"
        } else {
            "schema allow_interaction"
        },
    )?;
    require(body["schema"].as_u64() == Some(1), "request-version")?;
    require(body["allow_interaction"].is_boolean(), "interaction-type")?;
    require(
        !confirm
            || body["ticket"].as_str().is_some_and(|s| hex(s, 64))
                && body["assertion"] == "saved-outside-this-computer",
        "job-plan-invalid",
    )?;
    Ok(body)
}
/// `BackupRemoteShare` (`test` or `remove`) or `BackupRemoteShareSetup`
/// (`share`: the NAS share fields; the passwords come as sealed descriptors).
#[cfg(feature = "update-worker")]
pub(crate) fn remote_share(bytes: &[u8], setup: bool) -> Result<Value> {
    let body = decode(bytes, 2048)?;
    fields(
        &body,
        if setup {
            "schema allow_interaction share"
        } else {
            "schema allow_interaction action"
        },
    )?;
    require(body["schema"].as_u64() == Some(1), "request-version")?;
    require(body["allow_interaction"].is_boolean(), "interaction-type")?;
    if setup {
        enzimos_policy::backup_restic_runtime::remote_share::selection(&body["share"])
            .map_err(|_| error("remote-share-invalid"))?;
    } else {
        require(
            matches!(body["action"].as_str(), Some("test" | "remove")),
            "operation-unavailable",
        )?;
    }
    Ok(body)
}
/// Decode a background-broker inspection request.
///
/// # Errors
///
/// Fails when the body is malformed or has unexpected fields or version.
pub fn background(bytes: &[u8]) -> Result<()> {
    let body = decode(bytes, 128)?;
    fields(&body, "schema")?;
    require(body["schema"].as_u64() == Some(1), "request-version")
}

/// A decoded job request for one operation and action.
#[derive(Clone)]
pub struct Operation {
    body: Value,
    /// Request schema version.
    pub schema: u64,
    /// Operation name from [`OPERATIONS`].
    pub operation: &'static str,
    /// Action: `plan`, `submit`, `status` or `cancel`.
    pub action: &'static str,
}
impl Operation {
    /// Decode a job request.
    ///
    /// # Errors
    ///
    /// Fails when the body is malformed, has unexpected fields, names an unavailable operation or
    /// action, or carries an invalid selection.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let body = decode(bytes, MAX_REQUEST)?;
        let schema = body["schema"]
            .as_u64()
            .filter(|n| (3..3 + OPERATIONS.len() as u64).contains(n))
            .ok_or_else(|| error("request-version"))?;
        let selected = !matches!(schema, 3 | 5);
        fields(
            &body,
            if selected {
                "schema operation action request_id plan_sha256 allow_interaction selection"
            } else {
                "schema operation action request_id plan_sha256 allow_interaction"
            },
        )?;
        let operation = OPERATIONS[(schema - 3) as usize];
        require(body["operation"] == operation, "operation-unavailable")?;
        let action = match body["action"].as_str() {
            Some("plan") => "plan",
            Some("submit") => "submit",
            Some("status") => "status",
            Some("cancel") => "cancel",
            _ => return Err(error("operation-unavailable")),
        };
        if selected {
            if action == "plan" {
                super::system_selection::validate(schema, &body["selection"])?;
            } else {
                require(body["selection"].is_null(), "job-plan-invalid")?;
            }
        }
        require(
            body["request_id"].as_str().is_some_and(|s| hex(s, 32)),
            "job-request-invalid",
        )?;
        require(body["allow_interaction"].is_boolean(), "interaction-type")?;
        require(
            if matches!(action, "plan" | "status") {
                body["plan_sha256"].is_null()
            } else {
                body["plan_sha256"].as_str().is_some_and(|s| hex(s, 64))
            },
            "job-plan-invalid",
        )?;
        Ok(Self {
            body,
            schema,
            operation,
            action,
        })
    }
    /// The decoded request body.
    pub fn body(&self) -> &Value {
        &self.body
    }
    /// Polkit action and whether interactive authorization is allowed.
    ///
    /// # Panics
    ///
    /// Never for a request built by this module, which requires a Boolean
    /// `allow_interaction` on every submit.
    pub fn authorization(&self) -> (String, bool) {
        if self.action == "submit" {
            (
                format!("org.enzimos.system.{}", self.operation),
                self.body["allow_interaction"]
                    .as_bool()
                    .expect("submit requests are parsed with a Boolean allow_interaction"),
            )
        } else {
            ("org.enzimos.system.query".into(), false)
        }
    }
}

/// Public failure code for `e`, hiding any message that is not a stable public code.
pub fn public_failure(e: &Error) -> &'static str {
    const CODES: &[&str] = &[
        "request-bound",
        "duplicate-field",
        "nonfinite-value",
        "malformed-request",
        "request-fields",
        "request-version",
        "operation-unavailable",
        "interaction-type",
        "unique-system-bus-sender-required",
        "sender-disconnected",
        "not-authorized",
        "background-broker-unavailable",
        "service-busy",
        "login-appearance-invalid",
        "login-appearance-public-consent-required",
        "login-image-invalid",
        "login-image-input-refused",
        "login-scene-untrusted",
        "backend-result-unknown-do-not-retry-automatically",
        "wire-method-unavailable",
        "wire-signature",
        "wire-reply-required",
        "job-result-uncertain-no-replay",
        "job-store-busy",
        "job-capacity",
        "job-not-found",
        "job-owner-mismatch",
        "job-store-needs-review",
        "job-storage-unsafe",
        "job-request-invalid",
        "job-plan-changed",
        "job-plan-invalid",
        "job-transition-refused",
        "backup-destination-absent",
        "backup-destination-not-mounted",
        "backup-destination-busy",
        "backup-destination-not-configured",
    ];
    let codes = CODES.iter();
    #[cfg(feature = "update-worker")]
    let codes = {
        use enzimos_policy::backup_restic_runtime::remote_share;
        codes
            .chain(remote_share::CODES.iter())
            .chain(std::iter::once(&remote_share::ROTATION_UNFINISHED))
    };
    codes
        .copied()
        .find(|code| *code == e.0)
        .unwrap_or("internal-result-unknown-do-not-retry-automatically")
}
