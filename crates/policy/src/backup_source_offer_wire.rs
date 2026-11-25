// SPDX-License-Identifier: MIT
//! Bounded readonly-source offer syntax. Validation creates no kernel authority.
use enzimos_platform::{Error, Result, fd_packet, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub(crate) const LIMIT: usize = 65536;
pub(crate) const BASE_FILES: usize = 3;
pub(crate) const CHUNK: usize = fd_packet::MAX_FILES - BASE_FILES;
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| Error("source offer text field".into()))
}
fn nonce(s: &str) -> Result<()> {
    crate::backup_worker_request::id(s)
}
pub(crate) fn targets(request: &Value) -> Result<Vec<String>> {
    let mut targets = request["sources"]
        .as_object()
        .ok_or_else(|| Error("source offer member map".into()))?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    targets.sort();
    Ok(targets)
}
pub(crate) fn request(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema kind id boot_id nonce caller worker input_sha256 sources arguments",
    )?;
    require(
        v["schema"] == 1 && v["kind"] == "readonly-source-offer",
        "closed source offer role",
    )?;
    let id = text(v, "id")?;
    nonce(id)?;
    nonce(text(v, "nonce")?)?;
    crate::identity::uuid(text(v, "boot_id")?)?;
    crate::identity::sha(text(v, "input_sha256")?)?;
    crate::backup_worker_intent::worker(&v["worker"], id)?;
    let caller = &v["caller"];
    json::fields(
        caller,
        "pid start_ticks uid executable executable_sha256 image_epoch",
    )?;
    require(
        caller["pid"]
            .as_u64()
            .is_some_and(|p| (1..=i32::MAX as u64).contains(&p))
            && caller["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && caller["uid"] == 0
            && caller["executable"] == "/usr/lib/enzimos-backend/enzimos-system-backend",
        "original backend source caller shape",
    )?;
    crate::identity::sha(text(caller, "executable_sha256")?)?;
    crate::backup_worker_request::file(&caller["image_epoch"])?;
    let image = &caller["image_epoch"];
    require(
        image[7].as_u64().is_some_and(|mode| {
            mode as u32 & libc::S_IFMT == libc::S_IFREG && mode & 0o7777 == 0o755
        }) && image[8] == 0
            && image[9] == 0
            && image[10] == 1
            && caller["pid"] != v["worker"]["worker"]["pid"],
        "closed separate backend image metadata",
    )?;
    let sources = v["sources"]
        .as_object()
        .ok_or_else(|| Error("source offer member map".into()))?;
    require(
        (4..=34).contains(&sources.len()),
        "bounded source offer count",
    )?;
    let mut mounts = BTreeSet::new();
    for source in sources.values() {
        json::fields(
            source,
            "inode source_mount detached_mount readonly nodev nosuid noexec",
        )?;
        crate::backup_worker_request::file(&source["inode"])?;
        let m = &source["inode"];
        require(
            m[7].as_u64().is_some_and(|mode| {
                mode as u32 & libc::S_IFMT == libc::S_IFDIR && mode & 0o7022 == 0
            }) && m[8] == 0
                && m[9] == 0
                && m[10].as_u64().is_some_and(|n| n > 0)
                && source["source_mount"].as_u64().is_some_and(|n| n > 0)
                && source["detached_mount"].as_u64().is_some_and(|n| n > 0)
                && source["source_mount"] != source["detached_mount"]
                && mounts.insert(enzimos_platform::json::unsigned(&source["detached_mount"])?)
                && ["readonly", "nodev", "nosuid", "noexec"]
                    .iter()
                    .all(|key| source[*key] == true),
            "readonly source offer metadata shape",
        )?;
    }
    let args = v["arguments"]
        .as_array()
        .ok_or_else(|| Error("source offer argument array".into()))?
        .iter()
        .map(|a| {
            a.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error("source offer argument text".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    crate::backup_capture_scope::validate_arguments_for_targets(
        &args,
        &targets(v)?.into_iter().collect(),
    )
}
pub(crate) fn frame(
    v: &Value,
    original: &Value,
    expected_index: usize,
    sender: &fd_packet::Credentials,
) -> Result<Vec<u32>> {
    request(original)?;
    json::fields(
        v,
        "schema kind id nonce request_sha256 index start targets fd_numbers",
    )?;
    let all = targets(original)?;
    let start = expected_index
        .checked_mul(CHUNK)
        .ok_or_else(|| Error("source offer chunk overflow".into()))?;
    require(start < all.len(), "source offer duplicate or excess chunk")?;
    let end = (start + CHUNK).min(all.len());
    require(
        v["schema"] == 1
            && v["kind"] == "readonly-source-chunk"
            && v["id"] == original["id"]
            && v["nonce"] == original["nonce"]
            && v["request_sha256"] == json::sha256(&json::canonical(original)?)
            && v["index"].as_u64() == Some(expected_index as u64)
            && v["start"].as_u64() == Some(start as u64)
            && v["targets"] == serde_json::json!(&all[start..end])
            && u64::from(sender.pid)
                == enzimos_platform::json::unsigned(&original["caller"]["pid"])?
            && sender.uid == 0
            && sender.gid == 0,
        "source offer chunk sender, order or binding mismatch",
    )?;
    let numbers = v["fd_numbers"]
        .as_array()
        .ok_or_else(|| Error("source offer original descriptions".into()))?;
    require(
        numbers.len() == BASE_FILES + end - start && numbers.len() <= fd_packet::MAX_FILES,
        "source offer descriptor count",
    )?;
    let mut seen = BTreeSet::new();
    numbers
        .iter()
        .map(|n| {
            let number = n
                .as_u64()
                .filter(|n| (3..=1_048_576).contains(n))
                .ok_or_else(|| Error("source offer original descriptor number".into()))?
                as u32;
            require(seen.insert(number), "source offer duplicate description")?;
            Ok(number)
        })
        .collect()
}
