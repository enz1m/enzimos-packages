// SPDX-License-Identifier: MIT
//! Authenticated vendor metadata syntax, never export or filesystem authority.
use enzimos_platform::{Error, Result, json, require};
use serde_json::{Value, json as value};
pub(crate) const MAX_FILE: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_METADATA: usize = 1024 * 1024;
pub(crate) fn file_path(path: &str) -> Result<&str> {
    let tail = path
        .strip_prefix("/backup-source/home/")
        .ok_or_else(|| Error("qualified selective home-file path required".into()))?;
    let parts = tail.split('/').collect::<Vec<_>>();
    require(
        path.len() <= 1024
            && parts.len() >= 2
            && parts.iter().enumerate().all(|(i, part)| {
                !part.is_empty()
                    && !matches!(*part, "." | ".." | ".snapshots")
                    && part.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || b"_.-".contains(&b) || (i > 0 && b == b' ')
                    })
            }),
        "noncanonical selective home-file path",
    )?;
    Ok(path)
}
pub(crate) fn snapshot_scope(code: Option<i32>, bytes: &[u8], snapshot: &str) -> Result<()> {
    require(
        code == Some(0),
        "restore snapshot observation failed or uncertain",
    )?;
    let rows = json::decode(bytes, crate::backup_points::LIMIT)?;
    let rows = rows
        .as_array()
        .ok_or_else(|| Error("restore snapshot array required".into()))?;
    require(
        rows.len() == 1,
        "one authenticated restore snapshot required",
    )?;
    crate::backup_points::scope(&rows[0], snapshot)
}
pub(crate) fn metadata(
    code: Option<i32>,
    bytes: &[u8],
    snapshot: &str,
    path: &str,
) -> Result<Value> {
    require(
        code == Some(0) && bytes.len() <= MAX_METADATA,
        "selective listing failed, uncertain or bounded out",
    )?;
    crate::identity::sha(snapshot)?;
    file_path(path)?;
    let mut rows = Vec::new();
    for line in bytes
        .split(|b| matches!(*b, b'\n' | b'\r'))
        .filter(|line| !line.is_empty())
    {
        require(rows.len() < 4, "single-file metadata row bound")?;
        rows.push(json::decode(line, MAX_METADATA)?);
    }
    require(rows.len() == 2, "exact single-file listing required")?;
    fn kind(row: &Value) -> Option<&str> {
        row.get("struct_type")
            .or_else(|| row.get("message_type"))
            .and_then(Value::as_str)
    }
    let headers = rows
        .iter()
        .filter(|row| kind(row) == Some("snapshot"))
        .collect::<Vec<_>>();
    let nodes = rows
        .iter()
        .filter(|row| kind(row) == Some("node"))
        .collect::<Vec<_>>();
    require(
        headers.len() == 1 && headers[0]["id"] == snapshot && nodes.len() == 1,
        "exact selected snapshot and one node required",
    )?;
    let node = nodes[0];
    require(
        node["path"] == path && node["type"] == "file",
        "regular file only; symlink, directory or special export refused",
    )?;
    let size = match node.get("size") {
        None => 0,
        Some(n) => n
            .as_u64()
            .filter(|n| *n <= MAX_FILE)
            .ok_or_else(|| Error("selective file size bound".into()))?,
    };
    Ok(value!({"path":path,"size":size,"node_sha256":json::fingerprint(node)?}))
}
