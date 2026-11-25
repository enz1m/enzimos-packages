// SPDX-License-Identifier: MIT
//! Actual immutable worker output. Data alone cannot close a worker or publish an export.
use enzimos_platform::{Error, Result, json, memfile, require};
use serde_json::{Value, json as value};
use std::fs::File;
const MAGIC: &[u8; 8] = b"EZFILE01";
const HEADER_LIMIT: usize = 65536;
pub(crate) const LIMIT: usize =
    crate::backup_selective_result::MAX_FILE as usize + HEADER_LIMIT + 12;
pub(crate) fn decode<'a>(bytes: &'a [u8], request: &Value) -> Result<(Value, &'a [u8])> {
    // Separate binary framing preserves a zero-byte selected file without relaxing
    // the nonempty sealed-request contract or treating JSON as execution authority.
    require(
        bytes.len() >= 12 && bytes.len() <= LIMIT && &bytes[..8] == MAGIC,
        "selected output framing or bound",
    )?;
    let size = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| enzimos_platform::Error("value out of range".into()))?,
    ) as usize;
    require(
        (1..=HEADER_LIMIT).contains(&size) && size <= bytes.len() - 12,
        "selected output header bound",
    )?;
    let header = json::decode(&bytes[12..12 + size], HEADER_LIMIT)?;
    json::fields(
        &header,
        "schema kind request_sha256 snapshot file content_sha256 worker_scope_closed export_complete live_home_written metadata_restored per_user_authorized",
    )?;
    let selection = &request["context"]["selection"];
    let kind = crate::backup_selective_request::Kind::parse(&request["kind"])?;
    json::fields(
        &header["file"],
        if kind == crate::backup_selective_request::Kind::Tree {
            "path size node_sha256 entries content_bytes"
        } else {
            "path size node_sha256"
        },
    )?;
    if kind == crate::backup_selective_request::Kind::Tree {
        require(
            header["file"]["entries"]
                .as_u64()
                .is_some_and(|n| (1..=crate::backup_tree_result::MAX_ENTRIES as u64).contains(&n))
                && header["file"]["content_bytes"]
                    .as_u64()
                    .is_some_and(|n| n <= crate::backup_selective_result::MAX_FILE),
            "tree output count/content bounds",
        )?;
    }
    let data = &bytes[12 + size..];
    require(
        header["schema"] == 1
            && header["kind"]
                == if kind == crate::backup_selective_request::Kind::Tree {
                    "selective-tree-observed"
                } else {
                    "selective-file-observed"
                }
            && header["request_sha256"] == json::fingerprint(request)?
            && header["snapshot"] == selection["snapshot"]
            && header["file"]["path"] == selection["path"]
            && header["file"]["size"].as_u64() == Some(data.len() as u64)
            && data.len() <= crate::backup_selective_result::MAX_FILE as usize
            && header["content_sha256"] == json::sha256(data)
            && [
                "worker_scope_closed",
                "export_complete",
                "live_home_written",
                "metadata_restored",
                "per_user_authorized",
            ]
            .iter()
            .all(|key| header[*key] == false),
        "selected output differs from original request or claims completion",
    )?;
    crate::identity::sha(
        header["file"]["node_sha256"]
            .as_str()
            .ok_or_else(|| Error("selected node digest required".into()))?,
    )?;
    Ok((header, data))
}
pub struct Observed {
    output: File,
    digest: String,
    request: Value,
}
impl Observed {
    // Only the actual fixed runtime seals this after successful scoped metadata
    // queries and exact bounded dump. Original worker closure remains with Root.
    pub(crate) fn seal(request: &Value, details: &Value, data: &[u8]) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let kind = crate::backup_selective_request::Kind::parse(&request["kind"])?;
        let header = value!({"schema":1,"kind":if kind==crate::backup_selective_request::Kind::Tree {"selective-tree-observed"}else{"selective-file-observed"},
            "request_sha256":json::fingerprint(request)?,"snapshot":request["context"]["selection"]["snapshot"],
            "file":details,"content_sha256":json::sha256(data),"worker_scope_closed":false,
            "export_complete":false,"live_home_written":false,"metadata_restored":false,"per_user_authorized":false});
        let bytes = encode(&header, data)?;
        decode(&bytes, request)?;
        let this = Self {
            output: memfile::sealed("selective-file-observed", &bytes)?,
            digest: json::sha256(&bytes),
            request: request.clone(),
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        let bytes = memfile::read_sealed(&self.output, LIMIT, 0)?;
        require(
            json::sha256(&bytes) == self.digest,
            "original selected output changed",
        )?;
        decode(&bytes, &self.request)?;
        Ok(())
    }
    pub(crate) fn require_request(&self, request: &Value) -> Result<()> {
        self.recheck()?;
        require(
            self.request == *request,
            "selected observation belongs to another original request",
        )
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.output)
    }
    pub fn digest(&self) -> Result<&str> {
        self.recheck()?;
        Ok(&self.digest)
    }
    pub fn value(&self) -> Result<Value> {
        self.recheck()?;
        let bytes = memfile::read_sealed(&self.output, LIMIT, 0)?;
        let (header, _) = decode(&bytes, &self.request)?;
        Ok(outcome(&header))
    }
}
pub(crate) fn outcome(header: &Value) -> Value {
    value!({"status":if header["kind"]=="selective-tree-observed" {"selected-tree-observed"}else{"selected-file-observed"},"snapshot":header["snapshot"],
        "file":header["file"],"sha256":header["content_sha256"],"worker_scope_closed":false,
        "export_complete":false,"live_home_written":false,"metadata_restored":false,"per_user_authorized":false})
}
fn encode(header: &Value, data: &[u8]) -> Result<Vec<u8>> {
    let header = json::canonical(header)?;
    require(
        header.len() <= HEADER_LIMIT
            && data.len() <= crate::backup_selective_result::MAX_FILE as usize,
        "selected output bounds",
    )?;
    let mut bytes = Vec::with_capacity(12 + header.len() + data.len());
    bytes.extend(MAGIC);
    bytes.extend((header.len() as u32).to_be_bytes());
    bytes.extend(header);
    bytes.extend(data);
    Ok(bytes)
}
