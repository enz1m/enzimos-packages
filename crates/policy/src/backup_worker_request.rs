// SPDX-License-Identifier: MIT
//! Closed private native worker records. JSON validation is never execution authority.
use crate::backup_worker_task::Work;
use enzimos_platform::{Error, Result, json, local_restic::Task, require};
use serde_json::Value;
pub(crate) const LIMIT: usize = 65536;
pub(crate) const REQUEST_SCHEMA: u64 = 3;
pub const FRAME_SCHEMA: u64 = 1;
pub fn id(id: &str) -> Result<()> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "fresh native backup worker ID required",
    )
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("native backup record text field required".into()))
}
fn sha(v: &Value, key: &str) -> Result<()> {
    crate::identity::sha(text(v, key)?).map(|_| ())
}
pub fn file(v: &Value) -> Result<()> {
    let a = v
        .as_array()
        .ok_or_else(|| Error("native original file identity required".into()))?;
    require(
        a.len() == 11
            && a.iter().all(|n| n.is_i64() || n.is_u64())
            && [0, 1].iter().all(|i| a[*i].as_u64().is_some_and(|n| n > 0))
            && a[2].is_u64()
            && [4, 6].iter().all(|i| {
                a[*i]
                    .as_i64()
                    .is_some_and(|n| (0..1_000_000_000).contains(&n))
            })
            && [7, 8, 9]
                .iter()
                .all(|i| a[*i].as_u64().is_some_and(|n| n <= u64::from(u32::MAX)))
            && a[10].is_u64(),
        "native original file metadata shape",
    )
}
fn private_root(v: &Value) -> Result<()> {
    file(v)?;
    require(
        v[7].as_u64()
            .is_some_and(|n| n as u32 & libc::S_IFMT == libc::S_IFREG && n & 0o7777 == 0o600)
            && v[8] == 0
            && v[9] == 0
            && v[10] == 1,
        "private original Root file required",
    )
}
pub fn directory(v: &Value) -> Result<()> {
    json::fields(v, "device inode mount mode uid gid")?;
    require(
        ["device", "inode", "mount"]
            .iter()
            .all(|key| v[*key].as_u64().is_some_and(|n| n > 0))
            && v["mode"].as_u64().is_some_and(|n| {
                n <= u64::from(u32::MAX)
                    && n as u32 & libc::S_IFMT == libc::S_IFDIR
                    && n & 0o022 == 0
            })
            && v["uid"] == 0
            && v["gid"] == 0,
        "native protected directory identity required",
    )
}
fn document(v: &Value) -> Result<()> {
    json::fields(v, "identity sha256")?;
    private_root(&v["identity"])?;
    sha(v, "sha256")
}
pub fn request(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema id stage task boot_id caller plan mount root repository header credential reader restic outer configuration consumer_input",
    )?;
    require(
        v["schema"].as_u64() == Some(REQUEST_SCHEMA),
        "native backup worker schema",
    )?;
    id(text(v, "id")?)?;
    crate::identity::uuid(text(v, "boot_id")?)?;
    crate::update_worker_record::process(&v["caller"])?;
    crate::backup_setup_plan::validate(&v["plan"])?;
    require(
        v["boot_id"] == v["plan"]["source"]["boot_id"]
            && v["caller"]["executable_sha256"] == v["plan"]["implementation_sha256"],
        "worker differs from original setup plan boot/image",
    )?;
    let task = Work::parse(text(v, "task")?)?;
    let stage = text(v, "stage")?;
    let adopted = v["plan"]["mode"] == "adopt";
    match stage {
        "adoption-probe" => require(
            adopted && task.input() && v["outer"].is_null() && v["configuration"].is_null(),
            "adoption probe must precede outer/permanent publication",
        )?,
        "adoption-confirm" => require(
            adopted && task.input() && !v["outer"].is_null() && v["configuration"].is_null(),
            "adoption confirmation requires original outer intent only",
        )?,
        "provision" => require(
            !v["outer"].is_null()
                && !v["configuration"].is_null()
                && matches!(
                    task,
                    Work::Single(Task::Initialize | Task::Authenticate | Task::CheckMetadata)
                        | Work::ProvisionInitialize
                        | Work::ProvisionAdopt
                )
                && (!matches!(
                    task,
                    Work::Single(Task::Initialize) | Work::ProvisionInitialize
                ) || !adopted)
                && (!matches!(
                    task,
                    Work::Single(Task::Authenticate) | Work::ProvisionAdopt
                ) || adopted),
            "provision task differs from reviewed mode/publication stage",
        )?,
        _ => return Err(Error("native backup stage unavailable".into())),
    }
    json::fields(
        &v["mount"],
        "mount_id unique_mount_id target filesystem_uuid",
    )?;
    require(
        v["mount"]["target"] == "/backup-repository"
            && v["mount"]["filesystem_uuid"] == v["plan"]["destination"]["filesystem_uuid"]
            && ["mount_id", "unique_mount_id"].iter().all(|key| {
                v["mount"][*key].as_u64().is_some_and(|n| n > 0)
                    && v["mount"][*key] != v["plan"]["source"]["mount"][*key]
            }),
        "worker must borrow exact independently owned destination mount",
    )?;
    directory(&v["root"])?;
    directory(&v["repository"])?;
    require(
        v["root"]["inode"] == 256
            && v["root"]["device"] == v["repository"]["device"]
            && v["root"]["mount"] == v["mount"]["unique_mount_id"]
            && v["repository"]["mount"] == v["root"]["mount"]
            && v["repository"]["inode"] != v["root"]["inode"],
        "worker repository must be original child of owned Btrfs top level",
    )?;
    if adopted {
        crate::backup_repository_header::validate(&v["header"])?;
        require(
            v["header"]["sha256"] == v["plan"]["destination"]["repository"]["configuration_sha256"],
            "worker encrypted header differs from original readonly review",
        )?;
    } else {
        require(
            v["header"].is_null(),
            "initialization cannot adopt an existing encrypted header",
        )?;
    }
    json::fields(&v["credential"], "kind identity")?;
    let credential = &v["credential"]["identity"];
    file(credential)?;
    require(
        credential[2]
            .as_u64()
            .is_some_and(|n| (1..=4096).contains(&n)),
        "worker credential length bound",
    )?;
    if task.input() {
        require(
            v["credential"]["kind"] == "sealed-caller-input"
                && credential[7]
                    .as_u64()
                    .is_some_and(|n| n as u32 & libc::S_IFMT == libc::S_IFREG && n & 0o7077 == 0)
                && credential[8] == v["plan"]["owner_uid"]
                && credential[10] == 0,
            "worker requires original private caller-owned sealed input metadata",
        )?;
        crate::settings_command::validate(&v["reader"])?;
        require(
            v["reader"]["path"] == "/usr/lib/enzimos-backend/enzimos-secret-validator",
            "input reader fixed native role required",
        )?;
    } else {
        require(
            v["credential"]["kind"] == "published-root-credential" && v["reader"].is_null(),
            "stored credential cannot substitute caller-input reader",
        )?;
        private_root(credential)?;
    }
    if !v["consumer_input"].is_null() {
        require(
            task.input(),
            "stored credential cannot substitute a temporary input",
        )?;
        consumer(
            &v["consumer_input"],
            text(v, "id")?,
            enzimos_platform::json::unsigned(&credential[2])?,
        )?;
    }
    crate::settings_command::validate(&v["restic"])?;
    require(
        v["restic"]["path"] == "/usr/bin/restic",
        "fixed original Restic image required",
    )?;
    if !v["outer"].is_null() {
        document(&v["outer"])?;
    }
    if !v["configuration"].is_null() {
        json::fields(&v["configuration"], "identity sha256 value")?;
        private_root(&v["configuration"]["identity"])?;
        sha(&v["configuration"], "sha256")?;
        crate::backup_configuration::validate(&v["configuration"]["value"])?;
        require(
            v["configuration"]["value"]["destination_uuid"] == v["mount"]["filesystem_uuid"],
            "published configuration differs from worker destination",
        )?;
    }
    let mut original_files = std::collections::BTreeSet::new();
    for metadata in [
        Some(credential),
        (!v["header"].is_null()).then_some(&v["header"]["identity"]),
        (!v["consumer_input"].is_null()).then_some(&v["consumer_input"]["identity"]),
        Some(&v["restic"]["inode"]),
        (!v["reader"].is_null()).then_some(&v["reader"]["inode"]),
        (!v["outer"].is_null()).then_some(&v["outer"]["identity"]),
        (!v["configuration"].is_null()).then_some(&v["configuration"]["identity"]),
    ]
    .into_iter()
    .flatten()
    {
        require(
            original_files.insert((
                enzimos_platform::json::unsigned(&metadata[0])?,
                enzimos_platform::json::unsigned(&metadata[1])?,
            )),
            "native backup input/document/image roles alias an inode",
        )?;
    }
    require(
        json::canonical(v)?.len() <= LIMIT,
        "native backup request bound",
    )
}
pub fn consumer(v: &Value, id: &str, length: u64) -> Result<()> {
    self::id(id)?;
    json::fields(v, "name parent directory mount identity")?;
    require(
        v["name"] == format!("backup-auth-input-{id}")
            && v["mount"].as_u64().is_some_and(|n| n > 0),
        "consumer input name/mount differs from fresh attempt",
    )?;
    private_root(&v["identity"])?;
    require(
        v["identity"][2] == length && (1..=4096).contains(&length),
        "consumer input length differs from original sealed input",
    )?;
    for key in ["parent", "directory"] {
        let a = v[key]
            .as_array()
            .ok_or_else(|| Error("private input directory shape required".into()))?;
        require(
            a.len() == 5
                && a.iter().all(Value::is_u64)
                && enzimos_platform::json::unsigned(&a[0])? > 0
                && enzimos_platform::json::unsigned(&a[1])? > 0
                && a[2] == (libc::S_IFDIR | 0o700)
                && a[3] == 0
                && a[4] == 0,
            "private original Root input directory required",
        )?;
    }
    require(
        v["parent"][0] == v["directory"][0]
            && v["parent"][1] != v["directory"][1]
            && v["directory"][0] == v["identity"][0],
        "consumer input directories/file must share original private tmpfs",
    )
}
pub fn executable(v: &Value) -> Result<()> {
    request(v)?;
    require(
        v["task"] != "authenticate-input" || !v["consumer_input"].is_null(),
        "prepared input request has no original consumer descriptor",
    )
}
pub fn descriptors(v: &Value) -> Result<usize> {
    request(v)?;
    Ok(9 + usize::from(!v["outer"].is_null())
        + usize::from(!v["configuration"].is_null())
        + usize::from(!v["consumer_input"].is_null()))
}
pub fn frame(
    v: &Value,
    request: &Value,
    sender: &enzimos_platform::fd_packet::Credentials,
) -> Result<Vec<u32>> {
    executable(request)?;
    json::fields(v, "schema id request_sha256 descriptor_numbers")?;
    require(
        v["schema"].as_u64() == Some(FRAME_SCHEMA)
            && v["id"] == request["id"]
            && v["request_sha256"] == json::fingerprint(request)?
            && sender.uid == 0
            && sender.gid == 0
            && request["caller"]["pid"].as_u64() == Some(u64::from(sender.pid)),
        "native backup frame differs from original Root sender/request",
    )?;
    let rows = v["descriptor_numbers"]
        .as_array()
        .ok_or_else(|| Error("native backup original descriptors missing".into()))?;
    require(
        rows.len() == descriptors(request)?,
        "native backup descriptor count differs from stage",
    )?;
    let mut unique = std::collections::BTreeSet::new();
    rows.iter()
        .map(|row| {
            let n = row
                .as_u64()
                .ok_or_else(|| Error("native backup descriptor number required".into()))?;
            require(
                (3..1_048_576).contains(&n) && unique.insert(n),
                "native backup original descriptors repeated or outside bound",
            )?;
            Ok(n as u32)
        })
        .collect()
}
#[cfg(test)]
#[path = "backup_worker_request_tests.rs"]
pub(crate) mod tests;
