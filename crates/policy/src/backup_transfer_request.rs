// SPDX-License-Identifier: MIT
//! Closed transfer request syntax; never setup, execution or cleanup authority.
use enzimos_platform::{Error, Result, fd_packet::Credentials, json, require};
use serde_json::Value;
use std::collections::BTreeSet;
pub const LIMIT: usize = 65536;
pub const DESCRIPTORS: usize = 11;
pub const ROLES: [&str; 9] = [
    "caller-pidfd",
    "caller-image",
    "root",
    "repository",
    "credential",
    "restic",
    "configuration",
    "pin",
    "operation-lock",
];
/// Descriptor roles of a backup into the NAS share, at the drive roles'
/// positions where the two share a role (caller, Restic, operation lock).
pub const SHARE_ROLES: [&str; 9] = [
    "caller-pidfd",
    "caller-image",
    "root-control",
    "remote-configuration",
    "remote-password",
    "restic",
    "remote-share-password",
    "remote-pin",
    "operation-lock",
];
/// Whether a validated context transfers into the NAS share.
pub fn share(context: &Value) -> bool {
    context["role"] == SHARE_ROLE
}
/// The descriptor roles of a validated context, in send order.
pub fn roles(context: &Value) -> &'static [&'static str; 9] {
    if share(context) { &SHARE_ROLES } else { &ROLES }
}
const SHARE_ROLE: &str = "backup-transfer-share-context";
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("transfer request text field".into()))
}
pub fn context(v: &Value) -> Result<()> {
    if share(v) {
        return share_context(v);
    }
    json::fields(
        v,
        "schema role id boot_id caller source destination pin configuration root_directory repository_directory operation_lock header credential restic input_sha256 arguments source_mounts_admitted transfer_complete worker_kernel_closed cleanup_complete backup_complete",
    )?;
    require(
        v["schema"] == 1 && v["role"] == "backup-transfer-context",
        "closed actual transfer context role",
    )?;
    crate::backup_worker_request::id(text(v, "id")?)?;
    crate::identity::uuid(text(v, "boot_id")?)?;
    for key in [
        "source_mounts_admitted",
        "transfer_complete",
        "worker_kernel_closed",
        "cleanup_complete",
        "backup_complete",
    ] {
        require(
            v[key] == false,
            "transfer request cannot assert admission or completion",
        )?;
    }
    crate::backup_existing_repository_wire::validate(v)?;
    let caller = &v["caller"];
    json::fields(&v["credential"], "inode mount")?;
    crate::backup_worker_request::file(&v["credential"]["inode"])?;
    let credential = &v["credential"]["inode"];
    require(
        credential[7] == (libc::S_IFREG | 0o600)
            && credential[8] == 0
            && credential[9] == 0
            && credential[10] == 1
            && credential[2]
                .as_u64()
                .is_some_and(|n| (1..=4096).contains(&n))
            && v["credential"]["mount"].as_u64().is_some_and(|n| n > 0),
        "original private transfer credential",
    )?;
    crate::identity::sha(text(v, "input_sha256")?)?;
    let mut original_files = BTreeSet::new();
    for inode in [
        &caller["image_epoch"],
        &v["header"]["identity"],
        &v["credential"]["inode"],
        &v["configuration"]["inode"],
        &v["pin"]["inode"],
        &v["restic"]["inode"],
    ] {
        require(
            original_files.insert((inode[0].as_u64().unwrap(), inode[1].as_u64().unwrap())),
            "transfer original file roles alias an inode",
        )?;
    }
    arguments(v)?;
    require(
        v["destination"].is_object() && json::canonical(v)?.len() <= LIMIT,
        "bounded transfer destination/context",
    )
}
/// Flags no request can assert, and the reviewed closed archive arguments.
fn common(v: &Value) -> Result<()> {
    crate::backup_worker_request::id(text(v, "id")?)?;
    crate::identity::uuid(text(v, "boot_id")?)?;
    for key in [
        "source_mounts_admitted",
        "transfer_complete",
        "worker_kernel_closed",
        "cleanup_complete",
        "backup_complete",
    ] {
        require(
            v[key] == false,
            "transfer request cannot assert admission or completion",
        )?;
    }
    crate::identity::sha(text(v, "input_sha256")?)?;
    arguments(v)
}
fn arguments(v: &Value) -> Result<()> {
    let args = v["arguments"]
        .as_array()
        .ok_or_else(|| Error("transfer arguments missing".into()))?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error("transfer argument type".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut start = 6;
    while args.get(start).is_some_and(|s| s == "--exclude") {
        start += 2;
    }
    if args.get(start).is_some_and(|s| s == "--exclude-file") {
        start += 2;
    }
    let targets = args
        .get(start..)
        .ok_or_else(|| Error("transfer arguments incomplete".into()))?
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    enzimos_platform::backup_command::validate(&args, &targets)
}
/// A transfer into the NAS share: the native caller, the live source, the
/// retained share context of that same caller and Restic image, the Root
/// control directory and the held operation lock. No drive role is present.
fn share_context(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema role id boot_id caller source share root_control operation_lock restic input_sha256 arguments source_mounts_admitted transfer_complete worker_kernel_closed cleanup_complete backup_complete",
    )?;
    require(v["schema"] == 1, "closed actual share transfer context")?;
    common(v)?;
    crate::backup_existing_repository_wire::caller(v)?;
    crate::backup_secret_persistence::root_binding(&v["source"])?;
    require(
        v["source"]["boot_id"] == v["boot_id"],
        "transfer source boot changed",
    )?;
    let share = &v["share"];
    let epochs = crate::backup_remote_request::remote(share, &v["source"])?;
    require(
        share["caller"] == v["caller"]
            && share["restic"] == v["restic"]
            && share["boot_id"] == v["boot_id"],
        "share context belongs to another caller, image or boot",
    )?;
    crate::backup_worker_request::directory(&v["root_control"])?;
    require(
        v["root_control"]["mode"] == (libc::S_IFDIR | 0o700)
            && v["root_control"]["uid"] == 0
            && v["root_control"]["gid"] == 0,
        "private Root control directory",
    )?;
    crate::backup_existing_repository_wire::operation_lock(&v["operation_lock"])?;
    crate::backup_existing_repository_wire::restic(&v["restic"])?;
    let mut objects = BTreeSet::new();
    for inode in epochs.iter().chain([
        &v["caller"]["image_epoch"],
        &v["restic"]["inode"],
        &share["pin_epoch"]["epoch"],
        &v["operation_lock"]["inode"],
    ]) {
        require(
            objects.insert((inode[0].as_u64(), inode[1].as_u64())),
            "share transfer original file roles alias an inode",
        )?;
    }
    require(
        json::canonical(v)?.len() <= LIMIT,
        "bounded share transfer context",
    )
}
pub fn request(v: &Value) -> Result<()> {
    json::fields(v, "schema kind id boot_id worker context")?;
    require(
        v["schema"] == 1 && v["kind"] == "captured-backup-transfer",
        "transfer request cannot substitute setup provisioning",
    )?;
    context(&v["context"])?;
    require(
        v["id"] == v["context"]["id"] && v["boot_id"] == v["context"]["boot_id"],
        "original transfer attempt/boot changed",
    )?;
    crate::backup_worker_intent::worker(&v["worker"], text(v, "id")?)?;
    require(
        json::canonical(v)?.len() <= LIMIT,
        "bounded sealed transfer request",
    )
}
pub fn frame(v: &Value, request_value: &Value, sender: &Credentials) -> Result<Vec<u32>> {
    request(request_value)?;
    json::fields(v, "schema kind id request_sha256 descriptor_numbers intent")?;
    require(
        v["schema"] == 1
            && v["kind"] == "captured-backup-transfer"
            && v["id"] == request_value["id"]
            && v["request_sha256"] == json::fingerprint(request_value)?
            && sender.uid == 0
            && sender.gid == 0
            && request_value["context"]["caller"]["pid"] == sender.pid,
        "transfer frame differs from actual original Root sender",
    )?;
    crate::backup_existing_repository_wire::intent(&v["intent"], LIMIT)?;
    let numbers = v["descriptor_numbers"]
        .as_array()
        .ok_or_else(|| Error("transfer original descriptor numbers".into()))?;
    require(
        numbers.len() == DESCRIPTORS,
        "closed transfer descriptor count",
    )?;
    let mut distinct = BTreeSet::new();
    numbers
        .iter()
        .map(|n| {
            let n = n
                .as_u64()
                .ok_or_else(|| Error("transfer descriptor number type".into()))?;
            require(
                (3..1_048_576).contains(&n) && distinct.insert(n),
                "distinct bounded transfer original descriptors",
            )?;
            Ok(n as u32)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BOOT: &str = "00000000-0000-4000-8000-000000000001";
    fn epoch(inode: u64, mode: u32, size: u64) -> Value {
        json!([2049, inode, size, 1, 0, 1, 0, mode, 0, 0, 1])
    }
    fn share_context() -> Value {
        let sha = "a".repeat(64);
        let source = json!({"configuration":{"root_subvol":"enzimos-root","home_subvol":"enzimos-home",
            "authority_subvol":"enzimos-authority","control_subvol":"enzimos-control",
            "filesystem_uuid":"00000000-0000-4000-8000-0000000000aa"},
            "mount":{"mount_id":10,"unique_mount_id":11,"device":"0:40","root":"/enzimos-root",
                "target":"/","fstype":"btrfs"},
            "root":{"path":"enzimos-root","id":256,"uuid":"00000000-0000-4000-8000-0000000000bb",
                "parent_uuid":null},"boot_id":BOOT});
        let caller = json!({"pid":100,"start_ticks":5,"uid":0,
            "executable":"/usr/lib/enzimos-backend/enzimos-system-backend","executable_sha256":sha,
            "image_epoch":epoch(10, libc::S_IFREG | 0o755, 1000)});
        let restic = json!({"path":"/usr/bin/restic","inode":epoch(11, libc::S_IFREG | 0o755, 2000),
            "mount":3,"sha256":sha});
        let configuration = json!({"schema":2,"server":"192.0.2.4","share":"backups",
            "folder":"enzimos/laptop","user":"ann"});
        let configuration_sha256 = "b".repeat(64);
        let inputs = [
            epoch(20, libc::S_IFREG | 0o644, 100),
            epoch(21, libc::S_IFREG | 0o600, 32),
            epoch(22, libc::S_IFREG | 0o600, 12),
        ];
        let metadata =
            |inode: u64, size: u64| json!([2049, inode, size, 1_000_000_000, 1_000_000_000]);
        let share = json!({"schema":1,"role":"remote-repository-context","boot_id":BOOT,
            "inputs":{"configuration":configuration,
                "binding":{"configuration_sha256":configuration_sha256,"credentials":{
                    "/etc/enzimos/backup-remote.password":metadata(21, 32),
                    "/etc/enzimos/backup-remote.share-password":metadata(22, 12)}},
                "original_epochs":inputs,"parent":[2049, 5, libc::S_IFDIR | 0o755, 0, 0],
                "mount":4,"source":source,"credential_bytes_read":false},
            "caller":caller,"restic":restic,
            "pin":{"schema":2,"repository_id":"c".repeat(64),"configuration_sha256":configuration_sha256},
            "pin_epoch":{"epoch":epoch(30, libc::S_IFREG | 0o600, 90),"mount":5,"bytes_sha256":sha},
            "rotation_epoch":null,"remote_identity_authenticated":false,"copy_complete":false,
            "worker_closed":false,"scheduler_enabled":false});
        let targets = ["system", "home", "boot", "inventory"]
            .map(|t| format!("/backup-source/{t}"))
            .into_iter()
            .collect();
        json!({"schema":1,"role":SHARE_ROLE,"id":"d".repeat(32),"boot_id":BOOT,"caller":caller,
            "source":source,"share":share,
            "root_control":{"device":2049,"inode":300,"mount":5,"mode":libc::S_IFDIR | 0o700,"uid":0,"gid":0},
            "operation_lock":{"inode":epoch(40, libc::S_IFREG | 0o600, 0),"mount":6},
            "restic":restic,"input_sha256":sha,
            "arguments":enzimos_platform::backup_command::arguments(&targets).unwrap(),
            "source_mounts_admitted":false,"transfer_complete":false,"worker_kernel_closed":false,
            "cleanup_complete":false,"backup_complete":false})
    }

    #[test]
    fn a_share_context_validates_and_sends_share_roles() {
        let share_context = share_context();
        context(&share_context).unwrap();
        assert!(share(&share_context));
        assert_eq!(roles(&share_context), &SHARE_ROLES);
        let positions = |roles: &[&str; 9], role: &str| roles.iter().position(|r| *r == role);
        for common in ["caller-pidfd", "caller-image", "restic", "operation-lock"] {
            assert_eq!(positions(&ROLES, common), positions(&SHARE_ROLES, common));
        }
        let mut drive = share_context;
        drive["role"] = json!("backup-transfer-context");
        assert_eq!(roles(&drive), &ROLES);
    }
    #[test]
    fn a_share_context_refuses_drive_roles_foreign_actors_and_aliases() {
        let mut with_drive = share_context();
        with_drive["destination"] = json!({});
        assert!(context(&with_drive).is_err());
        let mut foreign_caller = share_context();
        foreign_caller["share"]["caller"]["pid"] = json!(101);
        assert!(context(&foreign_caller).is_err());
        let mut foreign_image = share_context();
        foreign_image["share"]["restic"]["sha256"] = json!("e".repeat(64));
        assert!(context(&foreign_image).is_err());
        let mut alias = share_context();
        alias["share"]["pin_epoch"]["epoch"] = alias["operation_lock"]["inode"].clone();
        alias["share"]["pin_epoch"]["epoch"][2] = json!(90);
        alias["share"]["pin_epoch"]["epoch"][7] = json!(libc::S_IFREG | 0o600);
        assert!(context(&alias).is_err());
        let mut open_control = share_context();
        open_control["root_control"]["mode"] = json!(libc::S_IFDIR | 0o755);
        assert!(context(&open_control).is_err());
        let mut completed = share_context();
        completed["backup_complete"] = json!(true);
        assert!(context(&completed).is_err());
        let mut source = share_context();
        source["share"]["inputs"]["source"]["boot_id"] =
            json!("00000000-0000-4000-8000-000000000002");
        assert!(context(&source).is_err());
    }
}
