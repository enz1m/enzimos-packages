// SPDX-License-Identifier: MIT
//! Initial private credential publication: durable intent, kernel copy, no overwrite.
use crate::{backup_secret_input::Validated, identity, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const LIMIT: usize = 32768;
const JOURNAL: &str = "backup-secret-input.json";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "protected credential publication parent required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn absent(parent: &File, name: &str) -> Result<()> {
    require(
        files::optional_relative(parent, Path::new(name))?.is_none(),
        "existing initial credential/setup state requires inspection; no replay",
    )
}
fn unconfigured(
    parent: &File,
    guard: &Guard,
    context: Option<&crate::backup_setup_context::Prepared<'_, '_, '_, '_>>,
) -> Result<()> {
    for name in [
        "backup.json",
        "backup.password",
        ".backup-password-input",
        ".backup-setup-config",
    ] {
        absent(parent, name)?;
    }
    for name in [
        "backup-destination.json",
        "backup.enabled",
        JOURNAL,
        "backup-setup.json",
    ] {
        absent(guard.control(), name)?;
    }
    if let Some(context) = context {
        context.check_source(guard, None)?;
    } else {
        absent(guard.control(), "backup-initial-setup.json")?;
    }
    Ok(())
}
fn unconfigured_control(
    guard: &Guard,
    context: Option<&crate::backup_setup_context::Prepared<'_, '_, '_, '_>>,
) -> Result<()> {
    for name in [
        "backup-destination.json",
        "backup.enabled",
        "backup-setup.json",
    ] {
        absent(guard.control(), name)?;
    }
    if let Some(context) = context {
        context.check_source(guard, None)?;
    } else {
        absent(guard.control(), "backup-initial-setup.json")?;
    }
    Ok(())
}
pub(crate) fn root_binding(v: &Value) -> Result<()> {
    json::fields(v, "configuration mount root boot_id")?;
    crate::storage::validate(&v["configuration"])?;
    identity::uuid(
        v["boot_id"]
            .as_str()
            .ok_or_else(|| Error("credential binding boot required".into()))?,
    )?;
    let m = &v["mount"];
    json::fields(m, "mount_id unique_mount_id device root target fstype")?;
    let path = v["configuration"]["root_subvol"].as_str().unwrap();
    let device = m["device"]
        .as_str()
        .ok_or_else(|| Error("credential Root device required".into()))?;
    let (a, b) = device
        .split_once(':')
        .ok_or_else(|| Error("credential Root device number required".into()))?;
    require(
        [a, b].iter().all(|s| {
            !s.is_empty()
                && s.len() <= 10
                && s.bytes().all(|b| b.is_ascii_digit())
                && s.parse::<u32>().is_ok()
        }) && m["target"] == "/"
            && m["root"] == format!("/{path}")
            && m["fstype"] == "btrfs"
            && ["mount_id", "unique_mount_id"]
                .iter()
                .all(|k| m[*k].as_u64().is_some_and(|n| n > 0)),
        "credential live Root mount binding invalid",
    )?;
    let root = &v["root"];
    json::fields(root, "path id uuid parent_uuid")?;
    require(
        root["path"] == path && root["id"].as_u64().is_some_and(|n| n >= 256),
        "credential Root object invalid",
    )?;
    identity::uuid(
        root["uuid"]
            .as_str()
            .ok_or_else(|| Error("credential Root UUID required".into()))?,
    )?;
    if !root["parent_uuid"].is_null() {
        identity::uuid(
            root["parent_uuid"]
                .as_str()
                .ok_or_else(|| Error("credential Root parent UUID required".into()))?,
        )?;
    }
    Ok(())
}
pub(crate) fn validate(v: &Value) -> Result<()> {
    json::fields(
        v,
        "schema phase owner_uid bytes root_binding credential_identity",
    )?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["owner_uid"]
                .as_u64()
                .is_some_and(|n| (1000..i32::MAX as u64).contains(&n))
            && v["bytes"].as_u64().is_some_and(|n| (1..=4096).contains(&n)),
        "credential receipt owner/length invalid",
    )?;
    root_binding(&v["root_binding"])?;
    match v["phase"].as_str() {
        Some("prepared") => require(
            v["credential_identity"].is_null(),
            "prepared credential cannot claim publication",
        ),
        Some("complete") => {
            let c = &v["credential_identity"];
            json::fields(c, "dev ino size mtime_ns ctime_ns")?;
            require(
                c["dev"].as_u64().is_some()
                    && c["ino"].as_u64().is_some_and(|n| n > 0)
                    && c["size"] == v["bytes"]
                    && ["mtime_ns", "ctime_ns"]
                        .iter()
                        .all(|k| c[*k].as_i64().is_some()),
                "original credential publication identity invalid",
            )
        }
        _ => Err(Error("credential receipt phase invalid".into())),
    }
}
pub(crate) fn publication(file: &File, length: usize, guard: &Guard) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() == length as u64
            && mount_identity::id(file.as_fd(), true)? == guard.root_mount_id(),
        "private original Root credential inode required",
    )?;
    let ns = |seconds: i64, nanos: i64| {
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(nanos))
            .ok_or_else(|| Error("credential metadata timestamp overflow".into()))
    };
    Ok(
        value!({"dev":m.dev(),"ino":m.ino(),"size":m.len(),"mtime_ns":ns(m.mtime(),m.mtime_nsec())?,"ctime_ns":ns(m.ctime(),m.ctime_nsec())?}),
    )
}
/// `authorize` binds the original current caller, session and reviewed operation.
/// No credential contents or digest enter this function's memory or receipts.
pub fn persist(
    input: &Validated,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    persist_inner(input, lock, authorize, None)?.public_result()
}
pub fn persist_owned_in_setup(
    input: &Validated,
    context: &crate::backup_setup_context::Prepared<'_, '_, '_, '_>,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<crate::backup_published_credential::Published> {
    require(
        context.plan_value()?["mode"] == "initialize",
        "adoption requires original completed confirmation",
    )?;
    persist_inner(input, lock, authorize, Some(context))
}
/// Adoption publication requires both completed mounts using the original input.
pub fn persist_confirmed_in_setup(
    confirmed: &crate::backup_input_authentication::Confirmed<'_, '_, '_>,
    context: &crate::backup_setup_context::Prepared<'_, '_, '_, '_>,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<crate::backup_published_credential::Published> {
    confirmed.recheck()?;
    require(
        confirmed.plan()? == context.plan_value()?,
        "credential confirmation differs from original outer plan",
    )?;
    let published = persist_inner(
        confirmed.input()?,
        lock,
        &|| {
            confirmed.recheck()?;
            authorize()
        },
        Some(context),
    )?;
    confirmed.recheck()?;
    Ok(published)
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fsync, linkat, openat, unlinkat)."
)]
fn persist_inner(
    input: &Validated,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
    context: Option<&crate::backup_setup_context::Prepared<'_, '_, '_, '_>>,
) -> Result<crate::backup_published_credential::Published> {
    crate::storage_runtime::initial_namespace()?;
    let idle = crate::transition_idle::Snapshot::online()?;
    let guard = &idle.guard;
    let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
    let parent_shape = shape(&parent)?;
    require(
        parent_shape.0 == guard.root_device()
            && mount_identity::id(parent.as_fd(), true)? == guard.root_mount_id(),
        "credential parent outside original Root mount",
    )?;
    let binding = guard.backup_root_binding()?;
    if let Some(context) = context {
        context.check_source(guard, Some(input.owner()))?;
    }
    let recheck = || {
        lock.recheck()?;
        idle.recheck()?;
        input.recheck()?;
        let named = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            shape(&named)? == parent_shape
                && shape(&parent)? == parent_shape
                && mount_identity::id(named.as_fd(), true)? == guard.root_mount_id()
                && mount_identity::id(parent.as_fd(), true)? == guard.root_mount_id()
                && guard.backup_root_binding()? == binding,
            "original credential Root authority changed",
        )?;
        if let Some(context) = context {
            context.check_source(guard, Some(input.owner()))?;
        }
        authorize()
    };
    recheck()?;
    unconfigured(&parent, guard, context)?;
    let mut record = value!({"schema":1,"phase":"prepared","owner_uid":input.owner(),"bytes":input.length()?,"root_binding":binding,"credential_identity":null});
    validate(&record)?;
    let bytes = json::canonical(&record)?;
    require(bytes.len() <= LIMIT, "credential receipt bound")?;
    if let Some(context) = context {
        context.claim(crate::backup_setup_context::Step::SecretInput)?;
    }
    let original = files::atomic_relative_retained(
        guard.control(),
        Path::new(JOURNAL),
        &bytes,
        0o600,
        Some(0),
        false,
        LIMIT,
    )?;
    let original_identity = files::identity(&original.metadata()?);
    let check_journal = || {
        let named = files::open_relative(guard.control(), Path::new(JOURNAL))?;
        require(
            files::identity(&named.metadata()?) == original_identity
                && files::identity(&original.metadata()?) == original_identity
                && mount_identity::id(original.as_fd(), true)? == guard.control_mount_id()
                && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id()
                && files::read_file(&original, LIMIT, Some(0), true)? == bytes,
            "original credential intent changed",
        )
    };
    recheck()?;
    check_journal()?;
    for name in ["backup.password", ".backup-password-input", "backup.json"] {
        absent(&parent, name)?;
    }
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c".backup-password-input".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(raw >= 0, "exclusive credential output refused")?;
    let output = unsafe { File::from_raw_fd(raw) };
    require(
        output.metadata()?.gid() == 0
            && mount_identity::id(output.as_fd(), true)? == guard.root_mount_id(),
        "private credential output mount/owner invalid",
    )?;
    input.copy_into_new(&output)?;
    let copied = publication(&output, input.length()?, guard)?;
    let copied_identity = files::identity(&output.metadata()?);
    recheck()?;
    check_journal()?;
    unconfigured_control(guard, context)?;
    let named = files::open_relative(&parent, Path::new(".backup-password-input"))?;
    require(
        files::identity(&named.metadata()?) == copied_identity
            && files::identity(&output.metadata()?) == copied_identity,
        "original credential temporary replaced",
    )?;
    drop(named);
    for name in ["backup.password", "backup.json"] {
        absent(&parent, name)?;
    }
    // Atomic no-overwrite publication; only this exact already-copied inode.
    require(
        unsafe {
            libc::linkat(
                parent.as_raw_fd(),
                c".backup-password-input".as_ptr(),
                parent.as_raw_fd(),
                c"backup.password".as_ptr(),
                0,
            )
        } == 0,
        "credential publication refused; private state retained",
    )?;
    let target = files::open_relative(&parent, Path::new("backup.password"))?;
    let temp = files::open_relative(&parent, Path::new(".backup-password-input"))?;
    let held = output.metadata()?;
    require(
        held.nlink() == 2
            && [target.metadata()?, temp.metadata()?]
                .iter()
                .all(|m| files::identity(m) == files::identity(&held))
            && held.dev() == copied["dev"].as_u64().unwrap()
            && held.ino() == copied["ino"].as_u64().unwrap()
            && held.uid() == 0
            && held.gid() == 0
            && held.mode() & 0o7777 == 0o600
            && held.len() == input.length()? as u64
            && held.mtime() == copied_identity.3
            && held.mtime_nsec() == copied_identity.4,
        "credential hardlink publication identity changed",
    )?;
    require(
        unsafe { libc::unlinkat(parent.as_raw_fd(), c".backup-password-input".as_ptr(), 0) } == 0
            && unsafe { libc::fsync(parent.as_raw_fd()) } == 0,
        "credential publication durability unknown; receipt retained",
    )?;
    recheck()?;
    check_journal()?;
    for name in ["backup.json", ".backup-password-input"] {
        absent(&parent, name)?;
    }
    let named = files::open_relative(&parent, Path::new("backup.password"))?;
    require(
        files::identity(&named.metadata()?) == files::identity(&output.metadata()?),
        "published original credential replaced",
    )?;
    unconfigured_control(guard, context)?;
    let published_identity = files::identity(&output.metadata()?);
    require(
        published_identity.3 == copied_identity.3 && published_identity.4 == copied_identity.4,
        "original credential bytes changed during publication",
    )?;
    record["phase"] = value!("complete");
    record["credential_identity"] = publication(&output, input.length()?, guard)?;
    validate(&record)?;
    let completed = files::atomic_replace_original(
        guard.control(),
        Path::new(JOURNAL),
        &json::canonical(&record)?,
        0o600,
        Some(0),
        LIMIT,
        &original,
    )?;
    require(
        files::read_file(&completed, LIMIT, Some(0), true)? == json::canonical(&record)?,
        "credential completion readback changed",
    )?;
    recheck()?;
    unconfigured_control(guard, context)?;
    let final_named = files::open_relative(&parent, Path::new("backup.password"))?;
    let completed_named = files::open_relative(guard.control(), Path::new(JOURNAL))?;
    require(
        files::identity(&named.metadata()?) == published_identity
            && files::identity(&final_named.metadata()?) == published_identity
            && files::identity(&output.metadata()?) == published_identity
            && files::identity(&completed_named.metadata()?)
                == files::identity(&completed.metadata()?)
            && files::read_file(&completed, LIMIT, Some(0), true)? == json::canonical(&record)?,
        "credential or completed original receipt changed before success",
    )?;
    crate::backup_published_credential::Published::new(
        idle,
        parent,
        final_named,
        published_identity,
        completed,
        json::canonical(&record)?,
        input.owner(),
    )
}
