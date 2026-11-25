// SPDX-License-Identifier: MIT
//! Whether /tmp is RAM-backed or on disk, applied at the next boot.
use crate::{operation, settings_command::Command, settings_file::Config};
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::path::Path;

const CONFIG: &str = "/etc/enzimos/tmp-storage.conf";
const BOOT_MODE: &str = "/run/enzimos/tmp-storage-current";
const GENERATOR: &str = "/usr/lib/systemd/system-generators/enzimos-tmp-storage";
const CUSTOM_UNITS: &[&str] = &[
    "/etc/systemd/system/tmp.mount",
    "/etc/systemd/system/tmp.mount.d",
    "/usr/local/lib/systemd/system/tmp.mount",
    "/usr/local/lib/systemd/system/tmp.mount.d",
];

fn configured(config: &Config) -> Result<&'static str> {
    match config.body.as_slice() {
        b"ram\n" => Ok("ram"),
        b"disk\n" => Ok("disk"),
        _ => Err(Error("invalid temporary storage configuration".into())),
    }
}

fn managed(findmnt: &Command) -> Result<bool> {
    if !Path::new(GENERATOR).is_file()
        || CUSTOM_UNITS
            .iter()
            .any(|path| Path::new(path).symlink_metadata().is_ok())
    {
        return Ok(false);
    }
    let entry = findmnt.run(
        &[
            "--fstab",
            "--mountpoint",
            "/tmp",
            "--noheadings",
            "--output",
            "TARGET",
        ],
        &[0, 1],
        4096,
    )?;
    Ok(entry.is_empty())
}

fn active_mode(findmnt: &Command) -> Result<&'static str> {
    let data = findmnt.run(
        &["--target", "/tmp", "--noheadings", "--output", "FSTYPE"],
        &[0],
        4096,
    )?;
    Ok(match data.trim_ascii() {
        b"tmpfs" | b"ramfs" => "ram",
        _ => "disk",
    })
}

/// The configured and active /tmp storage.
///
/// # Errors
///
/// Fails when the configuration or mount cannot be read.
pub fn query() -> Result<Value> {
    let findmnt = Command::open("/usr/bin/findmnt")?;
    let active = active_mode(&findmnt)?;
    if !managed(&findmnt)? {
        return Ok(json!({"active":active,"configured":null}));
    }
    let config = Config::open(CONFIG, 16)?;
    let mode = configured(&config)?;
    Ok(json!({"active":active,"configured":mode}))
}

fn evidence(config: &Config, findmnt: &Command) -> Result<Value> {
    require(managed(findmnt)?, "operation-unavailable")?;
    Ok(json!({"configured":configured(config)?,"configuration":config.evidence()?}))
}

/// The current observation.
///
/// # Errors
///
/// Fails when the configuration or mount cannot be read.
pub fn observation() -> Result<Value> {
    let findmnt = Command::open("/usr/bin/findmnt")?;
    evidence(&Config::open(CONFIG, 16)?, &findmnt)
}

/// Configure /tmp storage `mode` (`ram` or `disk`) if the state still matches `expected`.
///
/// # Errors
///
/// Fails for invalid modes, a changed state, failed authorization, or a failed write.
pub fn set(
    mode: &Value,
    expected: &Value,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    operation::root_only()?;
    let body: &[u8] = match mode.as_str() {
        Some("ram") => b"ram\n",
        Some("disk") => b"disk\n",
        _ => return Err(Error("job-plan-invalid".into())),
    };
    let lock = operation::lock()?;
    let findmnt = Command::open("/usr/bin/findmnt")?;
    let mut config = Config::open(CONFIG, 16)?;
    let active = active_mode(&findmnt)?;
    authorize()?;
    lock.recheck()?;
    require(
        evidence(&config, &findmnt)? == *expected,
        "job-plan-changed",
    )?;
    if config.body != body {
        // Generators rerun on daemon-reload, so pin the active choice until reboot.
        let boot_mode: &[u8] = if active == "ram" { b"ram\n" } else { b"disk\n" };
        files::atomic(Path::new(BOOT_MODE), boot_mode, 0o644, Some(0), true)?;
        config.publish(body)?;
    }
    Ok(json!({"configured":mode,"applied_live":false,"reboot_required":mode != active}))
}
