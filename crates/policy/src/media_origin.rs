// SPDX-License-Identifier: MIT
//! A media marker is bound to this direct PID1 boot and measured native code.
use crate::{namespaces, operation, recovery_records};
use enzimos_platform::{Result, files, json, require, stream_copy};
use serde_json::{Value, json as value};
use std::path::Path;
pub(crate) const MARKER: &str = "/run/enzimos/installer-rescue-origin.json";
pub const POLICY: &str = "/usr/lib/enzimos-native/enzimos-policy";
fn observed() -> Result<Value> {
    operation::root_only()?;
    require(
        std::process::id() == 1,
        "installer rescue requires direct PID1",
    )?;
    namespaces::initial()?;
    let cmdline = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
    require(
        std::str::from_utf8(&cmdline).ok().is_some_and(|s| {
            s.split_whitespace()
                .filter(|w| *w == "enzimos.installer-rescue=1")
                .count()
                == 1
        }),
        "installer rescue boot entry required",
    )?;
    let rows = crate::storage_runtime::rows()?;
    let roots = rows.iter().filter(|r| r.target == "/").collect::<Vec<_>>();
    require(
        roots.len() == 1 && matches!(roots[0].filesystem.as_str(), "tmpfs" | "rootfs" | "ramfs"),
        "independent RAM-root installer rescue required",
    )?;
    require(
        !files::read(Path::new("/etc/initrd-release"), 8192, Some(0), true)?.is_empty(),
        "independent initramfs required",
    )?;
    let parent = files::directory(Path::new("/usr/lib/enzimos-native"), Some(0))?;
    let mut policy = files::open_relative(&parent, Path::new("enzimos-policy"))?;
    let identity = files::identity(&policy.metadata()?);
    require(
        files::read_file(&policy, 128 * 1024 * 1024, Some(0), true)?.starts_with(b"\x7fELF"),
        "native rescue executable required",
    )?;
    let (_, sha) = stream_copy::hash(&mut policy, 128 * 1024 * 1024, Some(0))?;
    let current = files::open_relative(&parent, Path::new("enzimos-policy"))?;
    require(
        files::identity(&current.metadata()?) == identity,
        "native rescue policy changed",
    )?;
    Ok(
        value!({"schema":1,"boot_id":operation::boot_id()?,"kernel":namespaces::kernel_release()?,"policy_sha256":sha}),
    )
}
pub fn initialize() -> Result<Value> {
    let value = observed()?;
    files::ensure_directory(Path::new("/run/enzimos"), 0o700, 0)?;
    let mut bytes = json::canonical(&value)?;
    bytes.push(b'\n');
    files::atomic(Path::new(MARKER), &bytes, 0o600, Some(0), false)?;
    current()
}
pub fn current() -> Result<Value> {
    let expected = observed()?;
    let value = json::decode(&files::read(Path::new(MARKER), 4096, Some(0), true)?, 4096)?;
    recovery_records::media_origin(&value)?;
    require(
        value == expected,
        "installer rescue boot or native policy identity changed",
    )?;
    Ok(value)
}
