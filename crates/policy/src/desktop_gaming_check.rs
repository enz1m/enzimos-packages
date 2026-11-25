// SPDX-License-Identifier: MIT
//! Bounded local gaming diagnostics; no downloads, overrides or game launches.
use enzimos_platform::{Result, process};
use serde_json::{Map, Value, json as value};
use std::{ffi::CString, path::Path, sync::OnceLock, time::Duration};

/// The caller's descriptor limit, recorded before the policy binary lowers its own.
pub static CALLER_NOFILE: OnceLock<(u64, u64)> = OnceLock::new();

const PACKAGES: &[&str] = &[
    "steam-devices",
    "gamemode",
    "lib32-gamemode",
    "lib32-mesa",
    "lib32-vulkan-icd-loader",
    "lib32-libpulse",
    "lib32-alsa-plugins",
    "steam",
    "gamescope",
    "linuxconsole",
];

/// Missing tools and timeouts are reported as an unsuccessful probe, not an error.
fn command(program: &str, args: &[&str]) -> Option<String> {
    let output = process::run(program, args, &[], Duration::from_secs(8), 16384).ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[allow(unsafe_code, reason = "Linux syscall ABI (access).")]
fn access(path: &Path, mode: libc::c_int) -> bool {
    CString::new(path.as_os_str().as_encoded_bytes())
        // SAFETY: `path` is a NUL-terminated CString.
        .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), mode) } == 0)
}

/// `pacman -Q NAME` prints `NAME VERSION`; keep only the version.
fn package_version(output: &str) -> Value {
    let line = output.trim();
    value!(line.split_once(' ').map_or(line, |(_, version)| version))
}

/// Only joystick nodes are reported; keyboard events and device serials are never read.
fn controllers() -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir("/sys/class/input") else {
        return Vec::new();
    };
    let mut names = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with("event"))
        .collect::<Vec<_>>();
    names.sort();
    names.truncate(256);
    names
        .into_iter()
        .filter_map(|name| {
            let dev = std::fs::read_to_string(format!("/sys/class/input/{name}/dev")).ok()?;
            let database =
                std::fs::read_to_string(format!("/run/udev/data/c{}", dev.trim())).ok()?;
            if !database.contains("E:ID_INPUT_JOYSTICK=1\n") {
                return None;
            }
            let node = Path::new("/dev/input").join(&name);
            Some(value!({
                "node": node.to_string_lossy(),
                "readable": access(&node, libc::R_OK),
                "writable": access(&node, libc::W_OK),
            }))
        })
        .collect()
}

pub fn check() -> Result<Value> {
    let mut packages = Map::new();
    for name in PACKAGES {
        let version = command("/usr/bin/pacman", &["-Q", name]);
        packages.insert(
            (*name).into(),
            version.as_deref().map_or(Value::Null, package_version),
        );
    }
    let metadata = command(
        "/usr/bin/flatpak",
        &["info", "--show-metadata", "com.valvesoftware.Steam"],
    );
    let namespaces = command(
        "/usr/bin/unshare",
        &["--user", "--map-root-user", "/usr/bin/true"],
    );
    let (soft, hard) = CALLER_NOFILE.get().copied().unwrap_or_default();
    Ok(value!({
        "schema": 1,
        "packages": packages,
        "steam_flatpak_installed": metadata.is_some(),
        "steam_flatpak_game_mode_direct_bus_declared":
            metadata.as_deref().is_some_and(|m| m.contains("com.feralinteractive.GameMode")),
        "user_namespaces_available": namespaces.is_some(),
        "uinput_writable": access(Path::new("/dev/uinput"), libc::W_OK),
        "ntsync_accessible": access(Path::new("/dev/ntsync"), libc::R_OK | libc::W_OK),
        "controllers": controllers(),
        "open_file_limit": {"soft": soft, "hard": hard},
        "hybrid_gpu": "not-qualified",
        "game_compatibility": "requires-per-game-testing",
        "changes_made": false,
    }))
}
