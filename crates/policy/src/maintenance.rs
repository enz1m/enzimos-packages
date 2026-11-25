// SPDX-License-Identifier: MIT
//! Fixed maintenance commands against the retained configured Root description.
//! Only pre-entry lock contention creates debt; a failed entered command does not.
use crate::{
    deferred::{self, Admission},
    operation,
    settings_command::Command,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, process, require};
use serde_json::{Value, json as value};
use std::{
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};
fn command(action: &str) -> Result<(&'static str, &'static [&'static str])> {
    match action {
        "scrub" => Ok(("/usr/bin/btrfs", &["scrub", "start", "-B", "@fd-dir:0"])),
        "trim" => Ok(("/usr/bin/fstrim", &["--verbose", "@fd-dir:0"])),
        _ => Err(enzimos_platform::Error(
            "unknown maintenance operation".into(),
        )),
    }
}
pub fn maintain(action: &str) -> Result<Value> {
    let (program, args) = command(action)?;
    operation::root_only()?;
    crate::namespaces::initial()?;
    // Observe the configured Root before contention admission, matching the
    // legacy contract and refusing debt for a foreign or unobservable filesystem.
    let guard = Guard::observe()?;
    let admission = deferred::admit(action)?;
    let lock = match admission {
        Admission::Deferred(_) => {
            return Ok(
                value!({"status":"deferred","action":action,"reason":"operation-lock-busy","owed_after_reboot":true}),
            );
        }
        Admission::Entered(lock) => lock,
    };
    guard.recheck()?;
    lock.recheck()?;
    let root = guard.root_descriptor()?;
    let flags = enzimos_platform::files::status_flags(&root);
    require(
        flags >= 0 && flags & libc::O_PATH == 0,
        "actual maintenance Root descriptor status required",
    )?;
    let image = Command::open(program)?;
    let original = image.evidence()?;
    let mut boundary = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        require(
            enzimos_platform::files::status_flags(&root) == flags && image.evidence()? == original,
            "maintenance original Root/image status changed; no replay",
        )
    };
    boundary()?;
    let output = process::run_pinned_with_checkpoint(
        program,
        image.descriptor()?,
        args,
        &[],
        Duration::from_secs(86400),
        1024 * 1024,
        &[root.as_fd()],
        &mut boundary,
    )?;
    boundary()?;
    require(
        output.status.code() == Some(0),
        "maintenance failed or uncertain; no automatic retry/debt",
    )?;
    Ok(value!({"status":"completed","action":action}))
}
