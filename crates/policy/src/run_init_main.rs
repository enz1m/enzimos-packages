// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, files};
use enzimos_policy::{
    native_boot_dispatch::{self, Parameters},
    recovery_bootstrap as bootstrap, recovery_run_boot,
};
use serde_json::json;
use std::{io::Write, path::Path};
fn command_line() -> Result<String> {
    let body = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
    String::from_utf8(body).map_err(|_| Error("run command line encoding".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (pause, umask).")]
fn main() {
    unsafe { libc::umask(0o077) };
    if let Err(error) = bootstrap::initialize() {
        eprintln!("ENZIMOS_RECOVERY_RUN_BOOTSTRAP_REFUSED {error}");
        std::process::exit(2);
    }
    let command = command_line();
    let root = command
        .as_ref()
        .is_ok_and(|s| native_boot_dispatch::is_root(s));
    let parameters = command.and_then(|s| Parameters::parse(&s));
    let poweroff = parameters.as_ref().is_ok_and(Parameters::poweroff);
    let case = if root {
        "root-retirement-coordinator-boot"
    } else {
        "recovery-run-boot"
    };
    let outcome = parameters.and_then(|p| match p {
        Parameters::Recovery(p) => recovery_run_boot::run(&p),
        Parameters::Root(p) => enzimos_policy::root_retirement_boot::run(&p),
    });
    let report = match outcome {
        Ok(detail) => json!({"case":case,"status":"PASS","detail":detail}),
        Err(error) => {
            let failure = if root {
                "native retirement coordinator refused; explicit review required"
            } else {
                "native recovery run refused; explicit review required"
            };
            eprintln!("{failure}: {error}");
            json!({"case":case,"status":"FAIL","failure":failure})
        }
    };
    let prefix = if root {
        "ENZIMOS_COORDINATOR_RESULT"
    } else {
        "ENZIMOS_RECOVERY_RUN_RESULT"
    };
    println!("{prefix}={report}");
    let _ = std::io::stdout().flush();
    if report["status"] == "PASS"
        && report["detail"]["ram_handoff"] == true
        && bootstrap::handoff_reboot().is_err()
    {
        eprintln!("ENZIMOS_RECOVERY_HANDOFF_REBOOT_FALLBACK");
    }
    if let Err(error) = bootstrap::reboot(poweroff) {
        eprintln!("{error}");
    }
    loop {
        unsafe { libc::pause() };
    }
}
