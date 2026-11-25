// SPDX-License-Identifier: MIT
//! Candidate worker entrypoint; production recipe activation requires guest qualification.
#[cfg(feature = "update-worker")]
#[allow(
    unsafe_code,
    reason = "Single-threaded startup sanitizes the process environment before launching workers."
)]
fn execute() -> enzimos_platform::Result<()> {
    use enzimos_platform::{Result, require};
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require(
        args.len() == 2 && args[0] == "serve",
        "native backup worker accepts only serve and a fresh ID",
    )?;
    enzimos_policy::backup_worker_request::id(&args[1])?;
    enzimos_policy::namespaces::initial()?;
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(
        // SAFETY: `core` is a valid rlimit that outlives the call.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0
            // SAFETY: prctl(PR_SET_DUMPABLE) takes no pointers.
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "backup worker process protection unavailable",
    )?;
    std::env::set_current_dir("/")?;
    for (name, _) in std::env::vars_os() {
        // SAFETY: The process is still single-threaded here, so no other thread reads the
        // environment.
        unsafe {
            std::env::remove_var(name);
        }
    }
    for (name, v) in [
        ("PATH", "/usr/bin"),
        ("HOME", "/nonexistent"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
    ] {
        // SAFETY: The process is still single-threaded here, so no other thread reads the
        // environment.
        unsafe {
            std::env::set_var(name, v);
        }
    }
    let result: Result<()> = enzimos_system_backend::backup_worker_service::serve(&args[1]);
    result
}
#[cfg(not(feature = "update-worker"))]
fn execute() -> enzimos_platform::Result<()> {
    Err(enzimos_platform::Error(
        "native backup worker feature unavailable".into(),
    ))
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
