// SPDX-License-Identifier: MIT
//! Candidate native service; production activation is changed only after qualification.
#[cfg(feature = "update-worker")]
fn migration_mode(args: &[std::ffi::OsString]) -> enzimos_platform::Result<bool> {
    if args.len() == 1 {
        return Ok(false);
    }
    enzimos_platform::require(
        args.len() == 2 && args[1] == "--remote-rotation-migrate",
        "backend-service-arguments-unavailable",
    )?;
    Ok(true)
}
#[cfg(feature = "update-worker")]
fn backup_mode(args: &[std::ffi::OsString]) -> enzimos_platform::Result<Option<bool>> {
    if args.len() == 2 && args[1] == "--backup-create" {
        return Ok(Some(false));
    }
    if args.len() == 2 && args[1] == "--backup-automatic" {
        return Ok(Some(true));
    }
    if args
        .iter()
        .skip(1)
        .any(|arg| arg.to_string_lossy().starts_with("--backup"))
    {
        return Err(enzimos_platform::Error(
            "closed standalone backup arguments required".into(),
        ));
    }
    Ok(None)
}
#[cfg(feature = "update-worker")]
#[allow(
    unsafe_code,
    reason = "Single-threaded startup sanitizes the process environment before launching workers."
)]
fn execute() -> enzimos_platform::Result<i32> {
    use enzimos_platform::{Error, files, require};
    use std::{
        os::unix::fs::{FileTypeExt, MetadataExt},
        path::Path,
        time::Duration,
    };
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let root_command = enzimos_system_backend::root_command::parse(&arguments)?;
    let backup = if root_command.is_some() {
        None
    } else {
        backup_mode(&arguments)?
    };
    let metadata_migration = if backup.is_some() || root_command.is_some() {
        false
    } else {
        migration_mode(&arguments)?
    };
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::operation::root_only()?;
    std::env::set_current_dir("/")?;
    for (name, _) in std::env::vars_os() {
        // SAFETY: The process is still single-threaded here, so no other thread reads the
        // environment.
        unsafe {
            std::env::remove_var(name);
        }
    }
    for (name, value) in [
        ("PATH", "/usr/bin"),
        ("HOME", "/nonexistent"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
    ] {
        // SAFETY: The process is still single-threaded here, so no other thread reads the
        // environment.
        unsafe {
            std::env::set_var(name, value);
        }
    }
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    require(
        // SAFETY: `core` is a valid rlimit that outlives the call.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0
            // SAFETY: prctl(PR_SET_DUMPABLE) takes no pointers.
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "backend-service-confinement-unavailable",
    )?;
    if let Some(command) = root_command {
        use std::io::Write;
        let result = enzimos_system_backend::root_command::execute(command)?;
        let mut bytes = enzimos_platform::json::canonical(&result)?;
        require(bytes.len() <= 65536, "standalone Root command result bound")?;
        bytes.push(b'\n');
        std::io::stdout().lock().write_all(&bytes)?;
        return Ok(0);
    }
    if let Some(automatic) = backup {
        use std::io::Write;
        let result = enzimos_system_backend::backup_cli::create(automatic)?;
        let code = if result["status"] == "deferred" && result["owed_after_reboot"] == true {
            75
        } else {
            0
        };
        let mut bytes = enzimos_platform::json::canonical(&result)?;
        require(bytes.len() <= 65536, "standalone backup result bound")?;
        bytes.push(b'\n');
        std::io::stdout().lock().write_all(&bytes)?;
        return Ok(code);
    }
    if metadata_migration {
        use std::io::Write;
        let guard = enzimos_policy::storage_runtime::Guard::observe()?;
        let lock = enzimos_policy::operation::lock()?;
        let mut permission = || {
            enzimos_policy::operation::root_only()?;
            enzimos_policy::namespaces::initial()?;
            guard.recheck()?;
            lock.recheck()
        };
        let result = enzimos_policy::backup_remote_rotation_context::Context::migrate_metadata(
            &guard,
            &lock,
            &mut permission,
        )?;
        let mut bytes = enzimos_platform::json::canonical(&result)?;
        require(bytes.len() <= 8192, "metadata migration result bound")?;
        bytes.push(b'\n');
        std::io::stdout().lock().write_all(&bytes)?;
        return Ok(0);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(12)
        .enable_all()
        .build()
        .map_err(|_| Error("backend-service-runtime-unavailable".into()))?;
    runtime
        .block_on(async {
            let path = Path::new("/run/dbus/system_bus_socket");
            let parent = files::directory(Path::new("/run/dbus"), Some(0))?;
            let parent_shape = files::identity(&parent.metadata()?);
            let before = std::fs::symlink_metadata(path)?;
            require(
                before.file_type().is_socket() && before.uid() == 0,
                "unsafe-system-bus-socket",
            )?;
            let identity = files::identity(&before);
            let builder =
                zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
                    .map_err(|_| Error("backend-service-bus-unavailable".into()))?
                    .max_queued(32);
            let connection = tokio::time::timeout(Duration::from_secs(5), builder.build())
                .await
                .map_err(|_| Error("backend-service-bus-unavailable".into()))?
                .map_err(|_| Error("backend-service-bus-unavailable".into()))?;
            let named_parent = files::directory(Path::new("/run/dbus"), Some(0))?;
            // Directory timestamps are not authority: the bus writes other names.
            let same_parent =
                |m: &std::fs::Metadata| (m.dev(), m.ino(), m.uid(), m.gid(), m.mode());
            require(
                files::identity(&std::fs::symlink_metadata(path)?) == identity
                    && same_parent(&named_parent.metadata()?) == same_parent(&parent.metadata()?)
                    && (
                        parent_shape.0,
                        parent_shape.1,
                        parent_shape.8,
                        parent_shape.9,
                        parent_shape.7,
                    ) == same_parent(&parent.metadata()?),
                "system-bus-endpoint-changed",
            )?;
            let api = enzimos_system_backend::system_api::Api::open(connection.clone()).await?;
            let rule = zbus::MatchRule::builder()
                .msg_type(zbus::message::Type::MethodCall)
                .build();
            let stream = tokio::time::timeout(
                Duration::from_secs(2),
                zbus::MessageStream::for_match_rule(rule, &connection, Some(32)),
            )
            .await
            .map_err(|_| Error("backend-service-bus-unavailable".into()))?
            .map_err(|_| Error("backend-service-bus-unavailable".into()))?;
            enzimos_system_backend::system_service::serve(stream, api, Duration::from_secs(60))
                .await
        })
        .map(|()| 0)
}
fn main() {
    #[cfg(feature = "update-worker")]
    match execute() {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(feature = "update-worker"))]
    {
        eprintln!("native-backend-feature-unavailable");
        std::process::exit(1);
    }
}
