// SPDX-License-Identifier: MIT
//! Actual frames and descriptor transfer on a private, owned Unix bus only.
#![cfg(feature = "update-worker")]
use enzimos_platform::{Error, Result};
use enzimos_system_backend::{
    system_service::{self, Call, Handler, Reply},
    system_wire as wire,
};
use serde_json::{Value, json};
use std::{
    fs::File,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, PermissionsExt},
    },
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::{
    MatchRule, Message, MessageStream, Proxy,
    connection::Builder,
    fdo::DBusProxy,
    message::{Flags, Type},
};
struct Fake {
    calls: Arc<AtomicU32>,
    active: Arc<AtomicBool>,
    public: File,
}
impl Handler for Fake {
    async fn handle(&self, call: Call) -> Result<Reply> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if call.member == "Operation" {
            return Err(Error("private untrusted vendor diagnostic".into()));
        }
        if call.member == "BackupSetupInput" {
            let mut bytes = [0u8; 14];
            let descriptor = call.descriptor.expect("input call carries a descriptor");
            assert_eq!(
                descriptor
                    .read_at(&mut bytes, 0)
                    .expect("readable descriptor"),
                14,
                "whole fixture read"
            );
            assert_eq!(&bytes, b"public fixture", "fixture content");
        }
        Ok(Reply {
            body: json!({"schema":1,"member":call.member}),
            descriptor: if call.member == "BackupRecoveryExport" {
                Some(self.public.try_clone()?)
            } else {
                None
            },
        })
    }
    fn active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_frames_descriptor_lifetime_redaction_and_owned_work_idle_gate() {
    let work = std::path::Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    let public = temp.path().join("fixture");
    std::fs::write(&public, b"public fixture").unwrap();
    let address = format!("unix:path={}", temp.path().join("bus").display());
    let mut daemon = tokio::process::Command::new("/usr/bin/dbus-daemon")
        .args([
            "--session",
            "--nofork",
            "--print-address=1",
            "--address",
            &address,
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(daemon.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(line.starts_with(&address));
    let server = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let stream = MessageStream::for_match_rule(
        MatchRule::builder().msg_type(Type::MethodCall).build(),
        &server,
        Some(32),
    )
    .await
    .unwrap();
    let calls = Arc::new(AtomicU32::new(0));
    let active = Arc::new(AtomicBool::new(true));
    let task = tokio::spawn(system_service::serve(
        stream,
        Fake {
            calls: std::sync::Arc::clone(&calls),
            active: std::sync::Arc::clone(&active),
            public: File::open(&public).unwrap(),
        },
        Duration::from_millis(100),
    ));
    let client = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let bus = DBusProxy::new(&client).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !bus
            .name_has_owner(wire::BUS.try_into().unwrap())
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let proxy = Proxy::new(&client, wire::BUS, wire::PATH, wire::BUS)
        .await
        .unwrap();
    let result: String = proxy.call("GetCapabilities", &()).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&result).unwrap(),
        json!({"schema":1,"member":"GetCapabilities"})
    );
    let no_reply = Message::method_call(wire::PATH, "Operation")
        .unwrap()
        .destination(wire::BUS)
        .unwrap()
        .interface(wire::BUS)
        .unwrap()
        .with_flags(Flags::NoReplyExpected)
        .unwrap()
        .build(&"{}")
        .unwrap();
    client.send(&no_reply).await.unwrap();
    let _: String = proxy.call("Query", &"{}").await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    for (member, body) in [
        ("Operation", "x".repeat(4097)),
        ("Query", "x".repeat(65536)),
        ("Unknown", "{}".into()),
    ] {
        assert!(matches!(
            proxy.call::<_, _, String>(member, &body).await,
            Err(zbus::Error::MethodError(_, _, _))
        ));
    }
    assert!(matches!(
        proxy.call::<_, _, String>("Operation", &7u32).await,
        Err(zbus::Error::MethodError(_, _, _))
    ));
    let wrong = Proxy::new(&client, wire::BUS, "/wrong", wire::BUS)
        .await
        .unwrap();
    assert!(matches!(
        wrong.call::<_, _, String>("Query", &"{}").await,
        Err(zbus::Error::MethodError(_, _, _))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    match proxy.call::<_, _, String>("Operation", &"{}").await {
        Err(zbus::Error::MethodError(name, Some(message), _)) => {
            assert_eq!(name.as_str(), "org.enzimos.System1.Refused");
            assert_eq!(
                message,
                "internal-result-unknown-do-not-retry-automatically"
            );
        }
        _ => panic!("expected closed public error"),
    }
    let fd = File::open(&public).unwrap();
    let nested = proxy
        .call::<_, _, String>(
            "BackupSetupInput",
            &(("{}", zbus::zvariant::Fd::from(fd.as_fd())),),
        )
        .await;
    assert!(matches!(nested, Err(zbus::Error::MethodError(_, _, _))));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let _: String = proxy
        .call(
            "BackupSetupInput",
            &("{}", zbus::zvariant::Fd::from(fd.as_fd())),
        )
        .await
        .unwrap();
    let (body, fd): (String, zbus::zvariant::OwnedFd) =
        proxy.call("BackupRecoveryExport", &"{}").await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["member"],
        "BackupRecoveryExport"
    );
    let receiver = File::from(std::os::fd::OwnedFd::from(fd));
    let mut bytes = [0; 14];
    assert_eq!(receiver.read_at(&mut bytes, 0).unwrap(), 14);
    assert_eq!(&bytes, b"public fixture");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished());
    let end = std::time::Instant::now();
    active.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(end.elapsed() >= Duration::from_millis(100));
    assert!(
        !bus.name_has_owner(wire::BUS.try_into().unwrap())
            .await
            .unwrap()
    );
    // The returned duplicate outlives the service and its sending description.
    assert_eq!(receiver.read_at(&mut bytes, 0).unwrap(), 14);
    drop(proxy);
    drop(wrong);
    drop(bus);
    drop(client);
    drop(server);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
