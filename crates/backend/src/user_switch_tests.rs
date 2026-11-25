// SPDX-License-Identifier: MIT
use super::*;
use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::connection::Builder;
const CALLER: &str = "/org/freedesktop/login1/session/c1";
const GREETER: &str = "/org/freedesktop/login1/session/g1";
#[derive(Clone)]
struct State {
    uid: u32,
    locked: Arc<AtomicBool>,
    remote: Arc<AtomicBool>,
    visible: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    activated: Arc<AtomicUsize>,
    started: Arc<AtomicUsize>,
    hold: Arc<AtomicBool>,
}
struct Login(State);
#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Login {
    #[zbus(name = "GetSessionByPID")]
    fn by_pid(&self, pid: u32) -> OwnedObjectPath {
        assert_eq!(pid, std::process::id());
        CALLER.try_into().unwrap()
    }
    #[zbus(name = "GetSession")]
    fn by_id(&self, id: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        match id {
            "c1" => Ok(CALLER.try_into().unwrap()),
            "g1" => Ok(GREETER.try_into().unwrap()),
            _ => Err(zbus::fdo::Error::Failed("unknown session".into())),
        }
    }
    #[zbus(name = "ListSessions")]
    fn sessions(&self) -> Vec<(String, u32, String, String, OwnedObjectPath)> {
        let mut rows = vec![(
            "c1".into(),
            self.0.uid,
            "user".into(),
            "seat0".into(),
            CALLER.try_into().unwrap(),
        )];
        if self.0.visible.load(Ordering::SeqCst) {
            rows.push((
                "g1".into(),
                900,
                "greeter".into(),
                "seat0".into(),
                GREETER.try_into().unwrap(),
            ));
        }
        rows
    }
}
struct FakeSession(State, bool);
#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl FakeSession {
    #[zbus(property)]
    fn id(&self) -> &str {
        if self.1 { "g1" } else { "c1" }
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        (
            if self.1 { 900 } else { self.0.uid },
            "/org/freedesktop/login1/user/test".try_into().unwrap(),
        )
    }
    #[zbus(property)]
    fn seat(&self) -> (String, OwnedObjectPath) {
        (
            "seat0".into(),
            "/org/freedesktop/login1/seat/seat0".try_into().unwrap(),
        )
    }
    #[zbus(property)]
    fn class(&self) -> &str {
        if self.1 { "greeter" } else { "user" }
    }
    #[zbus(property, name = "Type")]
    fn session_type(&self) -> &str {
        "wayland"
    }
    #[zbus(property)]
    fn service(&self) -> &str {
        "greetd"
    }
    #[zbus(property, name = "VTNr")]
    fn vt(&self) -> u32 {
        if self.1 { 4 } else { 3 }
    }
    #[zbus(property)]
    fn active(&self) -> bool {
        self.0.active.load(Ordering::SeqCst) == self.1
    }
    #[zbus(property)]
    fn remote(&self) -> bool {
        !self.1 && self.0.remote.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.0.locked.load(Ordering::SeqCst)
    }
    #[zbus(name = "Activate")]
    async fn activate(&self) {
        assert!(self.1);
        self.0.activated.fetch_add(1, Ordering::SeqCst);
        while self.0.hold.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.0.active.store(true, Ordering::SeqCst);
    }
}
struct Seat(State);
#[zbus::interface(name = "org.freedesktop.login1.Seat")]
impl Seat {
    #[zbus(property)]
    fn active_session(&self) -> (String, OwnedObjectPath) {
        if self.0.active.load(Ordering::SeqCst) {
            ("g1".into(), GREETER.try_into().unwrap())
        } else {
            ("c1".into(), CALLER.try_into().unwrap())
        }
    }
}
struct Systemd(State);
#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Systemd {
    #[zbus(name = "GetUnit")]
    fn get_unit(&self, unit: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        assert!(
            POOL.iter()
                .any(|vt| unit == format!("enzimos-greetd@{vt}.service"))
        );
        Ok("/org/freedesktop/systemd1/unit/test".try_into().unwrap())
    }
    #[zbus(name = "StartUnit")]
    fn start(&self, unit: &str, mode: &str) -> OwnedObjectPath {
        assert_eq!(unit, "enzimos-greetd@4.service");
        assert_eq!(mode, "fail");
        self.0.started.fetch_add(1, Ordering::SeqCst);
        self.0.visible.store(true, Ordering::SeqCst);
        self.0.active.store(true, Ordering::SeqCst);
        "/org/freedesktop/systemd1/job/1".try_into().unwrap()
    }
}
struct Unit;
#[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
impl Unit {
    #[zbus(property)]
    fn active_state(&self) -> &str {
        "inactive"
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_private_bus_switch_start_refusal_and_provider_revocation() {
    let work = std::path::Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let temp = tempfile::Builder::new()
        .prefix("user-switch-")
        .tempdir_in(work)
        .unwrap();
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
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        BufReader::new(daemon.stdout.take().unwrap()).read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(line.starts_with(&address));
    let state = State {
        uid: enzimos_platform::process_identity::real_uid(),
        locked: Arc::new(AtomicBool::new(true)),
        remote: Arc::new(AtomicBool::new(false)),
        visible: Arc::new(AtomicBool::new(true)),
        active: Arc::new(AtomicBool::new(false)),
        activated: Arc::new(AtomicUsize::new(0)),
        started: Arc::new(AtomicUsize::new(0)),
        hold: Arc::new(AtomicBool::new(false)),
    };
    let login = Builder::address(address.as_str())
        .unwrap()
        .name(LOGIN)
        .unwrap()
        .serve_at("/org/freedesktop/login1", Login(state.clone()))
        .unwrap()
        .serve_at(CALLER, FakeSession(state.clone(), false))
        .unwrap()
        .serve_at(GREETER, FakeSession(state.clone(), true))
        .unwrap()
        .serve_at("/org/freedesktop/login1/seat/seat0", Seat(state.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let systemd = Builder::address(address.as_str())
        .unwrap()
        .name(SYSTEMD)
        .unwrap()
        .serve_at("/org/freedesktop/systemd1", Systemd(state.clone()))
        .unwrap()
        .serve_at("/org/freedesktop/systemd1/unit/test", Unit)
        .unwrap()
        .build()
        .await
        .unwrap();
    let server = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let client = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let sender = client.unique_name().unwrap().to_string();
    let provider = Provider::observe(server, 900).await.unwrap();
    state.locked.store(false, Ordering::SeqCst);
    assert!(provider.switch(&sender, None).await.is_err());
    assert_eq!(state.activated.load(Ordering::SeqCst), 0);
    state.locked.store(true, Ordering::SeqCst);
    state.remote.store(true, Ordering::SeqCst);
    assert!(provider.switch(&sender, None).await.is_err());
    assert_eq!(state.activated.load(Ordering::SeqCst), 0);
    state.remote.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), provider.switch(&sender, None))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.activated.load(Ordering::SeqCst), 1);
    assert_eq!(state.started.load(Ordering::SeqCst), 0);
    state.active.store(false, Ordering::SeqCst);
    state.visible.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), provider.switch(&sender, None))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.started.load(Ordering::SeqCst), 1);
    state.active.store(false, Ordering::SeqCst);
    assert!(provider.switch(&sender, Some("g1")).await.is_err());
    assert_eq!(state.activated.load(Ordering::SeqCst), 1);
    state.active.store(false, Ordering::SeqCst);
    state.visible.store(true, Ordering::SeqCst);
    let wire_server = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let task = tokio::spawn(serve_on(wire_server, 900));
    let daemon_proxy = DBusProxy::new(&client).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !daemon_proxy
            .name_has_owner(BusName::try_from(NAME).unwrap())
            .await
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let proxy = Proxy::new(&client, NAME, PATH, NAME).await.unwrap();
    let introspect = Proxy::new(&client, NAME, PATH, "org.freedesktop.DBus.Introspectable")
        .await
        .unwrap();
    let xml: String = introspect.call("Introspect", &()).await.unwrap();
    assert!(xml.contains("ActivateExisting"));
    state.hold.store(true, Ordering::SeqCst);
    let first_client = client.clone();
    let first = tokio::spawn(async move {
        Proxy::new(&first_client, NAME, PATH, NAME)
            .await
            .unwrap()
            .call::<_, _, ()>("OpenGreeter", &())
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.activated.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let busy = proxy
        .call::<_, _, ()>("OpenGreeter", &())
        .await
        .unwrap_err();
    assert!(
        busy.to_string()
            .contains("Switching is already in progress")
    );
    state.hold.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    state.active.store(false, Ordering::SeqCst);
    let count = state.activated.load(Ordering::SeqCst);
    assert!(
        proxy
            .call::<_, _, ()>("ActivateExisting", &("../../g1",))
            .await
            .is_err()
    );
    assert_eq!(state.activated.load(Ordering::SeqCst), count);
    task.abort();
    let _ = task.await;
    login.release_name(LOGIN).await.unwrap();
    assert!(provider.switch(&sender, None).await.is_err());
    assert_eq!(state.started.load(Ordering::SeqCst), 1);
    systemd.release_name(SYSTEMD).await.unwrap();
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
