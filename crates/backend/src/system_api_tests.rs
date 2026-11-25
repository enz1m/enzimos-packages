// SPDX-License-Identifier: MIT
//! Native API authority is exercised on a disposable bus with fake providers.
use super::super::system_service;
use super::*;
use std::{
    collections::HashMap,
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    process::Stdio,
    sync::{Mutex, atomic::AtomicUsize},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use zbus::{
    MatchRule, MessageStream, Proxy,
    connection::Builder,
    fdo::DBusProxy,
    zvariant::{OwnedObjectPath, OwnedValue},
};
const SESSION: &str = "/org/freedesktop/login1/session/c1";
#[derive(Clone)]
struct State {
    uid: u32,
    locked: Arc<AtomicBool>,
    allowed: Arc<AtomicBool>,
    actions: Arc<Mutex<Vec<(String, u32)>>>,
    hold_setup: Arc<AtomicBool>,
    setup_approval_entered: Arc<AtomicBool>,
}
struct Login;
#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Login {
    #[zbus(name = "GetSessionByPID")]
    fn session(&self, pid: u32) -> OwnedObjectPath {
        assert_eq!(pid, std::process::id());
        SESSION.try_into().unwrap()
    }
}
struct Session(State);
#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl Session {
    #[zbus(property)]
    fn active(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn remote(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.0.locked.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        (
            self.0.uid,
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
        "user"
    }
    #[zbus(property, name = "Type")]
    fn kind(&self) -> &str {
        "wayland"
    }
    #[zbus(property)]
    fn id(&self) -> &str {
        "c1"
    }
}
struct Policy(State);
#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Policy {
    async fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedValue>),
        action: &str,
        details: HashMap<String, String>,
        flags: u32,
        id: &str,
    ) -> (bool, bool, HashMap<String, String>) {
        assert_eq!(subject.0, "system-bus-name");
        assert_eq!(subject.1.len(), 1);
        let sender = String::try_from(subject.1["name"].try_clone().unwrap()).unwrap();
        assert!(sender.starts_with(':'));
        assert!(matches!(
            action,
            "org.enzimos.system.query"
                | "org.enzimos.system.home-history-set"
                | "org.enzimos.system.home-history-create"
                | "org.enzimos.system.backup-setup"
                | "org.enzimos.system.backup-remote-check"
                | "org.enzimos.system.backup-export"
                | "org.enzimos.system.backup-confirm-copy"
        ));
        assert!(details.is_empty() && flags <= 1 && !id.is_empty());
        self.0.actions.lock().unwrap().push((action.into(), flags));
        if action == "org.enzimos.system.backup-setup" {
            self.0.setup_approval_entered.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.0.hold_setup.load(Ordering::SeqCst) {
                assert!(
                    Instant::now() < deadline,
                    "fixture approval deadline exceeded"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        (self.0.allowed.load(Ordering::SeqCst), false, HashMap::new())
    }
    fn cancel_check_authorization(&self, _id: &str) {}
}
struct Fake {
    planned: AtomicUsize,
    mutations: AtomicUsize,
    snapshots: AtomicUsize,
    hold: AtomicBool,
    entered: AtomicBool,
    revoke_read: AtomicBool,
    recoveries: AtomicUsize,
    shares: AtomicUsize,
    state: State,
}
impl Provider for Fake {
    fn backup_supported(&self) -> bool {
        true
    }
    fn backup_review(
        &self,
        _: &Value,
        authorize: &dyn Fn() -> Result<()>,
        _: &mut dyn FnMut(&enzimos_policy::backup_setup_plan::Plan<'_, '_, '_>) -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.entered.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.hold.load(Ordering::SeqCst) {
            require(Instant::now() < deadline, "fixture deadline exceeded")?;
            std::thread::sleep(Duration::from_millis(1));
        }
        authorize()?;
        Err(Error("fixture declines native device review".into()))
    }
    fn backup_recovery_export(
        &self,
        uid: u32,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<(Value, std::fs::File)> {
        authorize()?;
        assert_eq!(uid, self.state.uid);
        self.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok((
            json!({"schema":1,"status":"backup-recovery-exported","ticket":"c".repeat(64),"sealed_descriptor":true}),
            enzimos_platform::memfile::sealed("recovery-fixture", b"recovery fixture\n")?,
        ))
    }
    fn backup_recovery_confirm(
        &self,
        uid: u32,
        ticket: &str,
        assertion: &str,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        authorize()?;
        assert_eq!(
            (uid, assertion),
            (self.state.uid, "saved-outside-this-computer")
        );
        require(
            ticket == "c".repeat(64),
            "recovery copy needs a fresh export",
        )?;
        self.recoveries.fetch_add(1, Ordering::SeqCst);
        Ok(
            json!({"schema":1,"status":"backup-recovery-copy-attested","automatic_backup_enabled":false}),
        )
    }
    fn backup_remote_share(
        &self,
        request: &Value,
        share: Option<&enzimos_platform::secret::Retained>,
        repository: Option<&enzimos_platform::secret::Retained>,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        authorize()?;
        self.shares.fetch_add(1, Ordering::SeqCst);
        if request["action"] == "test" {
            return Ok(json!({"schema":1,"status":"remote-share-tested","reachable":true}));
        }
        // The provider receives the sealed inputs, never their bytes in JSON.
        assert_eq!(request["share"]["server"], "nas.local");
        assert_eq!(share.unwrap().length()?, b"share secret".len());
        Ok(
            json!({"schema":1,"status":"remote-share-configured","repository_password":
            if repository.is_some() {"entered"} else {"local-backup"}}),
        )
    }
    fn operations(&self) -> &[&'static str] {
        &["home-history-set"]
    }
    fn plan(&self, operation: &str, selection: &Value, id: &str, uid: u32) -> Result<Value> {
        self.planned.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"operation":operation,"selection":selection,"request_id":id,"uid":uid}))
    }
    fn verify(&self, _: &Value) -> Result<()> {
        Ok(())
    }
    fn run(
        &self,
        plan: &Value,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        progress("capturing")?;
        self.entered.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.hold.load(Ordering::SeqCst) {
            require(Instant::now() < deadline, "fixture deadline exceeded")?;
            std::thread::sleep(Duration::from_millis(1));
        }
        commit()?;
        self.mutations.fetch_add(1, Ordering::SeqCst);
        progress("finishing")?;
        Ok(
            json!({"enabled":plan["selection"]["enabled"],"state":"enabled","existing_history_removed":false}),
        )
    }
    fn history(&self, commit: &mut dyn FnMut() -> Result<()>) -> Result<u64> {
        commit()?;
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        Ok(42)
    }
    fn query(&self, _: &str) -> Result<Value> {
        if self.revoke_read.load(Ordering::SeqCst) {
            self.state.locked.store(true, Ordering::SeqCst);
        }
        Ok(json!({"read_only":true}))
    }
}
fn request(id: &str, action: &str, sha: Value) -> String {
    json!({"schema":26,"operation":"home-history-set","request_id":id,"action":action,"plan_sha256":sha,
        "selection":if action=="plan" {json!({"enabled":true})} else {Value::Null},"allow_interaction":true}).to_string()
}
async fn operation(proxy: &Proxy<'_>, id: &str, action: &str, sha: Value) -> Value {
    let body: String = proxy
        .call("Operation", &request(id, action, sha))
        .await
        .unwrap();
    let result: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        result["schema"], 26,
        "operation replies preserve their wire version"
    );
    result
}
async fn terminal(proxy: &Proxy<'_>, id: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let value = operation(proxy, id, "status", Value::Null).await;
            if matches!(value["state"].as_str(), Some("completed" | "uncertain")) {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_sender_authority_revocation_and_provider_owner_changes_never_replay() {
    let _fork_guard = crate::LOCK_FIXTURE_GUARD.lock().unwrap();
    let uid = enzimos_platform::process_identity::real_uid();
    assert!(
        uid >= 1000,
        "this fixture requires the ordinary lab account"
    );
    let work = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let temp = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
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
    let mut reader = BufReader::new(daemon.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(line.starts_with(&address));
    let state = State {
        uid,
        locked: Arc::new(AtomicBool::new(false)),
        allowed: Arc::new(AtomicBool::new(true)),
        actions: Arc::new(Mutex::new(Vec::new())),
        hold_setup: Arc::new(AtomicBool::new(false)),
        setup_approval_entered: Arc::new(AtomicBool::new(false)),
    };
    let login = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.login1")
        .unwrap()
        .serve_at("/org/freedesktop/login1", Login)
        .unwrap()
        .serve_at(SESSION, Session(state.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let policy = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.PolicyKit1")
        .unwrap()
        .serve_at(
            "/org/freedesktop/PolicyKit1/Authority",
            Policy(state.clone()),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let server = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let authority = Authority::new(server.clone()).await.unwrap();
    let guard: Box<dyn Fn() -> Result<()> + Send + Sync> = Box::new(|| Ok(()));
    let store = Store::open_owned(&temp.path().join("ledger"), uid, guard).unwrap();
    let provider = Arc::new(Fake {
        planned: AtomicUsize::new(0),
        mutations: AtomicUsize::new(0),
        snapshots: AtomicUsize::new(0),
        hold: AtomicBool::new(false),
        entered: AtomicBool::new(false),
        revoke_read: AtomicBool::new(false),
        recoveries: AtomicUsize::new(0),
        shares: AtomicUsize::new(0),
        state: state.clone(),
    });
    let stream = MessageStream::for_match_rule(
        MatchRule::builder()
            .msg_type(zbus::message::Type::MethodCall)
            .build(),
        &server,
        Some(32),
    )
    .await
    .unwrap();
    let guard: super::super::history_jobs::Guard = Box::new(|| Ok(()));
    let history =
        super::super::jobs::JobStore::open_owned(&temp.path().join("history"), uid, guard).unwrap();
    let setup_guard: super::super::backup_setup_jobs::Guard = Box::new(|| Ok(()));
    let setup = super::super::backup_setup_store::SetupStore::open_owned(
        &temp.path().join("setup"),
        uid,
        setup_guard,
    )
    .unwrap();
    let approval_authority = authority.clone();
    let api = Api::new(authority, store, provider.clone())
        .with_history(history)
        .with_setup(setup);
    let service = tokio::spawn(system_service::serve(stream, api, Duration::from_secs(60)));
    let caller = Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let bus = DBusProxy::new(&caller).await.unwrap();
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
    let proxy = Proxy::new(&caller, wire::BUS, wire::PATH, wire::BUS)
        .await
        .unwrap();
    let sender = caller.unique_name().unwrap().as_str();
    let peer = approval_authority
        .authorize(
            sender,
            "org.enzimos.system.query",
            false,
            Instant::now(),
            10000,
        )
        .await
        .unwrap()
        .peer;
    let approval = approval_authority
        .approve_setup(sender, true, Instant::now(), &peer)
        .await
        .unwrap();
    approval.recheck(&approval_authority).await.unwrap();
    state.locked.store(true, Ordering::SeqCst);
    assert!(approval.recheck(&approval_authority).await.is_err());
    state.locked.store(false, Ordering::SeqCst);
    state.allowed.store(false, Ordering::SeqCst);
    assert!(approval.recheck(&approval_authority).await.is_err());
    state.allowed.store(true, Ordering::SeqCst);
    let mut wrong = peer.clone();
    wrong.pid += 1;
    assert!(
        approval_authority
            .approve_setup(sender, false, Instant::now(), &wrong)
            .await
            .is_err()
    );
    assert!(
        approval_authority
            .approve_setup(
                sender,
                false,
                Instant::now() - Duration::from_secs(151),
                &peer
            )
            .await
            .is_err()
    );
    state.actions.lock().unwrap().clear();
    // Cancellation must observe the real pending authorization boundary,
    // rather than relying on timing between a reply and worker entry.
    let cancel_id = "66666666666666666666666666666666";
    let cancel_request = |action: &str, sha: Value| {
        json!({"schema":1,"request_id":cancel_id,"action":action,"plan_sha256":sha,
        "selection_id":if action=="plan" {json!("c".repeat(64))} else {Value::Null},
        "mode":if action=="plan" {json!("adopt")} else {Value::Null},"allow_interaction":action=="plan"}).to_string()
    };
    state.hold_setup.store(true, Ordering::SeqCst);
    state.setup_approval_entered.store(false, Ordering::SeqCst);
    let response: String = proxy
        .call("BackupSetupControl", &cancel_request("plan", Value::Null))
        .await
        .unwrap();
    let queued: Value = serde_json::from_str(&response).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.setup_approval_entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let cancelled: String = proxy
        .call(
            "BackupSetupControl",
            &cancel_request("cancel", queued["plan_sha256"].clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&cancelled).unwrap()["state"],
        "cancelled"
    );
    let repeated: String = proxy
        .call(
            "BackupSetupControl",
            &cancel_request("cancel", queued["plan_sha256"].clone()),
        )
        .await
        .unwrap();
    assert_eq!(cancelled, repeated);
    assert!(!provider.entered.load(Ordering::SeqCst));
    state.hold_setup.store(false, Ordering::SeqCst);
    // Wait until the actual original ticket releases its shared permit.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match proxy
                .call::<_, _, String>("BackupSetupControl", &cancel_request("plan", Value::Null))
                .await
            {
                Ok(body) => {
                    assert_eq!(
                        serde_json::from_str::<Value>(&body).unwrap()["state"],
                        "cancelled"
                    );
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    })
    .await
    .unwrap();
    assert!(!provider.entered.load(Ordering::SeqCst));
    state.actions.lock().unwrap().clear();
    let id = "11111111111111111111111111111111";
    let plan = operation(&proxy, id, "plan", Value::Null).await;
    assert_eq!(
        state.actions.lock().unwrap()[0],
        ("org.enzimos.system.query".into(), 0)
    );
    operation(&proxy, id, "submit", plan["plan_sha256"].clone()).await;
    assert_eq!(terminal(&proxy, id).await["state"], "completed");
    assert!(
        state
            .actions
            .lock()
            .unwrap()
            .contains(&("org.enzimos.system.home-history-set".into(), 1))
    );
    assert_eq!(
        operation(&proxy, id, "submit", plan["plan_sha256"].clone()).await["state"],
        "completed"
    );
    assert_eq!(provider.mutations.load(Ordering::SeqCst), 1);
    let setup_id = "77777777777777777777777777777777";
    let setup_request = |action: &str, sha: Value| {
        json!({"schema":1,"request_id":setup_id,"action":action,"plan_sha256":sha,"selection_id":if action=="plan" {json!("a".repeat(64))} else {Value::Null},"mode":if action=="plan" {json!("initialize")} else {Value::Null},"allow_interaction":action=="plan"}).to_string()
    };
    provider.hold.store(true, Ordering::SeqCst);
    provider.entered.store(false, Ordering::SeqCst);
    let setup_reply: String = proxy
        .call("BackupSetupControl", &setup_request("plan", Value::Null))
        .await
        .unwrap();
    let setup_value: Value = serde_json::from_str(&setup_reply).unwrap();
    assert_eq!(setup_value["state"], "review-awaiting-approval");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !provider.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let status: String = proxy
        .call("BackupSetupControl", &setup_request("status", Value::Null))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&status).unwrap()["state"],
        "reviewing"
    );
    assert!(
        proxy
            .call::<_, _, String>("BackupSetupControl", &setup_request("plan", Value::Null))
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<_, _, String>(
                "BackupSetupControl",
                &setup_request("cancel", setup_value["plan_sha256"].clone())
            )
            .await
            .is_err()
    );
    assert!(
        proxy
            .call::<_, _, String>(
                "Execute",
                &r#"{"schema":1,"operation":"home-history-create","allow_interaction":false}"#
            )
            .await
            .is_err()
    );
    state.locked.store(true, Ordering::SeqCst);
    provider.hold.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let bytes =
                std::fs::read(temp.path().join("setup").join(format!("{setup_id}.json"))).unwrap();
            if serde_json::from_slice::<Value>(&bytes).unwrap()["state"] == "uncertain" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    state.locked.store(false, Ordering::SeqCst);
    let duplicate: String = proxy
        .call("BackupSetupControl", &setup_request("plan", Value::Null))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&duplicate).unwrap()["state"],
        "uncertain"
    );
    assert!(
        state
            .actions
            .lock()
            .unwrap()
            .contains(&("org.enzimos.system.backup-setup".into(), 1))
    );
    let history_id = "99999999999999999999999999999999";
    let history_request = |action: &str| {
        json!({"schema":2,"operation":"home-history-create","action":action,"request_id":history_id,"allow_interaction":true}).to_string()
    };
    let response: String = proxy.call("Job", &history_request("submit")).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap(),
        json!({"schema":2,"operation":"home-history-create","request_id":history_id,"state":"completed","snapshot":42})
    );
    let repeated: String = proxy.call("Job", &history_request("submit")).await.unwrap();
    assert_eq!(repeated, response);
    assert_eq!(provider.snapshots.load(Ordering::SeqCst), 1);
    let execute: String = proxy
        .call(
            "Execute",
            &r#"{"schema":1,"operation":"home-history-create","allow_interaction":true}"#,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&execute).unwrap(),
        json!({"schema":1,"operation":"home-history-create","status":"completed","snapshot":42})
    );
    assert_eq!(provider.snapshots.load(Ordering::SeqCst), 2);
    // Recovery export replies with its JSON and one sealed descriptor; the
    // confirmation names that export's ticket. Each has its own polkit action.
    state.actions.lock().unwrap().clear();
    let reply = proxy
        .call_method(
            "BackupRecoveryExport",
            &r#"{"schema":1,"allow_interaction":true}"#,
        )
        .await
        .unwrap();
    let (text, fd): (String, zbus::zvariant::OwnedFd) = reply.body().deserialize().unwrap();
    let exported: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(exported["status"], "backup-recovery-exported");
    let copy = std::fs::File::from(std::os::fd::OwnedFd::from(fd));
    assert_eq!(
        std::fs::read(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&copy)
        ))
        .unwrap(),
        b"recovery fixture\n"
    );
    assert_eq!(
        state.actions.lock().unwrap()[0],
        ("org.enzimos.system.backup-export".into(), 1)
    );
    let confirm = |ticket: &str| {
        json!({"schema":1,"allow_interaction":false,"ticket":ticket,"assertion":"saved-outside-this-computer"}).to_string()
    };
    let confirmed: String = proxy
        .call(
            "BackupRecoveryConfirm",
            &confirm(exported["ticket"].as_str().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&confirmed).unwrap()["status"],
        "backup-recovery-copy-attested"
    );
    assert!(
        state
            .actions
            .lock()
            .unwrap()
            .contains(&("org.enzimos.system.backup-confirm-copy".into(), 0))
    );
    assert!(
        proxy
            .call::<_, _, String>("BackupRecoveryConfirm", &confirm(&"d".repeat(64)))
            .await
            .is_err()
    );
    // Malformed or refused requests never reach the provider.
    let actions = state.actions.lock().unwrap().len();
    assert!(
        proxy
            .call::<_, _, String>(
                "BackupRecoveryExport",
                &r#"{"schema":1,"allow_interaction":true,"ticket":"x"}"#
            )
            .await
            .is_err()
    );
    assert_eq!(state.actions.lock().unwrap().len(), actions);
    state.allowed.store(false, Ordering::SeqCst);
    assert!(
        proxy
            .call_method(
                "BackupRecoveryExport",
                &r#"{"schema":1,"allow_interaction":false}"#
            )
            .await
            .is_err()
    );
    state.allowed.store(true, Ordering::SeqCst);
    assert_eq!(provider.recoveries.load(Ordering::SeqCst), 2);
    // NAS share setup takes sealed private inputs only, under the backup-setup
    // action; an ordinary readable descriptor never reaches the provider.
    state.actions.lock().unwrap().clear();
    let setup = json!({"schema":1,"allow_interaction":true,"share":
        {"server":"nas.local","share":"backups","folder":"enzimos/pc","user":"ann"}})
    .to_string();
    let share = enzimos_platform::memfile::sealed("share-fixture", b"share secret").unwrap();
    let reply = proxy
        .call_method(
            "BackupRemoteShareSetup",
            &(
                setup.as_str(),
                vec![zbus::zvariant::Fd::from(std::os::fd::AsFd::as_fd(&share))],
            ),
        )
        .await
        .unwrap();
    let text: String = reply.body().deserialize().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["repository_password"],
        "local-backup"
    );
    assert_eq!(
        state.actions.lock().unwrap()[0],
        ("org.enzimos.system.backup-setup".into(), 1)
    );
    let plain = std::fs::File::open("/dev/null").unwrap();
    let refused = proxy
        .call_method(
            "BackupRemoteShareSetup",
            &(
                setup.as_str(),
                vec![zbus::zvariant::Fd::from(std::os::fd::AsFd::as_fd(&plain))],
            ),
        )
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("remote-share-secret-refused"),
        "{refused}"
    );
    let injected = setup.replace("\"ann\"", "\"ann,uid=0\"");
    assert!(
        proxy
            .call_method(
                "BackupRemoteShareSetup",
                &(
                    injected.as_str(),
                    vec![zbus::zvariant::Fd::from(std::os::fd::AsFd::as_fd(&share))]
                ),
            )
            .await
            .is_err()
    );
    let tested: String = proxy
        .call(
            "BackupRemoteShare",
            &r#"{"schema":1,"allow_interaction":false,"action":"test"}"#,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&tested).unwrap()["reachable"],
        true
    );
    assert!(
        state
            .actions
            .lock()
            .unwrap()
            .contains(&("org.enzimos.system.backup-remote-check".into(), 0)),
        "a test asks to check the share, not to configure it"
    );
    assert_eq!(provider.shares.load(Ordering::SeqCst), 2);
    let id = "22222222222222222222222222222222";
    let plan = operation(&proxy, id, "plan", Value::Null).await;
    provider.hold.store(true, Ordering::SeqCst);
    provider.entered.store(false, Ordering::SeqCst);
    operation(&proxy, id, "submit", plan["plan_sha256"].clone()).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !provider.entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let query: String = proxy
        .call("Query", &r#"{"schema":1,"query":"network-trust"}"#)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&query).unwrap()["result"]["read_only"],
        true
    );
    let history_status: String = proxy.call("Job", &history_request("status")).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&history_status).unwrap()["state"],
        "completed"
    );
    let busy = json!({"schema":2,"operation":"home-history-create","action":"submit","request_id":"88888888888888888888888888888888","allow_interaction":false}).to_string();
    assert!(proxy.call::<_, _, String>("Job", &busy).await.is_err());
    assert_eq!(provider.snapshots.load(Ordering::SeqCst), 2);
    assert!(
        proxy
            .call::<_, _, String>(
                "Operation",
                &request(id, "cancel", plan["plan_sha256"].clone())
            )
            .await
            .is_err()
    );
    state.locked.store(true, Ordering::SeqCst);
    provider.hold.store(false, Ordering::SeqCst);
    // Keep revocation in force until the actual fixture ledger records the
    // failed boundary. A sleep cannot prove that the worker observed the lock.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let bytes =
                std::fs::read(temp.path().join("ledger").join(format!("{id}.json"))).unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            if body["state"] == "uncertain" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        proxy
            .call::<_, _, String>("Operation", &request(id, "status", Value::Null))
            .await
            .is_err()
    );
    state.locked.store(false, Ordering::SeqCst);
    assert_eq!(terminal(&proxy, id).await["state"], "uncertain");
    assert!(
        proxy
            .call::<_, _, String>(
                "Operation",
                &request(id, "submit", plan["plan_sha256"].clone())
            )
            .await
            .is_err()
    );
    assert_eq!(provider.mutations.load(Ordering::SeqCst), 1);
    provider.revoke_read.store(true, Ordering::SeqCst);
    assert!(
        proxy
            .call::<_, _, String>("Query", &r#"{"schema":1,"query":"network-trust"}"#)
            .await
            .is_err()
    );
    state.locked.store(false, Ordering::SeqCst);
    provider.revoke_read.store(false, Ordering::SeqCst);
    state.allowed.store(false, Ordering::SeqCst);
    assert!(
        proxy
            .call::<_, _, String>(
                "Operation",
                &request("33333333333333333333333333333333", "plan", Value::Null)
            )
            .await
            .is_err()
    );
    assert_eq!(provider.planned.load(Ordering::SeqCst), 2);
    state.allowed.store(true, Ordering::SeqCst);
    policy
        .release_name("org.freedesktop.PolicyKit1")
        .await
        .unwrap();
    let replacement = Builder::address(address.as_str())
        .unwrap()
        .name("org.freedesktop.PolicyKit1")
        .unwrap()
        .serve_at(
            "/org/freedesktop/PolicyKit1/Authority",
            Policy(state.clone()),
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let actions = state.actions.lock().unwrap().len();
    assert!(
        proxy
            .call::<_, _, String>("Operation", &request(id, "status", Value::Null))
            .await
            .is_err()
    );
    assert_eq!(state.actions.lock().unwrap().len(), actions);
    assert!(approval.recheck(&approval_authority).await.is_err());
    assert_eq!(provider.mutations.load(Ordering::SeqCst), 1);
    service.abort();
    let _ = service.await;
    drop(proxy);
    drop(bus);
    drop(caller);
    drop(server);
    drop(replacement);
    drop(policy);
    drop(login);
    daemon.kill().await.unwrap();
    daemon.wait().await.unwrap();
}
