// SPDX-License-Identifier: MIT
//! Bus/session authority surrounds private plans and owned one-shot job bodies.
use super::{
    authority::Authority,
    operation_store::Store,
    system_jobs::Jobs,
    system_provider::{Native, Provider},
    system_service::{Call, Handler, Reply},
    system_wire as wire,
};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
/// Whether the backend may advertise the native backup enrollment workflow.
pub const BACKUP_SETUP_RUNTIME_QUALIFIED: bool = true;
/// The `backup_setup` capability. It is advertised as runtime-qualified only
/// when this backend actually serves it: a native provider and an open ledger.
pub(crate) fn backup_setup_capability(served: bool) -> Value {
    json!({"schema":1,"control":"BackupSetupControl(s)->s","input":"BackupSetupInput(sh)->s",
        "runtime_qualified":BACKUP_SETUP_RUNTIME_QUALIFIED && served,
        "ui_qualified":false,"sealed_input_only":true})
}
/// A read-only query that fails while a mutation worker (a backup setup or a
/// job) is running observed state that worker is changing: it is busy, not an
/// unknown result. The internal reason is journaled either way.
pub(crate) fn query_failure(query: &str, error: Error, worker_active: bool) -> Error {
    eprintln!(
        "enzimos-system-backend: {query} query refused: {}",
        enzimos_policy::diagnostic::bounded(&error.0)
    );
    if worker_active && wire::public_failure(&error).starts_with("internal-result-unknown") {
        Error("service-busy".into())
    } else {
        error
    }
}
/// Jobs that, once started, keep running without the approving session, like
/// the scheduled backup: `backup-create` only reads sources and adds a
/// snapshot, and its retention step removes snapshots only by the policy that
/// was approved separately. Planning, approval and the start boundary still
/// bind the live caller; every other job keeps the per-boundary session check.
pub(crate) fn continues_without_session(operation: &str) -> bool {
    operation == "backup-create"
}
/// Session boundary of one admitted job. Returns `Ok(true)` exactly once, on
/// the check that detaches a continuing job from the session.
pub(crate) struct StartBound<F> {
    session: F,
    detach: bool,
    passed: u8,
}
impl<F: FnMut() -> Result<()>> StartBound<F> {
    pub(crate) fn new(detach: bool, session: F) -> Self {
        Self {
            session,
            detach,
            passed: 0,
        }
    }
    pub(crate) fn check(&mut self) -> Result<bool> {
        // Ticket::run checks before verification and the provider checks again
        // at its own entry; a continuing job detaches after both have passed.
        if self.detach && self.passed >= 2 {
            return Ok(false);
        }
        (self.session)()?;
        self.passed = self.passed.saturating_add(1);
        Ok(self.detach && self.passed == 2)
    }
}
struct Alive(Arc<AtomicBool>);
impl Drop for Alive {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
pub struct Api<P> {
    authority: Authority,
    provider: Arc<P>,
    jobs: Arc<Jobs<P>>,
    calls: Arc<tokio::sync::Semaphore>,
    history: Option<super::history_jobs::Ledger>,
    setup: Option<super::backup_setup_jobs::Ledger>,
}
impl Api<Native> {
    pub async fn open(connection: zbus::Connection) -> Result<Self> {
        let provider = Arc::new(Native::open()?);
        let original = provider.clone();
        let guard: Box<dyn Fn() -> Result<()> + Send + Sync> = Box::new(move || original.recheck());
        let store = Store::open(
            &Path::new(enzimos_policy::operation::CONTROL).join("backend-operations"),
            guard,
        )?;
        let original = provider.clone();
        let history_guard: super::history_jobs::Guard = Box::new(move || original.recheck());
        let history = super::jobs::JobStore::open(
            &Path::new(enzimos_policy::operation::CONTROL).join("backend-jobs"),
            history_guard,
        )?;
        let original = provider.clone();
        let setup_guard: super::backup_setup_jobs::Guard = Box::new(move || original.recheck());
        let setup = super::backup_setup_store::SetupStore::open(
            &Path::new(enzimos_policy::operation::CONTROL).join("backend-backup-setup"),
            setup_guard,
        )?;
        Ok(
            Self::new(Authority::new(connection).await?, store, provider)
                .with_history(history)
                .with_setup(setup),
        )
    }
}
impl<P: Provider> Api<P> {
    pub fn new(
        authority: Authority,
        store: Store<Box<dyn Fn() -> Result<()> + Send + Sync>>,
        provider: Arc<P>,
    ) -> Self {
        Self {
            authority,
            jobs: Arc::new(Jobs::new(store, provider.clone())),
            provider,
            calls: Arc::new(tokio::sync::Semaphore::new(8)),
            history: None,
            setup: None,
        }
    }
    pub fn with_history(
        mut self,
        store: super::jobs::JobStore<super::history_jobs::Guard>,
    ) -> Self {
        self.history = Some(Arc::new(std::sync::Mutex::new(store)));
        self
    }
    pub fn with_setup(
        mut self,
        store: super::backup_setup_store::SetupStore<super::backup_setup_jobs::Guard>,
    ) -> Self {
        self.setup = Some(Arc::new(std::sync::Mutex::new(store)));
        self
    }
    fn capabilities(&self) -> Value {
        let mut operations = self.provider.operations().to_vec();
        if self.history.is_some() {
            operations.push("home-history-create");
        }
        json!({"schema":1,"deployment":"dbus-activated",
            "queries":["network-trust","memory-policy","power-policy","history","snapshots","backup-candidates","backups","backup-points"],"operations":operations,
            "arbitrary_command_or_path":false,"long_jobs":"server-made reviewed plans; uncertain results never replay",
            "durable_jobs":"owner UID bound; completed deduplicated; uncertain never replayed",
            "cancellation":"no cancellation after backend entry; disconnect is not rollback",
            "retry":"never retry automatically after timeout/disconnect; result may be unknown",
            "authorization":"polkit system-bus-name; fresh active local session checks",
            "admission":"one mutation worker; queries and status/cancel remain available; no internal queue",
            "ui_qualified":false,"runtime_qualified":false,
            "backup_setup":backup_setup_capability(self.setup.is_some() && self.provider.backup_supported()),
            "login_appearance":{"method":"LoginAppearance(sh)->s","available":self.provider.login_appearance_supported(),"public_opt_in":true,"runtime_qualified":false,"ui_qualified":false},
            "backup_recovery":{"schema":1,"export":"BackupRecoveryExport(s)->sh","confirm":"BackupRecoveryConfirm(s)->s","runtime_qualified":false,"ui_qualified":false,"physical_copy_verified":false,"automatic_backup_enabled":false},
            "backup_remote_share":{"schema":1,"setup":"BackupRemoteShareSetup(sah)->s","control":"BackupRemoteShare(s)->s",
                "actions":["test","remove"],"authorization":"org.enzimos.system.backup-setup","sealed_input_only":true,
                "available":self.provider.backup_supported(),"runtime_qualified":false,"ui_qualified":false},
            "backup_scheduling":{"schema":27,"runtime_qualified":false,"ui_qualified":false,"enable_effect":"next-boot","requires_current_recovery_confirmation":true},
            "background_broker_witness":"InspectBackgroundBroker schema1; observation only, no activation or stop grant"})
    }
    async fn operation(&self, call: Call) -> Result<Reply> {
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let request = wire::Operation::decode(call.body.as_deref().unwrap_or("").as_bytes())?;
        let (operation, step) = (request.operation, request.action);
        let request_id = request.body()["request_id"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let (action, interaction) = request.authorization();
        let grant = Arc::new(
            self.authority
                .authorize(&call.sender, &action, interaction, call.arrived, 150000)
                .await?,
        );
        let uid = grant.peer.uid;
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        let jobs = self.jobs.clone();
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = alive.0.clone();
        let sender = call.sender;
        let (response, ticket) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut check = || {
                require(active.load(Ordering::Acquire), "sender-disconnected")?;
                runtime.block_on(authority.recheck(&grant))
            };
            let mut response = match request.action {
                "plan" => (jobs.plan(&request, uid, &mut check)?, None),
                "status" => {
                    check()?;
                    (jobs.status(&request, uid)?, None)
                }
                "cancel" => (jobs.cancel(&request, uid, &mut check)?, None),
                "submit" => jobs.submit(&request, uid, &mut check)?,
                _ => return Err(Error("operation-unavailable".into())),
            };
            // Storage has its own schema. The method's public version remains
            // the exact request version, including status and deduplication.
            response.0["schema"] = Value::from(request.schema);
            // Keep the original identity with the worker; receiving a queued
            // reply is not a fresh authorization grant for subsequent effects.
            Ok::<_, Error>((response, grant))
        })
        .await
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))?
        .map(|((response, ticket), grant)| (response, ticket.map(|ticket| (ticket, grant))))
        .inspect_err(|error| {
            // The caller only sees the fixed public code; keep the reason.
            eprintln!(
                "enzimos-system-backend: {operation} {step} refused: {}",
                enzimos_policy::diagnostic::bounded(&error.0)
            )
        })?;
        if let Some((ticket, grant)) = ticket {
            let authority = self.authority.clone();
            let runtime = tokio::runtime::Handle::current();
            // This task owns its permit independently of the transport reply.
            // Its durable ticket settles failure and cannot retry the provider.
            tokio::task::spawn_blocking(move || {
                // Admitted jobs (backups, copies, updates) outlive the 150 s
                // request window. Each boundary re-binds the same live caller and
                // a fresh non-interactive authorization, without that deadline, so
                // a lock or session change still stops the job at its next step.
                // A started backup-create is the exception (see StartBound).
                // block_in_place: commit may run inside a coordinator's private
                // runtime, where a bare Handle::block_on panics.
                let wait = |f| tokio::task::block_in_place(|| runtime.block_on(f));
                let session = || {
                    wait(authority.still_bound(&grant))?;
                    let fresh = tokio::task::block_in_place(|| {
                        runtime.block_on(authority.authorize(
                            &sender,
                            "org.enzimos.system.query",
                            false,
                            Instant::now(),
                            10000,
                        ))
                    })?;
                    require(fresh.peer == grant.peer, "not-authorized")?;
                    wait(authority.still_bound(&grant))
                };
                let peer = grant.peer.clone();
                let mut boundary = StartBound::new(continues_without_session(operation), session);
                let mut commit = || {
                    let detached = boundary.check()?;
                    if detached {
                        // Audit: who approved the job that now runs unattended.
                        eprintln!(
                            "enzimos-system-backend: {operation} {request_id} started; approved by uid {} pid {} session {}; continues across screen lock and logout",
                            peer.uid, peer.pid, peer.id
                        );
                    }
                    Ok(())
                };
                if let Err(error) = ticket.run(&mut commit) {
                    eprintln!(
                        "enzimos-system-backend: admitted job ended with error: {}",
                        enzimos_policy::diagnostic::bounded(&error.0)
                    );
                }
            });
        }
        drop(alive);
        Ok(response.into())
    }
    async fn query(&self, call: Call) -> Result<Reply> {
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let request = wire::query(call.body.as_deref().unwrap_or("").as_bytes())?;
        let grant = self
            .authority
            .authorize(
                &call.sender,
                "org.enzimos.system.query",
                false,
                call.arrived,
                150000,
            )
            .await?;
        let peer = grant.peer.clone();
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        let provider = self.provider.clone();
        let query = request["query"].as_str().unwrap().to_owned();
        let name = query.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            runtime.block_on(authority.recheck(&grant))?;
            let result = provider.query(&query)?;
            runtime.block_on(authority.recheck(&grant))?;
            Ok::<_, Error>(result)
        })
        .await
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))?
        .map_err(|error| query_failure(&name, error, self.jobs.active()))?;
        let fresh = self
            .authority
            .authorize(
                &call.sender,
                "org.enzimos.system.query",
                false,
                call.arrived,
                150000,
            )
            .await?;
        require(fresh.peer == peer, "not-authorized")?;
        Ok(json!({"schema":1,"query":request["query"],"result":result}).into())
    }
    async fn history(&self, call: Call, execute: bool) -> Result<Reply> {
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let body = call.body.as_deref().unwrap_or("").as_bytes();
        let request = if execute {
            wire::execute(body)?
        } else {
            wire::job(body)?
        };
        let history = self
            .history
            .clone()
            .ok_or_else(|| Error("operation-unavailable".into()))?;
        let grant = self
            .authority
            .authorize(
                &call.sender,
                "org.enzimos.system.home-history-create",
                request["allow_interaction"].as_bool().unwrap(),
                call.arrived,
                150000,
            )
            .await?;
        let id = if execute {
            enzimos_platform::files::random_hex(16)?
        } else {
            request["request_id"].as_str().unwrap().into()
        };
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        let jobs = self.jobs.clone();
        let provider = self.provider.clone();
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = alive.0.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut commit = || {
                require(active.load(Ordering::Acquire),"sender-disconnected")?;
                runtime.block_on(authority.recheck(&grant))?;
                let fresh = runtime.block_on(authority.authorize(&call.sender,"org.enzimos.system.query",false,Instant::now(),10000))?;
                require(fresh.peer == grant.peer,"not-authorized")?;
                runtime.block_on(authority.recheck(&grant))
            };
            if !execute && request["action"] == "status" {
                commit()?;
                return super::history_jobs::status(&history,&id,grant.peer.uid);
            }
            let result = super::history_jobs::run(&history,&jobs,provider.as_ref(),&id,grant.peer.uid,&mut commit)
                .map_err(|error| {
                    // Execute v1 has no durable job ID in its public reply. Its
                    // legacy failure remains unknown; Job v2 exposes the exact
                    // durable uncertain/no-replay refusal instead.
                    if execute && error.0 == "job-result-uncertain-no-replay" {
                        Error("backend-result-unknown-do-not-retry-automatically".into())
                    } else { error }
                })?;
            if execute {
                Ok(json!({"schema":1,"status":"completed","operation":"home-history-create","snapshot":result["snapshot"]}))
            } else {Ok(result)}
        }).await.map_err(|_|Error("backend-result-unknown-do-not-retry-automatically".into()))??;
        drop(alive);
        Ok(result.into())
    }
}
impl<P: Provider> Handler for Api<P> {
    async fn handle(&self, call: Call) -> Result<Reply> {
        match call.member.as_str() {
            "GetCapabilities" => Ok(self.capabilities().into()),
            "Operation" => self.operation(call).await,
            "Query" => self.query(call).await,
            "Execute" => self.history(call, true).await,
            "Job" => self.history(call, false).await,
            "BackupSetupControl" | "BackupSetupInput" => self.setup(call).await,
            "BackupRecoveryExport" | "BackupRecoveryConfirm" => self.recovery(call).await,
            "BackupRemoteShare" | "BackupRemoteShareSetup" => self.remote_share(call).await,
            "LoginAppearance" => self.appearance(call).await,
            // Remaining providers cannot fall back to Python or arbitrary argv.
            _ => Err(Error("operation-unavailable".into())),
        }
    }
    fn active(&self) -> bool {
        self.jobs.active() || self.calls.available_permits() < 8
    }
    fn stale(&self) -> bool {
        self.authority.stale()
    }
}

#[path = "system_appearance.rs"]
mod appearance;
#[path = "system_recovery.rs"]
mod recovery;
#[path = "system_remote_share.rs"]
mod remote_share;
#[path = "system_setup.rs"]
mod setup;
#[cfg(test)]
#[path = "system_api_tests.rs"]
mod tests;
