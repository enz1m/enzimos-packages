// SPDX-License-Identifier: MIT
//! One admitted setup worker; retained sealed input and no queued/replayed effects.
use crate::{
    authority::{Authority, Peer},
    backup_setup_store::SetupStore,
    system_provider::Provider,
};
use enzimos_platform::{Error, Result, require, secret};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::sync::OwnedSemaphorePermit;
pub(crate) type Guard = Box<dyn Fn() -> Result<()> + Send + Sync>;
pub(crate) type Ledger = Arc<Mutex<SetupStore<Guard>>>;
pub(crate) fn lock(ledger: &Ledger) -> Result<std::sync::MutexGuard<'_, SetupStore<Guard>>> {
    ledger
        .lock()
        .map_err(|_| Error("job-store-needs-review".into()))
}
pub(crate) struct Ticket<P> {
    ledger: Ledger,
    provider: Arc<P>,
    _permit: OwnedSemaphorePermit,
    id: String,
    uid: u32,
    sha: String,
    peer: Peer,
    sender: String,
    interaction: bool,
    input: Option<secret::Retained>,
    arrived: std::time::Instant,
    caller: Arc<enzimos_platform::peer_lifetime::PeerLifetime>,
    entered: bool,
    settled: bool,
}
impl<P: Provider> Ticket<P> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument is a distinct admitted request input."
    )]
    pub(crate) fn review(
        ledger: Ledger,
        provider: Arc<P>,
        permit: OwnedSemaphorePermit,
        id: &str,
        selection: &str,
        mode: &str,
        peer: Peer,
        sender: String,
        interaction: bool,
        arrived: std::time::Instant,
    ) -> Result<(Value, Option<Self>)> {
        let caller = Arc::new(enzimos_platform::peer_lifetime::PeerLifetime::capture(
            peer.pid, peer.uid,
        )?);
        let (response, created) = lock(&ledger)?.admit_review(id, peer.uid, selection, mode)?;
        if !created {
            return Ok((response, None));
        }
        let sha = enzimos_platform::json::string(&response["plan_sha256"])?.into();
        Ok((
            response,
            Some(Self {
                ledger,
                provider,
                _permit: permit,
                id: id.into(),
                uid: peer.uid,
                sha,
                peer,
                sender,
                interaction,
                input: None,
                arrived,
                caller,
                entered: false,
                settled: false,
            }),
        ))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument is a distinct admitted request input."
    )]
    pub(crate) fn input(
        ledger: Ledger,
        provider: Arc<P>,
        permit: OwnedSemaphorePermit,
        id: &str,
        sha: &str,
        peer: Peer,
        sender: String,
        interaction: bool,
        input: secret::Retained,
        arrived: std::time::Instant,
    ) -> Result<(Value, Self)> {
        let caller = Arc::new(enzimos_platform::peer_lifetime::PeerLifetime::capture(
            peer.pid, peer.uid,
        )?);
        let response = lock(&ledger)?.queue_input(id, peer.uid, sha, &input)?;
        Ok((
            response,
            Self {
                ledger,
                provider,
                _permit: permit,
                id: id.into(),
                uid: peer.uid,
                sha: sha.into(),
                peer,
                sender,
                interaction,
                input: Some(input),
                arrived,
                caller,
                entered: false,
                settled: false,
            },
        ))
    }
    /// Run the admitted worker once. Every failure is written to the journal
    /// with the request ID, the phase and a bounded reason (never input bytes).
    pub(crate) fn run(self, authority: Authority, runtime: tokio::runtime::Handle) -> Result<()> {
        let id = self.id.clone();
        let input = self.input.is_some();
        let result = self.execute(authority, runtime);
        if let Err(error) = &result {
            crate::backup_setup_failure::log(&format!(
                "request {id} ({}) ended with error: {}",
                if input { "enrollment" } else { "review" },
                error.0
            ));
        }
        result
    }
    fn execute(mut self, authority: Authority, runtime: tokio::runtime::Handle) -> Result<()> {
        self.caller.recheck()?;
        let scope = blocking(
            &runtime,
            authority.approve_setup(&self.sender, self.interaction, self.arrived, &self.peer),
        )
        .map_err(|e| Error(format!("approval: {}", e.0)))?;
        let caller = std::sync::Arc::clone(&self.caller);
        let authorize = || {
            caller.recheck()?;
            blocking(&runtime, scope.recheck(&authority))?;
            caller.recheck()
        };
        authorize()?;
        let state = lock(&self.ledger)?.private(&self.id, self.uid, &self.sha)?;
        if state["state"] == "cancelled" {
            self.settled = true;
            return Ok(());
        }
        let phase = if self.input.is_some() {
            "running"
        } else {
            "reviewing"
        };
        authorize()?;
        lock(&self.ledger)?.change(&self.id, self.uid, &self.sha, phase)?;
        self.entered = true;
        if let Some(input) = &self.input {
            let finished =
                match self
                    .provider
                    .backup_setup(&state["plan"], &self.sha, input, &authorize)
                {
                    Ok(finished) => finished,
                    Err(error) if crate::backup_setup_failure::proven_rollback(&error) => {
                        // Proven rollback: terminal and distinct from uncertain. No
                        // fresh authorization is needed to record our own outcome.
                        lock(&self.ledger)?.change(&self.id, self.uid, &self.sha, "rolled-back")?;
                        self.settled = true;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
            authorize()?;
            lock(&self.ledger)?.settle(&self.id, self.uid, &self.sha, &finished, &authorize)?;
            self.settled = true;
            return Ok(());
        }
        let ledger = std::sync::Arc::clone(&self.ledger);
        let id = self.id.clone();
        let uid = self.uid;
        let sha = self.sha.clone();
        let mut publish = |plan: &enzimos_policy::backup_setup_plan::Plan<'_, '_, '_>| {
            authorize()?;
            lock(&ledger)?.reviewed(&id, uid, &sha, plan)?;
            self.settled = true;
            Ok(())
        };
        let provider = std::sync::Arc::clone(&self.provider);
        provider.backup_review(&state["plan"], &authorize, &mut publish)?;
        require(
            self.settled,
            "review provider did not publish original typed plan",
        )
    }
}
/// Block on the service runtime from a worker thread. Provision and input
/// workers drive their PID1/IPC futures on a private runtime and call the
/// approval recheck from inside it; a bare `Handle::block_on` there panics
/// ("Cannot start a runtime from within a runtime"). `block_in_place` leaves
/// that runtime context first and is a plain call on a blocking-pool thread.
pub(crate) fn blocking<F: std::future::Future>(
    runtime: &tokio::runtime::Handle,
    future: F,
) -> F::Output {
    tokio::task::block_in_place(|| runtime.block_on(future))
}
impl<P> Drop for Ticket<P> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // No fresh execution authority is needed to classify this original
        // abandoned ticket. Store source/epoch/exclusion guards still apply.
        let outcome = || -> Result<()> {
            let mut store = lock(&self.ledger)?;
            let current = store.private(&self.id, self.uid, &self.sha)?;
            if matches!(
                current["state"].as_str(),
                Some("review-awaiting-approval" | "reviewing" | "awaiting-approval" | "running")
            ) {
                store.change(
                    &self.id,
                    self.uid,
                    &self.sha,
                    if self.entered { "uncertain" } else { "refused" },
                )?;
            }
            Ok(())
        };
        if let Err(error) = outcome() {
            crate::backup_setup_failure::log(&format!(
                "request {} could not be classified after an abandoned run: {}",
                self.id, error.0
            ));
        }
    }
}
