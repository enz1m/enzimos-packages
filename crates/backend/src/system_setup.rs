// SPDX-License-Identifier: MIT
//! Live setup wire admission and asynchronous one-shot reviewed/input workers.
use super::{Alive, Api};
use crate::{
    backup_setup_jobs::{self, Ticket},
    backup_setup_wire::Request,
    system_provider::Provider,
    system_service::{Call, Reply},
};
use enzimos_platform::{Error, Result, require, secret};
use std::{
    os::fd::AsFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
impl<P: Provider> Api<P> {
    pub(super) async fn setup(&self, call: Call) -> Result<Reply> {
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let input_call = call.member == "BackupSetupInput";
        let request = Request::decode(call.body.as_deref().unwrap_or("").as_bytes(), input_call)?;
        let ledger = self
            .setup
            .clone()
            .ok_or_else(|| Error("operation-unavailable".into()))?;
        require(self.provider.backup_supported(), "operation-unavailable")?;
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
        require(grant.peer.uid < i32::MAX as u32, "not-authorized")?;
        let peer = grant.peer.clone();
        let uid = peer.uid;
        let worker = if matches!(request.action, "plan" | "submit") {
            Some(self.jobs.worker_permit()?)
        } else {
            None
        };
        let input = if input_call {
            let file = call
                .descriptor
                .as_ref()
                .ok_or_else(|| Error("wire-signature".into()))?;
            Some(secret::retain(file.as_fd(), uid)?)
        } else {
            require(call.descriptor.is_none(), "wire-signature")?;
            None
        };
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        let provider = self.provider.clone();
        let sender = call.sender;
        let arrived = call.arrived;
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = alive.0.clone();
        let (response, ticket) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            require(active.load(Ordering::Acquire), "sender-disconnected")?;
            runtime.block_on(authority.recheck(&grant))?;
            let body = request.body();
            let id = body["request_id"].as_str().unwrap();
            let sha = body["plan_sha256"].as_str().unwrap_or("");
            let response = match request.action {
                "status" => {
                    let mut store = backup_setup_jobs::lock(&ledger)?;
                    reconcile_reset(&mut store, id, uid);
                    (store.status(id, uid)?, None)
                }
                "cancel" => {
                    let mut store = backup_setup_jobs::lock(&ledger)?;
                    let old = store.private(id, uid, sha)?;
                    if old["state"] == "cancelled" {
                        (store.status(id, uid)?, None)
                    } else {
                        (store.change(id, uid, sha, "cancelled")?, None)
                    }
                }
                "plan" => Ticket::review(
                    ledger,
                    provider,
                    worker.unwrap(),
                    id,
                    body["selection_id"].as_str().unwrap(),
                    body["mode"].as_str().unwrap(),
                    peer,
                    sender,
                    body["allow_interaction"].as_bool().unwrap(),
                    arrived,
                )?,
                "submit" => {
                    let (response, ticket) = Ticket::input(
                        ledger,
                        provider,
                        worker.unwrap(),
                        id,
                        sha,
                        peer,
                        sender,
                        body["allow_interaction"].as_bool().unwrap(),
                        input.unwrap(),
                        arrived,
                    )?;
                    (response, Some(ticket))
                }
                _ => return Err(Error("operation-unavailable".into())),
            };
            runtime.block_on(authority.recheck(&grant))?;
            Ok::<_, Error>(response)
        })
        .await
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))??;
        if let Some(ticket) = ticket {
            let authority = self.authority.clone();
            let runtime = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                // Errors are journaled inside run(); a panic is journaled here
                // and the ticket's Drop still records the attempt as uncertain.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    ticket.run(authority, runtime)
                }));
                if let Err(panic) = outcome {
                    let text = panic
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_owned())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-text panic".into());
                    crate::backup_setup_failure::log(&format!("worker panicked: {text}"));
                }
            });
        }
        drop(alive);
        Ok(response.into())
    }
}
/// A later `reset-uncertain` may have proven this request's rollback; settle
/// the job record before reporting it. Never fails the status read.
fn reconcile_reset<G: Fn() -> Result<()>>(
    store: &mut crate::backup_setup_store::SetupStore<G>,
    id: &str,
    uid: u32,
) {
    let outcome = crate::backup_setup_failure::reset_proof().and_then(|proof| {
        let Some(proof) = proof else {
            return Ok(false);
        };
        let facts = crate::backup_setup_failure::observe(false)?;
        store.reconcile_reset(id, uid, Some(&proof), facts)
    });
    match outcome {
        Ok(true) => crate::backup_setup_failure::log(&format!(
            "request {id} recorded rolled-back after reset-uncertain proved its retraction"
        )),
        Ok(false) => {}
        Err(error) => crate::backup_setup_failure::log(&format!(
            "reset proof for request {id} not applied: {}",
            error.0
        )),
    }
}
