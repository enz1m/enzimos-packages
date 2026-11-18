// SPDX-License-Identifier: MIT
//! Recovery password export (JSON plus one sealed descriptor) and the owner's
//! later copy confirmation. Each is one freshly approved call that holds the
//! single mutation worker; the reply goes only to the same still-authorized
//! caller. Nothing is queued, retried or replayed.
use super::{Alive, Api};
use crate::{
    system_provider::Provider,
    system_service::{Call, Reply},
    system_wire as wire,
};
use enzimos_platform::{Error, Result, require};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
impl<P: Provider> Api<P> {
    pub(super) async fn recovery(&self, call: Call) -> Result<Reply> {
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let confirm = call.member == "BackupRecoveryConfirm";
        require(call.descriptor.is_none(), "wire-signature")?;
        let request = wire::recovery(call.body.as_deref().unwrap_or("").as_bytes(), confirm)?;
        require(self.provider.backup_supported(), "operation-unavailable")?;
        let action = if confirm {
            "org.enzimos.system.backup-confirm-copy"
        } else {
            "org.enzimos.system.backup-export"
        };
        let grant = self
            .authority
            .authorize(
                &call.sender,
                action,
                request["allow_interaction"].as_bool().unwrap(),
                call.arrived,
                150000,
            )
            .await?;
        let uid = grant.peer.uid;
        require((1000..i32::MAX as u32).contains(&uid), "not-authorized")?;
        let peer = grant.peer.clone();
        let worker = self.jobs.worker_permit()?;
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        let provider = self.provider.clone();
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = alive.0.clone();
        let (body, descriptor) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _worker = worker;
            let check = || {
                require(active.load(Ordering::Acquire), "sender-disconnected")?;
                // May run inside a worker client's private runtime.
                tokio::task::block_in_place(|| runtime.block_on(authority.recheck(&grant)))
            };
            check()?;
            let result = if confirm {
                let result = provider.backup_recovery_confirm(
                    uid,
                    request["ticket"].as_str().unwrap(),
                    request["assertion"].as_str().unwrap(),
                    &check,
                )?;
                (result, None)
            } else {
                let (result, copy) = provider.backup_recovery_export(uid, &check)?;
                (result, Some(copy))
            };
            check()?;
            Ok::<_, Error>(result)
        })
        .await
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))??;
        // A sealed copy is handed only to the caller that is still the same
        // authorized session now; otherwise it is closed here.
        let fresh = self
            .authority
            .authorize(
                &call.sender,
                "org.enzimos.system.query",
                false,
                Instant::now(),
                10000,
            )
            .await?;
        require(fresh.peer == peer, "not-authorized")?;
        drop(alive);
        Ok(Reply { body, descriptor })
    }
}
