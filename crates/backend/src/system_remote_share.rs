// SPDX-License-Identifier: MIT
//! NAS share setup (`BackupRemoteShareSetup`, sealed share password and an
//! optional sealed repository password) and its test/removal
//! (`BackupRemoteShare`). Each is one administrator-approved call holding the
//! single mutation worker; nothing is queued, retried or replayed.
use super::{Alive, Api};
use crate::{
    system_provider::Provider,
    system_service::{Call, Reply},
    system_wire as wire,
};
use enzimos_platform::{Error, Result, require, secret};
use std::{
    os::fd::AsFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
impl<P: Provider> Api<P> {
    pub(super) async fn remote_share(&self, call: Call) -> Result<Reply> {
        let permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let setup = call.member == "BackupRemoteShareSetup";
        require(setup || call.descriptor.is_none(), "wire-signature")?;
        let request = wire::remote_share(call.body.as_deref().unwrap_or("").as_bytes(), setup)?;
        require(self.provider.backup_supported(), "operation-unavailable")?;
        let grant = self
            .authority
            .authorize(
                &call.sender,
                // A test only checks the share; its prompt says so.
                if request["action"] == "test" {
                    "org.enzimos.system.backup-remote-check"
                } else {
                    "org.enzimos.system.backup-setup"
                },
                request["allow_interaction"].as_bool().unwrap(),
                call.arrived,
                150000,
            )
            .await?;
        let uid = grant.peer.uid;
        require((1000..i32::MAX as u32).contains(&uid), "not-authorized")?;
        // Only sealed private memfds of the approved caller are accepted.
        let retain = |file: &Option<std::fs::File>| {
            file.as_ref()
                .map(|f| secret::retain(f.as_fd(), uid))
                .transpose()
                .map_err(|_| Error("remote-share-secret-refused".into()))
        };
        let share = retain(&call.descriptor)?;
        let repository = retain(&call.second)?;
        let peer = grant.peer.clone();
        let worker = self.jobs.worker_permit()?;
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        let provider = self.provider.clone();
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = alive.0.clone();
        let body = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _worker = worker;
            let check = || {
                require(active.load(Ordering::Acquire), "sender-disconnected")?;
                tokio::task::block_in_place(|| runtime.block_on(authority.recheck(&grant)))
            };
            check()?;
            let result = provider.backup_remote_share(
                &request,
                share.as_ref(),
                repository.as_ref(),
                &check,
            )?;
            check()?;
            Ok::<_, Error>(result)
        })
        .await
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))??;
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
        Ok(body.into())
    }
}
