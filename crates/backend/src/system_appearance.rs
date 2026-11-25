// SPDX-License-Identifier: MIT
//! Publish caller-selected public login data through the existing session authority.
use super::{Alive, Api};
use crate::{
    system_provider::Provider,
    system_service::{Call, Reply},
    system_wire,
};
use enzimos_platform::{Error, Result, require};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

impl<P: Provider> Api<P> {
    pub(super) async fn appearance(&self, call: Call) -> Result<Reply> {
        require(
            self.provider.login_appearance_supported(),
            "operation-unavailable",
        )?;
        let permit = std::sync::Arc::clone(&self.calls)
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let request = system_wire::decode(
            call.body.as_deref().unwrap_or("").as_bytes(),
            system_wire::MAX_REQUEST,
        )?;
        enzimos_policy::login_appearance::request(&request)?;
        let grant = self
            .authority
            .authorize(
                &call.sender,
                "org.enzimos.system.login-appearance",
                request["allow_interaction"].as_bool().unwrap_or(false),
                call.arrived,
                150000,
            )
            .await?;
        require(
            grant.peer.uid >= 1000 && matches!(grant.peer.kind.as_str(), "wayland" | "x11"),
            "not-authorized",
        )?;
        let descriptor = call
            .descriptor
            .ok_or_else(|| Error("wire-signature".into()))?;
        let alive = Alive(Arc::new(AtomicBool::new(true)));
        let active = Arc::clone(&alive.0);
        let authority = self.authority.clone();
        let runtime = tokio::runtime::Handle::current();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            enzimos_policy::login_appearance::publish(
                grant.peer.uid,
                &request,
                &descriptor,
                &|| {
                    require(active.load(Ordering::Acquire), "request-cancelled")?;
                    runtime.block_on(authority.recheck(&grant))
                },
            )
        })
        .await
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))??;
        drop(alive);
        Ok(result.into())
    }
}
