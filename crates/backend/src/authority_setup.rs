// SPDX-License-Identifier: MIT
//! Fixed five-minute setup approval, freshly checked at every worker boundary.
use super::{Authority, Peer, refused};
use enzimos_platform::{Result, peer_lifetime::PeerLifetime, require};
use std::time::{Duration, Instant};
pub(crate) const ACTION: &str = "org.enzimos.system.backup-setup";
pub(crate) struct SetupApproval {
    sender: String,
    peer: Peer,
    caller: PeerLifetime,
    deadline: Instant,
    login_owner: String,
    polkit_owner: String,
}
impl Authority {
    pub(crate) async fn approve_setup(
        &self,
        sender: &str,
        interaction: bool,
        arrived: Instant,
        expected: &Peer,
    ) -> Result<SetupApproval> {
        let grant = self
            .authorize(sender, ACTION, interaction, arrived, 150000)
            .await?;
        require(&grant.peer == expected, "job-owner-mismatch")?;
        let caller = PeerLifetime::capture(grant.peer.pid, grant.peer.uid)?;
        self.recheck(&grant).await?;
        let this = SetupApproval {
            sender: sender.into(),
            peer: grant.peer,
            caller,
            deadline: Instant::now() + Duration::from_secs(300),
            login_owner: self.login_owner.to_string(),
            polkit_owner: self.polkit_owner.as_ref().ok_or_else(refused)?.to_string(),
        };
        this.recheck(self).await?;
        Ok(this)
    }
}
impl SetupApproval {
    pub(crate) async fn recheck(&self, authority: &Authority) -> Result<()> {
        require(
            Instant::now() < self.deadline
                && authority.login_owner.as_str() == self.login_owner
                && authority.polkit_owner.as_ref().map(|o| o.as_str())
                    == Some(self.polkit_owner.as_str()),
            "setup approval expired or changed authority",
        )?;
        self.caller.recheck()?;
        let fresh = authority
            .authorize(
                &self.sender,
                "org.enzimos.system.query",
                false,
                Instant::now(),
                10000,
            )
            .await?;
        require(fresh.peer == self.peer, "job-owner-mismatch")?;
        authority.recheck(&fresh).await?;
        self.caller.recheck()?;
        require(Instant::now() < self.deadline, "setup approval expired")
    }
}
