// SPDX-License-Identifier: MIT
//! Original before-worker last-copy member; completion consumes actual closed work.
use crate::{
    backup_completion::Member, backup_remote_copy_context::Context, backup_remote_report::Closed,
};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
use std::sync::Arc;
/// The last-copy record of a replication, captured before the worker starts.
pub struct Replication {
    actor: Arc<()>,
    member: Member,
}
impl Replication {
    /// Capture the last-copy record for `context`.
    ///
    /// # Errors
    ///
    /// Fails when `context` is not a replication or `authorize` fails.
    pub fn prepare(
        context: &Context<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        require(
            context.evidence(authorize)?["direction"] == "replicate",
            "original replication context required",
        )?;
        let member = Member::observe(
            context.guard().control(),
            "backup-remote-last-copy.json",
            32768,
        )?;
        if let Some(bytes) = member.original_bytes()? {
            crate::backup_remote_record::copied(&json::decode(&bytes, 32768)?)?;
        }
        context.recheck(authorize)?;
        Ok(Self {
            actor: context.actor_identity(),
            member,
        })
    }
    /// The original actor and original target member stay held through readback.
    ///
    /// # Errors
    ///
    /// Fails when the closed worker is not this replication's or the record cannot be written.
    pub fn complete(
        mut self,
        closed: Closed<'_>,
        context: &Context<'_, '_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        closed.require_context(context, authorize)?;
        require(
            Arc::ptr_eq(&self.actor, &context.actor_identity()),
            "replication completion requires original before-worker actor",
        )?;
        self.member.recheck()?;
        let outcome = closed.result()?;
        let original = context.evidence(authorize)?;
        require(
            outcome["direction"] == "replicate" && original["direction"] == "replicate",
            "original replication closed role differs",
        )?;
        let receipt = value!({"schema":1,"source_snapshot":outcome["snapshot"],"remote_snapshot":outcome["copied_snapshot"],"repository_id":outcome["repository_id"],"boot_id":original["remote"]["boot_id"]});
        crate::backup_remote_record::copied(&receipt)?;
        let bytes = json::canonical(&receipt)?;
        let mut check = || {
            closed.require_context(context, authorize)?;
            Ok(())
        };
        check()?;
        self.member.publish(&bytes, &mut check)?;
        check()?;
        require(
            self.member.published_bytes()? == bytes,
            "original replication receipt readback differs",
        )?;
        check()?;
        Ok(
            value!({"status":"recovery-point-replicated","source_snapshot":receipt["source_snapshot"],"remote_snapshot":receipt["remote_snapshot"],"repository_id":receipt["repository_id"],"scheduler_enabled":false}),
        )
    }
}
