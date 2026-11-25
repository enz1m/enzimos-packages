// SPDX-License-Identifier: MIT
//! Remote repository cleanup by the same retention policy as the local one.
//!
//! Runs after a successful remote copy, between two authenticated identity
//! observations of the pinned remote repository: inventory, exact-ID
//! `forget --prune`, then a fresh inventory must equal the planned remainder.
//! Without a durable receipt; every run plans from a fresh inventory, so an
//! interrupted run is never replayed with stale IDs.
use super::{Runtime, retention::Plan};
use crate::backup_remote_context::Context;
use enzimos_platform::{
    Result,
    remote_restic::{self, Task},
    require,
};
use serde_json::{Value, json as value};
use std::fs::File;

impl Runtime {
    pub fn retain_remote(
        &self,
        context: &Context<'_>,
        policy: &Value,
        protect: &[String],
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        crate::backup_retention::validate_policy(policy)?;
        self.recheck()?;
        self.empty()?;
        let descriptors = context.descriptors(authorize)?;
        let share_password = File::from(descriptors["remote-share-password"].try_clone_to_owned()?);
        let credential = File::from(descriptors["remote-password"].try_clone_to_owned()?);
        let image = File::from(descriptors["restic"].try_clone_to_owned()?);
        require(
            self.image_evidence()? == context.evidence(authorize)?["restic"],
            "original remote retention vendor image changed",
        )?;
        let (attachment, endpoint) =
            super::remote_share(context.configuration(authorize)?, &share_password)?;
        let binding = context.binding(authorize)?.clone();
        let mut boundary = || {
            self.recheck()?;
            context.recheck(authorize)?;
            attachment.recheck()
        };
        let read = |task: Task,
                    boundary: &mut dyn FnMut() -> Result<()>|
         -> Result<(Option<i32>, Vec<u8>)> {
            boundary()?;
            let output = remote_restic::rotation_read(
                &attachment,
                &endpoint,
                task,
                &"0".repeat(64),
                &image,
                &credential,
                &self.scratch,
                boundary,
            )?;
            boundary()?;
            self.empty()?;
            Ok((output.status.code(), output.stdout))
        };
        let identify = |(code, bytes): (Option<i32>, Vec<u8>)| -> Result<Value> {
            require(
                code == Some(0),
                "remote authentication failed or unknown; no retry",
            )?;
            super::remote_check::authenticated(&bytes, &binding)
        };
        let first = identify(read(Task::RemoteIdentity, &mut boundary)?)?;
        let (code, inventory) = read(Task::RemoteInventory, &mut boundary)?;
        let plan = Plan::observe(code, &inventory, policy, protect)?;
        if plan.remove.is_empty() {
            context.compare_identity_data(&first, authorize)?;
            return Ok(value!({"status":"nothing-to-remove","removed":0}));
        }
        let output = remote_restic::prune(
            &attachment,
            &endpoint,
            &plan.remove,
            &image,
            &credential,
            &self.scratch,
            &mut boundary,
        )?;
        boundary()?;
        self.empty()?;
        require(
            output.status.code() == Some(0),
            "remote cleanup failed or uncertain; next run plans from a fresh inventory",
        )?;
        let (code, inventory) = read(Task::RemoteInventory, &mut boundary)?;
        plan.require_after(code, &inventory)?;
        let last = identify(read(Task::RemoteIdentity, &mut boundary)?)?;
        require(
            last == first,
            "authenticated remote identity changed during cleanup",
        )?;
        context.compare_identity_data(&last, authorize)?;
        Ok(value!({"status":"removed","removed":plan.remove.len()}))
    }
}

/// After a successful remote copy: clean up the remote repository by policy.
/// Never fails the copy; the outcome is published as backup status.
pub fn after_copy_locked(
    guard: &crate::storage_runtime::Guard,
    lock: &enzimos_platform::files::Lock,
    copied: Option<&str>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Value {
    let outcome = (|| {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        let policy = crate::backup_retention::policy()?;
        if policy["automatic"] != true {
            return Ok(value!({"status":"automatic-cleanup-off","removed":0}));
        }
        let context = Context::observe(guard, lock, authorize)?;
        let runtime = Runtime::create(&enzimos_platform::files::random_hex(16)?, &mut || {
            context.recheck(authorize)
        })?;
        // The snapshot just copied stays even when its (original) time falls in
        // a bucket newer remote snapshots already cover.
        let protect = copied.map(|id| vec![id.to_owned()]).unwrap_or_default();
        runtime.retain_remote(&context, &policy, &protect, authorize)
    })();
    let status = match outcome {
        Ok(value) => value,
        Err(error) => {
            value!({"status":"failed","reason":error.0.chars().take(160).collect::<String>()})
        }
    };
    let _ = crate::backup_retention::publish_status("remote", &status);
    status
}
