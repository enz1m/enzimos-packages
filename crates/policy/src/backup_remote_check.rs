// SPDX-License-Identifier: MIT
//! Fixed remote metadata check between two authenticated original pin observations.
use super::Runtime;
use crate::backup_remote_context::Context;
use enzimos_platform::{
    Result, json,
    remote_restic::{self, Task},
    require,
};
use serde_json::{Value, json as value};
use std::fs::File;
pub(crate) fn authenticated(bytes: &[u8], binding: &Value) -> Result<Value> {
    let data = json::decode(bytes, 32768)?;
    require(
        data.is_object() && matches!(data["version"].as_u64(), Some(1 | 2)),
        "authenticated remote repository version required",
    )?;
    crate::identity::sha(data["id"].as_str().unwrap_or(""))?;
    crate::backup_remote_record::new_pin(&data["id"], binding)
}
impl Runtime {
    pub(crate) fn check_remote(
        &self,
        context: &Context<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.recheck()?;
        self.empty()?;
        let descriptors = context.descriptors(authorize)?;
        let share_password = File::from(descriptors["remote-share-password"].try_clone_to_owned()?);
        let credential = File::from(descriptors["remote-password"].try_clone_to_owned()?);
        let image = File::from(descriptors["restic"].try_clone_to_owned()?);
        require(
            self.image_evidence()? == context.evidence(authorize)?["restic"],
            "original remote check vendor image changed",
        )?;
        let (attachment, endpoint) =
            super::remote_share(context.configuration(authorize)?, &share_password)?;
        let binding = context.binding(authorize)?.clone();
        let mut boundary = || {
            self.recheck()?;
            context.recheck(authorize)?;
            attachment.recheck()
        };
        let mut observe = || -> Result<Value> {
            boundary()?;
            let output = remote_restic::rotation_read(
                &attachment,
                &endpoint,
                Task::RemoteIdentity,
                &"0".repeat(64),
                &image,
                &credential,
                &self.scratch,
                &mut boundary,
            )?;
            boundary()?;
            self.empty()?;
            require(
                output.status.code() == Some(0),
                "remote authentication failed or unknown; no retry",
            )?;
            authenticated(&output.stdout, &binding)
        };
        let first = observe()?;
        drop(observe);
        drop(boundary);
        context.compare_identity_data(&first, authorize)?;
        let mut boundary = || {
            self.recheck()?;
            context.recheck(authorize)?;
            attachment.recheck()
        };
        let checked = remote_restic::check(
            &attachment,
            &endpoint,
            &image,
            &credential,
            &self.scratch,
            &mut boundary,
        )?;
        boundary()?;
        self.empty()?;
        require(
            checked.status.code() == Some(0),
            "remote metadata check failed or uncertain; no retry",
        )?;
        let last = remote_restic::rotation_read(
            &attachment,
            &endpoint,
            Task::RemoteIdentity,
            &"0".repeat(64),
            &image,
            &credential,
            &self.scratch,
            &mut boundary,
        )?;
        boundary()?;
        self.empty()?;
        require(
            last.status.code() == Some(0),
            "remote final authentication failed or unknown",
        )?;
        let last = authenticated(&last.stdout, &binding)?;
        require(
            last == first,
            "authenticated remote identity changed during metadata check",
        )?;
        drop(boundary);
        context.compare_identity_data(&last, authorize)?;
        Ok(
            value!({"status":"remote-repository-checked","repository_id":last["repository_id"],"append_only":false}),
        )
    }
}
pub fn check_locked(
    guard: &crate::storage_runtime::Guard,
    lock: &enzimos_platform::files::Lock,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    let context = Context::observe(guard, lock, authorize)?;
    let runtime = Runtime::create(&enzimos_platform::files::random_hex(16)?, &mut || {
        context.recheck(authorize)
    })?;
    runtime.check_remote(&context, authorize)
}
