// SPDX-License-Identifier: MIT
//! One authoritative caller's original recipient, export, grant and supervised output.
use enzimos_platform::{Result, json, require};
use enzimos_policy::{
    backup_configuration::Configuration, backup_destination::Destination,
    backup_selective_context::Context, backup_selective_export::Staging, backup_selective_review,
    own_file_restore::Prepared, storage_runtime::Guard,
};
use serde_json::{Value, json as value};
fn measure(
    context: &Context<'_, '_>,
    recipient: &Prepared<'_>,
    authorize: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let export = backup_selective_review::measure(context, authorize)?;
    let original = recipient.evidence()?;
    context.recheck(authorize)?;
    recipient.recheck()?;
    Ok(
        value!({"schema":1,"operation":"own-file-restore","uid":original["uid"],"account":original["account"],
        "filename":original["filename"],"boot_id":export["boot_id"],"selection":export["selection"],
        "export_context_sha256":export["context_sha256"],"recipient_sha256":json::fingerprint(&original["recipient"] )?,
        "grant_registry_sha256":original["grant_registry_sha256"]}),
    )
}
pub(crate) fn observe(guard: &Guard, selection: &Value, uid: u32) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    let lock = enzimos_policy::operation::lock()?;
    let attached = || -> Result<()> {
        guard.recheck()?;
        lock.recheck()
    };
    enzimos_policy::backup_destination_attach::with_destination(guard, &lock, &attached, || {
        let configuration = Configuration::open()?;
        let destination = Destination::open(&configuration, guard)?;
        let recipient = Prepared::observe(guard, selection, uid)?;
        let context = Context::observe(
            guard,
            &lock,
            selection,
            &destination,
            &"0".repeat(32),
            &mut || Ok(()),
        )?;
        measure(&context, &recipient, &mut || Ok(()))
    })
}
pub(crate) fn run(
    guard: &Guard,
    id: &str,
    selection: &Value,
    expected: &Value,
    uid: u32,
    authorize: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    enzimos_policy::operation::root_only()?;
    enzimos_policy::namespaces::initial()?;
    require(
        expected["uid"] == uid && expected["account"]["uid"] == uid,
        "own-file caller differs from original ledger owner",
    )?;
    authorize()?;
    let lock = enzimos_policy::operation::lock()?;
    let attached = || -> Result<()> {
        authorize()?;
        guard.recheck()?;
        lock.recheck()
    };
    enzimos_policy::backup_destination_attach::with_destination(guard, &lock, &attached, || {
        let configuration = Configuration::open()?;
        let destination = Destination::open(&configuration, guard)?;
        let recipient = Prepared::observe(guard, selection, uid)?;
        let mut permission = || {
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            configuration.recheck()
        };
        let context = Context::observe(guard, &lock, selection, &destination, id, &mut permission)?;
        require(
            measure(&context, &recipient, &mut permission)? == *expected,
            "job-plan-changed",
        )?;
        progress("capturing")?;
        let stage = Staging::enter(&context, &mut || {
            recipient.recheck()?;
            permission()
        })?;
        let closed = super::backup_selective_client::launch(&context, &|| {
            recipient.recheck()?;
            authorize()?;
            guard.recheck()?;
            lock.recheck()?;
            configuration.recheck()
        })?;
        recipient.recheck()?;
        permission()?;
        let completed = stage.publish(closed, &mut || {
            recipient.recheck()?;
            permission()
        })?;
        let exported = completed.result(&mut permission)?;
        require(
            exported["id"] == selection["id"] && exported["snapshot"] == selection["snapshot"],
            "original own-file export changed",
        )?;
        progress("transferring")?;
        let grant = recipient.grant(&completed, &lock, &mut permission)?;
        let result = grant.deliver(&lock, &mut || completed.recheck(&mut permission))?;
        require(
            result["recipient_uid"] == uid
                && result["filename"] == expected["filename"]
                && result["bytes"] == exported["bytes"]
                && result["sha256"] == exported["sha256"],
            "actual own-file result differs from original recipient/export",
        )?;
        completed.recheck(&mut permission)?;
        permission()?;
        progress("finishing")?;
        Ok(result)
    })
}
