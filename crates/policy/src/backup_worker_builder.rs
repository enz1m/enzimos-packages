// SPDX-License-Identifier: MIT
//! Server requests assembled from original plan, mount, input and publication objects.
use crate::{
    backup_restic_runtime::Image, backup_secret_input::Validated,
    backup_setup_configuration::Configuration, backup_setup_context::Prepared,
    backup_setup_mount::Scope, backup_setup_plan::Plan, backup_setup_repository::Repository,
};
use enzimos_platform::{Result, files, json, require};
use serde_json::{Value, json as value};
use std::fs::File;
fn document(file: &File) -> Result<Value> {
    let bytes = files::read_file(file, 65536, Some(0), true)?;
    Ok(value!({"identity":files::identity(&file.metadata()?),"sha256":json::sha256(&bytes)}))
}
fn base(
    plan: &Plan<'_, '_, '_>,
    scope: &Scope<'_, '_, '_>,
    repository: &Repository,
    id: &str,
    restic: &Image,
) -> Result<Value> {
    crate::namespaces::initial()?;
    crate::backup_worker_request::id(id)?;
    plan.recheck_identity()?;
    scope.recheck()?;
    repository.recheck(scope)?;
    require(
        scope.evidence()?["filesystem_uuid"] == plan.original()["destination"]["filesystem_uuid"],
        "worker mount differs from original server plan",
    )?;
    let root = File::from(scope.descriptor()?.try_clone_to_owned()?);
    Ok(
        value!({"schema":crate::backup_worker_request::REQUEST_SCHEMA,"id":id,"stage":null,"task":null,
        "boot_id":plan.original()["source"]["boot_id"],"caller":plan.actor()?,"plan":plan.original(),
        "mount":scope.evidence()?,"root":crate::backup_worker_scope::directory(&root)?,"repository":repository.binding(scope)?,"header":repository.header(scope)?,
        "credential":null,"reader":null,"restic":restic.evidence()?,"outer":null,"configuration":null,"consumer_input":null}),
    )
}
/// Worker request authenticating `input` for the adoption in `plan`.
///
/// # Errors
///
/// Fails when the input belongs to another owner or a resource differs.
pub fn input(
    plan: &Plan<'_, '_, '_>,
    scope: &Scope<'_, '_, '_>,
    repository: &Repository,
    id: &str,
    input: &Validated,
    restic: &Image,
    outer: Option<&Prepared<'_, '_, '_, '_>>,
) -> Result<Value> {
    require(
        plan.original()["mode"] == "adopt" && plan.original()["owner_uid"] == input.owner(),
        "input authentication must belong to original adoption owner",
    )?;
    input.recheck()?;
    let mut v = base(plan, scope, repository, id, restic)?;
    let file = File::from(input.descriptor()?.try_clone_to_owned()?);
    v["credential"] =
        value!({"kind":"sealed-caller-input","identity":files::identity(&file.metadata()?)});
    v["reader"] = input.reader_evidence()?;
    v["task"] = value!("authenticate-input");
    v["stage"] = value!(if outer.is_some() {
        "adoption-confirm"
    } else {
        "adoption-probe"
    });
    if let Some(outer) = outer {
        require(
            outer.plan_value()? == plan.original(),
            "confirmation outer intent differs from original plan",
        )?;
        v["outer"] = document(outer.descriptor()?)?;
    }
    crate::backup_worker_request::request(&v)?;
    plan.recheck_identity()?;
    scope.recheck()?;
    input.recheck()?;
    Ok(v)
}
/// Worker request provisioning the repository for `plan`.
///
/// # Errors
///
/// Fails when the publications differ from the reviewed plan.
pub fn provision(
    plan: &Plan<'_, '_, '_>,
    scope: &Scope<'_, '_, '_>,
    repository: &Repository,
    id: &str,
    restic: &Image,
    outer: &Prepared<'_, '_, '_, '_>,
    configuration: &Configuration<'_>,
) -> Result<Value> {
    outer.recheck()?;
    configuration.recheck()?;
    require(
        outer.plan_value()? == plan.original()
            && plan.original()["owner_uid"] == configuration.credential_owner(),
        "provision publications differ from original reviewed owner/plan",
    )?;
    let mut v = base(plan, scope, repository, id, restic)?;
    let credential = File::from(
        configuration
            .credential_descriptor()?
            .try_clone_to_owned()?,
    );
    v["credential"] = value!({"kind":"published-root-credential","identity":files::identity(&credential.metadata()?)});
    v["stage"] = value!("provision");
    v["task"] = value!(if plan.original()["mode"] == "adopt" {
        "provision-adopt"
    } else {
        "provision-initialize"
    });
    v["outer"] = document(outer.descriptor()?)?;
    let mut config = document(configuration.descriptor()?)?;
    config["value"] = configuration.value()?;
    v["configuration"] = config;
    crate::backup_worker_request::executable(&v)?;
    plan.recheck_identity()?;
    scope.recheck()?;
    configuration.recheck()?;
    Ok(v)
}
