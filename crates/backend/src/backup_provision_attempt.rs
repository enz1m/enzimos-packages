// SPDX-License-Identifier: MIT
//! One composite provision worker inside one original normal-close mount scope.
use enzimos_platform::{Result, files, require};
use enzimos_policy::{
    backup_input_authentication::Confirmed,
    backup_provisioned::Provisioned,
    backup_restic_runtime::Image,
    backup_setup_configuration::Configuration,
    backup_setup_context::Prepared,
    backup_setup_mount,
    backup_setup_plan::{Mode, Plan},
    backup_setup_repository::Repository,
    backup_worker_builder,
    backup_worker_intent::Intent,
    backup_worker_producer::Inputs,
};
use std::fs::File;
pub fn run<'g>(
    plan: &'g Plan<'_, '_, '_>,
    restic: &Image,
    outer: &Prepared<'_, '_, '_, '_>,
    configuration: &'g Configuration<'_>,
    confirmation: Option<&'g Confirmed<'_, '_, '_>>,
    id: &str,
    lock: &'g files::Lock,
    authorize: &'g dyn Fn() -> Result<()>,
) -> Result<Provisioned<'g>> {
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::backup_worker_request::id(id)?;
    let mode = plan.mode()?;
    require(
        confirmation.is_some() == (mode == Mode::Adopt),
        "adoption provision requires original confirmation; initialization cannot borrow it",
    )?;
    if let Some(confirmed) = confirmation {
        confirmed.matches_plan(plan)?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let mounted =
        backup_setup_mount::with_owned_mount(plan.review()?, id, lock, authorize, |scope| {
            let repository = if mode == Mode::Initialize {
                Repository::initialize(scope, outer)?
            } else {
                Repository::adopt(scope)?
            };
            let request = backup_worker_builder::provision(
                plan,
                scope,
                &repository,
                id,
                restic,
                outer,
                configuration,
            )?;
            let mut intent = Intent::prepare_checked(
                &request,
                plan.source_guard()?,
                lock,
                authorize,
                Box::new(move || {
                    configuration.recheck()?;
                    if let Some(confirmed) = confirmation {
                        confirmed.matches_plan(plan)?;
                    }
                    Ok(())
                }),
            )?;
            let credential = File::from(
                configuration
                    .credential_descriptor()?
                    .try_clone_to_owned()?,
            );
            let mut finished = {
                let inputs = Inputs {
                    repository: repository.descriptor(scope)?,
                    credential: &credential,
                    restic: restic.descriptor()?,
                    outer: Some(outer.descriptor()?),
                    configuration: Some(configuration.descriptor()?),
                    temporary: None,
                };
                runtime.block_on(crate::backup_worker_client::launch(
                    &mut intent,
                    scope,
                    &inputs,
                ))?
            };
            if let Some(confirmed) = confirmation {
                require(
                    finished.observation.result()["key_id"] == confirmed.key_id()?,
                    "stored adoption credential differs from confirmed original current key",
                )?;
            }
            configuration.recheck()?;
            let bound = enzimos_policy::backup_setup_binding::Bound::publish(
                plan,
                &intent,
                &finished.observation,
                &finished.closed,
                scope,
                configuration,
                outer,
                confirmation,
                lock,
                authorize,
            )?;
            finished
                .observation
                .retire_header(&request, &finished.closed, scope)?;
            drop(credential);
            drop(repository);
            Ok((intent, finished, bound))
        })?;
    let ((mut intent, finished, bound), mount) = mounted.split()?;
    intent.complete(&finished.observation, &finished.closed, &mount, None)?;
    Provisioned::from_bound(intent, bound)
}
