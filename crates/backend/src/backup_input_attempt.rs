// SPDX-License-Identifier: MIT
//! One input authentication with original worker, temporary and mount closure.
use enzimos_platform::{Result, files, require};
use enzimos_policy::{
    backup_auth_input::Temporary,
    backup_input_authentication::Authenticated,
    backup_restic_runtime::Image,
    backup_secret_input::Validated,
    backup_setup_context::Prepared,
    backup_setup_mount,
    backup_setup_plan::Plan,
    backup_setup_repository::Repository,
    backup_worker_builder,
    backup_worker_intent::{Completed, Intent},
    backup_worker_producer::Inputs,
};
use serde_json::{Value, json};
use std::fs::File;

pub enum Outcome<'g, 'i> {
    Authenticated(Authenticated<'g, 'i>),
    IncorrectPassword(Rejected<'g>),
}
pub struct Rejected<'g> {
    intent: Completed<'g>,
}
impl Outcome<'_, '_> {
    pub fn retry_result(&self) -> Result<Value> {
        let Self::IncorrectPassword(rejected) = self else {
            return Err(enzimos_platform::Error(
                "retry requires a completed probe with incorrect password".into(),
            ));
        };
        rejected.intent.recheck()?;
        let record = rejected.intent.value()?;
        require(
            record["phase"] == "complete"
                && record["worker_scope_closed"] == true
                && record["request"]["stage"] == "adoption-probe"
                && record["result"]["status"] == "incorrect-password",
            "retry requires original completed probe with incorrect password",
        )?;
        Ok(json!({"status":"backup-password-retry","retryable":true,
            "credential_enrolled":false,"automatic_backup_enabled":false}))
    }
}
/// Call on the blocking coordinator thread. An uncertain attempt is retained,
/// never retried here; confirmation failure cannot become a password retry.
pub fn authenticate<'g, 'i>(
    plan: &'g Plan<'_, '_, '_>,
    input: &'i Validated,
    restic: &Image,
    outer: Option<&Prepared<'_, '_, '_, '_>>,
    id: &str,
    lock: &'g files::Lock,
    authorize: &'g dyn Fn() -> Result<()>,
) -> Result<Outcome<'g, 'i>> {
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::backup_worker_request::id(id)?;
    let source = plan.source_guard()?;
    let review = plan.review()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let mounted = backup_setup_mount::with_owned_mount(review, id, lock, authorize, |scope| {
        let repository = Repository::adopt(scope)?;
        let request =
            backup_worker_builder::input(plan, scope, &repository, id, input, restic, outer)?;
        // Durable prepared intent precedes copying input or starting PID1.
        let mut intent = Intent::prepare(&request, source, lock, authorize)?;
        let temporary = Temporary::create(id, input, &mut || {
            intent.recheck()?;
            scope.recheck()
        })?;
        intent.attach_input(&temporary)?;
        let credential = File::from(input.descriptor()?.try_clone_to_owned()?);
        let finished = {
            let inputs = Inputs {
                repository: repository.descriptor(scope)?,
                credential: &credential,
                restic: restic.descriptor()?,
                outer: outer.map(|o| o.descriptor()).transpose()?,
                configuration: None,
                temporary: Some(temporary.descriptor()?),
            };
            runtime.block_on(crate::backup_worker_client::launch(
                &mut intent,
                scope,
                &inputs,
            ))?
        };
        // Only actual pidfd exit plus the original whole cgroup permits removal.
        let retired = temporary.retire(&finished.closed)?;
        drop(credential);
        drop(repository);
        Ok((intent, finished, retired))
    })?;
    let ((mut intent, finished, retired), mount) = mounted.split()?;
    let completed = intent.complete(
        &finished.observation,
        &finished.closed,
        &mount,
        Some(&retired),
    )?;
    match completed["result"]["status"].as_str() {
        Some("authenticated") => Ok(Outcome::Authenticated(Authenticated::from_completed(
            intent, input,
        )?)),
        Some("incorrect-password") if outer.is_none() => Ok(Outcome::IncorrectPassword(Rejected {
            intent: intent.into_completed()?,
        })),
        _ => Err(enzimos_platform::Error(
            "adoption confirmation/authentication failed; original intent retained".into(),
        )),
    }
}
