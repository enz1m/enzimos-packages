// SPDX-License-Identifier: MIT
//! Native initial setup: probe before publication, fresh confirmation, one provision.
use crate::{
    backup_input_attempt::{self, Outcome},
    backup_setup_failure::{self as failure, step},
};
use enzimos_platform::{Result, files, require};
use enzimos_policy::{
    backup_input_authentication::Confirmed,
    backup_restic_runtime::Image,
    backup_secret_input::Validated,
    backup_secret_persistence,
    backup_setup_configuration::Configuration,
    backup_setup_context::Prepared,
    backup_setup_plan::{Mode, Plan},
};
use serde_json::Value;
use std::{fs::File, os::unix::fs::MetadataExt};
pub struct Finished {
    plan: Value,
    result: Value,
}
impl Finished {
    pub fn result(&self) -> &Value {
        &self.result
    }
    pub(crate) fn plan(&self) -> &Value {
        &self.plan
    }
}

/// Caller owns the reviewed original plan, sealed validated input, operation
/// lock and fresh unique-owner/session grant. No path/input/worker is adopted
/// from an interrupted receipt, and this function never retries internally.
///
/// Every error names its step. Once the outer intent exists, a failure is
/// settled by `backup_setup_failure`: this run's own publications are retracted
/// when no repository can exist and no pin was bound; otherwise they are kept
/// for inspection and `enzimos-policy backup-setup reset-uncertain`.
pub fn run(
    plan: &Plan<'_, '_, '_>,
    review_sha: &str,
    input: &Validated,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Finished> {
    step("admission", admit(plan, review_sha, input, lock, authorize))?;
    let original = plan.value()?;
    let restic = step("restic-image", Image::open())?;
    let mode = plan.mode()?;
    if mode == Mode::Initialize {
        let outer = step(
            "setup-intent",
            Prepared::begin(plan, review_sha, lock, authorize),
        )?;
        let credential = match step(
            "credential-publish",
            backup_secret_persistence::persist_owned_in_setup(input, &outer, lock, authorize),
        ) {
            Ok(credential) => credential,
            Err(error) => return Err(abandon_intent(error, outer, lock)),
        };
        return publish_and_provision(
            plan, &restic, outer, credential, None, original, lock, authorize,
        );
    }
    let probe = step(
        "adoption-probe",
        backup_input_attempt::authenticate(
            plan,
            input,
            &restic,
            None,
            &files::random_hex(16)?,
            lock,
            authorize,
        ),
    )?;
    let first = match probe {
        Outcome::Authenticated(authenticated) => authenticated,
        rejected @ Outcome::IncorrectPassword(_) => {
            return Ok(Finished {
                plan: original,
                result: rejected.retry_result()?,
            });
        }
    };
    // Permanent input and even the outer intent are absent on password retry.
    step(
        "adoption-recheck",
        (|| {
            plan.recheck_initial()?;
            first.recheck()?;
            lock.recheck()?;
            authorize()
        })(),
    )?;
    let outer = step(
        "setup-intent",
        Prepared::begin(plan, review_sha, lock, authorize),
    )?;
    let second = match step(
        "adoption-confirm",
        backup_input_attempt::authenticate(
            plan,
            input,
            &restic,
            Some(&outer),
            &files::random_hex(16)?,
            lock,
            authorize,
        ),
    ) {
        Ok(Outcome::Authenticated(authenticated)) => authenticated,
        Ok(Outcome::IncorrectPassword(_)) => {
            let error = enzimos_platform::Error(
                "adoption-confirm: confirmation cannot become a password retry".into(),
            );
            return Err(abandon_intent(error, outer, lock));
        }
        Err(error) => return Err(abandon_intent(error, outer, lock)),
    };
    let confirmation = match step(
        "adoption-confirm",
        (|| {
            let confirmation = Confirmed::new(&first, &second)?;
            confirmation.matches_plan(plan)?;
            Ok(confirmation)
        })(),
    ) {
        Ok(confirmation) => confirmation,
        Err(error) => return Err(abandon_intent(error, outer, lock)),
    };
    let credential = match step(
        "credential-publish",
        backup_secret_persistence::persist_confirmed_in_setup(
            &confirmation,
            &outer,
            lock,
            authorize,
        ),
    ) {
        Ok(credential) => credential,
        Err(error) => return Err(abandon_intent(error, outer, lock)),
    };
    publish_and_provision(
        plan,
        &restic,
        outer,
        credential,
        Some(&confirmation),
        original,
        lock,
        authorize,
    )
}
fn admit(
    plan: &Plan<'_, '_, '_>,
    review_sha: &str,
    input: &Validated,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<()> {
    enzimos_policy::namespaces::initial()?;
    enzimos_policy::identity::sha(review_sha)?;
    plan.recheck_initial()?;
    input.recheck()?;
    lock.recheck()?;
    authorize()?;
    require(
        plan.digest()? == review_sha,
        "original setup review digest changed",
    )?;
    let input_file = File::from(input.descriptor()?.try_clone_to_owned()?);
    require(
        plan.value()?["owner_uid"] == input_file.metadata()?.uid(),
        "validated input differs from original setup owner",
    )?;
    Ok(())
}
/// Only the outer intent exists (credential publication did not complete).
fn abandon_intent(
    error: enzimos_platform::Error,
    outer: Prepared<'_, '_, '_, '_>,
    lock: &files::Lock,
) -> enzimos_platform::Error {
    let entered = outer.repository_entered();
    let facts = failure::observe(entered).map(|mut facts| {
        // A partial credential (temporary, receipt or final name) cannot be
        // attributed to a held handle here; keep everything for inspection.
        facts.drafts_present |= ["backup.password", ".backup-password-input"]
            .iter()
            .any(|name| std::path::Path::new("/etc/enzimos").join(name).exists())
            || std::path::Path::new(enzimos_policy::operation::CONTROL)
                .join("backup-secret-input.json")
                .exists();
        facts
    });
    failure::settle(error, facts, || outer.retract(lock))
}
#[allow(clippy::too_many_arguments)]
fn publish_and_provision(
    plan: &Plan<'_, '_, '_>,
    restic: &Image,
    outer: Prepared<'_, '_, '_, '_>,
    credential: enzimos_policy::backup_published_credential::Published,
    confirmation: Option<&Confirmed<'_, '_, '_>>,
    original: Value,
    lock: &files::Lock,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Finished> {
    let configuration = match step(
        "configuration-publish",
        Configuration::publish(&outer, &credential, lock, authorize),
    ) {
        Ok(configuration) => configuration,
        Err(error) => {
            let entered = outer.repository_entered();
            let facts = failure::observe(entered).map(|mut facts| {
                // Publication may have linked backup.json before failing; this
                // run holds no handle to it, so keep everything for inspection.
                facts.drafts_present |= std::path::Path::new("/etc/enzimos/backup.json").exists();
                facts
            });
            return Err(failure::settle(error, facts, || {
                credential.retract(lock)?;
                outer.retract(lock)
            }));
        }
    };
    let provisioned = step(
        "provision",
        crate::backup_provision_attempt::run(
            plan,
            restic,
            &outer,
            &configuration,
            confirmation,
            &files::random_hex(16)?,
            lock,
            authorize,
        ),
    );
    let provisioned = match provisioned {
        Ok(provisioned) => provisioned,
        Err(error) => {
            let entered = outer.repository_entered();
            return Err(failure::settle(error, failure::observe(entered), || {
                configuration.retract(lock)?;
                credential.retract(lock)?;
                outer.retract(lock)
            }));
        }
    };
    // The pin is bound: completion failures are never rolled back.
    let completed = step(
        "setup-complete",
        outer.complete(provisioned, lock, authorize),
    );
    if let Err(error) = &completed {
        failure::log(&format!(
            "failed at {}; destination pin retained for inspection",
            error.0
        ));
    }
    Ok(Finished {
        plan: original,
        result: completed?.result()?,
    })
}
