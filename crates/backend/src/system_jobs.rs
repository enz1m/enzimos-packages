// SPDX-License-Identifier: MIT
//! A bounded worker owns a durable queued record; losing it never retries work.
use super::{
    operation_record as record, operation_store::Store, system_provider::Provider,
    system_wire::Operation,
};
use enzimos_platform::{Error, Result, require};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
type Guard = Box<dyn Fn() -> Result<()> + Send + Sync>;
type Ledger = Arc<Mutex<Store<Guard>>>;
/// Original backend ledger view for retirement providers; no JSON constructor.
pub struct ReferenceView {
    ledger: Ledger,
    original: super::operation_store::References,
}
impl ReferenceView {
    fn observe(ledger: &Ledger, own: Option<&str>) -> Result<Self> {
        let original = lock(ledger)?.reference_snapshot(own)?;
        Ok(Self {
            ledger: ledger.clone(),
            original,
        })
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck(&*lock(&self.ledger)?)
    }
    pub fn records(&self) -> Result<Value> {
        self.original.records(&*lock(&self.ledger)?)
    }
    pub fn evidence(&self) -> Result<Value> {
        self.original.evidence(&*lock(&self.ledger)?)
    }
    /// Stable measurement of all other original records. Planning precedes the
    /// own row, so its later server-owned exemption is not part of the plan hash.
    /// The full original view is still checked at every call.
    pub fn planning_evidence(&self) -> Result<Value> {
        let mut evidence = self.evidence()?;
        evidence.as_object_mut().unwrap().remove("own_request");
        Ok(evidence)
    }
    pub fn require_root_target(
        &self,
        filesystem_uuid: &str,
        root_uuid: &str,
        plan_sha256: &str,
    ) -> Result<()> {
        self.original.require_root_target(
            &*lock(&self.ledger)?,
            filesystem_uuid,
            root_uuid,
            plan_sha256,
        )
    }
    pub fn require_unmentioned_with_conclusions(
        &self,
        generation: &str,
        conclusions: &enzimos_policy::recovery_conclusions::Observation<'_>,
    ) -> Result<()> {
        self.original.require_unmentioned_with_conclusions(
            &*lock(&self.ledger)?,
            generation,
            conclusions,
        )
    }
    pub fn require_unmentioned(&self, generation: &str) -> Result<()> {
        self.original
            .require_unmentioned(&*lock(&self.ledger)?, generation)
    }
}
impl enzimos_policy::root_retirement_references::References for ReferenceView {
    fn recheck(&self) -> Result<()> {
        ReferenceView::recheck(self)
    }
    fn records(&self) -> Result<Value> {
        ReferenceView::records(self)
    }
    fn planning_evidence(&self) -> Result<Value> {
        ReferenceView::planning_evidence(self)
    }
}
impl enzimos_policy::boot_retirement_context::runtime::References for ReferenceView {
    fn require_unmentioned(&self, generation: &str) -> Result<()> {
        ReferenceView::require_unmentioned(self, generation)
    }
}
pub struct Jobs<P> {
    provider: Arc<P>,
    ledger: Ledger,
    worker: Arc<Semaphore>,
}
pub struct Ticket<P> {
    provider: Arc<P>,
    ledger: Ledger,
    _permit: OwnedSemaphorePermit,
    id: String,
    uid: u32,
    digest: String,
    settled: bool,
    references: Option<ReferenceView>,
}
fn lock(ledger: &Ledger) -> Result<std::sync::MutexGuard<'_, Store<Guard>>> {
    ledger
        .lock()
        .map_err(|_| Error("job-store-needs-review".into()))
}
fn matches_request(body: &Value, request: &Operation, uid: u32) -> Result<()> {
    require(body["owner_uid"] == uid, "job-owner-mismatch")?;
    require(
        body["operation"] == request.operation,
        "job-request-invalid",
    )?;
    if request.action == "plan" {
        require(
            body["plan"]["selection"] == request.body()["selection"],
            "job-plan-changed",
        )?;
    } else if request.action != "status" {
        require(
            body["plan_sha256"] == request.body()["plan_sha256"],
            "job-plan-changed",
        )?;
    }
    Ok(())
}
impl<P: Provider> Jobs<P> {
    pub fn new(store: Store<Guard>, provider: Arc<P>) -> Self {
        Self {
            provider,
            ledger: Arc::new(Mutex::new(store)),
            worker: Arc::new(Semaphore::new(1)),
        }
    }
    pub fn active(&self) -> bool {
        self.worker.available_permits() == 0
    }
    pub(crate) fn worker_permit(&self) -> Result<OwnedSemaphorePermit> {
        self.worker
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))
    }
    pub fn status(&self, request: &Operation, uid: u32) -> Result<Value> {
        let body =
            lock(&self.ledger)?.status(request.body()["request_id"].as_str().unwrap(), uid)?;
        matches_request(&body, request, uid)?;
        record::public(&body)
    }
    pub fn plan(
        &self,
        request: &Operation,
        uid: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        require(request.action == "plan", "job-request-invalid")?;
        require(
            self.provider.operations().contains(&request.operation),
            "operation-unavailable",
        )?;
        authorize()?;
        let id = request.body()["request_id"].as_str().unwrap();
        match lock(&self.ledger)?.status(id, uid) {
            Ok(body) => {
                matches_request(&body, request, uid)?;
                return record::public(&body);
            }
            Err(e) if e.0 == "job-not-found" => (),
            Err(e) => return Err(e),
        }
        // A provider can wait for a bounded vendor query without holding the
        // ledger mutex. A racing same-id plan is compared again below.
        let references = if super::operation_store::retirement_operation(request.operation) {
            Some(ReferenceView::observe(&self.ledger, None)?)
        } else {
            None
        };
        let plan = if let Some(references) = &references {
            self.provider.plan_referenced(
                request.operation,
                &request.body()["selection"],
                id,
                uid,
                references,
            )?
        } else {
            self.provider
                .plan(request.operation, &request.body()["selection"], id, uid)?
        };
        if let Some(references) = &references {
            references.recheck()?;
        }
        authorize()?;
        let body = lock(&self.ledger)?.plan(id, uid, request.operation, || Ok(plan))?;
        matches_request(&body, request, uid)?;
        record::public(&body)
    }
    pub fn cancel(
        &self,
        request: &Operation,
        uid: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        require(request.action == "cancel", "job-request-invalid")?;
        authorize()?;
        let mut store = lock(&self.ledger)?;
        let id = request.body()["request_id"].as_str().unwrap();
        let body = store.status(id, uid)?;
        matches_request(&body, request, uid)?;
        if body["state"] == "cancelled" {
            return record::public(&body);
        }
        require(
            matches!(body["state"].as_str(), Some("planned" | "queued")),
            "job-transition-refused",
        )?;
        let next = store.advance(
            id,
            uid,
            body["plan_sha256"].as_str().unwrap(),
            "cancelled",
            body["progress"].as_str().unwrap(),
            Value::Null,
        )?;
        record::public(&next)
    }
    /// The caller must retain and run the returned ticket exactly once.
    /// A duplicate terminal submit returns status without allocating a worker.
    pub fn submit(
        &self,
        request: &Operation,
        uid: u32,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Value, Option<Ticket<P>>)> {
        require(request.action == "submit", "job-request-invalid")?;
        authorize()?;
        let id = request.body()["request_id"].as_str().unwrap();
        let body = lock(&self.ledger)?.status(id, uid)?;
        matches_request(&body, request, uid)?;
        match body["state"].as_str() {
            Some("planned") => (),
            Some("queued" | "running" | "completed" | "cancelled") => {
                return Ok((record::public(&body)?, None));
            }
            _ => return Err(Error("job-result-uncertain-no-replay".into())),
        }
        let permit = self
            .worker
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error("service-busy".into()))?;
        let references = if body["operation"]
            .as_str()
            .is_some_and(super::operation_store::retirement_operation)
        {
            let references = ReferenceView::observe(&self.ledger, Some(id))?;
            self.provider
                .verify_referenced(&body["plan"], &references)?;
            Some(references)
        } else {
            self.provider.verify(&body["plan"])?;
            None
        };
        authorize()?;
        if let Some(references) = &references {
            references.recheck()?;
        }
        let digest = body["plan_sha256"].as_str().unwrap().to_owned();
        let queued =
            lock(&self.ledger)?.advance(id, uid, &digest, "queued", "queued", Value::Null)?;
        let ticket = Ticket {
            provider: self.provider.clone(),
            ledger: self.ledger.clone(),
            _permit: permit,
            id: id.into(),
            uid,
            digest,
            settled: false,
            references,
        };
        Ok((record::public(&queued)?, Some(ticket)))
    }
}
impl<P: Provider> Ticket<P> {
    pub fn run(mut self, commit: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        let body = lock(&self.ledger)?.status(&self.id, self.uid)?;
        if body["state"] == "cancelled" {
            self.settled = true;
            return record::public(&body);
        }
        require(body["state"] == "queued", "job-transition-refused")?;
        // A disconnect before body entry still consumes the admitted attempt.
        // Errors are recorded as uncertain by the owned ticket's Drop below.
        commit()?;
        if let Some(references) = &self.references {
            self.provider.verify_referenced(&body["plan"], references)?;
        } else {
            self.provider.verify(&body["plan"])?;
        }
        lock(&self.ledger)?.advance(
            &self.id,
            self.uid,
            &self.digest,
            "running",
            "validating",
            Value::Null,
        )?;
        let ledger = self.ledger.clone();
        let mut progress = |phase: &str| -> Result<()> {
            lock(&ledger)?.advance(
                &self.id,
                self.uid,
                &self.digest,
                "running",
                phase,
                Value::Null,
            )?;
            Ok(())
        };
        let result = if let Some(references) = &self.references {
            let result = self.provider.run_referenced(
                &body["plan"],
                self.uid,
                references,
                &mut progress,
                commit,
            )?;
            references.recheck()?;
            result
        } else {
            self.provider
                .run_owned(&body["plan"], self.uid, &mut progress, commit)?
        };
        let next = lock(&self.ledger)?.advance(
            &self.id,
            self.uid,
            &self.digest,
            "completed",
            "completed",
            result,
        )?;
        self.settled = true;
        record::public(&next)
    }
}
impl<P> Drop for Ticket<P> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Ok(mut store) = lock(&self.ledger) {
            if let Ok(body) = store.status(&self.id, self.uid) {
                if matches!(body["state"].as_str(), Some("queued" | "running")) {
                    // Failure to persist is never interpreted as permission to
                    // replay. Startup retires surviving active rows as uncertain.
                    let _ = store.advance(
                        &self.id,
                        self.uid,
                        &self.digest,
                        "uncertain",
                        body["progress"].as_str().unwrap(),
                        Value::Null,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "system_jobs_tests.rs"]
mod tests;
