// SPDX-License-Identifier: MIT
//! Legacy synchronous history work releases its ledger mutex around the provider.
use crate::{
    jobs::{self, JobStore},
    system_jobs::Jobs,
    system_provider::Provider,
};
use enzimos_platform::{Error, Result, require};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::sync::OwnedSemaphorePermit;
pub(crate) type Guard = Box<dyn Fn() -> Result<()> + Send + Sync>;
pub(crate) type Ledger = Arc<Mutex<JobStore<Guard>>>;
fn lock(ledger: &Ledger) -> Result<std::sync::MutexGuard<'_, JobStore<Guard>>> {
    ledger
        .lock()
        .map_err(|_| Error("job-store-needs-review".into()))
}
struct Attempt {
    ledger: Ledger,
    _permit: OwnedSemaphorePermit,
    id: String,
    uid: u32,
    settled: bool,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Ok(mut store) = lock(&self.ledger)
            && let Ok(row) = store.status(&self.id, self.uid)
            && matches!(row["state"].as_str(), Some("prepared" | "running"))
        {
            let _ = store.phase(&self.id, self.uid, "uncertain", None);
        }
    }
}
pub(crate) fn status(ledger: &Ledger, id: &str, uid: u32) -> Result<Value> {
    jobs::public(&lock(ledger)?.status(id, uid)?)
}
pub(crate) fn run<P: Provider>(
    ledger: &Ledger,
    shared: &Jobs<P>,
    provider: &P,
    id: &str,
    uid: u32,
    commit: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    commit()?;
    let existing = lock(ledger)?.status(id, uid);
    match existing {
        Ok(row) => {
            require(
                row["state"] == "completed",
                "job-result-uncertain-no-replay",
            )?;
            return jobs::public(&row);
        }
        Err(e) if e.0 == "job-not-found" => (),
        Err(e) => return Err(e),
    }
    let permit = shared.worker_permit()?;
    commit()?;
    let (row, fresh) = lock(ledger)?.prepare(id, uid)?;
    if !fresh {
        return jobs::public(&row);
    }
    let mut attempt = Attempt {
        ledger: std::sync::Arc::clone(ledger),
        _permit: permit,
        id: id.into(),
        uid,
        settled: false,
    };
    commit()?;
    lock(ledger)?.phase(id, uid, "running", None)?;
    // A failed or missing provider result leaves an uncertain durable attempt.
    // No error path creates another snapshot or reacquires mutation admission.
    let snapshot = match provider.history(commit) {
        Ok(snapshot) if snapshot > 0 && snapshot < (1u64 << 63) => snapshot,
        // Match the legacy durable Job contract: the first failed provider call,
        // including an invalid result, publishes uncertainty before replying with
        // the same no-replay refusal as every later submit. Provider diagnostics
        // are private; an effect may already have happened.
        _ => {
            lock(ledger)?.phase(id, uid, "uncertain", None)?;
            attempt.settled = true;
            return Err(Error("job-result-uncertain-no-replay".into()));
        }
    };
    let complete = lock(ledger)?.phase(id, uid, "completed", Some(snapshot))?;
    attempt.settled = true;
    jobs::public(&complete)
}
