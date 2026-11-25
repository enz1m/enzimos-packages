// SPDX-License-Identifier: MIT
use super::*;
use serde_json::json;
use std::{
    os::unix::fs::PermissionsExt,
    sync::atomic::{AtomicUsize, Ordering},
};
struct Fake {
    calls: AtomicUsize,
    owner: AtomicUsize,
    fail: bool,
}
impl Provider for Fake {
    fn operations(&self) -> &[&'static str] {
        &["home-history-set"]
    }
    fn plan(
        &self,
        operation: &str,
        selection: &Value,
        request_id: &str,
        uid: u32,
    ) -> Result<Value> {
        Ok(
            json!({"operation":operation,"selection":selection,"request_id":request_id,"uid":u32::MAX,"planning_uid":uid}),
        )
    }
    fn verify(&self, _: &Value) -> Result<()> {
        Ok(())
    }
    fn run(
        &self,
        plan: &Value,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        progress("capturing")?;
        commit()?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(Error("simulated unknown vendor outcome".into()));
        }
        progress("finishing")?;
        Ok(
            json!({"enabled":plan["selection"]["enabled"],"state":"enabled","existing_history_removed":false}),
        )
    }
    fn run_owned(
        &self,
        plan: &Value,
        owner: u32,
        progress: &mut dyn FnMut(&str) -> Result<()>,
        commit: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.owner.store(owner as usize, Ordering::SeqCst);
        self.run(plan, progress, commit)
    }
    fn history(&self, _: &mut dyn FnMut() -> Result<()>) -> Result<u64> {
        panic!("not a history request")
    }
    fn query(&self, _: &str) -> Result<Value> {
        panic!("not a query")
    }
}
const ID: &str = "11111111111111111111111111111111";
const OTHER: &str = "22222222222222222222222222222222";
fn request(id: &str, action: &str, digest: Value, selection: Value) -> Operation {
    Operation::decode(
        &serde_json::to_vec(
            &json!({"schema":26,"operation":"home-history-set","action":action,
        "request_id":id,"plan_sha256":digest,"allow_interaction":false,"selection":selection}),
        )
        .unwrap(),
    )
    .unwrap()
}
fn fixture(fail: bool) -> (tempfile::TempDir, Jobs<Fake>, Arc<Fake>, u32) {
    let work = std::path::PathBuf::from(
        std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    );
    let temp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    let uid = enzimos_platform::process_identity::effective_uid();
    let guard: Guard = Box::new(|| Ok(()));
    let store = Store::open_owned(temp.path(), uid, guard).unwrap();
    let provider = Arc::new(Fake {
        calls: AtomicUsize::new(0),
        owner: AtomicUsize::new(usize::MAX),
        fail,
    });
    (
        temp,
        Jobs::new(store, std::sync::Arc::clone(&provider)),
        provider,
        uid,
    )
}
fn planned(jobs: &Jobs<Fake>, id: &str, uid: u32) -> Value {
    jobs.plan(
        &request(id, "plan", Value::Null, json!({"enabled":true})),
        uid,
        &mut || Ok(()),
    )
    .unwrap()
}
#[test]
fn cancellation_before_entry_and_dropped_ticket_never_execute() {
    let (_temp, jobs, provider, uid) = fixture(false);
    let plan = planned(&jobs, ID, uid);
    let submit = request(ID, "submit", plan["plan_sha256"].clone(), Value::Null);
    let ticket = jobs
        .submit(&submit, uid, &mut || Ok(()))
        .unwrap()
        .1
        .unwrap();
    let cancel = request(ID, "cancel", plan["plan_sha256"].clone(), Value::Null);
    assert_eq!(
        jobs.cancel(&cancel, uid, &mut || Ok(())).unwrap()["state"],
        "cancelled"
    );
    assert_eq!(
        jobs.cancel(&cancel, uid, &mut || Ok(())).unwrap()["state"],
        "cancelled"
    );
    assert_eq!(
        ticket
            .run(&mut || panic!("cancelled body must not authorize or execute"))
            .unwrap()["state"],
        "cancelled"
    );
    let other = planned(&jobs, OTHER, uid);
    let submit = request(OTHER, "submit", other["plan_sha256"].clone(), Value::Null);
    drop(jobs.submit(&submit, uid, &mut || Ok(())).unwrap().1);
    assert_eq!(
        jobs.status(&request(OTHER, "status", Value::Null, Value::Null), uid)
            .unwrap()["state"],
        "uncertain"
    );
    assert_eq!(
        jobs.submit(&submit, uid, &mut || Ok(())).err().unwrap().0,
        "job-result-uncertain-no-replay"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}
