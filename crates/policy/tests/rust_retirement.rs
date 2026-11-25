// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, json as document};
use enzimos_policy::{
    recovery_journal::Records,
    retirement_journal::{self as engine, Executor},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn intent() -> Value {
    let steps = ["uefi-entry","bios-menu","root-subvolume","catalog"].iter().enumerate().map(|(n,kind)|json!({"id":format!("step{n}"),"kind":kind,"before":"a".repeat(64),"after":"b".repeat(64)})).collect::<Vec<_>>();
    let mut value = json!({"schema":1,"id":"retire-one","filesystem_uuid":"00000000-0000-0000-0000-000000000001","boot_uuid":"ABCD-1234","created_boot":"00000000-0000-0000-0000-000000000002","observation_sha256":"c".repeat(64),"protected_sha256":"d".repeat(64),"steps":steps});
    value["intent_sha256"] = json!(document::fingerprint(&value).expect("test fixture"));
    value
}
struct Memory {
    records: Records,
    objects: BTreeMap<String, String>,
    applied: Vec<String>,
    interrupt: bool,
}
impl Memory {
    fn new() -> Self {
        Self {
            records: Records::new(),
            objects: (0..4)
                .map(|i| (format!("step{i}"), "a".repeat(64)))
                .collect(),
            applied: Vec::new(),
            interrupt: false,
        }
    }
}
impl Executor for Memory {
    fn records(&mut self) -> Result<Records> {
        Ok(self.records.clone())
    }
    fn save(&mut self, next: &Value, previous: Option<&Value>) -> Result<()> {
        engine::validate(next, "retire-one")?;
        assert_eq!(
            self.records.get("retire-one"),
            previous,
            "saved over the expected previous record"
        );
        self.records.insert("retire-one".into(), next.clone());
        Ok(())
    }
    fn verify_context(&mut self, intent: &Value) -> Result<()> {
        engine::intent(intent)
    }
    fn observe(&mut self, step: &Value) -> Result<String> {
        Ok(self.objects[step["id"].as_str().expect("test fixture")].clone())
    }
    fn apply(&mut self, step: &Value) -> Result<()> {
        let id = step["id"].as_str().expect("test fixture");
        let record = &self.records["retire-one"];
        assert_eq!(record["phase"], "executing", "applied while executing");
        assert_eq!(
            record["inflight"], record["next_step"],
            "in-flight step recorded before apply"
        );
        assert_eq!(
            record["intent"]["steps"][record["next_step"].as_u64().expect("test fixture") as usize],
            *step,
            "applied step is the recorded next step"
        );
        self.applied.push(id.into());
        self.objects.insert(
            id.into(),
            step["after"].as_str().expect("test fixture").into(),
        );
        if self.interrupt && id == "step2" {
            return Err(Error("simulated interruption after side effect".into()));
        }
        Ok(())
    }
}
#[test]
fn recorded_after_outcome_resumes_without_repeating_resource_mutation() {
    let mut memory = Memory::new();
    engine::start(&mut memory, &intent()).unwrap();
    memory.interrupt = true;
    assert!(engine::replay(&mut memory, "retire-one").is_err());
    assert_eq!(memory.records["retire-one"]["inflight"], 2);
    memory.interrupt = false;
    engine::replay(&mut memory, "retire-one").unwrap();
    assert_eq!(memory.applied, vec!["step0", "step1", "step2", "step3"]);
    assert_eq!(memory.records["retire-one"]["phase"], "complete");
    engine::replay(&mut memory, "retire-one").unwrap();
    assert_eq!(memory.applied.len(), 4);
    assert!(engine::start(&mut memory, &intent()).is_err());
}
#[test]
fn both_loader_detaches_and_final_tombstone_are_required_before_deletion() {
    for replacement in [json!("root-subvolume"), json!("catalog")] {
        let mut bad = intent();
        bad.as_object_mut().unwrap().remove("intent_sha256");
        bad["steps"][0]["kind"] = replacement;
        bad["intent_sha256"] = json!(document::fingerprint(&bad).unwrap());
        assert!(engine::intent(&bad).is_err());
    }
    let mut bad = intent();
    bad.as_object_mut().unwrap().remove("intent_sha256");
    bad["steps"].as_array_mut().unwrap().pop();
    bad["intent_sha256"] = json!(document::fingerprint(&bad).unwrap());
    assert!(engine::intent(&bad).is_err());
    let mut memory = Memory::new();
    let mut record = engine::start(&mut memory, &intent()).unwrap();
    record["inflight"] = json!(false);
    assert!(engine::validate(&record, "retire-one").is_err());
}
