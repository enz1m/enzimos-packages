// SPDX-License-Identifier: MIT
use enzimos_policy::{deferred, deferred_start};
use serde_json::json as value;
const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const OTHER: &str = "22222222-2222-4222-8222-222222222222";
#[test]
fn start_attempts_bind_exact_debt_and_cannot_replay_after_failure_or_caller_loss() {
    let marker = deferred::next(None, "authority", OTHER, 10).unwrap();
    let key = deferred_start::id("authority", &marker).unwrap();
    let intent = value!({"schema":1,"id":key,"action":"authority","boot_id":BOOT,
        "marker":marker,"phase":"intent"});
    deferred_start::transition(None, &intent, &key).unwrap();
    assert!(deferred_start::transition(Some(&intent), &intent, &key).is_err());
    for phase in ["requested", "uncertain"] {
        let mut terminal = intent.clone();
        terminal["phase"] = value!(phase);
        deferred_start::transition(Some(&intent), &terminal, &key).unwrap();
        assert!(deferred_start::transition(Some(&terminal), &intent, &key).is_err());
        assert!(deferred_start::transition(Some(&terminal), &terminal, &key).is_err());
        assert!(deferred_start::transition(None, &terminal, &key).is_err());
    }
    let mut changed = intent.clone();
    changed["marker"]["deferrals"] = value!(2);
    assert!(deferred_start::validate(&changed, &key).is_err());
    let mut current_boot = intent;
    current_boot["boot_id"] = value!(OTHER);
    assert!(deferred_start::validate(&current_boot, &key).is_err());
    let next = deferred::next(Some(&marker), "authority", OTHER, 11).unwrap();
    assert_ne!(deferred_start::id("authority", &next).unwrap(), key);
}
