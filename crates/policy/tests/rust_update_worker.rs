// SPDX-License-Identifier: MIT
use enzimos_platform::json;
use enzimos_policy::update_worker_record as record;
use serde_json::{Value, json as value};
fn request() -> Value {
    value!({"schema":1,"id":"update-fixture","boot_id":"11111111-1111-4111-8111-111111111111",
        "filesystem_uuid":"22222222-2222-4222-8222-222222222222",
        "caller":{"pid":123,"start_ticks":1234,"executable_sha256":json::sha256(b"native-policy")},
        "module_view":{"schema":2,"id":"module-fixture","phase":"active",
            "boot_id":"11111111-1111-4111-8111-111111111111","kernel":"6.18-fixture",
            "filesystem_uuid":"22222222-2222-4222-8222-222222222222","inventory_sha256":json::sha256(b"modules"),
            "source":{"device":1,"inode":10,"mount":1},"runtime":{"device":1,"inode":20,"mount":1},
            "alias":{"device":1,"inode":10,"mount":2},"live":{"device":1,"inode":20,"mount":3}},
        "boot_stage":{"device":1,"inode":30,"mount":1},"config_sha256":json::sha256(b"config"),
        "cohort_sha256":json::sha256(b"cohort")})
}
fn intent() -> Value {
    let request = request();
    value!({"schema":1,"id":"update-fixture","phase":"intent","request_sha256":json::sha256(&json::canonical(&request).expect("test fixture")),
        "request":request,"supervisor":null,"invocation":null,"exit_code":null})
}
#[test]
fn worker_journal_requires_owned_handoff_stop_and_success_without_replay() {
    let id = "update-fixture";
    let mut current = intent();
    record::transition(None, &current, id).unwrap();
    let mut skipped = current.clone();
    skipped["phase"] = value!("running");
    assert!(record::transition(Some(&current), &skipped, id).is_err());
    for phase in ["starting", "handed-off", "running", "stopping", "complete"] {
        let mut next = current.clone();
        next["phase"] = value!(phase);
        if phase == "handed-off" {
            next["supervisor"] =
                value!({"pid":456,"start_ticks":4567,"executable_sha256":json::sha256(b"worker")});
            next["invocation"] = value!("11111111111111111111111111111111");
        }
        if phase == "stopping" {
            next["exit_code"] = value!(0);
        }
        record::transition(Some(&current), &next, id).unwrap();
        current = next;
    }
    assert!(record::transition(Some(&current), &intent(), id).is_err());
    let mut failure = current;
    failure["exit_code"] = value!(1);
    assert!(record::validate(&failure, id).is_err());
    for phase in ["failed", "uncertain"] {
        let mut stopped = intent();
        stopped["phase"] = value!(phase);
        record::transition(Some(&intent()), &stopped, id).unwrap();
        assert!(record::transition(Some(&stopped), &intent(), id).is_err());
    }
}
