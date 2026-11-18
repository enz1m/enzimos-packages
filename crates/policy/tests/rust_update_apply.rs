// SPDX-License-Identifier: MIT
use enzimos_policy::update_apply_record as record;
use serde_json::{Value, json};
const ID: &str = "api-0123456789abcdef0123456789abcdef";
fn initial() -> Value {
    let hash = "a".repeat(64);
    let plan = json!({"schema":1,"operation":"update-apply","boot_id":"11111111-1111-1111-1111-111111111111",
        "storage":{"filesystem_uuid":"22222222-2222-2222-2222-222222222222","root_subvol":"root","home_subvol":"home","control_subvol":"control","authority_subvol":"authority"},
        "inventory_sha256":hash,"current_kernels":{"linux":"6.18.1","linux-lts":"6.12.99"},
        "target_kernels":{"linux":"6.18.2","linux-lts":"6.12.100"},"options":"rootflags=subvol=root rw",
        "authority":{"ownertrust":hash,"pubring.gpg":hash,"gpg.conf":hash,"approved.trust":hash},"cohort_sha256":hash,"implementation_sha256":hash});
    record::initial(
        ID,
        &plan,
        &json!({"pid":123,"start_ticks":100,"executable_sha256":hash}),
    )
    .unwrap()
}
fn reseal(value: &mut Value) {
    value.as_object_mut().unwrap().remove("journal_sha256");
    value["journal_sha256"] = json!(enzimos_platform::json::fingerprint(value).unwrap());
}
#[test]
fn every_apply_prefix_is_durable_but_never_authorizes_a_skipped_or_replayed_body() {
    let mut current = initial();
    record::validate(&current, ID).unwrap();
    for (index, phase) in record::STEPS.iter().enumerate() {
        for future in record::STEPS.iter().skip(index + 1) {
            assert!(record::advance(&current, future, &json!({"observed":true}), None).is_err());
        }
        let previous = current.clone();
        current = record::advance(
            &previous,
            phase,
            &json!({"observed":phase}),
            (*phase == "complete").then_some("prepared-not-rebooted"),
        )
        .unwrap();
        record::transition(&previous, &current, ID).unwrap();
        record::validate(&current, ID).unwrap();
        assert!(record::transition(&current, &current, ID).is_err());
        assert!(record::advance(&current, phase, &json!({"observed":phase}), None).is_err());
        let mut drift = current.clone();
        drift["plan"]["target_kernels"]["linux"] = json!("6.18.3");
        reseal(&mut drift);
        assert!(record::transition(&previous, &drift, ID).is_err());
        let mut rewritten = current.clone();
        rewritten["steps"][0]["sha256"] = json!("b".repeat(64));
        reseal(&mut rewritten);
        if index > 0 {
            assert!(record::transition(&previous, &rewritten, ID).is_err());
        }
        let mut corrupt = current.clone();
        corrupt["journal_sha256"] = json!("f".repeat(64));
        assert!(record::validate(&corrupt, ID).is_err());
    }
    assert!(
        record::advance(
            &current,
            "complete",
            &json!({}),
            Some("prepared-not-rebooted")
        )
        .is_err()
    );
}
