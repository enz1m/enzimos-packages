// SPDX-License-Identifier: MIT
//! Wire admission of System1 requests.
use enzimos_platform::{Error, json};
use enzimos_system_backend::system_wire as wire;
use serde_json::{Value, json as v};
const ID: &str = "11111111111111111111111111111111";
fn selection(schema: u64) -> Value {
    let sha = "a".repeat(64);
    let uuid = "11111111-1111-4111-8111-111111111111";
    match schema {
        4 => v!({"birth":"birth1","generation":"gen1"}),
        6 => v!({"id":"grant1","grant_sha256":sha}),
        7 | 10 => v!({"id":"enrollment1"}),
        8 => v!({"id":"enrollment1","review_sha256":sha}),
        9 => v!({"generation":"gen1","plan_sha256":sha}),
        11 => v!({"id":"rotate1","review_sha256":sha,"action":"switch"}),
        12 => v!({"root_uuid":uuid,"plan_sha256":sha}),
        13 => v!({"id":format!("root-{ID}"),"image":format!("ri-{sha}"),"exit":"poweroff"}),
        14 => v!({"id":format!("root-{ID}")}),
        15 => v!({"rotation":"remote"}),
        16 => v!({"rotation":"remote","review_sha256":sha,"action":"discard"}),
        17 => {
            v!({"id":"recover1","plan_sha256":sha,"image":format!("ri-{sha}"),"flavor":"linux-lts","exit":"reboot"})
        }
        18 => v!({"id":"recover1"}),
        19 | 24 | 29 => {
            v!({"id":"restore1","snapshot":sha,"path":"/backup-source/home/admin/Documents/a.txt"})
        }
        20 => v!({"id":"grant1","export":"restore1","uid":1000}),
        21 => v!({"id":"grant1","grant_sha256":sha}),
        22 => v!({"snapshot":sha}),
        23 => v!({"id":"fetch1","snapshot":sha}),
        25 => v!({"connection":uuid,"trusted":false}),
        26 | 27 => v!({"enabled":true}),
        28 => v!({"action":"ignore","risk_acknowledged":true}),
        30 => v!({"hourly":1,"daily":2,"weekly":3,"monthly":4,"yearly":5,"manual":1}),
        31 => v!({"automatic":true,"last":3,"daily":14,"weekly":8,"monthly":12,"yearly":2}),
        32 => v!({"mode":"balanced","risk_acknowledged":false}),
        _ => Value::Null,
    }
}
fn request(schema: u64, action: &str) -> Value {
    let mut body = v!({"schema":schema,"operation":wire::OPERATIONS[(schema-3)as usize],"action":action,
        "request_id":ID,"plan_sha256":if matches!(action,"submit"|"cancel") {v!("b".repeat(64))}else{Value::Null},"allow_interaction":true});
    if !matches!(schema, 3 | 5) {
        body["selection"] = if action == "plan" {
            selection(schema)
        } else {
            Value::Null
        };
    }
    body
}
fn admitted(body: &Value) -> bool {
    wire::Operation::decode(&json::canonical(body).expect("canonical fixture")).is_ok()
}
#[test]
fn malformed_wire_and_restore_or_risk_boundary_inputs_never_become_operations() {
    assert_eq!(
        wire::decode(br#"{"schema":1,"schema":2}"#, 4096)
            .err()
            .unwrap()
            .0,
        "duplicate-field"
    );
    assert_eq!(
        wire::decode(br#"{"a":NaN}"#, 4096).err().unwrap().0,
        "nonfinite-value"
    );
    assert!(wire::decode(br#"{"a":"Infinity", "b":"escaped \" NaN"}"#, 4096).is_ok());
    assert!(wire::decode(&[b'x'; 4097], 4096).is_err());
    for peer in ["root", ":1", "1.2", ":1.2.3", ":a.1"] {
        assert!(wire::sender(peer).is_err());
    }
    assert!(wire::call(wire::PATH, wire::BUS, "Operation", "s", false, ":1.22").is_ok());
    assert!(wire::call(wire::PATH, wire::BUS, "Operation", "s", true, ":1.22").is_err());
    assert!(
        wire::call(
            wire::PATH,
            wire::BUS,
            "LoginAppearance",
            "sh",
            false,
            ":1.22"
        )
        .is_ok()
    );
    assert!(
        wire::call(
            wire::PATH,
            wire::BUS,
            "LoginAppearance",
            "s",
            false,
            ":1.22"
        )
        .is_err()
    );
    assert!(
        wire::call(
            wire::PATH,
            wire::BUS,
            "BackupSetupInput",
            "s",
            false,
            ":1.22"
        )
        .is_err()
    );
    assert_eq!(
        wire::public_failure(&Error("secret=/private/password".into())),
        "internal-result-unknown-do-not-retry-automatically"
    );
    for code in [
        "service-busy",
        "backup-destination-busy",
        "backup-destination-not-configured",
    ] {
        assert_eq!(wire::public_failure(&Error(code.into())), code);
    }
    for path in [
        "/backup-source/home/admin/../a",
        "/backup-source/home/admin/.snapshots/a",
        "/backup-source/home/admin",
        "/home/admin/a",
        "/backup-source/home/admin/a//b",
    ] {
        let mut body = request(29, "plan");
        body["selection"]["path"] = v!(path);
        assert!(!admitted(&body));
    }
    for schema in [28, 32] {
        let mut body = request(schema, "plan");
        body["selection"]["risk_acknowledged"] =
            v!(!body["selection"]["risk_acknowledged"].as_bool().unwrap());
        assert!(!admitted(&body));
    }
    let mut body = request(30, "plan");
    body["selection"]["manual"] = v!(0);
    assert!(!admitted(&body));
    let mut body = request(31, "plan");
    body["selection"]["last"] = v!(0);
    assert!(!admitted(&body));
}
