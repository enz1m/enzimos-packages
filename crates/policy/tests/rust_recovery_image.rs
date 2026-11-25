// SPDX-License-Identifier: MIT
use enzimos_platform::json as document;
use enzimos_policy::{
    recovery_image as image,
    recovery_journal::{self, Kind},
};
use serde_json::{Value, json};
fn descriptor(native: bool) -> Value {
    let policies = if native {
        json!({"enzimos-policy":"a".repeat(64),"enzimos-recovery-image-init":"b".repeat(64),"enzimos-recovery-run-init":"c".repeat(64),"recovery-pacman.conf":"d".repeat(64)})
    } else {
        json!({"recovery_image.py":"a".repeat(64),"native.py":"b".repeat(64),"generation_registry.py":"c".repeat(64),"recovery-pacman.conf":"d".repeat(64)})
    };
    json!({"schema":if native {2} else {1},"kernel_release":"6.18.1","kernel_sha256":"e".repeat(64),"base_initrd_sha256":"f".repeat(64),"policy_files":policies})
}
fn record() -> Value {
    let descriptor = descriptor(true);
    let id = image::image_id(&descriptor).expect("test fixture");
    json!({"schema":1,"id":id,"phase":"intent","created_boot":"00000000-0000-0000-0000-000000000001","filesystem_uuid":"00000000-0000-0000-0000-000000000002","control":{"path":"control","id":260,"uuid":"00000000-0000-0000-0000-000000000003","parent_uuid":null},"boot_uuid":"ABCD-1234","inputs":{"schema":1,"identity":descriptor,"files":{"kernel":{"bytes":200,"sha256":"e".repeat(64)},"initrd.img":{"bytes":300,"sha256":"f".repeat(64)}}},"options":format!("console=tty0 enzimos.recovery={id}"),"observations":{}})
}
#[test]
fn publication_is_ordered_and_independent_boot_observation_keeps_first_receipt() {
    let intent = record();
    let id = intent["id"].as_str().unwrap();
    image::validate(&intent, id).unwrap();
    let mut artifacts = intent.clone();
    artifacts["phase"] = json!("artifacts");
    let mut ready = intent.clone();
    ready["phase"] = json!("ready");
    recovery_journal::transition(Kind::Images, None, &intent, id).unwrap();
    recovery_journal::transition(Kind::Images, Some(&intent), &artifacts, id).unwrap();
    recovery_journal::transition(Kind::Images, Some(&artifacts), &ready, id).unwrap();
    assert!(recovery_journal::transition(Kind::Images, Some(&intent), &ready, id).is_err());
    let observation = json!({"boot_id":"00000000-0000-0000-0000-000000000004","kernel":"6.18.1","identity_sha256":document::fingerprint(&ready["inputs"]["identity"]).unwrap(),"assurance":image::ASSURANCE,"selected_entry":format!("{id}.conf")});
    let mut confirmed = ready.clone();
    confirmed["observations"]["uefi"] = json!({"first":observation,"latest":observation});
    recovery_journal::transition(Kind::Images, Some(&ready), &confirmed, id).unwrap();
    let mut later = confirmed.clone();
    later["observations"]["uefi"]["latest"]["boot_id"] =
        json!("00000000-0000-0000-0000-000000000005");
    recovery_journal::transition(Kind::Images, Some(&confirmed), &later, id).unwrap();
    let mut changed = later.clone();
    changed["observations"]["uefi"]["first"] = changed["observations"]["uefi"]["latest"].clone();
    assert!(recovery_journal::transition(Kind::Images, Some(&confirmed), &changed, id).is_err());
    changed["observations"]["uefi"]["latest"]["boot_id"] = ready["created_boot"].clone();
    assert!(image::validate(&changed, id).is_err());
}
