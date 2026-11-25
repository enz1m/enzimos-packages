// SPDX-License-Identifier: MIT
//! Generation registry transitions.
use enzimos_platform::json;
use enzimos_policy::catalog;
use serde_json::{Value, json as v};
const FS: &str = "11111111-1111-1111-1111-111111111111";
const BOOT: &str = "22222222-2222-2222-2222-222222222222";
fn material() -> Value {
    let artifacts = [
        "vmlinuz-linux",
        "vmlinuz-linux-lts",
        "initramfs-linux.img",
        "initramfs-linux-lts.img",
    ]
    .map(|n| v!({"name":n,"bytes":20,"sha256":"a".repeat(64)}));
    v!({"kernels":{"linux":"6.18.1","linux-lts":"6.12.9"},"files":artifacts,"options":"rootflags=subvol=root enzimos.generation=gen1","root_identity":{"path":"root","id":256,"uuid":FS,"ownership":"not-established"},"inventory_sha256":"b".repeat(64)})
}
fn fingerprints() -> Value {
    v!({"uefi":{"enzimos-gen1-linux.conf":"c".repeat(64),"enzimos-gen1-linux-lts.conf":"d".repeat(64)},"bios":{"enzimOS gen1 linux":"e".repeat(64),"enzimOS gen1 linux-lts":"f".repeat(64)}})
}
#[test]
fn interrupted_publication_later_boot_confirmation_and_no_name_reuse() {
    let empty = catalog::empty(FS).unwrap();
    let m = material();
    let reserved = catalog::reserve_document(&empty, "gen1", &m, BOOT).unwrap();
    assert_eq!(
        enzimos_policy::system_query::generations(&empty).unwrap(),
        v!([])
    );
    assert_eq!(
        enzimos_policy::system_query::generations(&reserved).unwrap(),
        v!([
            {"name":"gen1","state":"preparing","ordinal":1,"kernels":["linux","linux-lts"],"confirmed":false}
        ])
    );
    assert_eq!(reserved["next_ordinal"], 2);
    assert_eq!(
        catalog::reserve_document(&reserved, "gen1", &m, BOOT).unwrap(),
        reserved
    );
    let mut changed = m.clone();
    changed["inventory_sha256"] = v!("e".repeat(64));
    assert!(catalog::reserve_document(&reserved, "gen1", &changed, BOOT).is_err());
    let observation = v!({"boot_id":BOOT,"kernel":"6.18.1","uefi":true,"filesystem_uuid":FS,"root_uuid":FS,"material_sha256":json::fingerprint(&m).unwrap(),"assurance":"software-local-observed-boot-not-firmware-authentication"});
    assert!(catalog::confirm_document(&reserved, "gen1", &observation).is_err());
    let ready = catalog::publish_document(&reserved, "gen1", &fingerprints()).unwrap();
    assert!(catalog::publish_document(&ready, "gen1", &fingerprints()).is_err());
    assert!(catalog::confirm_document(&ready, "gen1", &observation).is_err());
    let mut later = observation;
    later["boot_id"] = v!("33333333-3333-3333-3333-333333333333");
    let confirmed = catalog::confirm_document(&ready, "gen1", &later).unwrap();
    assert_eq!(
        enzimos_policy::system_query::generations(&confirmed).unwrap(),
        v!([
            {"name":"gen1","state":"ready","ordinal":1,"kernels":["linux","linux-lts"],"confirmed":true}
        ])
    );
    let mut last = later.clone();
    last["boot_id"] = v!("44444444-4444-4444-4444-444444444444");
    last["kernel"] = v!("6.12.9");
    let confirmed = catalog::confirm_document(&confirmed, "gen1", &last).unwrap();
    assert_eq!(
        confirmed["generations"]["gen1"]["first_confirmation"],
        later
    );
    assert_eq!(confirmed["generations"]["gen1"]["last_confirmation"], last);
    let mut retired = catalog::empty(FS).unwrap();
    retired["next_ordinal"] = v!(2);
    retired["retired"] = v!({"gen1":{"ordinal":1,"material_sha256":json::fingerprint(&m).unwrap(),"retired_boot":BOOT}});
    assert!(catalog::reserve_document(&retired, "gen1", &m, BOOT).is_err());
    assert_eq!(empty["generations"], v!({}));
}
