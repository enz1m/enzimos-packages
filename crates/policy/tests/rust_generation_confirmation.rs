// SPDX-License-Identifier: MIT
//! Generation boot confirmation records.
use enzimos_platform::json;
use enzimos_policy::{catalog, generation_confirmation::observation};
use serde_json::{Value, json as v};
const FS: &str = "11111111-1111-1111-1111-111111111111";
const CREATED: &str = "22222222-2222-2222-2222-222222222222";
const BOOT: &str = "33333333-3333-3333-3333-333333333333";
const OPTIONS: &str = "rootflags=subvol=root enzimos.generation=gen1";
fn ready() -> Value {
    let files = [
        "vmlinuz-linux",
        "vmlinuz-linux-lts",
        "initramfs-linux.img",
        "initramfs-linux-lts.img",
    ]
    .map(|name| v!({"name":name,"bytes":20,"sha256":"a".repeat(64)}));
    let material = v!({"kernels":{"linux":"6.18.1","linux-lts":"6.12.9"},"files":files,
        "options":OPTIONS,"root_identity":{"path":"root","id":256,"uuid":FS,"ownership":"not-established"},
        "inventory_sha256":json::sha256(b"linux 6.18.1\nlinux-lts 6.12.9")});
    let reserved = catalog::reserve_document(
        &catalog::empty(FS).expect("test fixture"),
        "gen1",
        &material,
        CREATED,
    )
    .expect("test fixture");
    catalog::publish_document(&reserved, "gen1", &v!({"uefi":{"enzimos-gen1-linux.conf":"c".repeat(64),"enzimos-gen1-linux-lts.conf":"d".repeat(64)},"bios":{"enzimOS gen1 linux":"e".repeat(64),"enzimOS gen1 linux-lts":"f".repeat(64)}})).expect("test fixture")
}
#[expect(
    clippy::too_many_arguments,
    reason = "Mirrors the observation it builds."
)]
fn observe(
    data: &Value,
    boot: &str,
    options: &str,
    root: &Value,
    kernel: &str,
    inventory: &str,
    entries: &Value,
    uefi: bool,
    selected: Option<&str>,
) -> enzimos_platform::Result<Value> {
    observation(
        &data["generations"]["gen1"],
        FS,
        boot,
        options,
        root,
        kernel,
        inventory,
        entries,
        uefi,
        selected,
    )
}
#[test]
fn confirms_actual_later_boot_and_preserves_first_observation_across_kernel_modes() {
    let data = ready();
    let row = &data["generations"]["gen1"];
    let first = observe(
        &data,
        BOOT,
        OPTIONS,
        &row["material"]["root_identity"],
        "6.18.1",
        "linux 6.18.1\nlinux-lts 6.12.9",
        &row["entry_fingerprints"],
        true,
        Some("enzimos-gen1-linux.conf"),
    )
    .unwrap();
    let confirmed = catalog::confirm_document(&data, "gen1", &first).unwrap();
    let last = observe(
        &confirmed,
        "44444444-4444-4444-4444-444444444444",
        OPTIONS,
        &row["material"]["root_identity"],
        "6.12.9",
        "linux 6.18.1\nlinux-lts 6.12.9",
        &row["entry_fingerprints"],
        false,
        None,
    )
    .unwrap();
    let confirmed = catalog::confirm_document(&confirmed, "gen1", &last).unwrap();
    assert_eq!(
        confirmed["generations"]["gen1"]["first_confirmation"],
        first
    );
    assert_eq!(confirmed["generations"]["gen1"]["last_confirmation"], last);
    assert_eq!(
        last["assurance"],
        "software-local-observed-boot-not-firmware-authentication"
    );
}
