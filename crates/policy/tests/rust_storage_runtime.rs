// SPDX-License-Identifier: MIT
use enzimos_platform::mountinfo;
use enzimos_policy::storage_runtime;
#[test]
fn mount_shadowing_wrong_identity_wrong_root_and_readonly_all_refuse() {
    let body =
        "44 1 0:31 /control /var/lib/enzimos-control rw,nosuid - btrfs /dev/mapper/root rw\n";
    let rows = mountinfo::parse(body).unwrap();
    storage_runtime::mount_row(&rows, "/var/lib/enzimos-control", Some("/control"), 44).unwrap();
    for changed in [
        body.replace("44 1", "45 1"),
        body.replace("/control /var", "/root /var"),
        body.replace("rw,nosuid", "ro,nosuid"),
        body.replace("rw,nosuid", "rw,ro,nosuid"),
        body.replace("- btrfs", "- ext4"),
        format!("{body}{}", body.replace("44 1", "45 1")),
    ] {
        let rows = mountinfo::parse(&changed).unwrap();
        assert!(
            storage_runtime::mount_row(&rows, "/var/lib/enzimos-control", Some("/control"), 44)
                .is_err()
        );
    }
}
