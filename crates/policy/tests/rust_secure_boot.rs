// SPDX-License-Identifier: MIT
use enzimos_platform::files;
use enzimos_policy::secure_boot::{self, Material};
use std::{os::unix::fs::PermissionsExt, path::Path};
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn owner_key_roundtrip_preserves_private_permissions_and_refuses_mismatch_and_replacement() {
    let work = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let temp = tempfile::Builder::new()
        .prefix("rust-owner-key-fixture-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    let uid = unsafe { libc::geteuid() };
    let material = Material::generate().unwrap();
    let certificate = openssl::x509::X509::from_der(&material.der).unwrap();
    assert_eq!(certificate.public_key().unwrap().rsa().unwrap().size(), 384);
    assert!(
        certificate
            .verify(&certificate.public_key().unwrap())
            .unwrap()
    );
    let directory = temp.path().join("owner");
    material.write_new(&directory, uid).unwrap();
    let loaded = Material::load(&directory, uid).unwrap();
    assert_eq!(loaded.der, material.der);
    assert!(material.write_new(&directory, uid).is_err());
    let key = directory.join("owner.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Material::load(&directory, uid).is_err());
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = Material::generate().unwrap();
    files::atomic(
        &directory.join("owner.crt"),
        &other.pem,
        0o644,
        Some(uid),
        true,
    )
    .unwrap();
    files::atomic(
        &directory.join("owner.cer"),
        &other.der,
        0o644,
        Some(uid),
        true,
    )
    .unwrap();
    assert!(Material::load(&directory, uid).is_err());
    files::atomic(
        &directory.join("owner.crt"),
        &material.pem,
        0o644,
        Some(uid),
        true,
    )
    .unwrap();
    files::atomic(
        &directory.join("owner.cer"),
        &material.der,
        0o644,
        Some(uid),
        true,
    )
    .unwrap();
    std::fs::remove_file(&key).unwrap();
    std::os::unix::fs::symlink("owner.crt", &key).unwrap();
    assert!(Material::load(&directory, uid).is_err());
    let efi = temp.path().join("efi");
    files::create_directory(&efi, 0o700, uid).unwrap();
    assert_eq!(
        secure_boot::firmware_at(&efi, uid).unwrap()["capable"],
        false
    );
    let flag = efi.join("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    files::atomic(&flag, &[7, 0, 0, 0, 1], 0o600, Some(uid), false).unwrap();
    assert!(secure_boot::firmware_at(&efi, uid).is_err());
    files::atomic(
        &efi.join("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        &[7, 0, 0, 0, 0],
        0o600,
        Some(uid),
        false,
    )
    .unwrap();
    assert_eq!(
        secure_boot::firmware_at(&efi, uid).unwrap()["enabled"],
        true
    );
    std::fs::remove_file(&flag).unwrap();
    std::os::unix::fs::symlink("missing", &flag).unwrap();
    assert!(secure_boot::firmware_at(&efi, uid).is_err());
}
