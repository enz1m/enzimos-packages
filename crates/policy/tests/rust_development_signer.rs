// SPDX-License-Identifier: MIT
//! The ephemeral development package signer.
use enzimos_platform::{files, process};
use enzimos_policy::{
    authority, authority_build,
    development_signer::{Signer, verify_local},
};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};
#[test]
fn real_machine_local_signatures_retire_the_exact_owned_agent_and_private_key() {
    let work = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let temporary = tempfile::Builder::new()
        .prefix("nds-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .unwrap();
    let owner = enzimos_platform::process_identity::effective_uid();
    let home = temporary.path().join("s");
    let mut signer = Signer::create(&home, owner).unwrap();
    let public = temporary.path().join("p");
    files::create_directory(&public, 0o700, owner).unwrap();
    files::atomic(
        &public.join("gpg.conf"),
        authority::CONFIG.as_bytes(),
        0o644,
        Some(owner),
        false,
    )
    .unwrap();
    let exported = signer.public().unwrap();
    let key = temporary.path().join("key.gpg");
    files::atomic(&key, &exported, 0o600, Some(owner), false).unwrap();
    let imported = process::run(
        "/usr/bin/gpg",
        &[
            "--no-options",
            "--homedir",
            public.to_str().unwrap(),
            "--batch",
            "--no-autostart",
            "--import",
            key.to_str().unwrap(),
        ],
        &[],
        Duration::from_secs(30),
        65536,
    )
    .unwrap();
    assert!(imported.status.success());
    authority_build::gpg(
        &public,
        &["--import-ownertrust"],
        format!("{}:5:\n", signer.fingerprint).as_bytes(),
    )
    .unwrap();
    let archive = temporary.path().join("package");
    files::atomic(
        &archive,
        b"owned development fixture bytes",
        0o600,
        Some(owner),
        false,
    )
    .unwrap();
    let file = std::fs::File::open(&archive).unwrap();
    let signature = temporary.path().join("package.sig");
    signer.sign(&file, &signature).unwrap();
    let signed = std::fs::File::open(&signature).unwrap();
    verify_local(&file, &signed, &public, &signer.fingerprint).unwrap();
    assert!(signer.sign(&file, &signature).is_err());
    files::atomic(
        &archive,
        b"changed development bytes",
        0o600,
        Some(owner),
        true,
    )
    .unwrap();
    assert!(
        verify_local(
            &std::fs::File::open(&archive).unwrap(),
            &signed,
            &public,
            &signer.fingerprint
        )
        .is_err()
    );
    signer.retire().unwrap();
    assert!(!home.join("private-keys-v1.d").exists());
    assert!(signer.public().is_err());
    assert!(
        signer
            .sign(&file, &temporary.path().join("again.sig"))
            .is_err()
    );
    assert!(
        authority_build::gpg(&public, &["--list-secret-keys"], &[])
            .unwrap()
            .is_empty()
    );
}
