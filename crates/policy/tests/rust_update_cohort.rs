// SPDX-License-Identifier: MIT
//! Admission of an offline update cohort.
use enzimos_policy::update_cohort::Cohort;
use serde_json::{Value, json};
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path};
fn append(archive: &mut tar::Builder<Vec<u8>>, name: &str, body: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    header.set_size(body.len() as u64);
    header.set_cksum();
    archive
        .append_data(&mut header, name, body)
        .expect("test fixture");
}
fn archive(name: &str, release: &str) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    append(
        &mut tar,
        ".PKGINFO",
        format!("pkgname = {name}\npkgver = 6.18.1-1\narch = x86_64\n").as_bytes(),
    );
    append(
        &mut tar,
        &format!("usr/lib/modules/{release}/vmlinuz"),
        b"owned kernel bytes",
    );
    zstd::stream::encode_all(tar.into_inner().expect("test fixture").as_slice(), 3)
        .expect("test fixture")
}
fn write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("test fixture");
    file.write_all(bytes).expect("test fixture");
    file.sync_all().expect("test fixture");
}
fn fixture(root: &Path) -> Value {
    let mut files = json!({});
    let mut database = tar::Builder::new(Vec::new());
    std::fs::create_dir(root.join("packages")).expect("test fixture");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join("packages"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("test fixture");
    for (name, release) in [("linux", "6.18.1-arch1-1"), ("linux-lts", "6.12.99-1-lts")] {
        let filename = format!("{name}-6.18.1-1-x86_64.pkg.tar.zst");
        let body = archive(name, release);
        let digest = enzimos_platform::json::sha256(&body);
        write(&root.join("packages").join(&filename), &body);
        write(
            &root.join("packages").join(format!("{filename}.sig")),
            b"signature fixture",
        );
        files[&filename] = json!({"bytes":body.len(),"sha256":digest});
        files[format!("{filename}.sig")] =
            json!({"bytes":17,"sha256":enzimos_platform::json::sha256(b"signature fixture")});
        let description = format!(
            "%NAME%\n{name}\n\n%VERSION%\n6.18.1-1\n\n%FILENAME%\n{filename}\n\n%CSIZE%\n{}\n\n%SHA256SUM%\n{digest}\n\n",
            body.len()
        );
        append(
            &mut database,
            &format!("{name}-6.18.1-1/desc"),
            description.as_bytes(),
        );
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(&database.into_inner().expect("test fixture"))
        .expect("test fixture");
    let bytes = encoder.finish().expect("test fixture");
    write(&root.join("packages/verified.db"), &bytes);
    files["verified.db"] =
        json!({"bytes":bytes.len(),"sha256":enzimos_platform::json::sha256(&bytes)});
    let document = json!({"schema":1,"files":files,"expires_at":"2099-01-01T00:00:00Z","signature_policy":"Required TrustedOnly"});
    write(
        &root.join("admission.json"),
        &enzimos_platform::json::canonical(&document).expect("test fixture"),
    );
    document
}
fn directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let work = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    tempfile::Builder::new()
        .prefix("rust-update-cohort-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(work)
        .expect("test fixture")
}
#[test]
fn original_cohort_requires_exact_database_kernels_and_preserves_replacement_refusal() {
    let root = directory();
    let document = fixture(root.path());
    let owner = enzimos_platform::process_identity::effective_uid();
    let source = Cohort::at(root.path(), owner).unwrap();
    assert_eq!(source.document(), &document);
    assert_eq!(source.packages_metadata().len(), 2);
    assert_eq!(
        source.kernels(),
        &json!({"linux":"6.18.1-arch1-1","linux-lts":"6.12.99-1-lts"})
    );
    source.recheck().unwrap();
    // Even byte-identical replacement of a held archive is a different authority.
    let name = root
        .path()
        .join("packages/linux-6.18.1-1-x86_64.pkg.tar.zst");
    let bytes = std::fs::read(&name).unwrap();
    let retained = directory();
    std::fs::rename(&name, retained.path().join("retained-original")).unwrap();
    write(&name, &bytes);
    assert!(source.recheck().is_err());
    // A separate fresh read can accept the same closed publication; the retained
    // source must still refuse to adopt its replaced member.
    Cohort::at(root.path(), owner).unwrap();
}
