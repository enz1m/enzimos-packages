// SPDX-License-Identifier: MIT
use enzimos_platform::{memfile, packet_socket};
use std::{os::fd::AsFd, path::Path, time::Duration};
fn work() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let root = Path::new(
        &std::env::var_os("ENZIMOS_TEST_TMPDIR")
            .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .to_path_buf();
    let directory = tempfile::Builder::new()
        .prefix("ps-")
        .tempdir_in(root)
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn named_listener_delivers_early_packets_with_actual_credentials_and_never_replaces_a_path() {
    let directory = work();
    let path = directory.path().join("request.sock");
    let uid = unsafe { libc::geteuid() };
    let listener = packet_socket::Listener::bind(&path, uid).unwrap();
    assert!(packet_socket::Listener::bind(&path, uid).is_err());
    let client = packet_socket::connect(&path, uid, Duration::from_secs(1)).unwrap();
    let request = memfile::sealed("named-packet", b"request").unwrap();
    client
        .send(b"ready", &[request.as_fd()], Duration::from_secs(1))
        .unwrap();
    let accepted = listener.accept(Duration::from_secs(1)).unwrap();
    let received = accepted.receive(64, 1, Duration::from_secs(1)).unwrap();
    assert_eq!(received.sender.pid, std::process::id());
    assert_eq!(received.sender.uid, uid);
    assert_eq!(received.body, b"ready");
    let retained: std::fs::File = received.files.into_iter().next().unwrap().into();
    assert_eq!(
        memfile::read_sealed(&retained, 64, uid).unwrap(),
        b"request"
    );
    drop(listener);
    assert!(path.exists());
    assert!(packet_socket::Listener::bind(&path, uid).is_err());
}
