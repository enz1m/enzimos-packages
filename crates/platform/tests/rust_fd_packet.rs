// SPDX-License-Identifier: MIT
use enzimos_platform::{fd_packet::Packet, files, memfile};
use std::{
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, getegid, geteuid).")]
fn packet_passes_sealed_descriptor_and_actual_kernel_sender_with_close_on_exec() {
    let _serial = SERIAL.lock().unwrap();
    let (sender, receiver) = Packet::pair().unwrap();
    let payload = memfile::sealed("packet-test", b"immutable payload").unwrap();
    sender
        .send(b"review", &[payload.as_fd()], Duration::from_secs(1))
        .unwrap();
    let message = receiver.receive(64, 1, Duration::from_secs(1)).unwrap();
    assert_eq!(message.body, b"review");
    assert_eq!(message.sender.pid, std::process::id());
    assert_eq!(message.sender.uid, unsafe { libc::geteuid() });
    assert_eq!(message.sender.gid, unsafe { libc::getegid() });
    assert_ne!(
        unsafe { libc::fcntl(message.files[0].as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let received: std::fs::File = message.files.into_iter().next().unwrap().into();
    assert_eq!(
        files::read_file(&received, 64, None, false).unwrap(),
        b"immutable payload"
    );
    assert_ne!(
        unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GET_SEALS) } & libc::F_SEAL_WRITE,
        0
    );
}
#[test]
fn truncated_or_extra_descriptors_are_closed_and_packets_are_not_replayed() {
    let _serial = SERIAL.lock().unwrap();
    let (sender, receiver) = Packet::pair().unwrap();
    let payload = memfile::sealed("packet-test", b"immutable payload").unwrap();
    let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let initial = count();
    sender
        .send(&[b'x'; 128], &[payload.as_fd()], Duration::from_secs(1))
        .unwrap();
    assert!(receiver.receive(64, 1, Duration::from_secs(1)).is_err());
    assert_eq!(count(), initial);
    sender
        .send(
            b"excess",
            &[payload.as_fd(), payload.as_fd()],
            Duration::from_secs(1),
        )
        .unwrap();
    assert!(receiver.receive(64, 1, Duration::from_secs(1)).is_err());
    assert_eq!(count(), initial);
    assert!(receiver.receive(64, 0, Duration::from_millis(20)).is_err());
    assert!(sender.send(b"", &[], Duration::from_secs(1)).is_err());
}
#[test]
#[allow(unsafe_code, reason = "Fork-child setup must run before exec.")]
fn inherited_socket_reports_actual_child_sender_instead_of_socket_creator() {
    use std::os::unix::process::CommandExt;
    let _serial = SERIAL.lock().unwrap();
    let (child_socket, parent_socket) = Packet::pair().unwrap();
    let source = child_socket.as_fd().as_raw_fd();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", "packet_child_sender", "--nocapture"])
        .env("ENZIMOS_TEST_PACKET_FD", "198");
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, 198) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(child_socket);
    let received = parent_socket
        .receive(64, 0, Duration::from_secs(5))
        .unwrap();
    assert_eq!(received.sender.pid, child.id());
    assert_ne!(received.sender.pid, std::process::id());
    assert_eq!(received.body, b"actual-child");
    assert!(child.wait().unwrap().success());
}
#[test]
#[ignore = "owned child fixture invoked by the parent test"]
#[allow(
    unsafe_code,
    reason = "Transfers an acquired native descriptor into Rust ownership."
)]
fn packet_child_sender() {
    use std::os::fd::FromRawFd;
    let descriptor: i32 = std::env::var("ENZIMOS_TEST_PACKET_FD")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(descriptor, 198);
    let socket = Packet::from_file(unsafe { std::fs::File::from_raw_fd(descriptor) }).unwrap();
    socket
        .send(b"actual-child", &[], Duration::from_secs(1))
        .unwrap();
}
