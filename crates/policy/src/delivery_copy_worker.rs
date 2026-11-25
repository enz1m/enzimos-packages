// SPDX-License-Identifier: MIT
//! Fixed unprivileged worker receives actual descriptors from its kernel-identified Root parent.
use crate::{delivery_copy, delivery_copy_request::Request};
use enzimos_platform::{
    Error, Result,
    fd_packet::{Credentials, Packet},
    files, json, memfile, mount_identity, process_identity, require,
};
use serde_json::json as value;
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::Duration,
};
pub(crate) const HELLO: &[u8] = b"ENZIMOS_DELIVERY_COPY_HELLO_2";
pub(crate) const FRAME: &[u8] = b"ENZIMOS_DELIVERY_COPY_2";
const DEADLINE: Duration = Duration::from_secs(5);
struct Parent {
    file: File,
    pid: u32,
    start: u64,
}
impl Parent {
    #[allow(unsafe_code, reason = "Linux syscall ABI (syscall).")]
    fn open(sender: &Credentials, request: &Request) -> Result<Self> {
        require(
            sender.uid == 0
                && sender.gid == 0
                && sender.pid == enzimos_platform::process_identity::parent_pid() as u32
                && sender.pid == request.supervisor_pid,
            "delivery Root sender is not original parent",
        )?;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, sender.pid, 0) as i32 };
        require(fd >= 0, "original delivery parent pidfd unavailable")?;
        let this = Self {
            file: unsafe { File::from_raw_fd(fd) },
            pid: sender.pid,
            start: request.supervisor_start,
        };
        this.recheck()?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (poll).")]
    fn recheck(&self) -> Result<()> {
        let mut poll = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(
            unsafe { libc::poll(&mut poll, 1, 0) } == 0
                && process_identity::pidfd_target(self.file.as_fd())? == self.pid
                && enzimos_platform::process_identity::parent_pid() as u32 == self.pid,
            "original delivery parent exited or changed",
        )?;
        let bytes = files::read_kernel(
            &Path::new("/proc").join(self.pid.to_string()).join("stat"),
            8192,
        )?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&bytes)
                .map_err(|_| Error("delivery parent stat encoding".into()))?,
            self.pid,
        )?;
        require(
            stat.start_ticks == self.start,
            "original delivery parent start epoch differs",
        )
    }
    fn sender(&self, sender: &Credentials) -> Result<()> {
        self.recheck()?;
        require(
            sender.pid == self.pid && sender.uid == 0 && sender.gid == 0,
            "delivery command sender differs",
        )
    }
}
fn dropped(request: &Request) -> Result<()> {
    privileges(request.recipient_uid, request.recipient_gid)
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (getgroups, getresgid, getresuid, prctl and others)."
)]
fn privileges(uid: u32, gid: u32) -> Result<()> {
    require(
        (1000..i32::MAX as u32).contains(&uid) && (1..i32::MAX as u32).contains(&gid),
        "ordinary delivery worker required",
    )?;
    let mut real = 0;
    let mut effective = 0;
    let mut saved = 0;
    require(
        unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } == 0
            && [real, effective, saved] == [uid; 3],
        "delivery worker UID drop differs",
    )?;
    require(
        unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) } == 0
            && [real, effective, saved] == [gid; 3]
            && unsafe { libc::getgroups(0, std::ptr::null_mut()) } == 0,
        "delivery worker GID/groups drop differs",
    )?;
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let mut data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    require(
        unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } == 0
            && data
                .iter()
                .all(|d| d.effective == 0 && d.permitted == 0 && d.inheritable == 0)
            && unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1,
        "delivery worker residual privilege refused",
    )?;
    let mut death = 0;
    require(
        unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut death, 0, 0, 0) } == 0
            && death == libc::SIGKILL,
        "delivery parent-death guard differs",
    )
}
fn group(request: &Request) -> Result<()> {
    let current = files::read_kernel(
        &Path::new("/proc")
            .join(std::process::id().to_string())
            .join("cgroup"),
        4096,
    )?;
    require(
        std::str::from_utf8(&current)
            .map_err(|_| Error("delivery worker cgroup encoding".into()))?
            .trim_end_matches('\n')
            == crate::delivery_worker_group::membership_value(&request.group_nonce)?,
        "delivery worker is outside its original private group",
    )
}
fn descriptors(request: &Request, source: &File, home: &File) -> Result<()> {
    let m = home.metadata()?;
    require(
        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode()) == request.home
            && m.is_dir()
            && mount_identity::id(home.as_fd(), true)? == request.home_mount
            && files::identity(&source.metadata()?) == request.source
            && mount_identity::id(source.as_fd(), true)? == request.source_mount
            && enzimos_platform::files::status_flags(&source) & libc::O_ACCMODE == libc::O_RDONLY
            && enzimos_platform::files::status_flags(&home) & libc::O_ACCMODE == libc::O_RDONLY,
        "delivery original descriptor epochs or rights differ",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (prctl).")]
pub fn entry(channel: Packet) -> Result<()> {
    privileges(
        enzimos_platform::process_identity::effective_uid(),
        enzimos_platform::process_identity::effective_gid(),
    )?;
    require(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "delivery worker dump protection unavailable",
    )?;
    channel.send(HELLO, &[], DEADLINE)?;
    run(channel)
}
fn run(channel: Packet) -> Result<()> {
    let message = channel.receive(crate::delivery_copy_request::LIMIT.min(128), 3, DEADLINE)?;
    require(
        message.body == FRAME
            && message.sender.uid == 0
            && message.sender.gid == 0
            && message.sender.pid == enzimos_platform::process_identity::parent_pid() as u32,
        "delivery handoff kernel sender or frame refused",
    )?;
    let mut descriptors_received = message.files.into_iter();
    let sealed = File::from(
        descriptors_received
            .next()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
    );
    let source = File::from(
        descriptors_received
            .next()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
    );
    let home = File::from(
        descriptors_received
            .next()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
    );
    let body = memfile::read_sealed(&sealed, crate::delivery_copy_request::LIMIT, 0)?;
    let request = Request::decode(&body)?;
    let parent = Parent::open(&message.sender, &request)?;
    dropped(&request)?;
    group(&request)?;
    descriptors(&request, &source, &home)?;
    require(
        crate::operation::boot_id()? == request.boot_id,
        "delivery worker boot epoch differs",
    )?;
    let digest = json::sha256(&body);
    let ready =
        value!({"schema":1,"status":"delivery-copy-ready","id":request.id,"request_sha256":digest});
    parent.recheck()?;
    channel.send(&json::canonical(&ready)?, &[], DEADLINE)?;
    let command = channel.receive(128, 0, DEADLINE)?;
    parent.sender(&command.sender)?;
    require(
        command.body == format!("COPY {digest}").as_bytes(),
        "delivery one-use copy command differs",
    )?;
    dropped(&request)?;
    group(&request)?;
    descriptors(&request, &source, &home)?;
    let output = delivery_copy::copy_named(
        &home,
        &source,
        &request.filename,
        request.bytes,
        &request.sha256,
        request.recipient_uid,
    )?;
    parent.recheck()?;
    group(&request)?;
    descriptors(&request, &source, &home)?;
    let complete = value!({"schema":1,"status":"delivery-copy-complete","id":request.id,"request_sha256":digest,"bytes":request.bytes,"sha256":request.sha256});
    channel.send(&json::canonical(&complete)?, &[output.as_fd()], DEADLINE)?;
    parent.recheck()
}
