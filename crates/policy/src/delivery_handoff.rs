// SPDX-License-Identifier: MIT
//! Original child handoff. The grant owner must durably enter delivery before invoking it.
use crate::{delivery_child::Child, delivery_copy_request::Request, delivery_worker_group::Group};
use enzimos_platform::{
    Result,
    fd_packet::{Credentials, Packet},
    files, json, memfile, mount_identity, process_identity, require, stream_copy,
};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
    time::Duration,
};
const DEADLINE: Duration = Duration::from_secs(5);

fn sender(actual: &Credentials, pid: u32, request: &Request) -> Result<()> {
    require(
        actual.pid == pid
            && actual.uid == request.recipient_uid
            && actual.gid == request.recipient_gid,
        "delivery reply kernel sender differs",
    )
}
fn inputs(request: &Request, source: &File, home: &File) -> Result<()> {
    let m = home.metadata()?;
    require(
        (m.dev(), m.ino(), m.uid(), m.gid(), m.mode()) == request.home
            && mount_identity::id(home.as_fd(), true)? == request.home_mount
            && files::identity(&source.metadata()?) == request.source
            && mount_identity::id(source.as_fd(), true)? == request.source_mount,
        "delivery original input epochs differ",
    )
}
fn reply(body: &[u8], expected: &Value) -> Result<()> {
    require(
        json::decode(body, 2048)? == *expected,
        "delivery worker reply differs",
    )
}
pub(crate) fn verify_output(request: &Request, home: &File, file: &File) -> Result<()> {
    let before = files::identity(&file.metadata()?);
    require(
        before.7 & libc::S_IFMT == libc::S_IFREG
            && before.7 & 0o7777 == 0o600
            && before.8 == request.recipient_uid
            && before.9 == request.recipient_gid
            && before.10 == 1
            && before.2 == request.bytes
            && mount_identity::id(file.as_fd(), true)? == request.home_mount,
        "delivery output ownership, shape or mount differs",
    )?;
    let (bytes, digest) = stream_copy::hash_borrowed(file, crate::delivery_export::MAX_FILE, None)?;
    let named = files::open_relative(home, Path::new(&request.filename))?;
    require(
        bytes == request.bytes
            && digest == request.sha256
            && files::identity(&file.metadata()?) == before
            && files::identity(&named.metadata()?) == before
            && mount_identity::id(named.as_fd(), true)? == request.home_mount,
        "original delivery output changed during independent verification",
    )
}
/// No grant is accepted from this data-only request. Callers retain their original
/// grant, lock, account and export, and recheck them through `authorize` at each gate.
/// Every failure keeps the entered intent and any final output; this never retries.
pub(crate) fn copy<F: FnMut() -> Result<()>>(
    approved: &crate::delivery_child::Image,
    body: &[u8],
    source: &File,
    home: &File,
    group: Group,
    authorize: &mut F,
) -> Result<File> {
    crate::operation::root_only()?;
    crate::namespaces::initial()?;
    let request = Request::decode(body)?;
    require(
        request.group_nonce == group.nonce()?
            && request.supervisor_pid == enzimos_platform::process_identity::current_pid() as u32
            && request.boot_id == crate::operation::boot_id()?,
        "delivery supervisor request differs",
    )?;
    let stat = files::read_kernel(
        &Path::new("/proc")
            .join(std::process::id().to_string())
            .join("stat"),
        8192,
    )?;
    let stat = process_identity::parse_stat(
        std::str::from_utf8(&stat)
            .map_err(|_| enzimos_platform::Error("delivery supervisor stat encoding".into()))?,
        request.supervisor_pid,
    )?;
    require(
        stat.start_ticks == request.supervisor_start,
        "delivery supervisor start differs",
    )?;
    inputs(&request, source, home)?;
    authorize()?;
    let sealed = memfile::sealed("enzimos-delivery-copy", body)?;
    let digest = json::sha256(body);
    let (channel, worker) = Packet::pair()?;
    let mut child = Child::spawn(
        approved,
        &group,
        &worker,
        request.recipient_uid,
        request.recipient_gid,
    )?;
    drop(worker);
    let hello = channel.receive(128, 0, DEADLINE)?;
    sender(&hello.sender, child.pid(), &request)?;
    require(
        hello.body == crate::delivery_copy_worker::HELLO,
        "delivery protected worker hello differs",
    )?;
    child.live()?;
    group.contains_only(child.pid())?;
    authorize()?;
    inputs(&request, source, home)?;
    channel.send(
        crate::delivery_copy_worker::FRAME,
        &[sealed.as_fd(), source.as_fd(), home.as_fd()],
        DEADLINE,
    )?;
    let ready = channel.receive(2048, 0, DEADLINE)?;
    sender(&ready.sender, child.pid(), &request)?;
    reply(
        &ready.body,
        &value!({"schema":1,"status":"delivery-copy-ready","id":request.id,"request_sha256":digest}),
    )?;
    child.live()?;
    group.contains_only(child.pid())?;
    authorize()?;
    inputs(&request, source, home)?;
    channel.send(format!("COPY {digest}").as_bytes(), &[], DEADLINE)?;
    let complete = channel.receive(2048, 1, DEADLINE)?;
    sender(&complete.sender, child.pid(), &request)?;
    reply(
        &complete.body,
        &value!({"schema":1,"status":"delivery-copy-complete","id":request.id,"request_sha256":digest,"bytes":request.bytes,"sha256":request.sha256}),
    )?;
    let file = File::from(complete.files.into_iter().next().unwrap());
    child.success(DEADLINE)?;
    approved.recheck()?;
    require(
        group.empty()?,
        "delivery worker group remains populated; no replay",
    )?;
    inputs(&request, source, home)?;
    authorize()?;
    verify_output(&request, home, &file)?;
    inputs(&request, source, home)?;
    group.retire()?;
    approved.recheck()?;
    Ok(file)
}
