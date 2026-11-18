// SPDX-License-Identifier: MIT
//! Private-mount hooks report contention through their inherited supervisor channel.
use crate::{deferred, identity, operation};
use enzimos_platform::{
    Error, Result,
    fd_packet::{Credentials, Packet},
    files, json, require,
};
use serde_json::{Value, json as value};
use std::{fs::File, os::fd::FromRawFd, time::Duration};
pub const FD_ENV: &str = "ENZIMOS_UPDATE_HOOK_FD";
pub const PID_ENV: &str = "ENZIMOS_UPDATE_SUPERVISOR_PID";
pub const ID_ENV: &str = "ENZIMOS_UPDATE_GENERATION";
pub fn request_frame(body: &Value, id: &str) -> Result<()> {
    identity::safe_id(id)?;
    json::fields(body, "schema action generation token")?;
    let token = body["token"]
        .as_str()
        .ok_or_else(|| Error("authority hook token missing".into()))?;
    require(
        body["schema"].as_u64() == Some(1)
            && body["action"] == "authority"
            && body["generation"] == id
            && token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "authority hook request refused",
    )
}
pub fn response_frame(
    body: &Value,
    sender: &Credentials,
    id: &str,
    token: &str,
    pid: u32,
) -> Result<()> {
    json::fields(body, "schema generation token status marker")?;
    require(
        body["schema"].as_u64() == Some(1)
            && body["generation"] == id
            && body["token"] == token
            && body["status"] == "deferred"
            && sender.pid == pid
            && sender.uid == 0
            && sender.gid == 0,
        "authority hook supervisor response refused",
    )?;
    deferred::validate(&body["marker"], "authority")
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
pub fn request() -> Result<Value> {
    operation::root_only()?;
    let decimal = |name: &str, maximum: u32| -> Result<u32> {
        let text = std::env::var(name)
            .map_err(|_| Error("authority hook inherited context missing".into()))?;
        let value = text
            .parse::<u32>()
            .map_err(|_| Error("authority hook inherited descriptor syntax".into()))?;
        require(
            value.to_string() == text && value < maximum,
            "authority hook inherited context bound",
        )?;
        Ok(value)
    };
    let descriptor = decimal(FD_ENV, 1_048_576)?;
    let pid = decimal(PID_ENV, i32::MAX as u32)?;
    require(
        descriptor >= 3 && pid > 1,
        "authority hook inherited context refused",
    )?;
    let id =
        std::env::var(ID_ENV).map_err(|_| Error("authority hook generation missing".into()))?;
    identity::safe_id(&id)?;
    let raw = unsafe { libc::fcntl(descriptor as i32, libc::F_DUPFD_CLOEXEC, 64) };
    require(raw >= 0, "authority hook inherited channel unavailable")?;
    let channel = Packet::from_file(unsafe { File::from_raw_fd(raw) })?;
    let token = files::random_hex(16)?;
    let body = value!({"schema":1,"action":"authority","generation":id,"token":token});
    request_frame(&body, &id)?;
    channel.send(&json::canonical(&body)?, &[], Duration::from_secs(5))?;
    let reply = channel.receive(4096, 0, Duration::from_secs(5))?;
    let body = json::decode(&reply.body, 4096)?;
    response_frame(&body, &reply.sender, &id, &token, pid)?;
    require(
        body["marker"]["last_boot_id"] == operation::boot_id()?,
        "authority hook supervisor boot changed",
    )?;
    Ok(value!({"status":"authority-refresh-deferred-to-next-boot"}))
}
