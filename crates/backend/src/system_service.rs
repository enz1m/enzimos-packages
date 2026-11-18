// SPDX-License-Identifier: MIT
//! Exact wire dispatch with bounded calls and no mutation after malformed input.
use super::system_wire as wire;
use enzimos_platform::{Error, Result, json, require};
use futures_util::StreamExt;
use serde_json::Value;
use std::{
    fs::File,
    future::Future,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use zbus::{
    AsyncDrop, Connection, Message, MessageStream,
    fdo::{RequestNameFlags, RequestNameReply},
    message::{Flags, Type},
};
pub struct Call {
    pub member: String,
    pub sender: String,
    pub body: Option<String>,
    pub descriptor: Option<File>,
    /// `BackupRemoteShareSetup` only: the optional second sealed input.
    pub second: Option<File>,
    pub arrived: Instant,
}
pub struct Reply {
    pub body: Value,
    pub descriptor: Option<File>,
}
impl From<Value> for Reply {
    fn from(body: Value) -> Self {
        Self {
            body,
            descriptor: None,
        }
    }
}
pub fn validate(message: &Message) -> Result<Call> {
    let arrived = Instant::now();
    let header = message.header();
    require(
        header.primary().msg_type() == Type::MethodCall,
        "wire-method-unavailable",
    )?;
    let member = header
        .member()
        .map(|v| v.as_str())
        .ok_or_else(|| Error("wire-method-unavailable".into()))?;
    let sender = header
        .sender()
        .map(|v| v.as_str())
        .ok_or_else(|| Error("unique-system-bus-sender-required".into()))?;
    wire::call(
        header.path().map(|v| v.as_str()).unwrap_or(""),
        header.interface().map(|v| v.as_str()).unwrap_or(""),
        member,
        &super::system_header::signature(message.data())?,
        header.primary().flags().contains(Flags::NoReplyExpected),
        sender,
    )?;
    require(
        message.body().len() <= wire::MAX_REQUEST + 32,
        "request-bound",
    )?;
    let descriptors = message.data().fds().len();
    require(
        if member == "BackupRemoteShareSetup" {
            matches!(descriptors, 1 | 2)
        } else {
            descriptors == usize::from(matches!(member, "BackupSetupInput" | "LoginAppearance"))
        },
        "wire-signature",
    )?;
    let mut second = None;
    let (body, descriptor) = if member == "GetCapabilities" {
        message
            .body()
            .deserialize::<()>()
            .map_err(|_| Error("wire-signature".into()))?;
        (None, None)
    } else if matches!(member, "BackupSetupInput" | "LoginAppearance") {
        let (body, fd): (String, zbus::zvariant::OwnedFd) = message
            .body()
            .deserialize()
            .map_err(|_| Error("wire-signature".into()))?;
        (Some(body), Some(File::from(std::os::fd::OwnedFd::from(fd))))
    } else if member == "BackupRemoteShareSetup" {
        let (body, fds): (String, Vec<zbus::zvariant::OwnedFd>) = message
            .body()
            .deserialize()
            .map_err(|_| Error("wire-signature".into()))?;
        require(fds.len() == descriptors, "wire-signature")?;
        let mut fds = fds
            .into_iter()
            .map(|fd| File::from(std::os::fd::OwnedFd::from(fd)));
        let first = fds.next();
        second = fds.next();
        (Some(body), first)
    } else {
        (
            Some(
                message
                    .body()
                    .deserialize::<String>()
                    .map_err(|_| Error("wire-signature".into()))?,
            ),
            None,
        )
    };
    require(
        body.as_ref().is_none_or(|b| b.len() <= wire::MAX_REQUEST),
        "request-bound",
    )?;
    Ok(Call {
        member: member.into(),
        sender: sender.into(),
        body,
        descriptor,
        second,
        arrived,
    })
}
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, call: Call) -> impl Future<Output = Result<Reply>> + Send;
    fn active(&self) -> bool;
    /// The pinned logind/polkit owner was replaced; this process can never
    /// authorize again and should exit once idle so activation restarts it.
    fn stale(&self) -> bool {
        false
    }
}
async fn bounded<T, E>(future: impl Future<Output = std::result::Result<T, E>>) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))?
        .map_err(|_| Error("backend-result-unknown-do-not-retry-automatically".into()))
}
async fn reply(connection: &Connection, message: &Message, result: Result<Reply>) -> Result<()> {
    match result {
        Ok(reply) => {
            require(
                reply.descriptor.is_none()
                    || message.header().member().map(|m| m.as_str())
                        == Some("BackupRecoveryExport"),
                "wire-signature",
            )?;
            let bytes = json::canonical(&reply.body)?;
            require(bytes.len() <= 1024 * 1024, "backend-reply-bound")?;
            let body =
                String::from_utf8(bytes).map_err(|_| Error("backend-reply-encoding".into()))?;
            if let Some(file) = reply.descriptor {
                use std::os::fd::AsFd;
                bounded(connection.reply(
                    &message.header(),
                    &(body, zbus::zvariant::Fd::from(file.as_fd())),
                ))
                .await
            } else {
                bounded(connection.reply(&message.header(), &body)).await
            }
        }
        Err(error) => {
            bounded(connection.reply_error(
                &message.header(),
                "org.enzimos.System1.Refused",
                &wire::public_failure(&error),
            ))
            .await
        }
    }
}
pub async fn serve<H: Handler>(
    mut stream: MessageStream,
    handler: H,
    idle: Duration,
) -> Result<()> {
    require(!idle.is_zero(), "backend-idle-deadline-invalid")?;
    let connection = Connection::from(&stream);
    require(
        bounded(connection.request_name_with_flags(wire::BUS, RequestNameFlags::DoNotQueue.into()))
            .await?
            == RequestNameReply::PrimaryOwner,
        "backend-service-name-unavailable",
    )?;
    let handler = std::sync::Arc::new(handler);
    let mut tasks = JoinSet::new();
    let mut last = tokio::time::Instant::now();
    let mut was_active = handler.active();
    // Poll only service-owned activity. No system service is activated to idle.
    let mut activity = tokio::time::interval(Duration::from_millis(250));
    activity.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            next = stream.next() => {
                let message = next.ok_or_else(|| Error("backend-service-bus-disconnected".into()))?.map_err(|_| Error("backend-service-bus-disconnected".into()))?;
                if message.header().primary().msg_type() != Type::MethodCall { continue; }
                let call = validate(&message);
                if tasks.len() >= 8 || call.is_err() {
                    // A refused reply that cannot be delivered only concerns that caller.
                    let _ = reply(&connection, &message, Err(call.err().unwrap_or_else(|| Error("service-busy".into())))).await;
                    last = tokio::time::Instant::now();
                    continue;
                }
                let call = call.unwrap();
                let connection = connection.clone();
                let handler = handler.clone();
                tasks.spawn(async move {
                    let result = tokio::time::timeout(Duration::from_secs(180), handler.handle(call)).await.unwrap_or_else(|_| Err(Error("backend-result-unknown-do-not-retry-automatically".into())));
                    reply(&connection, &message, result).await
                });
            },
            finished = tasks.join_next(), if !tasks.is_empty() => {
                // An oversized or timed-out reply concerns one caller; never let it
                // end the service (and any detached job worker) for everyone.
                if let Some(Ok(Err(error))) = finished {
                    eprintln!("enzimos-system-backend: reply failed: {}", wire::public_failure(&error));
                }
                last = tokio::time::Instant::now();
            },
            _ = activity.tick() => {
                let active = handler.active();
                if active || was_active { last = tokio::time::Instant::now(); }
                was_active = active;
                if tasks.is_empty() && !active && (last.elapsed() >= idle || handler.stale()) { break; }
            }
        }
    }
    bounded(connection.release_name(wire::BUS)).await?;
    stream.async_drop().await;
    Ok(())
}
