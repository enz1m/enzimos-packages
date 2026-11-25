// SPDX-License-Identifier: MIT
//! Candidate UserSwitch1 service: fixed local bus, pinned providers, one bounded request.
use enzimos_platform::{Error, Result, require};
use enzimos_policy::user_switch_policy::{self as policy, Choice, POOL, Session};
use futures_util::StreamExt;
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    time::Duration,
};
use zbus::{
    Connection, Message, MessageStream, Proxy,
    fdo::{DBusProxy, RequestNameFlags, RequestNameReply},
    names::{BusName, UniqueName},
    zvariant::{OwnedObjectPath, OwnedValue},
};
const NAME: &str = "org.enzimos.UserSwitch1";
const PATH: &str = "/org/enzimos/UserSwitch1";
const LOGIN: &str = "org.freedesktop.login1";
const SYSTEMD: &str = "org.freedesktop.systemd1";
fn unavailable() -> Error {
    Error("Unavailable".into())
}
async fn bounded<T, E, F: Future<Output = std::result::Result<T, E>>>(f: F) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(2), f)
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())
}
type Properties = HashMap<String, OwnedValue>;
fn field<T: TryFrom<OwnedValue>>(p: &Properties, k: &str) -> Result<T> {
    T::try_from(
        p.get(k)
            .ok_or_else(unavailable)?
            .try_clone()
            .map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())
}
fn string(p: &Properties, k: &str) -> Result<String> {
    let s: String = field(p, k)?;
    require(
        s.len() <= 512 && !s.chars().any(char::is_control),
        "Unavailable",
    )?;
    Ok(s)
}
fn session(p: &Properties, path: &str) -> Result<Session> {
    require(
        path.starts_with("/org/freedesktop/login1/session/") && path.len() <= 512,
        "Unavailable",
    )?;
    Ok(Session {
        path: path.into(),
        id: string(p, "Id")?,
        uid: field::<(u32, OwnedObjectPath)>(p, "User")?.0,
        seat: field::<(String, OwnedObjectPath)>(p, "Seat")?.0,
        kind: string(p, "Class")?,
        session_type: string(p, "Type")?,
        service: string(p, "Service")?,
        vt: field(p, "VTNr")?,
        active: field(p, "Active")?,
        remote: field(p, "Remote")?,
        locked: field(p, "LockedHint")?,
    })
}
struct Provider {
    connection: Connection,
    login_owner: String,
    systemd_owner: String,
    greeter: u32,
}
impl Provider {
    async fn observe(connection: Connection, greeter: u32) -> Result<Self> {
        let daemon = bounded(DBusProxy::new(&connection)).await?;
        let login_owner =
            bounded(daemon.get_name_owner(BusName::try_from(LOGIN).map_err(|_| unavailable())?))
                .await?
                .to_string();
        let systemd_owner =
            bounded(daemon.get_name_owner(BusName::try_from(SYSTEMD).map_err(|_| unavailable())?))
                .await?
                .to_string();
        let result = Self {
            connection,
            login_owner,
            systemd_owner,
            greeter,
        };
        result.owners().await?;
        Ok(result)
    }
    async fn owners(&self) -> Result<()> {
        let daemon = bounded(DBusProxy::new(&self.connection)).await?;
        for (name, owner) in [(LOGIN, &self.login_owner), (SYSTEMD, &self.systemd_owner)] {
            require(
                bounded(daemon.get_name_owner(BusName::try_from(name).map_err(|_| unavailable())?))
                    .await?
                    .as_str()
                    == owner,
                "Unavailable",
            )?;
        }
        Ok(())
    }
    async fn proxy<'a>(
        &'a self,
        systemd: bool,
        path: &'a str,
        interface: &'a str,
    ) -> Result<Proxy<'a>> {
        bounded(Proxy::new(
            &self.connection,
            if systemd {
                self.systemd_owner.as_str()
            } else {
                self.login_owner.as_str()
            },
            path,
            interface,
        ))
        .await
    }
    async fn properties(&self, systemd: bool, path: &str, interface: &str) -> Result<Properties> {
        self.owners().await?;
        let proxy = self
            .proxy(systemd, path, "org.freedesktop.DBus.Properties")
            .await?;
        let p: Properties = bounded(proxy.call("GetAll", &(interface,))).await?;
        require(p.len() <= 128, "Unavailable")?;
        Ok(p)
    }
    async fn session(&self, path: &str) -> Result<Session> {
        session(
            &self
                .properties(false, path, "org.freedesktop.login1.Session")
                .await?,
            path,
        )
    }
    async fn credentials(&self, sender: &str) -> Result<(u32, u32)> {
        let sender = UniqueName::try_from(sender).map_err(|_| Error("Not authorized".into()))?;
        let daemon = bounded(DBusProxy::new(&self.connection)).await?;
        let uid = bounded(daemon.get_connection_unix_user(BusName::Unique(sender.clone()))).await?;
        let pid = bounded(daemon.get_connection_unix_process_id(BusName::Unique(sender))).await?;
        require(
            uid < u32::MAX && pid > 0 && pid < i32::MAX as u32,
            "Not authorized",
        )?;
        Ok((uid, pid))
    }
    async fn peer(&self, sender: &str) -> Result<Session> {
        self.owners().await?;
        let (uid, pid) = self.credentials(sender).await?;
        let login = self
            .proxy(
                false,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
            )
            .await?;
        let origin = tokio::time::timeout(
            Duration::from_secs(2),
            login.call::<_, _, OwnedObjectPath>("GetSessionByPID", &(pid,)),
        )
        .await
        .map_err(|_| unavailable())?;
        let mut row = match origin {
            Ok(path) => Some(self.session(path.as_str()).await?),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.login1.NoSessionForPID" =>
            {
                None
            }
            Err(_) => return Err(Error("Not authorized".into())),
        };
        if row.as_ref().is_none_or(|s| s.kind == "manager") {
            require(row.as_ref().is_none_or(|s| s.uid == uid), "Not authorized")?;
            let path: OwnedObjectPath = bounded(login.call("GetUserByPID", &(pid,))).await?;
            let p = self
                .properties(false, path.as_str(), "org.freedesktop.login1.User")
                .await?;
            require(
                field::<u32>(&p, "UID")? == uid
                    && string(&p, "Service")? == format!("user@{uid}.service"),
                "Not authorized",
            )?;
            let display: (String, OwnedObjectPath) = field(&p, "Display")?;
            let sessions: Vec<(String, OwnedObjectPath)> = field(&p, "Sessions")?;
            require(
                !display.0.is_empty()
                    && display.1.as_str() != "/"
                    && sessions.len() <= 128
                    && sessions.contains(&display),
                "Not authorized",
            )?;
            let current = self.session(display.1.as_str()).await?;
            require(current.id == display.0, "Not authorized")?;
            row = Some(current);
        }
        let row = row.ok_or_else(unavailable)?;
        require(
            row.uid == uid && self.credentials(sender).await? == (uid, pid),
            "Not authorized",
        )?;
        Ok(row)
    }
    async fn sessions(&self) -> Result<Vec<Session>> {
        let proxy = self
            .proxy(
                false,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
            )
            .await?;
        let rows: Vec<(String, u32, String, String, OwnedObjectPath)> =
            bounded(proxy.call("ListSessions", &())).await?;
        require(rows.len() <= 128, "Unavailable")?;
        let mut result = Vec::new();
        for (id, uid, _, _, path) in rows {
            let row = self.session(path.as_str()).await?;
            require(row.id == id && row.uid == uid, "Unavailable")?;
            result.push(row);
        }
        Ok(result)
    }
    async fn states(&self) -> Result<BTreeMap<u32, String>> {
        let proxy = self
            .proxy(
                true,
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
            )
            .await?;
        let mut result = BTreeMap::new();
        for vt in POOL {
            let raw = tokio::time::timeout(
                Duration::from_secs(2),
                proxy.call::<_, _, OwnedObjectPath>(
                    "GetUnit",
                    &(format!("enzimos-greetd@{vt}.service"),),
                ),
            )
            .await
            .map_err(|_| unavailable())?;
            let state = match raw {
                Ok(path) => string(
                    &self
                        .properties(true, path.as_str(), "org.freedesktop.systemd1.Unit")
                        .await?,
                    "ActiveState",
                )?,
                Err(zbus::Error::MethodError(name, _, _))
                    if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
                {
                    "inactive".into()
                }
                Err(_) => return Err(unavailable()),
            };
            result.insert(vt, state);
        }
        Ok(result)
    }
    async fn activate(
        &self,
        sender: &str,
        caller: &Session,
        target: &Session,
        existing: bool,
    ) -> Result<()> {
        self.owners().await?;
        let current = self.peer(sender).await?;
        require(
            current.path == caller.path && current.id == caller.id && current.uid == caller.uid,
            "Not authorized",
        )?;
        let fresh = self.session(&target.path).await?;
        require(
            fresh.id == target.id && fresh.uid == target.uid && fresh.vt == target.vt,
            "Unavailable",
        )?;
        if existing {
            policy::existing(&current, &fresh, self.greeter)?;
        } else {
            policy::local(&current, caller.uid, "user", Some(true), Some(true))?;
            policy::local(&fresh, self.greeter, "greeter", None, None)?;
        }
        let proxy = self
            .proxy(false, &target.path, "org.freedesktop.login1.Session")
            .await?;
        bounded(proxy.call::<_, _, ()>("Activate", &())).await
    }
    async fn active(&self, target: &Session) -> Result<bool> {
        let current = self.session(&target.path).await?;
        require(
            current.id == target.id && current.uid == target.uid && current.vt == target.vt,
            "Unavailable",
        )?;
        let seat = self
            .properties(
                false,
                "/org/freedesktop/login1/seat/seat0",
                "org.freedesktop.login1.Seat",
            )
            .await?;
        let selected: (String, OwnedObjectPath) = field(&seat, "ActiveSession")?;
        Ok(current.active
            && current.seat == "seat0"
            && selected.0 == target.id
            && selected.1.as_str() == target.path)
    }
    async fn switch(&self, sender: &str, target_id: Option<&str>) -> Result<()> {
        let caller = self.peer(sender).await?;
        let mut target;
        let vt;
        if let Some(id) = target_id {
            require(
                !id.is_empty()
                    && id.len() <= 64
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "Not authorized",
            )?;
            let proxy = self
                .proxy(
                    false,
                    "/org/freedesktop/login1",
                    "org.freedesktop.login1.Manager",
                )
                .await?;
            let path: OwnedObjectPath = bounded(proxy.call("GetSession", &(id,))).await?;
            let row = self.session(path.as_str()).await?;
            policy::existing(&caller, &row, self.greeter)?;
            self.activate(sender, &caller, &row, true).await?;
            vt = row.vt;
            target = Some(row);
        } else {
            policy::local(&caller, caller.uid, "user", Some(true), Some(true))?;
            let sessions = self.sessions().await?;
            let states = self.states().await?;
            match policy::choose(&sessions, &states, self.greeter)? {
                Choice::Activate(i) => {
                    let row = sessions[i].clone();
                    self.activate(sender, &caller, &row, false).await?;
                    vt = row.vt;
                    target = Some(row);
                }
                Choice::Start(n) => {
                    vt = n;
                    target = None;
                    require(
                        !self.sessions().await?.iter().any(|s| s.vt == vt),
                        "Unavailable",
                    )?;
                    require(
                        self.states()
                            .await?
                            .get(&vt)
                            .is_some_and(|s| matches!(s.as_str(), "inactive" | "failed")),
                        "Unavailable",
                    )?;
                    let fresh = self.peer(sender).await?;
                    require(
                        fresh.path == caller.path
                            && fresh.id == caller.id
                            && fresh.uid == caller.uid,
                        "Not authorized",
                    )?;
                    policy::local(&fresh, caller.uid, "user", Some(true), Some(true))?;
                    self.owners().await?;
                    let proxy = self
                        .proxy(
                            true,
                            "/org/freedesktop/systemd1",
                            "org.freedesktop.systemd1.Manager",
                        )
                        .await?;
                    let _: OwnedObjectPath = bounded(proxy.call(
                        "StartUnit",
                        &(format!("enzimos-greetd@{vt}.service"), "fail"),
                    ))
                    .await?;
                }
            }
        }
        loop {
            self.owners().await?;
            let peer = self.peer(sender).await?;
            require(
                peer.uid == caller.uid && peer.id == caller.id && peer.path == caller.path,
                "Not authorized",
            )?;
            if target_id.is_none() {
                policy::local(
                    &self.session(&caller.path).await?,
                    caller.uid,
                    "user",
                    None,
                    Some(true),
                )?;
                if target.is_none() {
                    let candidates: Vec<_> = self
                        .sessions()
                        .await?
                        .into_iter()
                        .filter(|s| s.vt == vt && s.uid == self.greeter && s.kind == "greeter")
                        .collect();
                    require(candidates.len() <= 1, "Unavailable")?;
                    if let Some(row) = candidates.into_iter().next() {
                        policy::local(&row, self.greeter, "greeter", None, None)?;
                        target = Some(row);
                    }
                }
            }
            if let Some(row) = &target {
                let fresh = self.session(&row.path).await?;
                if target_id.is_some() {
                    policy::local(&fresh, row.uid, "user", None, Some(true))?;
                } else {
                    policy::local(&fresh, self.greeter, "greeter", None, None)?;
                }
                if self.active(row).await? {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
fn request(message: &Message) -> Result<(String, Option<String>)> {
    let h = message.header();
    require(
        h.path().is_some_and(|s| s.as_str() == PATH)
            && h.interface().is_some_and(|s| s.as_str() == NAME)
            && message.data().fds().is_empty()
            && message.body().len() <= 512,
        "Unavailable",
    )?;
    require(
        !h.primary()
            .flags()
            .contains(zbus::message::Flags::NoReplyExpected),
        "Unavailable",
    )?;
    let sender = h.sender().ok_or_else(unavailable)?.to_string();
    require(sender.starts_with(':'), "Not authorized")?;
    let target = match h.member().map(zbus::names::MemberName::as_str) {
        Some("OpenGreeter") => {
            message
                .body()
                .deserialize::<()>()
                .map_err(|_| unavailable())?;
            None
        }
        Some("ActivateExisting") => {
            let (id,): (String,) = message.body().deserialize().map_err(|_| unavailable())?;
            require(
                !id.is_empty()
                    && id.len() <= 64
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "Not authorized",
            )?;
            Some(id)
        }
        _ => return Err(unavailable()),
    };
    Ok((sender, target))
}
async fn reply(c: &Connection, m: &Message, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => bounded(c.reply(&m.header(), &())).await,
        Err(error) => {
            let public = match error.0.as_str() {
                "Not authorized"
                | "Session must be locked"
                | "Switching timed out"
                | "Switching is already in progress"
                | "No more sessions can be opened" => error.0.as_str(),
                _ => "Unavailable",
            };
            bounded(c.reply_error(&m.header(), "org.enzimos.UserSwitch1.Refused", &public)).await
        }
    }
}
const XML: &str = "<node><interface name='org.enzimos.UserSwitch1'><method name='OpenGreeter'/><method name='ActivateExisting'><arg name='session_id' type='s' direction='in'/></method></interface><interface name='org.freedesktop.DBus.Introspectable'><method name='Introspect'><arg type='s' direction='out'/></method></interface><interface name='org.freedesktop.DBus.Peer'><method name='Ping'/></interface></node>";
async fn standard(connection: &Connection, message: &Message) -> Result<bool> {
    let h = message.header();
    if h.path().is_none_or(|p| p.as_str() != PATH) {
        return Ok(false);
    }
    let standard = matches!(
        (
            h.interface().map(zbus::names::InterfaceName::as_str),
            h.member().map(zbus::names::MemberName::as_str)
        ),
        (
            Some("org.freedesktop.DBus.Introspectable"),
            Some("Introspect")
        ) | (Some("org.freedesktop.DBus.Peer"), Some("Ping"))
    );
    if !standard {
        return Ok(false);
    }
    if message.body().deserialize::<()>().is_err()
        || !message.data().fds().is_empty()
        || h.primary()
            .flags()
            .contains(zbus::message::Flags::NoReplyExpected)
    {
        reply(connection, message, Err(unavailable())).await?;
        return Ok(true);
    }
    if h.member().is_some_and(|s| s.as_str() == "Introspect") {
        bounded(connection.reply(&h, &XML)).await?;
    } else {
        bounded(connection.reply(&h, &())).await?;
    }
    Ok(true)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (getpwnam_r).")]
fn greeter_uid() -> Result<u32> {
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    require(
        // SAFETY: The name is a NUL-terminated literal and the record, buffer and result pointers
        // are valid for the given sizes.
        unsafe {
            libc::getpwnam_r(
                c"greeter".as_ptr(),
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        } == 0
            && !result.is_null(),
        "greeter account unavailable",
    )?;
    // SAFETY: getpwnam_r returned 0 with a non-null result, so it initialized `record`.
    let uid = unsafe { record.assume_init() }.pw_uid;
    require(uid > 0 && uid < u32::MAX, "greeter account unavailable")?;
    Ok(uid)
}
/// Serve the user-switch bus service until idle.
///
/// # Errors
///
/// Fails unless started by bus activation as Root, or when the greeter account or bus is
/// unavailable.
pub async fn serve() -> Result<()> {
    require(
        std::env::args_os().count() == 1
            && enzimos_platform::process_identity::real_uid() == 0
            && enzimos_platform::process_identity::effective_uid() == 0,
        "system activation required",
    )?;
    let greeter = greeter_uid()?;
    let connection = bounded(
        zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
            .map_err(|_| unavailable())?
            .build(),
    )
    .await?;
    serve_on(connection, greeter).await
}
async fn serve_on(connection: Connection, greeter: u32) -> Result<()> {
    let mut stream = MessageStream::from(&connection);
    require(
        bounded(connection.request_name_with_flags(NAME, RequestNameFlags::DoNotQueue.into()))
            .await?
            == RequestNameReply::PrimaryOwner,
        "service name unavailable",
    )?;
    let mut pending = tokio::task::JoinSet::new();
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::select! {
            result=pending.join_next(),if !pending.is_empty()=>{result.ok_or_else(unavailable)?.map_err(|_|unavailable())??;last=tokio::time::Instant::now();},
            message=stream.next()=>{
                let Some(message)=message else {return Ok(())};let message=message.map_err(|_|unavailable())?;
                if message.header().primary().msg_type()!=zbus::message::Type::MethodCall {continue}
                if standard(&connection, &message).await? {continue}
                let (sender,target)=match request(&message) {
                    Ok(call) if pending.is_empty() => call,
                    Err(error) if pending.is_empty() => {reply(&connection,&message,Err(error)).await?;continue}
                    _ => {reply(&connection,&message,Err(Error("Switching is already in progress".into()))).await?;continue}
                };let c=connection.clone();last=tokio::time::Instant::now();
                pending.spawn(async move {let result=tokio::time::timeout(Duration::from_secs(20),async {let p=Provider::observe(c.clone(),greeter).await?;p.switch(&sender,target.as_deref()).await}).await.unwrap_or_else(|_|Err(Error("Switching timed out".into())));reply(&c,&message,result).await});
            },
            ()=tokio::time::sleep_until(last+Duration::from_secs(60)),if pending.is_empty()=>return Ok(())
        }
    }
}
#[cfg(test)]
#[path = "user_switch_tests.rs"]
mod tests;
