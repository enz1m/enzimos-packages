// SPDX-License-Identifier: MIT
//! D-Bus names authorize callers. Bus-derived PIDs only bind the live logind session.
use enzimos_platform::{Error, Result, files, require};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    time::{Duration, Instant},
};
use zbus::{
    Connection, Proxy,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName, UniqueName},
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};
type Properties = HashMap<String, OwnedValue>;
fn refused() -> Error {
    Error("not-authorized".into())
}
async fn bounded<T, E, F: Future<Output = std::result::Result<T, E>>>(
    future: F,
    seconds: u64,
) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(seconds), future)
        .await
        .map_err(|_| refused())?
        .map_err(|_| refused())
}
fn field<T: TryFrom<OwnedValue>>(p: &Properties, key: &str) -> Result<T> {
    let value = p
        .get(key)
        .ok_or_else(refused)?
        .try_clone()
        .map_err(|_| refused())?;
    T::try_from(value).map_err(|_| refused())
}
fn string(p: &Properties, key: &str, max: usize) -> Result<String> {
    let s = field::<String>(p, key)?;
    require(
        !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control),
        "not-authorized",
    )?;
    Ok(s)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub session: String,
    pub origin_session: Option<String>,
    pub id: String,
    pub uid: u32,
    pub pid: u32,
    pub seat: String,
    #[serde(rename = "type")]
    pub kind: String,
}
pub fn session_peer(
    p: &Properties,
    session: &str,
    origin: Option<String>,
    uid: u32,
    pid: u32,
) -> Result<Peer> {
    require(
        (1000..u32::MAX).contains(&uid)
            && (1..i32::MAX as u32).contains(&pid)
            && session.len() <= 512
            && session.starts_with("/org/freedesktop/login1/session/"),
        "not-authorized",
    )?;
    for (key, expected) in [("Active", true), ("Remote", false), ("LockedHint", false)] {
        require(field::<bool>(p, key)? == expected, "not-authorized")?;
    }
    let user = field::<(u32, OwnedObjectPath)>(p, "User")?;
    let seat = field::<(String, OwnedObjectPath)>(p, "Seat")?;
    require(
        user.0 == uid
            && !seat.0.is_empty()
            && seat.0.len() <= 128
            && seat.1.as_str() != "/"
            && string(p, "Class", 32)? == "user",
        "not-authorized",
    )?;
    let kind = string(p, "Type", 32)?;
    require(
        matches!(kind.as_str(), "tty" | "wayland" | "x11"),
        "not-authorized",
    )?;
    Ok(Peer {
        session: session.into(),
        origin_session: origin,
        id: string(p, "Id", 128)?,
        uid,
        pid,
        seat: seat.0,
        kind,
    })
}
#[derive(Clone)]
pub struct Authority {
    connection: Connection,
    login_owner: OwnedUniqueName,
    /// None for a session-only authority, which can bind peers but never authorize.
    polkit_owner: Option<OwnedUniqueName>,
    /// Set once logind or polkit has a new owner; the pinned identities can
    /// never authorize again, so long-lived services should restart.
    stale: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
pub struct Grant {
    sender: String,
    pub peer: Peer,
    deadline: Instant,
}
#[cfg(feature = "update-worker")]
#[path = "authority_setup.rs"]
mod setup;
#[cfg(feature = "update-worker")]
pub use setup::SetupApproval;
struct PendingAuthorization {
    connection: Connection,
    owner: OwnedUniqueName,
    id: String,
    finished: bool,
}
impl Drop for PendingAuthorization {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let connection = self.connection.clone();
        let owner = self.owner.clone();
        let id = self.id.clone();
        runtime.spawn(async move {
            let cancelled = async {
                let p = Proxy::new(
                    &connection,
                    owner.as_str(),
                    "/org/freedesktop/PolicyKit1/Authority",
                    "org.freedesktop.PolicyKit1.Authority",
                )
                .await?;
                p.call::<_, _, ()>("CancelCheckAuthorization", &(id,)).await
            };
            let _ = tokio::time::timeout(Duration::from_secs(2), cancelled).await;
        });
    }
}
impl Authority {
    pub async fn system() -> Result<Self> {
        require(
            enzimos_platform::process_identity::effective_uid() == 0,
            "root authorization required",
        )?;
        let c = bounded(Connection::system(), 5).await?;
        Self::new(c).await
    }
    pub async fn new(connection: Connection) -> Result<Self> {
        let mut authority = Self::sessions(connection).await?;
        let daemon = bounded(DBusProxy::new(&authority.connection), 2).await?;
        authority.polkit_owner = Some(
            bounded(
                daemon.get_name_owner(
                    BusName::try_from("org.freedesktop.PolicyKit1").map_err(|_| refused())?,
                ),
                2,
            )
            .await?,
        );
        Ok(authority)
    }
    /// logind session binding only, for services whose callers need no polkit
    /// approval; polkit need not be running.
    pub async fn sessions(connection: Connection) -> Result<Self> {
        let daemon = bounded(DBusProxy::new(&connection), 2).await?;
        let login_owner = bounded(
            daemon.get_name_owner(
                BusName::try_from("org.freedesktop.login1").map_err(|_| refused())?,
            ),
            2,
        )
        .await?;
        Ok(Self {
            connection,
            login_owner,
            polkit_owner: None,
            stale: Default::default(),
        })
    }
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    async fn owners(&self) -> Result<()> {
        let daemon = bounded(DBusProxy::new(&self.connection), 2).await?;
        for (name, owner) in [
            ("org.freedesktop.login1", Some(&self.login_owner)),
            ("org.freedesktop.PolicyKit1", self.polkit_owner.as_ref()),
        ] {
            let Some(owner) = owner else { continue };
            let current = bounded(
                daemon.get_name_owner(BusName::try_from(name).map_err(|_| refused())?),
                2,
            )
            .await?;
            if &current != owner {
                self.stale.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            require(&current == owner, "authorization authority changed")?;
        }
        Ok(())
    }
    /// True after a pinned authority (logind or polkit) was replaced.
    pub fn stale(&self) -> bool {
        self.stale.load(std::sync::atomic::Ordering::Relaxed)
    }
    async fn proxy<'a>(
        &'a self,
        owner: &'a str,
        path: &'a str,
        interface: &'a str,
    ) -> Result<Proxy<'a>> {
        bounded(Proxy::new(&self.connection, owner, path, interface), 2).await
    }
    async fn properties(&self, path: &str, interface: &str) -> Result<Properties> {
        let proxy = self
            .proxy(
                self.login_owner.as_str(),
                path,
                "org.freedesktop.DBus.Properties",
            )
            .await?;
        let result: Properties = bounded(proxy.call("GetAll", &(interface,)), 2).await?;
        require(result.len() <= 128, "session property bound")?;
        Ok(result)
    }
    async fn credentials(&self, sender: &str) -> Result<(u32, u32)> {
        let name = UniqueName::try_from(sender)
            .map_err(|_| Error("unique-system-bus-sender-required".into()))?;
        let daemon = bounded(DBusProxy::new(&self.connection), 2).await?;
        require(
            bounded(daemon.name_has_owner(BusName::Unique(name.clone())), 2).await?,
            "sender-disconnected",
        )?;
        let uid = bounded(
            daemon.get_connection_unix_user(BusName::Unique(name.clone())),
            2,
        )
        .await?;
        let pid = bounded(
            daemon.get_connection_unix_process_id(BusName::Unique(name)),
            2,
        )
        .await?;
        require(
            (1000..u32::MAX).contains(&uid) && (1..i32::MAX as u32).contains(&pid),
            "not-authorized",
        )?;
        Ok((uid, pid))
    }
    pub async fn peer(&self, sender: &str) -> Result<Peer> {
        self.owners().await?;
        let (uid, pid) = self.credentials(sender).await?;
        let result = self.session_for(uid, pid).await?;
        require(
            self.credentials(sender).await? == (uid, pid),
            "caller-session-changed",
        )?;
        self.owners().await?;
        Ok(result)
    }
    /// Bind credentials the caller obtained from another bus (such as a user
    /// bus) to their live logind session. The caller rechecks its own peer.
    pub async fn session_for(&self, uid: u32, pid: u32) -> Result<Peer> {
        require(
            (1000..u32::MAX).contains(&uid) && (1..i32::MAX as u32).contains(&pid),
            "not-authorized",
        )?;
        self.owners().await?;
        let login = self
            .proxy(
                self.login_owner.as_str(),
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
            )
            .await?;
        let raw = tokio::time::timeout(
            Duration::from_secs(2),
            login.call::<_, _, OwnedObjectPath>("GetSessionByPID", &(pid,)),
        )
        .await
        .map_err(|_| refused())?;
        let origin = match raw {
            Ok(path) => Some(path.to_string()),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.login1.NoSessionForPID" =>
            {
                None
            }
            Err(_) => return Err(refused()),
        };
        let mut session = origin.clone();
        let mut values = if let Some(path) = &session {
            self.properties(path, "org.freedesktop.login1.Session")
                .await?
        } else {
            HashMap::new()
        };
        if session.is_none() || string(&values, "Class", 32)? == "manager" {
            if session.is_some() {
                require(
                    field::<(u32, OwnedObjectPath)>(&values, "User")?.0 == uid,
                    "not-authorized",
                )?;
            }
            let user: OwnedObjectPath = bounded(login.call("GetUserByPID", &(pid,)), 2).await?;
            let properties = self
                .properties(user.as_str(), "org.freedesktop.login1.User")
                .await?;
            require(
                field::<u32>(&properties, "UID")? == uid
                    && string(&properties, "Service", 128)? == format!("user@{uid}.service"),
                "not-authorized",
            )?;
            let display = field::<(String, OwnedObjectPath)>(&properties, "Display")?;
            let sessions = field::<Vec<(String, OwnedObjectPath)>>(&properties, "Sessions")?;
            require(
                !display.0.is_empty()
                    && display.1.as_str() != "/"
                    && sessions.len() <= 256
                    && sessions.contains(&display),
                "not-authorized",
            )?;
            values = self
                .properties(display.1.as_str(), "org.freedesktop.login1.Session")
                .await?;
            require(
                string(&values, "Id", 128)? == display.0
                    && matches!(string(&values, "Type", 32)?.as_str(), "wayland" | "x11"),
                "not-authorized",
            )?;
            session = Some(display.1.to_string());
        }
        let result = session_peer(
            &values,
            session.as_deref().ok_or_else(refused)?,
            origin,
            uid,
            pid,
        )?;
        self.owners().await?;
        Ok(result)
    }
    pub async fn authorize(
        &self,
        sender: &str,
        action: &str,
        interaction: bool,
        arrived: Instant,
        valid_for_ms: u64,
    ) -> Result<Grant> {
        require(
            (1000..=150000).contains(&valid_for_ms)
                && action.starts_with("org.enzimos.")
                && action.len() <= 128
                && action
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)),
            "request-deadline-or-interaction",
        )?;
        let deadline = arrived
            .checked_add(Duration::from_millis(valid_for_ms))
            .ok_or_else(refused)?;
        require(Instant::now() < deadline, "request-expired")?;
        let peer = tokio::time::timeout_at(deadline.into(), self.peer(sender))
            .await
            .map_err(|_| Error("request-expired".into()))??;
        let polkit_owner = self.polkit_owner.clone().ok_or_else(refused)?;
        let proxy = self
            .proxy(
                polkit_owner.as_str(),
                "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority",
            )
            .await?;
        let subject = (
            "system-bus-name",
            HashMap::from([("name", Value::from(sender))]),
        );
        let details = HashMap::<&str, &str>::new();
        let flags = u32::from(interaction);
        let id = format!("enzimos-rust-{}", files::random_hex(16)?);
        let mut pending = PendingAuthorization {
            connection: self.connection.clone(),
            owner: polkit_owner.clone(),
            id: id.clone(),
            finished: false,
        };
        let until = deadline.min(Instant::now() + Duration::from_secs(120));
        let args = (subject, action, details, flags, id);
        let (authorized, challenge, _details): (bool, bool, HashMap<String, String>) =
            tokio::time::timeout_at(until.into(), proxy.call("CheckAuthorization", &args))
                .await
                .map_err(|_| Error("request-expired".into()))?
                .map_err(|_| refused())?;
        pending.finished = true;
        require(authorized && !challenge, "not-authorized")?;
        let grant = Grant {
            sender: sender.into(),
            peer,
            deadline,
        };
        self.recheck(&grant).await?;
        Ok(grant)
    }
    /// The original caller is still the same live peer in the same active,
    /// unlocked local session. Unlike `recheck`, this has no request deadline:
    /// an admitted job may legitimately run far longer than its request window.
    pub async fn still_bound(&self, grant: &Grant) -> Result<()> {
        require(
            tokio::time::timeout(Duration::from_secs(5), self.peer(&grant.sender))
                .await
                .map_err(|_| Error("caller-session-changed".into()))??
                == grant.peer,
            "caller-session-changed",
        )
    }
    pub async fn recheck(&self, grant: &Grant) -> Result<()> {
        require(Instant::now() < grant.deadline, "request-expired")?;
        require(
            tokio::time::timeout_at(grant.deadline.into(), self.peer(&grant.sender))
                .await
                .map_err(|_| Error("request-expired".into()))??
                == grant.peer,
            "caller-session-changed",
        )?;
        require(Instant::now() < grant.deadline, "request-expired")
    }
}
