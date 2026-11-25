// SPDX-License-Identifier: MIT
//! The update manager is pinned to the initial system manager's unique owner.
use enzimos_platform::{Error, Result, files, process_identity, require};
use std::{future::Future, path::PathBuf, time::Duration};
use zbus::{
    Connection, Proxy,
    fdo::DBusProxy,
    names::{BusName, OwnedUniqueName},
    zvariant::{DynamicDeserialize, DynamicType},
};
/// Object path of the systemd manager.
pub const PATH: &str = "/org/freedesktop/systemd1";
pub(crate) const MANAGER: &str = "org.freedesktop.systemd1.Manager";
async fn bounded<T, F: Future<Output = zbus::Result<T>>>(future: F) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .map_err(|_| Error("update manager provider deadline; outcome may be uncertain".into()))?
        .map_err(|_| Error("update manager provider unavailable; no automatic retry".into()))
}
/// Systemd on the system bus, pinned to its current owner and process.
pub struct Manager {
    connection: Connection,
    owner: OwnedUniqueName,
    process: process_identity::Retained,
}
impl Manager {
    /// Connect to the system bus and pin systemd's owner and PID 1.
    ///
    /// # Errors
    ///
    /// Fails when the bus or systemd is unavailable or its owner is not PID 1 running as Root.
    pub async fn new() -> Result<Self> {
        enzimos_policy::namespaces::initial()?;
        let connection = bounded(Connection::system()).await?;
        let daemon = DBusProxy::new(&connection)
            .await
            .map_err(|_| Error("system bus unavailable".into()))?;
        let name = BusName::try_from("org.freedesktop.systemd1")
            .map_err(|_| Error("system manager name".into()))?;
        let owner = tokio::time::timeout(Duration::from_secs(2), daemon.get_name_owner(name))
            .await
            .map_err(|_| Error("system manager owner deadline".into()))?
            .map_err(|_| Error("system manager unavailable".into()))?;
        let bus_name = BusName::from(owner.as_ref());
        let process = tokio::time::timeout(
            Duration::from_secs(2),
            daemon.get_connection_unix_process_id(bus_name.clone()),
        )
        .await
        .map_err(|_| Error("system manager PID deadline".into()))?
        .map_err(|_| Error("system manager PID unavailable".into()))?;
        let root = tokio::time::timeout(
            Duration::from_secs(2),
            daemon.get_connection_unix_user(bus_name),
        )
        .await
        .map_err(|_| Error("system manager UID deadline".into()))?
        .map_err(|_| Error("system manager UID unavailable".into()))?;
        require(
            process == 1 && root == 0,
            "initial Root system manager required",
        )?;
        let body = files::read_kernel(&PathBuf::from("/proc/1/stat"), 8192)?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&body)
                .map_err(|_| Error("system manager identity encoding".into()))?,
            1,
        )?;
        let retained = process_identity::Retained::open(
            1,
            stat.start_ticks,
            0,
            &[PathBuf::from("/usr/lib/systemd/systemd")],
        )?;
        let manager = Self {
            connection,
            owner,
            process: retained,
        };
        manager.recheck().await?;
        Ok(manager)
    }
    /// Verify systemd still has its original owner and process.
    ///
    /// # Errors
    ///
    /// Fails when systemd's owner or process changed.
    pub async fn recheck(&self) -> Result<()> {
        self.process.recheck()?;
        let daemon = DBusProxy::new(&self.connection)
            .await
            .map_err(|_| Error("system bus unavailable".into()))?;
        let owner = tokio::time::timeout(
            Duration::from_secs(2),
            daemon.get_name_owner(
                BusName::try_from("org.freedesktop.systemd1")
                    .map_err(|_| Error("system manager name".into()))?,
            ),
        )
        .await
        .map_err(|_| Error("system manager owner deadline".into()))?
        .map_err(|_| Error("system manager owner lost".into()))?;
        require(
            owner == self.owner,
            "system manager owner changed; no retry",
        )
    }
    /// Call `method` on a systemd object, rechecking the owner before and after.
    ///
    /// # Errors
    ///
    /// Fails when the owner changed, the call fails, or it times out.
    pub async fn call<B, R>(&self, path: &str, interface: &str, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + DynamicType,
        R: for<'d> DynamicDeserialize<'d>,
    {
        self.recheck().await?;
        let proxy = bounded(Proxy::new(
            &self.connection,
            self.owner.as_str(),
            path,
            interface,
        ))
        .await?;
        let result = bounded(proxy.call(method, body)).await?;
        self.recheck().await?;
        Ok(result)
    }
    /// Object path of the loaded unit `name`, or `None` when systemd does not know it.
    ///
    /// # Errors
    ///
    /// Fails for a name that is not a plain service unit, or when the lookup fails.
    pub async fn unit(&self, name: &str) -> Result<Option<zbus::zvariant::OwnedObjectPath>> {
        require(
            name.ends_with(".service")
                && name.len() <= 255
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "system manager unit name refused",
        )?;
        self.recheck().await?;
        let proxy = bounded(Proxy::new(
            &self.connection,
            self.owner.as_str(),
            PATH,
            MANAGER,
        ))
        .await?;
        let result = tokio::time::timeout(Duration::from_secs(5), proxy.call("GetUnit", &(name,)))
            .await
            .map_err(|_| Error("terminal lookup deadline".into()))?;
        self.recheck().await?;
        match result {
            Ok(path) => Ok(Some(path)),
            Err(zbus::Error::MethodError(name, _, _))
                if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
            {
                Ok(None)
            }
            Err(_) => Err(Error("terminal lookup failed; no automatic retry".into())),
        }
    }
    /// A fresh explicit caller authorizes one fixed power target; an uncertain
    /// reply never causes this operation to be retried.
    ///
    /// # Errors
    ///
    /// Fails for targets other than `reboot.target` and `poweroff.target`, when the call fails, or
    /// when systemd returns something other than a job path.
    pub async fn request_power_target(&self, target: &str) -> Result<String> {
        require(
            matches!(target, "reboot.target" | "poweroff.target"),
            "power target outside fixed registry",
        )?;
        let path: zbus::zvariant::OwnedObjectPath = self
            .call(
                PATH,
                MANAGER,
                "StartUnit",
                &(target, "replace-irreversibly"),
            )
            .await?;
        let id = path
            .as_str()
            .strip_prefix("/org/freedesktop/systemd1/job/")
            .ok_or_else(|| Error("power request returned another object role".into()))?;
        require(
            !id.is_empty()
                && id.len() <= 20
                && id.bytes().all(|b| b.is_ascii_digit())
                && id.parse::<u64>().is_ok_and(|n| n > 0),
            "power request returned an invalid job identity",
        )?;
        Ok(path.as_str().into())
    }
}
