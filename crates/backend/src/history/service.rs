// SPDX-License-Identifier: MIT
//! `org.enzimos.History1` on the system bus: D-Bus activated, root, exits when
//! idle. Reads need an active, local, unlocked session; removing files from
//! history asks for the person's own password every time (so nothing running
//! as them can quietly erase their history); the free-space floor needs an
//! administrator.
use super::{
    Owner, measure, prune,
    store::{self, Removal, Store},
};
use crate::authority::Authority;
use enzimos_platform::{Error, Result, fsview};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::{fdo, message::Header, zvariant::OwnedFd};

/// Bus name and object path.
pub const NAME: &str = "org.enzimos.History1";
const PATH: &str = "/org/enzimos/History1";
const IDLE: Duration = Duration::from_secs(60);
const MEASURE_UNIT: &str = "enzimos-history-measure.service";
const BACKUP_UNIT: &str = "enzimos-backup-now.service";
const BACKUP_CONFIG: &str = "/etc/enzimos/backup.json";

fn failed(e: Error) -> fdo::Error {
    fdo::Error::Failed(e.0)
}

struct History {
    authority: Authority,
    store: Store,
    last: Arc<Mutex<Instant>>,
    busy: Arc<std::sync::atomic::AtomicUsize>,
}

/// Counts a long call as activity until it ends.
struct Busy(Arc<std::sync::atomic::AtomicUsize>);
impl Busy {
    fn new(counter: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(Arc::clone(counter))
    }
}
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl History {
    fn touch(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = Instant::now();
        }
    }
    async fn caller(&self, header: &Header<'_>) -> fdo::Result<Owner> {
        self.touch();
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("not-authorized".into()))?;
        let peer = self
            .authority
            .peer(sender.as_str())
            .await
            .map_err(|_| fdo::Error::AccessDenied("not-authorized".into()))?;
        Owner::lookup(peer.uid).map_err(failed)
    }
    async fn approved(&self, header: &Header<'_>, action: &str) -> fdo::Result<Owner> {
        self.touch();
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("not-authorized".into()))?;
        let grant = self
            .authority
            .authorize(sender.as_str(), action, true, Instant::now(), 120_000)
            .await
            .map_err(|_| fdo::Error::AccessDenied("not-authorized".into()))?;
        self.touch();
        Owner::lookup(grant.peer.uid).map_err(failed)
    }
}

fn snapshots_dir() -> Result<std::fs::File> {
    fsview::open_directory(Path::new(super::SNAPSHOTS)).map_err(|_| Error("no-history".into()))
}
fn home_root() -> Result<std::fs::File> {
    fsview::open_directory(Path::new(super::HOME_ROOT))
}
fn relative(owner: &Owner, path: &str) -> fdo::Result<PathBuf> {
    owner
        .relative(path)
        .map_err(failed)?
        .ok_or_else(|| fdo::Error::Failed("path-not-allowed".into()))
}

async fn start_unit(unit: &str) -> fdo::Result<()> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|e| fdo::Error::Failed(e.to_string()))?;
    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .await
    .map_err(|e| fdo::Error::Failed(e.to_string()))?;
    let _job: zbus::zvariant::OwnedObjectPath = proxy
        .call("StartUnit", &(unit, "replace"))
        .await
        .map_err(|e| fdo::Error::Failed(e.to_string()))?;
    Ok(())
}

#[zbus::interface(name = "org.enzimos.History1")]
impl History {
    /// Home history snapshots holding the caller's home: (number, time).
    async fn snapshots(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<Vec<(u32, i64)>> {
        let owner = self.caller(&header).await?;
        let dir = snapshots_dir().map_err(failed)?;
        let list = super::list(&dir).map_err(failed)?;
        Ok(list
            .iter()
            .filter(|s| {
                super::open_snapshot(&dir, s.number).is_ok_and(|root| owner.home_in(&root).is_ok())
            })
            .map(|s| (s.number, s.time))
            .collect())
    }

    /// Distinct earlier versions of one of the caller's files or folders,
    /// newest first: (snapshot, taken, size, modified, same-as-now).
    async fn versions(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: String,
    ) -> fdo::Result<Vec<(u32, i64, u64, i64, bool)>> {
        let owner = self.caller(&header).await?;
        let rel = relative(&owner, &path)?;
        let dir = snapshots_dir().map_err(failed)?;
        let list = super::list(&dir).map_err(failed)?;
        let live = home_root()
            .ok()
            .and_then(|root| super::live_meta(&owner, &root, &rel));
        let versions = tokio::task::block_in_place(|| {
            super::versions(&owner, &dir, &list, &rel, live.as_ref())
        })
        .map_err(failed)?;
        Ok(versions
            .into_iter()
            .map(|v| (v.number, v.time, v.size, v.mtime, v.current))
            .collect())
    }

    /// A folder of the caller's as it was in a snapshot:
    /// (name, kind f/d/l/o, size, modified, still-exists).
    async fn folder(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: String,
        number: u32,
    ) -> fdo::Result<Vec<(String, String, u64, i64, bool)>> {
        let owner = self.caller(&header).await?;
        let rel = owner.relative(&path).map_err(failed)?;
        let dir = snapshots_dir().map_err(failed)?;
        require_history(&dir, number)?;
        let root = super::open_snapshot(&dir, number).map_err(failed)?;
        let live = home_root()
            .ok()
            .and_then(|home| super::live_folder(&owner, &home, rel.as_deref()));
        let items = super::folder(&owner, &root, rel.as_deref(), live.as_ref()).map_err(failed)?;
        Ok(items
            .into_iter()
            .map(|i| (i.name, i.kind.to_string(), i.size, i.mtime, i.exists))
            .collect())
    }

    /// A read-only descriptor of one of the caller's files as it was.
    async fn open(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: String,
        number: u32,
    ) -> fdo::Result<OwnedFd> {
        let owner = self.caller(&header).await?;
        let rel = relative(&owner, &path)?;
        let dir = snapshots_dir().map_err(failed)?;
        require_history(&dir, number)?;
        let root = super::open_snapshot(&dir, number).map_err(failed)?;
        let file = super::open(&owner, &root, &rel).map_err(failed)?;
        Ok(OwnedFd::from(std::os::fd::OwnedFd::from(file)))
    }

    /// The caller's rules: (automatic rules on, excluded absolute paths).
    async fn rules(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<(bool, Vec<String>)> {
        let owner = self.caller(&header).await?;
        let rules = self.store.rules(owner.uid);
        let home = Path::new(super::HOME_ROOT).join(&owner.home);
        Ok((
            rules.automatic,
            rules
                .excluded
                .iter()
                .map(|p| home.join(p).to_string_lossy().into_owned())
                .collect(),
        ))
    }

    /// Turn the automatic rules (build output, caches, games, Trash) on or off.
    async fn set_automatic(
        &self,
        #[zbus(header)] header: Header<'_>,
        automatic: bool,
    ) -> fdo::Result<()> {
        let owner = self.caller(&header).await?;
        let _lock = self.store.lock(Duration::from_secs(10)).map_err(failed)?;
        let mut rules = self.store.rules(owner.uid);
        rules.automatic = automatic;
        self.store.set_rules(owner.uid, &rules).map_err(failed)
    }

    /// Exclude one of the caller's folders or files from backups and history
    /// (from now on), or include it again.
    async fn set_excluded(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: String,
        excluded: bool,
    ) -> fdo::Result<()> {
        let owner = self.caller(&header).await?;
        let rel = relative(&owner, &path)?;
        let text = rel
            .to_str()
            .ok_or_else(|| fdo::Error::Failed("path-not-allowed".into()))?
            .to_owned();
        let _lock = self.store.lock(Duration::from_secs(10)).map_err(failed)?;
        let mut rules = self.store.rules(owner.uid);
        rules.excluded.retain(|p| *p != text);
        if excluded {
            rules.excluded.push(text);
        }
        self.store.set_rules(owner.uid, &rules).map_err(failed)
    }

    /// Remove the caller's files from every home history snapshot now, and from
    /// the backup drive at its next backup. Asks for their password.
    /// Returns (entries removed, snapshots changed, queued for the backup drive).
    async fn forget(
        &self,
        #[zbus(header)] header: Header<'_>,
        paths: Vec<String>,
    ) -> fdo::Result<(u64, u32, bool)> {
        if paths.is_empty() || paths.len() > 256 {
            return Err(fdo::Error::InvalidArgs("paths".into()));
        }
        let owner = self.caller(&header).await?;
        let rels: Vec<PathBuf> = paths
            .iter()
            .map(|p| relative(&owner, p))
            .collect::<fdo::Result<_>>()?;
        let owner = self.approved(&header, "org.enzimos.history.forget").await?;
        let busy = Busy::new(&self.busy);
        let store = self.store.clone();
        let last = Arc::clone(&self.last);
        let result = tokio::task::spawn_blocking(move || -> Result<(u64, u32, bool)> {
            let _lock = store.lock(Duration::from_secs(60))?;
            let mut outcome = prune::Outcome::default();
            if let Ok(dir) = snapshots_dir() {
                let list = super::list(&dir)?;
                let refs: Vec<&Path> = rels.iter().map(PathBuf::as_path).collect();
                outcome = prune::forget(&owner, &dir, &list, &refs)?;
            }
            let queued = Path::new(BACKUP_CONFIG).exists();
            if queued {
                let mut removals = store.removals();
                for rel in &rels {
                    let path = owner.home.join(rel).to_string_lossy().into_owned();
                    if !removals.iter().any(|r| r.path == path) {
                        removals.push(Removal {
                            uid: owner.uid,
                            path,
                            requested: store::now(),
                        });
                    }
                }
                store.set_removals(&removals)?;
            }
            if let Ok(mut l) = last.lock() {
                *l = Instant::now();
            }
            drop(busy);
            Ok((outcome.removed, outcome.snapshots, queued))
        })
        .await
        .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        result.map_err(failed)
    }

    /// The caller's files still to be removed from the backup drive: (path, asked).
    async fn removals(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<Vec<(String, i64)>> {
        let owner = self.caller(&header).await?;
        Ok(self
            .store
            .removals()
            .into_iter()
            .filter(|r| r.uid == owner.uid)
            .map(|r| (format!("{}/{}", super::HOME_ROOT, r.path), r.requested))
            .collect())
    }

    /// Cached measurement (JSON): totals plus the caller's own home breakdown.
    async fn usage(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<String> {
        let owner = self.caller(&header).await?;
        let mut usage = measure::for_caller(self.store.usage(), owner.uid);
        if let Ok((percent, free, size)) = prune::free_percent(Path::new(super::HOME_ROOT)) {
            usage["disk"] = serde_json::json!({"free_percent": percent, "free": free, "size": size, "keep_free_percent": self.store.free_percent()});
        }
        Ok(usage.to_string())
    }

    /// Ask for a new measurement in the background (at most every 10 minutes).
    async fn measure(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<()> {
        self.caller(&header).await?;
        let recent = self
            .store
            .usage()
            .and_then(|u| u["time"].as_i64())
            .is_some_and(|t| store::now() - t < 600);
        if recent {
            return Ok(());
        }
        start_unit(MEASURE_UNIT).await
    }

    /// Start a backup to the configured backup drive now.
    async fn back_up_now(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<()> {
        self.approved(&header, "org.enzimos.history.backup-now")
            .await?;
        if !Path::new(BACKUP_CONFIG).exists() {
            return Err(fdo::Error::Failed("no-backup-drive".into()));
        }
        start_unit(BACKUP_UNIT).await
    }

    /// Free space home history always leaves on the disk, percent.
    async fn free_percent(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<u32> {
        self.caller(&header).await?;
        Ok(self.store.free_percent())
    }

    /// Change the free space floor (administrator).
    async fn set_free_percent(
        &self,
        #[zbus(header)] header: Header<'_>,
        percent: u32,
    ) -> fdo::Result<()> {
        self.approved(&header, "org.enzimos.history.settings")
            .await?;
        self.store.set_free_percent(percent).map_err(failed)
    }
}

fn require_history(dir: &std::fs::File, number: u32) -> fdo::Result<()> {
    let list = super::list(dir).map_err(failed)?;
    if list.iter().any(|s| s.number == number) {
        Ok(())
    } else {
        Err(fdo::Error::Failed("not-found".into()))
    }
}

/// Serve until idle.
///
/// # Errors
/// Fails when the bus or authority is unavailable.
pub async fn serve() -> Result<()> {
    let authority = Authority::system().await?;
    let last = Arc::new(Mutex::new(Instant::now()));
    let busy = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let history = History {
        authority,
        store: Store::default(),
        last: Arc::clone(&last),
        busy: Arc::clone(&busy),
    };
    let connection = zbus::connection::Builder::system()
        .map_err(|e| Error(e.to_string()))?
        .serve_at(PATH, history)
        .map_err(|e| Error(e.to_string()))?
        .name(NAME)
        .map_err(|e| Error(e.to_string()))?
        .build()
        .await
        .map_err(|e| Error(e.to_string()))?;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let idle = busy.load(std::sync::atomic::Ordering::SeqCst) == 0
            && last.lock().map_or(true, |l| l.elapsed() > IDLE);
        if idle {
            drop(connection);
            return Ok(());
        }
    }
}
