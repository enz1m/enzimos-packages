// SPDX-License-Identifier: MIT
//! Retained kernel filesystem and mount identities around storage transactions.
use crate::{filesystem, operation, topology};
use enzimos_platform::{Error, Result, files, mount_identity, mountinfo, require};
use serde_json::Value;
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
/// Mount table of the current process.
///
/// # Errors
///
/// Fails when mountinfo cannot be read or parsed.
pub fn rows() -> Result<Vec<mountinfo::Row>> {
    let body = files::read_kernel(
        &PathBuf::from(format!("/proc/{}/mountinfo", std::process::id())),
        2 * 1024 * 1024,
    )?;
    mountinfo::parse(
        std::str::from_utf8(&body).map_err(|_| Error("storage mount encoding".into()))?,
    )
}
fn namespace(pid: u32) -> Result<(u64, u64)> {
    let p = PathBuf::from(format!("/proc/{pid}/ns/mnt"));
    // This is an explicitly fixed kernel namespace handle, never a caller path.
    let m = std::fs::metadata(p)?;
    Ok((m.dev(), m.ino()))
}
/// Require the caller to run in the initial mount namespace.
///
/// # Errors
///
/// Fails in any other mount namespace.
pub fn initial_namespace() -> Result<()> {
    operation::root_only()?;
    require(
        namespace(std::process::id())? == namespace(1)?,
        "initial system mount namespace required",
    )
}
/// The unique, unshadowed Btrfs mount row of `path` with the expected root and mount ID.
///
/// # Errors
///
/// Fails when the path is not mounted, is shadowed, or the row differs.
pub fn mount_row<'a>(
    rows: &'a [mountinfo::Row],
    path: &str,
    root: Option<&str>,
    normal_id: u64,
) -> Result<&'a mountinfo::Row> {
    let matches = rows.iter().filter(|r| r.target == path).collect::<Vec<_>>();
    require(matches.len() == 1, "storage mount is missing or shadowed")?;
    let row = matches[0];
    require(
        row.id == normal_id
            && row.filesystem == "btrfs"
            && root.is_none_or(|root| row.root == root)
            && row.options.split(',').any(|s| s == "rw")
            && !row.options.split(',').any(|s| s == "ro"),
        "storage mount identity mismatch",
    )?;
    Ok(row)
}
fn directory_identity(m: &std::fs::Metadata) -> (u64, u64, u32, u32) {
    (m.dev(), m.ino(), m.uid(), m.mode())
}
struct Mounted {
    path: PathBuf,
    file: File,
    identity: (u64, u64, u32, u32),
    unique: u64,
    normal: u64,
    filesystem: Value,
}
impl Mounted {
    fn open(path: &Path) -> Result<Self> {
        let file = files::directory(path, Some(0))?;
        let m = file.metadata()?;
        require(
            m.uid() == 0 && m.mode() & 0o022 == 0,
            "unsafe storage directory",
        )?;
        let unique = mount_identity::id(file.as_fd(), true)?;
        let normal = mount_identity::id(file.as_fd(), false)?;
        let filesystem = filesystem::observe(file.as_fd())?;
        Ok(Self {
            path: path.into(),
            file,
            identity: directory_identity(&m),
            unique,
            normal,
            filesystem,
        })
    }
    fn recheck(&self) -> Result<()> {
        require(
            directory_identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(self.file.as_fd(), true)? == self.unique
                && filesystem::observe(self.file.as_fd())? == self.filesystem,
            "held storage filesystem changed",
        )?;
        let current = files::directory(&self.path, Some(0))?;
        require(
            directory_identity(&current.metadata()?) == self.identity
                && mount_identity::id(current.as_fd(), true)? == self.unique,
            "named storage mount replaced",
        )
    }
}
/// The installed system's Btrfs control and root mounts with their configuration.
pub struct Guard {
    /// Validated storage configuration.
    pub configuration: Value,
    original_configuration: crate::storage_configuration::Configuration,
    control: Mounted,
    root: Mounted,
    topology: topology::Graph,
    namespace: (u64, u64),
}
impl Guard {
    /// Observe the configured control and root mounts and their filesystem.
    ///
    /// # Errors
    ///
    /// Fails when the configuration is invalid, the control storage is unsafe, or the mounted
    /// filesystem differs.
    pub fn observe() -> Result<Self> {
        initial_namespace()?;
        let original_configuration = crate::storage_configuration::Configuration::open()?;
        let configuration = original_configuration.value().clone();
        let control = Mounted::open(Path::new(operation::CONTROL))?;
        require(
            control.file.metadata()?.mode() & 0o7777 == 0o700,
            "unsafe private control storage",
        )?;
        let root = Mounted::open(Path::new("/"))?;
        for mounted in [&control, &root] {
            require(
                mounted.filesystem["filesystem_uuid"] == configuration["filesystem_uuid"],
                "configured storage filesystem mismatch",
            )?;
        }
        let expected = format!(
            "/{}",
            enzimos_platform::json::string(&configuration["control_subvol"])?
        );
        let observed = rows()?;
        mount_row(
            &observed,
            operation::CONTROL,
            Some(&expected),
            control.normal,
        )?;
        mount_row(&observed, "/", None, root.normal)?;
        let topology = topology::mounted_btrfs(enzimos_platform::json::string(
            &configuration["filesystem_uuid"],
        )?)?;
        let namespace = namespace(std::process::id())?;
        let guard = Self {
            configuration,
            original_configuration,
            control,
            root,
            topology,
            namespace,
        };
        guard.recheck()?;
        Ok(guard)
    }
    /// The retained control directory.
    pub fn control(&self) -> &File {
        &self.control.file
    }
    /// Mount ID of the control mount.
    pub fn control_mount_id(&self) -> u64 {
        self.control.unique
    }
    pub(crate) fn root_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.root.file)
    }
    /// Mount ID of the root mount.
    pub fn root_mount_id(&self) -> u64 {
        self.root.unique
    }
    /// Device of the root mount.
    pub fn root_device(&self) -> u64 {
        self.root.identity.0
    }
    pub(crate) fn backup_topology(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.topology.json())
    }
    /// JSON binding of the writable live root subvolume for backup records.
    ///
    /// # Errors
    ///
    /// Fails when the root subvolume is not the configured writable one.
    pub fn backup_root_binding(&self) -> Result<Value> {
        self.recheck()?;
        let root_path = enzimos_platform::json::string(&self.configuration["root_subvol"])?;
        let rows = rows()?;
        let row = mount_row(&rows, "/", Some(&format!("/{root_path}")), self.root.normal)?;
        let (object, readonly) = crate::subvolume::observe(self.root.file.as_fd(), root_path)?;
        require(
            !readonly && self.root.file.metadata()?.ino() == 256,
            "configured writable live Root subvolume required",
        )?;
        let value = serde_json::json!({"configuration":self.configuration,
            "mount":{"mount_id":self.root.normal,"unique_mount_id":self.root.unique,
                "device":format!("{}:{}",row.major,row.minor),"root":row.root,"target":"/","fstype":"btrfs"},
            "root":object,"boot_id":operation::boot_id()?});
        self.recheck()?;
        Ok(value)
    }
    /// Verify the mounts, filesystem and topology are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when any of them changed.
    pub fn recheck(&self) -> Result<()> {
        enzimos_platform::recheck_scope::once(self, "storage-guard", || self.recheck_fresh())
    }
    fn recheck_fresh(&self) -> Result<()> {
        initial_namespace()?;
        self.original_configuration.recheck()?;
        require(
            namespace(std::process::id())? == self.namespace
                && *self.original_configuration.value() == self.configuration,
            "storage transaction authority changed",
        )?;
        self.control.recheck()?;
        self.root.recheck()?;
        let observed = rows()?;
        let expected = format!(
            "/{}",
            enzimos_platform::json::string(&self.configuration["control_subvol"])?
        );
        mount_row(
            &observed,
            operation::CONTROL,
            Some(&expected),
            self.control.normal,
        )?;
        mount_row(&observed, "/", None, self.root.normal)?;
        require(
            topology::mounted_btrfs(enzimos_platform::json::string(
                &self.configuration["filesystem_uuid"],
            )?)? == self.topology,
            "storage members changed",
        )?;
        self.original_configuration.recheck()
    }
}
/// The Btrfs top level mounted privately for one transaction.
pub struct TopMount {
    path: PathBuf,
    mounted: Option<Mounted>,
    close_on_drop: bool,
}
impl TopMount {
    /// Mount the Btrfs top level, unmounting it when dropped.
    ///
    /// # Errors
    ///
    /// Fails when the guard changed or the top level cannot be mounted and verified.
    pub fn open(guard: &Guard) -> Result<Self> {
        Self::open_inner(guard, true)
    }
    /// Explicit normal cleanup only; an uncertain close is never repeated by Drop.
    ///
    /// # Errors
    ///
    /// As [`TopMount::open`].
    pub fn open_retained(guard: &Guard) -> Result<Self> {
        Self::open_inner(guard, false)
    }
    fn open_inner(guard: &Guard, close_on_drop: bool) -> Result<Self> {
        guard.recheck()?;
        let base = Path::new("/run/enzimos");
        files::ensure_directory(base, 0o700, 0)?;
        let path = base.join("root-birth-top");
        files::ensure_directory(&path, 0o700, 0)?;
        require(
            !rows()?
                .iter()
                .any(|r| path.to_str() == Some(r.target.as_str()))
                && std::fs::read_dir(&path)?.next().is_none(),
            "birth inspection mount occupied",
        )?;
        let source = format!(
            "UUID={}",
            enzimos_platform::json::string(&guard.configuration["filesystem_uuid"])?
        );
        operation::query(
            "/usr/bin/mount",
            &[
                "-t",
                "btrfs",
                "-o",
                "subvolid=5,nodiscard,nodev,nosuid,noexec",
                &source,
                path.to_str()
                    .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
            ],
            Duration::from_secs(30),
            65536,
            &[0],
        )?;
        // A failed observation retains this unadopted mount for explicit review.
        let mounted = Mounted::open(&path)?;
        let mut top = Self {
            path,
            mounted: Some(mounted),
            close_on_drop,
        };
        let result = (|| {
            let m = top
                .mounted
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("missing value".into()))?;
            mount_row(
                &rows()?,
                top.path
                    .to_str()
                    .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
                Some("/"),
                m.normal,
            )?;
            require(
                m.filesystem["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
                "wrong birth top-level filesystem",
            )?;
            guard.recheck()
        })();
        if let Err(error) = result {
            top.close()?;
            return Err(error);
        }
        Ok(top)
    }
    /// Mount point of the top level.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// The top-level directory.
    ///
    /// # Errors
    ///
    /// Fails after the mount was closed.
    pub fn directory(&self) -> Result<&File> {
        self.mounted
            .as_ref()
            .map(|m| &m.file)
            .ok_or_else(|| Error("top mount closed".into()))
    }
    /// Verify the top-level mount is still the one opened.
    ///
    /// # Errors
    ///
    /// Fails after close or when the mount changed.
    pub fn recheck(&self) -> Result<()> {
        initial_namespace()?;
        let m = self
            .mounted
            .as_ref()
            .ok_or_else(|| Error("top mount closed".into()))?;
        m.recheck()?;
        mount_row(
            &rows()?,
            self.path
                .to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?,
            Some("/"),
            m.normal,
        )?;
        Ok(())
    }
    /// Unmount the top level.
    ///
    /// # Errors
    ///
    /// Fails when the unmount fails or is uncertain; the path is then retained for review.
    pub fn close(&mut self) -> Result<()> {
        if self.mounted.is_none() {
            return Ok(());
        }
        self.recheck()?;
        // Close our retained descriptor first. Other retained references cause a
        // normal unmount refusal; there is no lazy detach or forced cleanup.
        let original = self
            .mounted
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?;
        let expected = (
            original.identity,
            original.unique,
            original.normal,
            original.filesystem.clone(),
        );
        drop(self.mounted.take());
        let outcome = operation::query(
            "/usr/bin/umount",
            &[self
                .path
                .to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?],
            Duration::from_secs(15),
            65536,
            &[0],
        );
        if let Err(error) = outcome {
            // A refused normal unmount must not erase the retained mount state.
            // Reopen only the exact original kernel mount, never a replacement.
            let current = Mounted::open(&self.path)?;
            require(
                (
                    current.identity,
                    current.unique,
                    current.normal,
                    current.filesystem.clone(),
                ) == expected,
                "top mount changed after cleanup refusal; retain path for review",
            )?;
            self.mounted = Some(current);
            return Err(error);
        }
        require(
            !rows()?
                .iter()
                .any(|r| self.path.to_str() == Some(r.target.as_str())),
            "top mount cleanup uncertain",
        )
    }
}
impl Drop for TopMount {
    fn drop(&mut self) {
        if self.close_on_drop {
            let _ = self.close();
        }
    }
}
/// Recovery authority is established from a genuine initial-namespace RAM root,
/// a validated plan and the separately mounted top/control objects. It does not
/// relax the installed-root guard or execute a restored root's programs.
pub struct IndependentGuard {
    plan: Value,
    control: Mounted,
    top: Mounted,
    ram: File,
    ram_mount: u64,
    namespaces: Vec<(u64, u64)>,
    topology: topology::Graph,
}
impl IndependentGuard {
    /// Mount point of the recovery top level.
    pub const TOP: &str = "/run/enzimos/recovery-top";
    /// Observe the independent recovery environment for `plan`.
    ///
    /// # Errors
    ///
    /// Fails outside the independent RAM-root recovery environment or when its filesystem differs
    /// from the plan.
    pub fn observe(plan: &Value) -> Result<Self> {
        crate::recovery_records::plan(plan)?;
        let namespaces = crate::namespaces::initial()?;
        let marker = files::read(Path::new("/etc/initrd-release"), 8192, Some(0), true)?;
        require(
            !marker.is_empty(),
            "independent initramfs release marker required",
        )?;
        let ram = files::directory(Path::new("/"), Some(0))?;
        let ram_mount = mount_identity::id(ram.as_fd(), true)?;
        let control = Mounted::open(Path::new(operation::CONTROL))?;
        let top = Mounted::open(Path::new(Self::TOP))?;
        let topology =
            topology::mounted_btrfs(enzimos_platform::json::string(&plan["filesystem_uuid"])?)?;
        let guard = Self {
            plan: plan.clone(),
            control,
            top,
            ram,
            ram_mount,
            namespaces,
            topology,
        };
        guard.recheck()?;
        Ok(guard)
    }
    /// Mount ID of the control mount.
    pub fn control_mount_id(&self) -> u64 {
        self.control.unique
    }
    /// The retained control directory.
    pub fn control(&self) -> &File {
        &self.control.file
    }
    /// The retained top-level directory.
    pub fn top(&self) -> &File {
        &self.top.file
    }
    /// The recovery plan this guard was observed for.
    pub fn plan(&self) -> &Value {
        &self.plan
    }
    /// Verify the recovery namespaces, RAM root and filesystem are unchanged.
    ///
    /// # Errors
    ///
    /// Fails when any of them changed.
    pub fn recheck(&self) -> Result<()> {
        require(
            crate::namespaces::initial()? == self.namespaces,
            "independent recovery namespaces changed",
        )?;
        let current = files::directory(Path::new("/"), Some(0))?;
        let a = self.ram.metadata()?;
        let b = current.metadata()?;
        require(
            (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
                && mount_identity::id(self.ram.as_fd(), true)? == self.ram_mount
                && mount_identity::id(current.as_fd(), true)? == self.ram_mount,
            "independent RAM root replaced",
        )?;
        let rows = rows()?;
        let roots = rows.iter().filter(|r| r.target == "/").collect::<Vec<_>>();
        require(
            roots.len() == 1
                && matches!(roots[0].filesystem.as_str(), "tmpfs" | "rootfs" | "ramfs")
                && roots[0].id == mount_identity::id(self.ram.as_fd(), false)?,
            "RAM-root recovery required; installed root cannot restore",
        )?;
        self.control.recheck()?;
        self.top.recheck()?;
        let uuid = enzimos_platform::json::string(&self.plan["filesystem_uuid"])?;
        for mounted in [&self.control, &self.top] {
            require(
                mounted.filesystem["filesystem_uuid"] == uuid,
                "recovery filesystem differs from plan",
            )?;
        }
        require(
            self.control.file.metadata()?.mode() & 0o7777 == 0o700,
            "unsafe independent control storage",
        )?;
        let control = &self.plan["protected"]["control"];
        let path = enzimos_platform::json::string(&control["path"])?;
        mount_row(
            &rows,
            operation::CONTROL,
            Some(&format!("/{path}")),
            self.control.normal,
        )?;
        mount_row(&rows, Self::TOP, Some("/"), self.top.normal)?;
        require(
            crate::subvolume::observe(self.control.file.as_fd(), path)?.0 == *control,
            "protected recovery control identity changed",
        )?;
        require(
            topology::mounted_btrfs(uuid)? == self.topology,
            "independent recovery members changed",
        )?;
        if self.plan["schema"].as_u64() == Some(1) {
            require(
                operation::boot_id()? != self.plan["created_boot"],
                "recovery plan cannot execute on preparation boot",
            )?;
        } else {
            require(
                crate::media_origin::current()? == self.plan["media_origin"],
                "independent media origin changed",
            )?;
        }
        let boot = crate::boot_volume::Volume::observe()?;
        require(
            boot.uuid == self.plan["boot_uuid"],
            "recovery boot volume differs from plan",
        )
    }
}
