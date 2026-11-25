// SPDX-License-Identifier: MIT
//! Existing local repositories are held on their original independent filesystem.
use crate::{backup_configuration::Configuration, filesystem, storage_runtime, topology};
use enzimos_platform::{Result, files, json, mount_identity, mountinfo, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
#[path = "backup_local_initialize.rs"]
pub mod initialize;
#[path = "backup_ram_destination.rs"]
pub(crate) mod ram;
const MOUNT: &str = "/backup-repository";
type Shape = (u64, u64, u32, u32, u32);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "protected backup destination directory required",
    )?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
pub(crate) fn mount(rows: &[mountinfo::Row], normal: u64) -> Result<mountinfo::Row> {
    require(
        !rows
            .iter()
            .any(|r| r.target.starts_with("/backup-repository/")),
        "nested backup destination mount refused",
    )?;
    // Setup and recovery copies attach the destination over a root-only bind
    // stub of the Root's own empty `backup-repository` directory; accept
    // exactly that stack and nothing else stacked on the target.
    let stack = rows
        .iter()
        .filter(|r| r.target == MOUNT)
        .collect::<Vec<_>>();
    if let [stub, top] = stack.as_slice() {
        // The stub is a bind of the Root's own directory, directly on `/`.
        let root = rows.iter().find(|r| r.target == "/");
        require(
            stub.filesystem == "btrfs"
                && root.is_some_and(|root| {
                    stub.parent == root.id
                        && (stub.major, stub.minor) == (root.major, root.minor)
                        && stub.root
                            == format!("{}/backup-repository", root.root.trim_end_matches('/'))
                })
                && (stub.optional.is_empty() || crate::private_bind::shared_group(&stub.optional))
                && top.parent == stub.id
                && rows.iter().all(|r| r.parent != stub.id || r.id == top.id),
            "backup destination stack is not the private stub with one destination",
        )?;
        let visible = rows
            .iter()
            .filter(|r| r.id != stub.id)
            .cloned()
            .collect::<Vec<_>>();
        return Ok(storage_runtime::mount_row(&visible, MOUNT, Some("/"), normal)?.clone());
    }
    Ok(storage_runtime::mount_row(rows, MOUNT, Some("/"), normal)?.clone())
}
pub(crate) fn independent(destination: &Value, source: &Value) -> Result<()> {
    let leaves = |v: &Value| -> Result<Vec<Value>> {
        let rows = v["leaves"]
            .as_array()
            .ok_or_else(|| enzimos_platform::Error("backup topology leaves required".into()))?;
        require(!rows.is_empty(), "backup topology leaves required")?;
        Ok(rows.clone())
    };
    let a = leaves(destination)?;
    let b = leaves(source)?;
    require(
        a.iter().all(|leaf| !b.contains(leaf)),
        "backup destination overlaps a protected system disk",
    )
}
/// Destination evidence that survives remounting: the same filesystem, the
/// same encrypted repository header and the same independent disk topology.
/// Plans bind this, so a plan made against a borrowed or detached destination
/// stays valid when execution owns a fresh temporary mount of the same drive.
pub(crate) fn stable(uuid: &str, repository_sha256: &Value, topology: &Value) -> Value {
    value!({"schema":1,"filesystem_uuid":uuid,"fsroot":"/","repository":crate::backup_configuration::REPOSITORY,
        "repository_sha256":repository_sha256,"topology":topology})
}
/// Review-document form of a worker context: the fields that name one mount
/// epoch (mount IDs, device numbers, descriptor identities on the destination)
/// are replaced by the same filesystem/header/topology they stand for. Worker
/// handoffs keep comparing the full context within one mount.
pub(crate) fn stable_context(context: &mut Value) -> Result<()> {
    let evidence = &context["destination"];
    let uuid = evidence["filesystem"]["filesystem_uuid"]
        .as_str()
        .ok_or_else(|| enzimos_platform::Error("destination evidence UUID required".into()))?
        .to_owned();
    let stable_destination = stable(
        &uuid,
        &evidence["pin"]["repository_sha256"],
        &evidence["topology"],
    );
    context["destination"] = stable_destination;
    for key in ["root_directory", "repository_directory"] {
        let d = &context[key];
        if !d.is_null() {
            context[key] =
                value!({"inode":d["inode"],"mode":d["mode"],"uid":d["uid"],"gid":d["gid"]});
        }
    }
    if !context["header"].is_null() {
        context["header"] = value!({"sha256":context["header"]["sha256"]});
    }
    Ok(())
}
pub(crate) fn writable(row: &mountinfo::Row) -> Result<()> {
    let flags = row
        .options
        .split(',')
        .collect::<std::collections::BTreeSet<_>>();
    require(
        ["rw", "nodev", "nosuid", "noexec"]
            .iter()
            .all(|s| flags.contains(s))
            && !flags.contains("ro")
            && !row.filesystem_options.split(',').any(|s| {
                s == "ro" || s == "nologreplay" || s == "norecovery" || s.starts_with("rescue=")
            }),
        "writable protected backup mount required",
    )
}
/// Historical receipt data from the original held live destination. This
/// rendering grants no mount, copy, restore or filesystem ownership authority.
pub(crate) fn legacy_binding(
    destination: &Value,
    source: &storage_runtime::Guard,
) -> Result<Value> {
    source.recheck()?;
    let mount = &destination["mount"];
    let uuid = enzimos_platform::json::string(&source.configuration["filesystem_uuid"])?;
    let result = value!({"filesystem_uuid":destination["filesystem"]["filesystem_uuid"],
        "mount":{"mount_id":mount["id"],"unique_mount_id":destination["unique_mount"],"device":format!("{}:{}",enzimos_platform::json::unsigned(&mount["major"])?,enzimos_platform::json::unsigned(&mount["minor"])?),"root":mount["root"],"target":mount["target"],"fstype":mount["filesystem"]},
        "repository_sha256":destination["pin"]["repository_sha256"],"storage_topology":{"destination":destination["topology"],"sources":{uuid:source.backup_topology()?}}});
    source.recheck()?;
    Ok(result)
}
/// Live-system guard only. Independent RAM recovery requires its separate
/// validated RecoveryPlan authority; it cannot borrow a live-system shortcut.
pub struct Destination<'a> {
    config: &'a Configuration,
    source: &'a storage_runtime::Guard,
    root: File,
    root_shape: Shape,
    unique: u64,
    normal: u64,
    filesystem: Value,
    mount: mountinfo::Row,
    topology: topology::Graph,
    repository: File,
    repository_shape: Shape,
    repository_config: File,
    config_identity: files::FileIdentity,
    config_body: Vec<u8>,
}
impl<'a> Destination<'a> {
    /// Label and free-space lookup use the actual original description.
    /// Free space comes from the actual original description. No directory
    /// traversal, mount, credential read or repository-size scan is performed.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
    pub(crate) fn status(&self) -> Result<Value> {
        self.recheck()?;
        // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut usage: libc::statvfs = unsafe { std::mem::zeroed() };
        use std::os::fd::AsRawFd;
        require(
            // SAFETY: `usage` is a writable `libc::statvfs` and `self.root` keeps the descriptor
            // open.
            unsafe { libc::fstatvfs(self.root.as_raw_fd(), &mut usage) } == 0,
            "backup status original filesystem space unavailable",
        )?;
        let free = usage
            .f_bavail
            .checked_mul(usage.f_frsize)
            .ok_or_else(|| enzimos_platform::Error("backup status free space overflow".into()))?;
        let label = filesystem::label(self.root.as_fd())?;
        self.recheck()?;
        Ok(
            value!({"destination_available":true,"destination_label":label,
            "destination_free_bytes":free,"repository_bytes":null}),
        )
    }
    /// Open the configured local repository destination.
    ///
    /// # Errors
    ///
    /// Fails when the destination is not independent of the source and control filesystems, or
    /// unsafe.
    pub fn open(config: &'a Configuration, source: &'a storage_runtime::Guard) -> Result<Self> {
        config.recheck()?;
        source.recheck()?;
        let uuid = enzimos_platform::json::string(&config.value()["destination_uuid"])?;
        require(
            source.configuration["filesystem_uuid"] != uuid,
            "backup destination must be independent of source/control filesystem",
        )?;
        let root = files::directory(Path::new(MOUNT), Some(0))?;
        let unique = mount_identity::id(root.as_fd(), true)?;
        let normal = mount_identity::id(root.as_fd(), false)?;
        let filesystem = filesystem::observe(root.as_fd())?;
        // The Root's own empty stub directory: the configured drive is not
        // mounted here. Callers that may mount attach it first
        // (`backup_destination_attach`); others refuse with a typed state.
        require(
            filesystem["filesystem_uuid"] != source.configuration["filesystem_uuid"],
            crate::backup_destination_attach::NOT_MOUNTED,
        )?;
        require(
            filesystem["filesystem_uuid"] == uuid,
            "backup destination filesystem mismatch",
        )?;
        let mount = mount(&storage_runtime::rows()?, normal)?;
        let topology = topology::mounted_btrfs(uuid)?;
        independent(
            &topology.json(),
            &topology::mounted_btrfs(enzimos_platform::json::string(
                &source.configuration["filesystem_uuid"],
            )?)?
            .json(),
        )?;
        let repository = files::directory_relative(&root, Path::new("restic"), Some(0))?;
        require(
            mount_identity::id(repository.as_fd(), true)? == unique,
            "backup repository crosses a mount boundary",
        )?;
        let repository_config = files::open_relative(&repository, Path::new("config"))?;
        let m = repository_config.metadata()?;
        require(
            m.uid() == 0
                && m.mode() & 0o022 == 0
                && m.nlink() == 1
                && mount_identity::id(repository_config.as_fd(), true)? == unique,
            "protected backup repository configuration required",
        )?;
        let this = Self {
            config,
            source,
            root_shape: shape(&root)?,
            root,
            unique,
            normal,
            filesystem,
            mount,
            topology,
            repository_shape: shape(&repository)?,
            repository,
            config_identity: files::identity(&m),
            config_body: files::read_file(&repository_config, 1024 * 1024, Some(0), true)?,
            repository_config,
        };
        this.recheck()?;
        Ok(this)
    }
    /// Verify the destination is unchanged.
    ///
    /// # Errors
    ///
    /// Fails when it changed or was replaced.
    pub fn recheck(&self) -> Result<()> {
        self.config.recheck()?;
        self.source.recheck()?;
        let named = files::directory(Path::new(MOUNT), Some(0))?;
        let repo = files::directory_relative(&self.root, Path::new("restic"), Some(0))?;
        let config = files::open_relative(&self.repository, Path::new("config"))?;
        require(
            shape(&named)? == self.root_shape
                && shape(&self.root)? == self.root_shape
                && mount_identity::id(named.as_fd(), true)? == self.unique
                && mount_identity::id(self.root.as_fd(), true)? == self.unique
                && mount_identity::id(self.root.as_fd(), false)? == self.normal
                && filesystem::observe(self.root.as_fd())? == self.filesystem
                && mount(&storage_runtime::rows()?, self.normal)? == self.mount
                && topology::mounted_btrfs(enzimos_platform::json::string(
                    &self.config.value()["destination_uuid"],
                )?)? == self.topology
                && shape(&repo)? == self.repository_shape
                && shape(&self.repository)? == self.repository_shape
                && mount_identity::id(repo.as_fd(), true)? == self.unique
                && mount_identity::id(self.repository.as_fd(), true)? == self.unique
                && files::identity(&config.metadata()?) == self.config_identity
                && files::identity(&self.repository_config.metadata()?) == self.config_identity
                && mount_identity::id(config.as_fd(), true)? == self.unique
                && mount_identity::id(self.repository_config.as_fd(), true)? == self.unique
                && files::read_file(&self.repository_config, 1024 * 1024, Some(0), true)?
                    == self.config_body,
            "original backup destination epoch changed or replaced",
        )
    }
    pub(crate) fn expected_pin(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"schema":1,"filesystem_uuid":self.filesystem["filesystem_uuid"],"fsroot":"/","repository":crate::backup_configuration::REPOSITORY,"repository_sha256":json::sha256(&self.config_body)}),
        )
    }
    /// Mount-independent evidence (see `stable`) for review documents.
    pub(crate) fn stable_evidence(&self) -> Result<Value> {
        let pin = self.expected_pin()?;
        Ok(stable(
            enzimos_platform::json::string(&self.filesystem["filesystem_uuid"])?,
            &pin["repository_sha256"],
            &self.topology.json(),
        ))
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"root":self.root_shape,"repository":self.repository_shape,
            "repository_configuration":self.config_identity,"unique_mount":self.unique,
            "filesystem":self.filesystem,"topology":self.topology.json(),
            "mount":{"id":self.mount.id,"parent":self.mount.parent,"major":self.mount.major,
            "minor":self.mount.minor,"root":self.mount.root,"target":self.mount.target,
            "filesystem":self.mount.filesystem,"options":self.mount.options,
            "filesystem_options":self.mount.filesystem_options,"optional":self.mount.optional},
            "pin":self.expected_pin()?}),
        )
    }
    /// Sample original writable repository space; no path reopening or estimate.
    #[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
    pub(crate) fn require_free_space(&self) -> Result<()> {
        use std::os::fd::AsRawFd;
        self.require_writable()?;
        // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
        let mut status: libc::statvfs = unsafe { std::mem::zeroed() };
        require(
            // SAFETY: `status` is a writable `libc::statvfs` and `self.repository` keeps the
            // descriptor open.
            unsafe { libc::fstatvfs(self.repository.as_raw_fd(), &mut status) } == 0,
            "original transfer repository space unavailable",
        )?;
        let available = status
            .f_bavail
            .checked_mul(status.f_frsize)
            .ok_or_else(|| enzimos_platform::Error("repository space overflow".into()))?;
        require(
            available >= self.config.minimum_free_bytes(),
            "original transfer repository minimum free space",
        )
    }
    /// Require that the destination is mounted writable.
    ///
    /// # Errors
    ///
    /// Fails when it is read-only.
    pub fn require_writable(&self) -> Result<()> {
        self.recheck()?;
        writable(&self.mount)
    }
    pub(crate) fn repository_descriptor(&self) -> Result<std::os::fd::BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.repository.as_fd())
    }
    pub(crate) fn root_descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.root)
    }
    pub(crate) fn configuration(&self) -> Result<&Configuration> {
        self.recheck()?;
        Ok(self.config)
    }
    pub(crate) fn storage(&self) -> &crate::storage_runtime::Guard {
        self.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_disk_must_be_disjoint_even_across_distinct_filesystems() {
        assert!(independent(&value!({"leaves":[[8,1]]}), &value!({"leaves":[[8,2]]})).is_ok());
        assert!(
            independent(
                &value!({"leaves":[[8,1],[8,2]]}),
                &value!({"leaves":[[8,2]]})
            )
            .is_err()
        );
        assert!(independent(&value!({"leaves":[]}), &value!({"leaves":[[8,2]]})).is_err());
    }
}
