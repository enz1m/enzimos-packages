// SPDX-License-Identifier: MIT
//! Actual retained Root targets for retirement observation. No deletion capability.
//! Decoded identities are comparisons only; all authority stays in original FDs.
use crate::{
    filesystem, identity, operation,
    storage_runtime::{Guard, TopMount},
    subvolume,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

fn flags(file: &File) -> Result<i32> {
    let value = enzimos_platform::files::status_flags(&file);
    require(
        value >= 0 && value & libc::O_ACCMODE == libc::O_RDONLY,
        "original retirement observation descriptor must be read only",
    )?;
    Ok(value)
}
fn path(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 4096
            && !value.starts_with('/')
            && value.split('/').count() <= 64,
        "bounded relative retirement object path",
    )?;
    for part in value.split('/') {
        require(
            !part.is_empty() && !matches!(part, "." | ".."),
            "canonical retirement path",
        )?;
        if part != ".snapshots" {
            identity::safe_id(part)?;
        }
    }
    Ok(())
}
pub(crate) struct Original {
    path: String,
    role: String,
    file: File,
    parent: File,
    parent_path: String,
    epoch: files::FileIdentity,
    parent_epoch: files::FileIdentity,
    parent_root: Value,
    flags: i32,
    parent_flags: i32,
    mount: u64,
    identity: Value,
    readonly: bool,
}
impl Original {
    pub(crate) fn apply_owned_change(
        mut self,
        top: &File,
        filesystem: &Value,
        change: &crate::root_retirement_cursor::Change,
    ) -> Result<Self> {
        self.epoch = change.parent_transition(&self.path, &self.identity, self.epoch)?;
        self.parent_epoch =
            change.parent_transition(&self.parent_path, &self.parent_root, self.parent_epoch)?;
        self.recheck(top, filesystem)?;
        Ok(self)
    }
    pub(crate) fn duplicate_original(&self, top: &File, filesystem: &Value) -> Result<Self> {
        self.recheck(top, filesystem)?;
        Ok(Self {
            path: self.path.clone(),
            role: self.role.clone(),
            file: self.file.try_clone()?,
            parent: self.parent.try_clone()?,
            parent_path: self.parent_path.clone(),
            epoch: self.epoch,
            parent_epoch: self.parent_epoch,
            parent_root: self.parent_root.clone(),
            flags: self.flags,
            parent_flags: self.parent_flags,
            mount: self.mount,
            identity: self.identity.clone(),
            readonly: self.readonly,
        })
    }
    pub(crate) fn recheck_after_first(
        &self,
        top: &File,
        filesystem: &Value,
        proof: &crate::root_retirement_first_delete::After<'_, '_, '_>,
    ) -> Result<()> {
        let epoch = proof.parent_transition(&self.path, &self.identity, self.epoch)?;
        let parent_epoch =
            proof.parent_transition(&self.parent_path, &self.parent_root, self.parent_epoch)?;
        self.recheck_epochs(top, filesystem, epoch, parent_epoch)
    }
    pub(crate) fn duplicate_after_first(
        &self,
        top: &File,
        filesystem: &Value,
        proof: &crate::root_retirement_first_delete::After<'_, '_, '_>,
    ) -> Result<Self> {
        self.recheck_after_first(top, filesystem, proof)?;
        Ok(Self {
            path: self.path.clone(),
            role: self.role.clone(),
            file: self.file.try_clone()?,
            parent: self.parent.try_clone()?,
            parent_path: self.parent_path.clone(),
            epoch: proof.parent_transition(&self.path, &self.identity, self.epoch)?,
            parent_epoch: proof.parent_transition(
                &self.parent_path,
                &self.parent_root,
                self.parent_epoch,
            )?,
            parent_root: self.parent_root.clone(),
            flags: self.flags,
            parent_flags: self.parent_flags,
            mount: self.mount,
            identity: self.identity.clone(),
            readonly: self.readonly,
        })
    }
    pub(crate) fn descriptions(&self) -> (&File, &File) {
        (&self.file, &self.parent)
    }
    pub(crate) fn identity(&self) -> &Value {
        &self.identity
    }
    pub(crate) fn readonly(&self) -> bool {
        self.readonly
    }
    pub(crate) fn evidence(&self) -> Value {
        value!({"role":self.role,"identity":self.identity,"readonly":self.readonly,
            "mount_id":self.mount})
    }
    pub(crate) fn observe(top: &File, row: &Value, filesystem_uuid: &Value) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        json::fields(row, "role path id uuid parent_uuid")?;
        let relative = row["path"]
            .as_str()
            .ok_or_else(|| Error("retirement target path".into()))?;
        path(relative)?;
        let role = row["role"]
            .as_str()
            .ok_or_else(|| Error("retirement target role".into()))?;
        require(
            matches!(
                role,
                "root-subvolume" | "history-store" | "nested-subvolume"
            ),
            "closed retirement target role",
        )?;
        let parent_path = Path::new(relative)
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?
            .to_owned();
        let parent = if parent_path.is_empty() {
            top.try_clone()?
        } else {
            files::directory_relative(top, Path::new(&parent_path), Some(0))?
        };
        let file = files::directory_relative(top, Path::new(relative), Some(0))?;
        require(
            file.metadata()?.ino() == 256
                && file.metadata()?.uid() == 0
                && file.metadata()?.gid() == 0
                && file.metadata()?.mode() & 0o022 == 0,
            "protected actual Btrfs subvolume root required",
        )?;
        let mount = mount_identity::id(top.as_fd(), true)?;
        require(
            mount_identity::id(file.as_fd(), true)? == mount
                && mount_identity::id(parent.as_fd(), true)? == mount
                && filesystem::observe(file.as_fd())?["filesystem_uuid"] == *filesystem_uuid,
            "retirement target crossed original top-level filesystem/mount",
        )?;
        let (actual, readonly) = subvolume::observe(file.as_fd(), relative)?;
        let mut expected = enzimos_platform::json::object(row)?.clone();
        expected.remove("role");
        require(
            actual == Value::Object(expected),
            "actual retirement subvolume differs from comparison",
        )?;
        Ok(Self {
            path: relative.into(),
            role: role.into(),
            epoch: files::identity(&file.metadata()?),
            parent_epoch: files::identity(&parent.metadata()?),
            parent_root: subvolume::containing_identity(parent.as_fd())?,
            flags: flags(&file)?,
            parent_flags: flags(&parent)?,
            mount,
            identity: actual,
            readonly,
            file,
            parent,
            parent_path,
        })
    }
    pub(crate) fn recheck(&self, top: &File, filesystem_uuid: &Value) -> Result<()> {
        self.recheck_epochs(top, filesystem_uuid, self.epoch, self.parent_epoch)
    }
    fn recheck_epochs(
        &self,
        top: &File,
        filesystem_uuid: &Value,
        epoch: files::FileIdentity,
        parent_epoch: files::FileIdentity,
    ) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        let named = files::directory_relative(top, Path::new(&self.path), Some(0))?;
        let parent = if self.parent_path.is_empty() {
            top.try_clone()?
        } else {
            files::directory_relative(top, Path::new(&self.parent_path), Some(0))?
        };
        require(
            files::identity(&self.file.metadata()?) == epoch
                && files::identity(&named.metadata()?) == epoch
                && files::identity(&self.parent.metadata()?) == parent_epoch
                && files::identity(&parent.metadata()?) == parent_epoch
                && flags(&self.file)? == self.flags
                && flags(&self.parent)? == self.parent_flags,
            "original retirement target/parent epoch or descriptor flags changed",
        )?;
        for file in [&self.file, &named, &self.parent, &parent] {
            require(
                mount_identity::id(file.as_fd(), true)? == self.mount
                    && filesystem::observe(file.as_fd())?["filesystem_uuid"] == *filesystem_uuid,
                "original retirement target replaced or covered",
            )?;
        }
        for file in [&self.file, &named] {
            require(
                subvolume::observe(file.as_fd(), &self.path)?
                    == (self.identity.clone(), self.readonly),
                "original retirement subvolume identity/readonly state changed",
            )?;
        }
        for file in [&self.parent, &parent] {
            require(
                subvolume::containing_identity(file.as_fd())? == self.parent_root,
                "original retirement parent belongs to a different kernel subvolume root",
            )?;
        }
        Ok(())
    }
}
/// This actor observes actual originals. It cannot destroy, rename or finish a
/// receipt. Offline exclusivity, live reference checks and durable intent remain
/// independent prerequisites for a future consuming executor.
pub struct Targets<'a> {
    guard: &'a Guard,
    top: &'a TopMount,
    lock: &'a files::Lock,
    source: Value,
    objects: Vec<Original>,
}
impl<'a> Targets<'a> {
    pub fn observe(
        guard: &'a Guard,
        top: &'a TopMount,
        lock: &'a files::Lock,
        rows: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        guard.recheck()?;
        top.recheck()?;
        lock.recheck()?;
        let rows = rows
            .as_array()
            .ok_or_else(|| Error("retirement targets array".into()))?;
        require((1..=64).contains(&rows.len()), "retirement target count")?;
        require(
            rows.last()
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["role"]
                == "root-subvolume"
                && rows
                    .iter()
                    .filter(|row| row["role"] == "root-subvolume")
                    .count()
                    == 1,
            "one last original root target required",
        )?;
        let root = rows
            .last()
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["path"]
            .as_str()
            .ok_or_else(|| Error("retirement root target path".into()))?;
        identity::safe_id(root)?;
        let mut nested = Vec::new();
        for row in rows {
            let target = row["path"]
                .as_str()
                .ok_or_else(|| Error("retirement object path".into()))?;
            for key in [
                "root_subvol",
                "home_subvol",
                "authority_subvol",
                "control_subvol",
            ] {
                require(
                    guard.configuration[key] != target,
                    "configured protected subvolume cannot be a retirement target",
                )?;
            }
            match row["role"].as_str() {
                Some("history-store") => require(
                    target == format!("{root}/.snapshots"),
                    "original history store must belong to exact target root",
                )?,
                Some("nested-subvolume") => {
                    require(
                        target.starts_with(&format!("{root}/")),
                        "nested retirement target must be below exact root",
                    )?;
                    nested.push(target);
                }
                Some("root-subvolume") => (),
                _ => return Err(Error("retirement target role".into())),
            }
        }
        require(
            nested.is_empty() || rows.iter().all(|row| row["role"] != "history-store"),
            "retirement target families cannot mix publisher history with superseded descendants",
        )?;
        let mut ordered = nested.clone();
        ordered.sort_by(|a, b| {
            b.matches('/')
                .count()
                .cmp(&a.matches('/').count())
                .then_with(|| a.cmp(b))
        });
        require(
            nested == ordered,
            "original nested retirement targets must be deepest first",
        )?;
        let source = guard.backup_root_binding()?;
        let fs = &guard.configuration["filesystem_uuid"];
        let mut objects = Vec::new();
        let mut ids = BTreeSet::new();
        let mut uuids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for row in rows {
            authorize()?;
            guard.recheck()?;
            top.recheck()?;
            lock.recheck()?;
            let object = Original::observe(top.directory()?, row, fs)?;
            require(
                object.role != "root-subvolume" || !object.readonly,
                "original retirement Root must remain writable",
            )?;
            require(
                ids.insert(enzimos_platform::json::unsigned(&object.identity["id"])?)
                    && uuids.insert(
                        enzimos_platform::json::string(&object.identity["uuid"])?.to_owned(),
                    )
                    && paths.insert(object.path.clone()),
                "distinct original retirement targets required",
            )?;
            objects.push(object);
        }
        let this = Self {
            guard,
            top,
            lock,
            source,
            objects,
        };
        this.recheck(authorize)?;
        Ok(this)
    }
    pub(crate) fn require_original_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock),
            "online targets belong to another original source actor",
        )?;
        self.recheck(authorize)
    }
    /// Stable original object and parent epochs for a server plan seal. Temporary
    /// inspection mount IDs are excluded; actual mount descriptions still recheck.
    pub(crate) fn planning_evidence(
        &self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(value!(
            self.objects
                .iter()
                .map(
                    |object| value!({"role":object.role,"identity":object.identity,
            "readonly":object.readonly,"epoch":object.epoch,"flags":object.flags,
            "parent_path":object.parent_path,"parent_root":object.parent_root,
            "parent_epoch":object.parent_epoch,"parent_flags":object.parent_flags})
                )
                .collect::<Vec<_>>()
        ))
    }
    pub(crate) fn rows(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(value!(
            self.objects
                .iter()
                .map(|object| {
                    let mut row = object
                        .identity
                        .as_object()
                        .cloned()
                        .expect("object identities are recorded as JSON objects");
                    row.insert("role".into(), value!(object.role));
                    Value::Object(row)
                })
                .collect::<Vec<_>>()
        ))
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.guard.recheck()?;
        self.top.recheck()?;
        self.lock.recheck()?;
        require(
            self.guard.backup_root_binding()? == self.source,
            "original retirement source changed",
        )?;
        for object in &self.objects {
            object.recheck(
                self.top.directory()?,
                &self.guard.configuration["filesystem_uuid"],
            )?;
            authorize()?;
        }
        self.guard.recheck()?;
        self.top.recheck()?;
        self.lock.recheck()?;
        authorize()
    }
    /// Online exact-ID deletion of the first retained target, for an owned
    /// receipt whose durable in-flight step names exactly this target. The
    /// caller has rechecked every protection immediately before. `before` is
    /// the complete current kernel inventory; afterwards exactly this one root
    /// must be gone from it, its literal name must be ENOENT in its retained
    /// parent and the filesystem must be committed. A refused or uncertain call
    /// leaves the in-flight receipt; the next run observes the outcome afresh.
    #[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
    pub(crate) fn destroy_first(
        &self,
        before: &crate::birth_runtime::Records,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        self.recheck(authorize)?;
        let object = self
            .objects
            .first()
            .ok_or_else(|| Error("no retained Root target to delete".into()))?;
        let top = self.top.directory()?;
        let name = Path::new(&object.path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error("Root target literal name".into()))?
            .to_owned();
        let id = object.identity["id"]
            .as_u64()
            .ok_or_else(|| Error("Root target subvolume ID".into()))?;
        let mut expected = before.clone();
        require(
            expected.remove(&object.path).as_ref() == Some(&object.identity),
            "Root target differs from the complete before-inventory",
        )?;
        crate::root_retirement_delete_observation::inventory_delta(
            before,
            &expected,
            &object.identity,
        )?;
        let mut args = crate::root_retirement_first_delete::selector(id)?;
        let parent_before = files::identity(&object.parent.metadata()?);
        flags(top)?;
        authorize()?;
        self.recheck(authorize)?;
        require(
            // SAFETY: BTRFS_IOC_SNAP_DESTROY_V2 reads the vol_args_v2 buffer the request expects,
            // and `top` stays open.
            unsafe {
                libc::ioctl(
                    top.as_raw_fd(),
                    0x5000943fu64 as libc::c_ulong,
                    args.as_mut_ptr(),
                )
            } == 0,
            "online exact-ID Root target deletion refused or uncertain; in-flight receipt retained",
        )?;
        let parent_after = files::identity(&object.parent.metadata()?);
        crate::root_retirement_delete_observation::parent_delta(
            parent_before,
            parent_after,
            &name,
        )?;
        crate::root_retirement_first_delete::absent(&object.parent, &name)?;
        require(
            // SAFETY: BTRFS_IOC_SYNC takes no argument.
            unsafe { libc::ioctl(top.as_raw_fd(), 0x9408 as libc::c_ulong) } == 0,
            "online Root target deletion durability uncertain; in-flight receipt retained",
        )?;
        let after = crate::root_retirement_kernel_inventory::query(top)?;
        crate::root_retirement_delete_observation::inventory_delta(
            before,
            &after,
            &object.identity,
        )?;
        self.guard.recheck()?;
        self.top.recheck()?;
        self.lock.recheck()?;
        authorize()?;
        Ok(value!({"role":object.role,"identity":object.identity}))
    }
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        let result = value!({"source":self.source,"targets":self.objects.iter().map(|object|
            value!({"role":object.role,"identity":object.identity,"readonly":object.readonly,
                "mount_id":object.mount})).collect::<Vec<_>>(), "execution_authorized":false});
        self.recheck(authorize)?;
        Ok(result)
    }
}
