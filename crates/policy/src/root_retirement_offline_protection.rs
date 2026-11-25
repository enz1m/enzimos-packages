// SPDX-License-Identifier: MIT
//! Protected configured subvolumes from the actual restored registered root.
//! Configuration data grants protection only; it cannot create execution actors.
use crate::{
    root_retirement_boot_artifacts::Restored, root_retirement_offline_catalog::Catalog,
    root_retirement_offline_control::Control, root_retirement_offline_scope::Mounts,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
const LIMIT: usize = 2 * 1024 * 1024;
const KEYS: &[&str] = &[
    "root_subvol",
    "home_subvol",
    "authority_subvol",
    "control_subvol",
];
fn flags(file: &File) -> Result<i32> {
    let flags = enzimos_platform::files::status_flags(&file);
    require(
        flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
        "original configured protection read-only descriptor required",
    )?;
    Ok(flags)
}
fn directory(file: &File, mount: u64, root: bool) -> Result<files::FileIdentity> {
    let m = file.metadata()?;
    require(
        m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o022 == 0
            && (!root || m.ino() == 256)
            && mount_identity::id(file.as_fd(), true)? == mount,
        "original protected configuration directory required",
    )?;
    Ok(files::identity(&m))
}
fn unmentioned(
    configuration: &Value,
    identities: &BTreeMap<String, Value>,
    targets: &Value,
) -> Result<()> {
    crate::storage::validate(configuration)?;
    let rows = targets
        .as_array()
        .filter(|rows| (1..=64).contains(&rows.len()))
        .ok_or_else(|| Error("configured protection target bound".into()))?;
    let retired = rows.last().unwrap()["path"]
        .as_str()
        .ok_or_else(|| Error("configured protection target root".into()))?;
    crate::identity::safe_id(retired)?;
    for key in KEYS {
        let path = configuration[*key].as_str().unwrap();
        let actual = identities
            .get(path)
            .ok_or_else(|| Error("original configured protection identity missing".into()))?;
        require(
            actual["path"] == path && actual["id"].as_u64().is_some_and(|id| id >= 256),
            "original configured protection identity mismatch",
        )?;
        crate::identity::uuid(actual["uuid"].as_str().unwrap_or(""))?;
        require(
            path != retired
                && !path.starts_with(&format!("{retired}/"))
                && rows.iter().all(|row| {
                    row["path"] != path
                        && row["id"] != actual["id"]
                        && row["uuid"] != actual["uuid"]
                }),
            "original configured root, home, authority or control protects retirement target",
        )?;
    }
    Ok(())
}
struct Root {
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    identity: Value,
    readonly: bool,
}
pub struct Protection<'a, 's> {
    control: &'a Control<'a, 's>,
    mounts: &'a Mounts<'s>,
    catalog: &'a Catalog<'a, 's>,
    boot: &'a Restored<'a, 's>,
    source: String,
    roots: BTreeMap<String, Root>,
    etc: File,
    etc_epoch: files::FileIdentity,
    etc_flags: i32,
    enzimos: File,
    enzimos_epoch: files::FileIdentity,
    enzimos_flags: i32,
    configuration_file: File,
    configuration_epoch: files::FileIdentity,
    configuration_flags: i32,
    bytes: Vec<u8>,
    configuration: Value,
    filesystem: Value,
    mount: u64,
}
impl<'a, 's> Protection<'a, 's> {
    pub(crate) fn require_original_actors(
        &self,
        catalog: &Catalog<'a, 's>,
        mounts: &Mounts<'s>,
        loaders: &crate::root_retirement_offline_loaders::Loaders<'a, 's>,
    ) -> Result<()> {
        require(
            std::ptr::eq(self.catalog, catalog) && std::ptr::eq(self.mounts, mounts),
            "original configured protection belongs to another catalog or mount actor",
        )?;
        loaders.require_original_boot(self.boot)?;
        self.recheck()
    }
    pub fn observe(
        control: &'a Control<'a, 's>,
        mounts: &'a Mounts<'s>,
        catalog: &'a Catalog<'a, 's>,
        boot: &'a Restored<'a, 's>,
    ) -> Result<Self> {
        control.require_original_mounts(mounts)?;
        catalog.require_original_control(control)?;
        boot.require_original_control(control)?;
        let source = boot.previous_root()?;
        let top = mounts.original_top()?;
        let mount = mount_identity::id(top.as_fd(), true)?;
        let source_file = files::directory_relative(top, Path::new(&source), Some(0))?;
        directory(&source_file, mount, true)?;
        let (source_identity, _) = crate::subvolume::observe(source_file.as_fd(), &source)?;
        catalog.require_registered_root(&source_identity)?;
        let etc = files::directory_relative(&source_file, Path::new("etc"), Some(0))?;
        let enzimos = files::directory_relative(&etc, Path::new("enzimos"), Some(0))?;
        let configuration_file = files::open_relative(&enzimos, Path::new("storage.json"))?;
        let bytes = files::read_file(&configuration_file, LIMIT, Some(0), true)?;
        let configuration = json::decode(&bytes, LIMIT)?;
        crate::storage::validate(&configuration)?;
        let filesystem = mounts.filesystem_binding()?["filesystem_uuid"].clone();
        require(
            configuration["filesystem_uuid"] == filesystem
                && configuration["root_subvol"] == source
                && configuration["control_subvol"] == control.evidence()?["identity"]["path"],
            "restored previous root configuration differs from actual filesystem, source or control",
        )?;
        let mut roots = BTreeMap::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut uuids = std::collections::BTreeSet::new();
        for key in KEYS {
            let name = configuration[*key].as_str().unwrap();
            let file = files::directory_relative(top, Path::new(name), Some(0))?;
            let epoch = directory(&file, mount, true)?;
            let (identity, readonly) = crate::subvolume::observe(file.as_fd(), name)?;
            require(
                ids.insert(identity["id"].as_u64().unwrap())
                    && uuids.insert(identity["uuid"].as_str().unwrap().to_owned())
                    && crate::filesystem::observe(file.as_fd())?["filesystem_uuid"] == filesystem,
                "configured protected subvolumes alias or cross filesystem",
            )?;
            roots.insert(
                name.into(),
                Root {
                    flags: flags(&file)?,
                    file,
                    epoch,
                    identity,
                    readonly,
                },
            );
        }
        require(
            roots[&source].identity == source_identity,
            "original selected source root changed during configuration admission",
        )?;
        let metadata = configuration_file.metadata()?;
        require(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o022 == 0
                && mount_identity::id(configuration_file.as_fd(), true)? == mount,
            "original protected single-link storage configuration required",
        )?;
        let result = Self {
            control,
            mounts,
            catalog,
            boot,
            source,
            roots,
            etc_epoch: directory(&etc, mount, false)?,
            etc_flags: flags(&etc)?,
            etc,
            enzimos_epoch: directory(&enzimos, mount, false)?,
            enzimos_flags: flags(&enzimos)?,
            enzimos,
            configuration_epoch: files::identity(&metadata),
            configuration_flags: flags(&configuration_file)?,
            configuration_file,
            bytes,
            configuration,
            filesystem,
            mount,
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        self.control.require_original_mounts(self.mounts)?;
        self.catalog.require_original_control(self.control)?;
        self.boot.require_original_control(self.control)?;
        require(
            self.boot.previous_root()? == self.source,
            "original selected configuration root changed",
        )?;
        let top = self.mounts.original_top()?;
        require(
            self.mounts.filesystem_binding()?["filesystem_uuid"] == self.filesystem,
            "original protection filesystem changed",
        )?;
        for (name, root) in &self.roots {
            let named = files::directory_relative(top, Path::new(name), Some(0))?;
            require(
                directory(&root.file, self.mount, true)? == root.epoch
                    && directory(&named, self.mount, true)? == root.epoch
                    && flags(&root.file)? == root.flags,
                "original configured subvolume replaced, changed or covered",
            )?;
            for file in [&root.file, &named] {
                require(
                    crate::subvolume::observe(file.as_fd(), name)?
                        == (root.identity.clone(), root.readonly)
                        && crate::filesystem::observe(file.as_fd())?["filesystem_uuid"]
                            == self.filesystem,
                    "original configured subvolume kernel identity changed",
                )?;
            }
        }
        self.catalog
            .require_registered_root(&self.roots[&self.source].identity)?;
        let etc =
            files::directory_relative(&self.roots[&self.source].file, Path::new("etc"), Some(0))?;
        let enzimos = files::directory_relative(&self.etc, Path::new("enzimos"), Some(0))?;
        require(
            directory(&self.etc, self.mount, false)? == self.etc_epoch
                && directory(&etc, self.mount, false)? == self.etc_epoch
                && flags(&self.etc)? == self.etc_flags
                && directory(&self.enzimos, self.mount, false)? == self.enzimos_epoch
                && directory(&enzimos, self.mount, false)? == self.enzimos_epoch
                && flags(&self.enzimos)? == self.enzimos_flags,
            "original storage configuration ancestry replaced or changed",
        )?;
        let named = files::open_relative(&self.enzimos, Path::new("storage.json"))?;
        require(
            files::identity(&self.configuration_file.metadata()?) == self.configuration_epoch
                && files::identity(&named.metadata()?) == self.configuration_epoch
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.configuration_file.as_fd(), true)? == self.mount
                && flags(&self.configuration_file)? == self.configuration_flags
                && files::read_file(&self.configuration_file, LIMIT, Some(0), true)? == self.bytes
                && files::identity(&self.configuration_file.metadata()?)
                    == self.configuration_epoch,
            "original storage configuration replaced or changed",
        )?;
        self.control.require_original_mounts(self.mounts)
    }
    pub fn require_unmentioned(
        &self,
        targets: &crate::root_retirement_offline_targets::Targets<'a, 's>,
    ) -> Result<()> {
        self.recheck()?;
        targets.require_original_catalog(self.catalog)?;
        targets.require_original_mounts(self.mounts)?;
        let identities = self
            .roots
            .iter()
            .map(|(name, root)| (name.clone(), root.identity.clone()))
            .collect();
        unmentioned(&self.configuration, &identities, targets.rows()?)?;
        self.recheck()
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            serde_json::json!({"original_restored_registered_root_configuration_retained":true,"protected_subvolumes":self.roots.keys().collect::<Vec<_>>(),"execution_authorized":false}),
        )
    }
}
