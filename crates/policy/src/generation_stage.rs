// SPDX-License-Identifier: MIT
//! Dual kernel artifacts are retained and matched to the actual source root.
use crate::{boot_options, catalog, filesystem, identity, initramfs, subvolume};
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
pub(crate) const NAMES: [&str; 4] = [
    "vmlinuz-linux",
    "initramfs-linux.img",
    "vmlinuz-linux-lts",
    "initramfs-linux-lts.img",
];
/// Kernel artifacts staged for a new generation.
pub struct Stage {
    path: PathBuf,
    directory: File,
    directory_identity: Value,
    root: File,
    root_path: PathBuf,
    root_shape: Value,
    root_name: String,
    root_identity: Value,
    filesystem: Value,
    inputs: BTreeMap<String, (File, files::FileIdentity)>,
    kernels: BTreeMap<String, (File, files::FileIdentity)>,
    pub(crate) material: Value,
}
fn shape(directory: &File) -> Result<Value> {
    let m = directory.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
        "protected generation directory required",
    )?;
    Ok(
        value!({"inode":[m.dev(),m.ino(),m.mode(),m.uid(),m.gid()],"mount":mount_identity::id(directory.as_fd(),true)?}),
    )
}
pub(crate) fn inventory(root: &File) -> Result<String> {
    let result = process::run_with_fds(
        "/usr/bin/pacman",
        &["--root", "@fd:0", "-Q"],
        &[],
        Duration::from_secs(30),
        catalog::MAX_CATALOG,
        &[root.as_fd()],
    )?;
    require(
        result.status.success(),
        "generation source package inventory refused",
    )?;
    let body = std::str::from_utf8(&result.stdout)
        .map_err(|_| Error("generation source inventory encoding".into()))?
        .trim();
    require(
        !body.is_empty() && body.lines().count() <= 16384,
        "generation source package inventory bound",
    )?;
    Ok(body.into())
}
/// Require that the initramfs `body` contains modules only for `release`.
///
/// # Errors
///
/// Fails when it contains modules for another release.
pub fn initrd_release(body: &[u8], release: &str) -> Result<()> {
    identity::safe_id(release)?;
    let members = initramfs::inventory(body, &BTreeSet::new())?;
    let versions = members
        .keys()
        .filter_map(|name| {
            name.strip_prefix("usr/lib/modules/")
                .and_then(|tail| tail.split_once('/').map(|(release, _)| release))
        })
        .collect::<BTreeSet<_>>();
    require(
        versions == BTreeSet::from([release]),
        "initramfs module releases differ from actual source kernel",
    )
}
impl Stage {
    pub(crate) fn observe(
        path: &Path,
        generation: &str,
        kernels: &Value,
        options: &str,
        root: &File,
        root_path: &Path,
        expected_root: &Value,
    ) -> Result<Self> {
        identity::safe_id(generation)?;
        json::fields(kernels, "linux linux-lts")?;
        require(
            kernels["linux"] != kernels["linux-lts"],
            "generation source kernel flavors overlap",
        )?;
        let directory = files::directory(path, Some(0))?;
        require(
            directory.metadata()?.mode() & 0o7777 == 0o700,
            "private generation stage required",
        )?;
        let actual = files::directory_names(&directory, 6)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        require(
            actual == NAMES.into_iter().map(std::ffi::OsString::from).collect(),
            "generation stage member set differs",
        )?;
        let directory_identity = shape(&directory)?;
        let root_shape = shape(root)?;
        let filesystem = filesystem::observe(root.as_fd())?;
        require(
            filesystem::observe(directory.as_fd())? == filesystem,
            "generation stage must belong to the original source filesystem",
        )?;
        let root_name = boot_options::subvolume_from_options(options)?;
        let (object, readonly) = subvolume::observe(root.as_fd(), &root_name)?;
        let root_identity = value!({"path":root_name,"id":object["id"],"uuid":object["uuid"],"ownership":"not-established"});
        require(
            !readonly && root_identity == *expected_root,
            "generation source root differs from actual writable subvolume",
        )?;
        let mut inputs = BTreeMap::new();
        let mut source_kernels = BTreeMap::new();
        let mut rows = Vec::new();
        for flavor in ["linux", "linux-lts"] {
            let release = kernels[flavor]
                .as_str()
                .ok_or_else(|| Error("generation kernel release type".into()))?;
            identity::safe_id(release)?;
            let kernel_name = format!("usr/lib/modules/{release}/vmlinuz");
            let kernel = files::open_relative(root, Path::new(&kernel_name))?;
            require(
                mount_identity::id(kernel.as_fd(), true)?
                    == mount_identity::id(root.as_fd(), true)?,
                "generation source kernel crosses another mount",
            )?;
            let kernel_identity = files::identity(&kernel.metadata()?);
            let kernel_hash = stream_copy::hash_borrowed(&kernel, 128 * 1024 * 1024, Some(0))?;
            for name in [
                format!("vmlinuz-{flavor}"),
                format!("initramfs-{flavor}.img"),
            ] {
                let input = files::open_relative(&directory, Path::new(&name))?;
                let before = files::identity(&input.metadata()?);
                require(
                    mount_identity::id(input.as_fd(), true)?
                        == enzimos_platform::json::unsigned(&directory_identity["mount"])?,
                    "generation stage member crosses another mount",
                )?;
                let (bytes, sha) = stream_copy::hash_borrowed(&input, 128 * 1024 * 1024, Some(0))?;
                require(bytes > 0, "generation stage member empty")?;
                if name.starts_with("vmlinuz-") {
                    require(
                        (bytes, sha.clone()) == kernel_hash,
                        "staged kernel differs from source module image",
                    )?;
                } else {
                    initrd_release(
                        &files::read_file(&input, 128 * 1024 * 1024, Some(0), true)?,
                        release,
                    )?;
                }
                rows.push(value!({"name":name,"bytes":bytes,"sha256":sha}));
                inputs.insert(name, (input, before));
            }
            source_kernels.insert(kernel_name, (kernel, kernel_identity));
        }
        let material = value!({"kernels":kernels,"options":boot_options::generation_options(options,generation)?,"files":rows,"root_identity":root_identity,"inventory_sha256":json::sha256(inventory(root)?.as_bytes())});
        catalog::material(&material, generation)?;
        let this = Self {
            path: path.into(),
            directory,
            directory_identity,
            root: root.try_clone()?,
            root_path: root_path.into(),
            root_shape,
            root_name,
            root_identity,
            filesystem,
            inputs,
            kernels: source_kernels,
            material,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        require(
            shape(&self.directory)? == self.directory_identity
                && shape(&files::directory(&self.path, Some(0))?)? == self.directory_identity,
            "original generation stage replaced or remounted",
        )?;
        require(
            shape(&self.root)? == self.root_shape
                && shape(&files::directory(&self.root_path, Some(0))?)? == self.root_shape,
            "original named generation source root replaced or remounted",
        )?;
        let actual = files::directory_names(&self.directory, 6)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        require(
            actual == self.inputs.keys().map(std::ffi::OsString::from).collect(),
            "original stage member set changed",
        )?;
        let (object, readonly) = subvolume::observe(self.root.as_fd(), &self.root_name)?;
        require(
            !readonly
                && value!({"path":self.root_name,"id":object["id"],"uuid":object["uuid"],"ownership":"not-established"})
                    == self.root_identity
                && filesystem::observe(self.root.as_fd())? == self.filesystem
                && json::sha256(inventory(&self.root)?.as_bytes())
                    == self.material["inventory_sha256"],
            "original generation source root or package inventory changed",
        )?;
        for (parent, members) in [(&self.directory, &self.inputs), (&self.root, &self.kernels)] {
            let mount = mount_identity::id(parent.as_fd(), true)?;
            for (name, (file, before)) in members {
                let named = files::open_relative(parent, Path::new(name))?;
                require(
                    files::identity(&file.metadata()?) == *before
                        && files::identity(&named.metadata()?) == *before
                        && mount_identity::id(file.as_fd(), true)? == mount
                        && mount_identity::id(named.as_fd(), true)? == mount,
                    "original generation artifact replaced or changed",
                )?;
            }
        }
        Ok(())
    }
    pub(crate) fn filesystem_uuid(&self) -> &Value {
        &self.filesystem["filesystem_uuid"]
    }
    /// Copy the staged artifacts into `destination`.
    ///
    /// # Errors
    ///
    /// Fails when an artifact changed or cannot be written.
    pub fn copy(&self, destination: &File) -> Result<()> {
        self.copy_authorized(destination, &mut || Ok(()))
    }
    pub(crate) fn copy_authorized(
        &self,
        destination: &File,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        authorize()?;
        self.recheck()?;
        for row in enzimos_platform::json::array(&self.material["files"])? {
            let name = enzimos_platform::json::string(&row["name"])?;
            let mut file = self.inputs[name].0.try_clone()?;
            stream_copy::verified_with_checkpoint(
                &mut file,
                destination,
                name,
                enzimos_platform::json::unsigned(&row["bytes"])?,
                enzimos_platform::json::string(&row["sha256"])?,
                0,
                &mut || {
                    authorize()?;
                    self.recheck()
                },
            )?;
        }
        authorize()?;
        self.recheck()
    }
}
