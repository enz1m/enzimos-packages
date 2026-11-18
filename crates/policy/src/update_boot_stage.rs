// SPDX-License-Identifier: MIT
//! Fresh staging copies retain the exact original boot publication and directory.
use crate::{
    boot_volume::{Artifact, Volume},
    catalog, generation_stage, operation, subvolume,
    update_plan::Plan,
    update_resources,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};
fn shape(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o700,
        "private update boot stage required",
    )?;
    Ok(
        value!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
pub struct Stage {
    pub path: PathBuf,
    directory: File,
    identity: Value,
    files: BTreeMap<String, (File, files::FileIdentity)>,
    rows: Value,
}
impl Stage {
    pub fn capture(plan: &Plan, id: &str, lock: &files::Lock) -> Result<Self> {
        Self::capture_authorized(plan, id, lock, &mut || lock.recheck())
    }
    pub fn capture_authorized(
        plan: &Plan,
        id: &str,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        authorize()?;
        lock.recheck()?;
        crate::identity::safe_id(id)?;
        plan.recheck_before_mutation()?;
        let document = plan.document();
        let volume = Volume::observe()?;
        volume.writable()?;
        let root = files::directory(Path::new("/"), Some(0))?;
        let (root_object, readonly) = subvolume::observe(
            root.as_fd(),
            document["storage"]["root_subvol"].as_str().unwrap(),
        )?;
        require(!readonly, "update live root is read-only")?;
        let state = files::directory(Path::new(operation::STATE), Some(0))?;
        let last = files::optional_relative(&state, Path::new("last-update.json"))?;
        let mut last_identity = None;
        let mut last_mount = None;
        let mut source = PathBuf::new();
        let mut expected = None;
        if let Some(file) = &last {
            last_identity = Some(files::identity(&file.metadata()?));
            last_mount = Some(mount_identity::id(file.as_fd(), true)?);
            require(
                file.metadata()?.mode() & 0o7777 == 0o600
                    && last_mount == Some(mount_identity::id(state.as_fd(), true)?),
                "unsafe or independently mounted last-update receipt",
            )?;
            let last = json::decode(
                &files::read_file(file, catalog::MAX_CATALOG, Some(0), true)?,
                catalog::MAX_CATALOG,
            )?;
            json::fields(&last, "generation kernels artifacts status")?;
            require(
                last["status"] == "prepared-not-rebooted"
                    && last["kernels"] == document["current_kernels"],
                "last update does not describe the actual installed kernels",
            )?;
            let generation = last["generation"]
                .as_str()
                .ok_or_else(|| Error("last update generation missing".into()))?;
            crate::identity::safe_id(generation)?;
            let transaction = catalog::Transaction::begin()?;
            let record = transaction.data["generations"]
                .get(generation)
                .ok_or_else(|| Error("last update generation unregistered".into()))?;
            require(
                record["state"] == "ready"
                    && record["material"]["kernels"] == document["current_kernels"]
                    && record["material"]["root"]["uuid"] == root_object["uuid"]
                    && record["material"]["root"]["id"] == root_object["id"]
                    && record["material"]["inventory_sha256"] == document["inventory_sha256"]
                    && last["artifacts"] == record["material"]["files"],
                "last update source differs from live root",
            )?;
            expected = Some(record["material"]["files"].clone());
            source = PathBuf::from(format!("enzimos/generations/{generation}"));
            transaction.recheck()?;
        }
        let mut artifacts = BTreeMap::<String, Artifact>::new();
        let mut rows = Vec::new();
        let mut total = 0u64;
        for name in generation_stage::NAMES {
            let artifact = volume.artifact(&source.join(name), 128 * 1024 * 1024)?;
            total = total
                .checked_add(artifact.bytes)
                .ok_or_else(|| Error("update artifact size overflow".into()))?;
            rows.push(value!({"name":name,"bytes":artifact.bytes,"sha256":artifact.sha}));
            artifacts.insert(name.into(), artifact);
        }
        if let Some(expected) = expected {
            require(
                value!(&rows) == expected,
                "retained last update artifacts differ",
            )?;
        }
        let transaction = catalog::Transaction::begin()?;
        update_resources::check(
            transaction.data["generations"].as_object().unwrap().len(),
            update_resources::transient("module-views", &document["storage"]["filesystem_uuid"])?,
            update_resources::transient("boot-stage", &document["storage"]["filesystem_uuid"])?,
            update_resources::available(&root)?,
            update_resources::available(&volume.directory)?,
            total,
            crate::secure_boot::configured()?,
        )?;
        transaction.recheck()?;
        drop(transaction);
        let verify_last = || -> Result<()> {
            if let (Some(held), Some(identity)) = (&last, &last_identity) {
                let named = files::open_relative(&state, Path::new("last-update.json"))?;
                require(
                    files::identity(&held.metadata()?) == *identity
                        && files::identity(&named.metadata()?) == *identity
                        && Some(mount_identity::id(held.as_fd(), true)?) == last_mount
                        && Some(mount_identity::id(named.as_fd(), true)?) == last_mount,
                    "original last-update receipt changed",
                )?;
            } else {
                require(
                    files::optional_relative(&state, Path::new("last-update.json"))?.is_none(),
                    "last-update receipt appeared",
                )?;
            }
            for artifact in artifacts.values() {
                artifact.recheck()?;
            }
            plan.admitted().recheck()?;
            volume.writable()
        };
        verify_last()?;
        let parent = Path::new(operation::STATE).join("boot-stage");
        authorize()?;
        lock.recheck()?;
        files::ensure_directory(&parent, 0o755, 0)
            .map_err(|error| Error(format!("update boot-stage parent: {error}")))?;
        authorize()?;
        let path = parent.join(id);
        let directory = files::create_directory(&path, 0o700, 0)?;
        let identity = shape(&directory)?;
        require(
            crate::filesystem::observe(directory.as_fd())?["filesystem_uuid"]
                == document["storage"]["filesystem_uuid"],
            "new boot stage belongs to a foreign filesystem",
        )?;
        for (name, artifact) in &artifacts {
            verify_last()?;
            stream_copy::verified_with_checkpoint(
                &mut artifact.file.try_clone()?,
                &directory,
                name,
                artifact.bytes,
                &artifact.sha,
                0,
                &mut || {
                    authorize()?;
                    lock.recheck()?;
                    verify_last()
                },
            )?;
        }
        verify_last()?;
        let mut members = BTreeMap::new();
        for name in generation_stage::NAMES {
            let file = files::open_relative(&directory, Path::new(name))?;
            members.insert(
                name.to_owned(),
                (file.try_clone()?, files::identity(&file.metadata()?)),
            );
        }
        let stage = Self {
            path,
            directory,
            identity,
            files: members,
            rows: value!(rows),
        };
        stage.recheck_original()?;
        let expected_root = value!({"path":document["storage"]["root_subvol"],"id":root_object["id"],"uuid":root_object["uuid"],"ownership":"not-established"});
        let source = generation_stage::Stage::observe(
            &stage.path,
            id,
            &document["current_kernels"],
            document["options"].as_str().unwrap(),
            &root,
            Path::new("/"),
            &expected_root,
        )?;
        source.recheck()?;
        drop(source);
        // The coordinator retains its original lock across this entire capture.
        require(
            lock.as_file().metadata()?.len() == 0,
            "unexpected operation lock body",
        )?;
        authorize()?;
        lock.recheck()?;
        Ok(stage)
    }
    pub fn directory(&self) -> &File {
        &self.directory
    }
    pub fn evidence(&self) -> Value {
        value!({"directory":self.identity,"files":self.rows})
    }
    pub fn recheck_directory(&self) -> Result<()> {
        let named = files::directory(&self.path, Some(0))?;
        require(
            shape(&named)? == self.identity && shape(&self.directory)? == self.identity,
            "original update stage directory replaced",
        )?;
        let names = files::directory_names(&self.directory, 6)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        require(
            names
                == generation_stage::NAMES
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect(),
            "update stage member set differs",
        )
    }
    pub fn recheck_original(&self) -> Result<()> {
        self.recheck_directory()?;
        for (name, (file, identity)) in &self.files {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&file.metadata()?) == *identity
                    && files::identity(&named.metadata()?) == *identity
                    && mount_identity::id(file.as_fd(), true)?
                        == self.identity["mount"].as_u64().unwrap()
                    && mount_identity::id(named.as_fd(), true)?
                        == self.identity["mount"].as_u64().unwrap(),
                "original update stage file replaced",
            )?;
        }
        Ok(())
    }
}
