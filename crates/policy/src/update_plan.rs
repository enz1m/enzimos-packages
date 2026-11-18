// SPDX-License-Identifier: MIT
//! A fresh native apply plan measures actual Root inputs under the operation lock.
use crate::{
    authority_identity, boot_entries, boot_options, boot_volume::Volume, catalog, generation_stage,
    identity, operation, root_rebind_boot, transition_idle::Snapshot, update_cohort_root::Admitted,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, fs::File, path::Path, time::Duration};
pub fn kernel_listing(body: &str) -> Result<String> {
    require(
        body.len() <= 2 * 1024 * 1024 && !body.contains('\0'),
        "kernel package listing bound",
    )?;
    let releases = body
        .lines()
        .filter_map(|line| {
            line.strip_prefix("/usr/lib/modules/")
                .and_then(|tail| tail.strip_suffix("/vmlinuz"))
        })
        .collect::<Vec<_>>();
    require(releases.len() == 1, "installed kernel release ambiguous")?;
    Ok(identity::safe_id(releases[0])?.into())
}
pub fn installed_kernels() -> Result<Value> {
    let mut result = value!({});
    for flavor in ["linux", "linux-lts"] {
        let body = operation::query(
            "/usr/bin/pacman",
            &["-Qlq", flavor],
            Duration::from_secs(30),
            2 * 1024 * 1024,
            &[0],
        )?;
        result[flavor] = value!(kernel_listing(
            std::str::from_utf8(&body).map_err(|_| Error("kernel listing encoding".into()))?
        )?);
    }
    require(
        result["linux"] != result["linux-lts"],
        "installed kernel flavors overlap",
    )?;
    Ok(result)
}
pub fn options(body: &str, root: &str) -> Result<String> {
    require(
        body.len() <= 65536 && !body.contains('\0'),
        "actual kernel options bound",
    )?;
    let mut words = Vec::new();
    let mut generation = 0;
    for word in body.split_whitespace() {
        require(
            !word.starts_with("init=")
                && !word.starts_with("rdinit=")
                && !word.starts_with("enzimos.staged=")
                && !word.starts_with("enzimos.run=")
                && !word.starts_with("enzimos.recovery="),
            "live update requires regular installed boot",
        )?;
        if let Some(marker) = word.strip_prefix("enzimos.generation=") {
            identity::safe_id(marker)?;
            generation += 1;
        } else {
            words.push(word);
        }
    }
    let result = words.join(" ");
    require(
        generation <= 1
            && result.len() <= 4096
            && boot_options::subvolume_from_options(&result)? == root,
        "live update options differ from actual root",
    )?;
    Ok(result)
}
pub struct Plan {
    actor: crate::update_actor::Actor,
    snapshot: Snapshot,
    admitted: Admitted,
    root: File,
    image: File,
    image_identity: files::FileIdentity,
    document: Value,
    registry: Value,
    volume: Volume,
    texts: BTreeMap<String, String>,
    boot_files: Vec<crate::boot_volume::Artifact>,
}
impl Plan {
    pub fn observe_locked(_lock: &files::Lock) -> Result<Self> {
        crate::namespaces::initial()?;
        let snapshot = Snapshot::online()?;
        require(
            files::optional_relative(
                &files::directory(Path::new("/var/lib/pacman"), Some(0))?,
                Path::new("db.lck"),
            )?
            .is_none(),
            "pacman transaction already active",
        )?;
        let admitted = Admitted::observe()?;
        require(
            admitted.guard().configuration == snapshot.guard.configuration,
            "update storage changed during admission",
        )?;
        let transaction = catalog::Transaction::begin()?;
        let registry = transaction.data.clone();
        require(
            registry["generations"].as_object().unwrap().len() + 2
                <= crate::update_resources::BOOT_GENERATIONS,
            "two fresh update generations require explicit retention review",
        )?;
        let volume = Volume::observe()?;
        volume.writable()?;
        root_rebind_boot::generations(&volume, &registry)?;
        let texts = root_rebind_boot::texts(&volume)?;
        let mut boot_files = Vec::new();
        for (name, text) in &texts {
            let artifact = volume.artifact(Path::new(name), boot_entries::MAX_TEXT as u64)?;
            require(
                files::read_file(&artifact.file, boot_entries::MAX_TEXT, Some(0), true)?
                    == text.as_bytes(),
                "boot metadata changed while retaining plan",
            )?;
            boot_files.push(artifact);
        }
        for (name, row) in registry["generations"].as_object().unwrap() {
            boot_files.push(volume.artifact(
                Path::new(&format!("enzimos/generations/{name}/READY.json")),
                catalog::MAX_CATALOG as u64,
            )?);
            for file in row["material"]["files"].as_array().unwrap() {
                boot_files.push(volume.artifact(
                    Path::new(&format!(
                        "enzimos/generations/{name}/{}",
                        file["name"].as_str().unwrap()
                    )),
                    128 * 1024 * 1024,
                )?);
            }
        }
        let entries = texts
            .iter()
            .filter_map(|(name, body)| {
                name.strip_prefix("loader/entries/")
                    .map(|key| (key.to_owned(), body.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        for row in registry["generations"].as_object().unwrap().values() {
            require(
                boot_entries::fingerprint_entries(row, &entries, &texts["limine/limine.conf"])?
                    == row["entry_fingerprints"],
                "ready generation boot fingerprint changed",
            )?;
        }
        transaction.recheck()?;
        drop(transaction);
        let root = files::directory(Path::new("/"), Some(0))?;
        let actor = crate::update_actor::Actor::current()?;
        let image = actor.image()?.try_clone()?;
        let image_identity = files::identity(&image.metadata()?);
        let bytes = files::read_file(&image, 32 * 1024 * 1024, Some(0), true)?;
        require(
            bytes.starts_with(b"\x7fELF"),
            "native update planner image required",
        )?;
        let cmdline = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
        let document = value!({"schema":2,"implementation_image":actor.path(),"operation":"update-apply","boot_id":operation::boot_id()?,
            "storage":snapshot.guard.configuration,"inventory_sha256":json::sha256(generation_stage::inventory(&root)?.as_bytes()),
            "current_kernels":installed_kernels()?,"target_kernels":admitted.source().kernels(),
            "options":options(std::str::from_utf8(&cmdline).map_err(|_| Error("kernel options encoding".into()))?,
                snapshot.guard.configuration["root_subvol"].as_str().unwrap())?,
            "authority":authority_identity::observe(&snapshot.guard)?,"cohort_sha256":admitted.source().raw_sha256(),
            "implementation_sha256":json::sha256(&bytes)});
        let plan = Self {
            actor,
            snapshot,
            admitted,
            root,
            image,
            image_identity,
            document,
            registry,
            volume,
            texts,
            boot_files,
        };
        plan.recheck_before_mutation()?;
        Ok(plan)
    }
    pub fn document(&self) -> &Value {
        &self.document
    }
    pub fn admitted(&self) -> &Admitted {
        &self.admitted
    }
    pub fn image(&self) -> &File {
        &self.image
    }
    pub fn recheck_before_mutation(&self) -> Result<()> {
        self.actor.recheck()?;
        self.snapshot.recheck()?;
        self.admitted.recheck()?;
        self.volume.writable()?;
        for file in &self.boot_files {
            file.recheck()?;
        }
        let transaction = catalog::Transaction::begin()?;
        require(
            transaction.data == self.registry
                && root_rebind_boot::texts(&self.volume)? == self.texts,
            "planned generation registry or boot text changed",
        )?;
        root_rebind_boot::generations(&self.volume, &transaction.data)?;
        let parent = files::directory(Path::new(self.actor.path()).parent().unwrap(), Some(0))?;
        require(
            files::identity(&self.image.metadata()?) == self.image_identity
                && files::identity(
                    &files::open_relative(
                        &parent,
                        Path::new(Path::new(self.actor.path()).file_name().unwrap()),
                    )?
                    .metadata()?,
                ) == self.image_identity
                && json::sha256(generation_stage::inventory(&self.root)?.as_bytes())
                    == self.document["inventory_sha256"]
                && installed_kernels()? == self.document["current_kernels"]
                && authority_identity::observe(&self.snapshot.guard)? == self.document["authority"]
                && operation::boot_id()? == self.document["boot_id"],
            "original native update plan changed",
        )?;
        transaction.recheck()?;
        self.admitted.recheck()?;
        self.snapshot.recheck()
    }
}
