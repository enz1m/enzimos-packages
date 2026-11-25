// SPDX-License-Identifier: MIT
//! One original Root boot retirement. No journal replay or cold adoption.
use super::*;
use crate::boot_volume::{ReplacedArtifact, RetiredArtifact};
use enzimos_platform::{
    created_directory,
    named_retirement::{Quarantined, Removed},
    publication,
    receipt_registry::Registry,
};
use std::path::PathBuf;
/// Implemented by trusted native code retaining the original backend ledger.
/// No wire object constructs that ledger or the original Root Context.
pub trait References {
    /// Require that no backend record mentions `generation`.
    ///
    /// # Errors
    ///
    /// Fails when one does.
    fn require_unmentioned(&self, generation: &str) -> Result<()>;
}
struct Runtime<'a, 'g, 'r, 'u> {
    context: Context<'a, 'g>,
    references: &'r dyn References,
    authorize: &'u mut dyn FnMut() -> Result<()>,
    registry: Registry,
    record: Value,
    intent: Value,
    after: Value,
    published: bool,
    catalog_done: bool,
    retired: BTreeMap<PathBuf, RetiredArtifact>,
    bios: Option<ReplacedArtifact>,
    directory: Option<(Directory, Removed)>,
}
impl Runtime<'_, '_, '_, '_> {
    fn barrier(&mut self) -> Result<()> {
        (self.authorize)()?;
        self.context.guard.recheck()?;
        self.context.lock.recheck()?;
        self.context.volume.writable()?;
        self.context.pins.recheck()?;
        self.references
            .require_unmentioned(&self.context.generation)?;
        require(
            firmware()? == self.context.firmware && command_line()? == self.context.command_line,
            "original actual firmware/current boot changed during retirement",
        )?;
        (self.authorize)()
    }
    fn verify(&mut self) -> Result<()> {
        self.barrier()?;
        let c = &self.context;
        c.transaction.recheck()?;
        require(
            c.transaction.config == c.guard.configuration
                && c.guard.backup_root_binding()? == c.original["source"]
                && c.transaction.data
                    == if self.catalog_done {
                        self.after.clone()
                    } else {
                        c.original["catalog"].clone()
                    },
            "original boot retirement source/catalog changed outside owned tombstone",
        )?;
        if self.published {
            c.idle
                .recheck_boot_retirement(&self.registry, &self.record)?;
        } else {
            c.idle.recheck()?;
        }
        for r in &c.reference_registries {
            r.recheck()?;
        }
        for j in &c.reference_journals {
            j.unchanged()?;
        }
        self.registry.recheck()?;
        for d in &c.directories {
            d.recheck(&c.volume)?;
        }
        for a in c.artifacts.values() {
            a.recheck()?;
        }
        if let Some(d) = &c.signed_inventory.directory {
            d.recheck(&c.volume)?;
        } else {
            require(
                matches!(std::fs::symlink_metadata(c.volume.path(Path::new("enzimos/secure-boot"))?),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "originally absent UKI directory appeared",
            )?;
        }
        if let Some(d) = &c.signed_inventory.autodiscovery {
            d.recheck(&c.volume)?;
            crate::boot_retirement_references::external_autodiscovery(&d.names)?;
        } else {
            require(
                matches!(std::fs::symlink_metadata(c.volume.path(Path::new("EFI/Linux"))?),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "originally absent EFI autodiscovery appeared",
            )?;
        }
        for a in c.signed_inventory.images.values() {
            a.recheck()?;
        }
        for v in &c.signed_inventory.verified {
            v.recheck_owned_retirements(&self.retired)?;
        }
        for a in self.retired.values() {
            a.recheck()?;
        }
        if let Some(b) = &self.bios {
            b.recheck()?;
        }
        if let Some((original, removed)) = &self.directory {
            removed.recheck()?;
            require(
                shape(&original.file)? == original.shape
                    && files::identity(&original.file.metadata()?)
                        == files::identity(&removed.descriptor()?.metadata()?)
                    && mount_identity::id(original.file.as_fd(), true)? == c.volume.unique,
                "original retired empty generation directory changed",
            )?;
        }
        require(
            root_rebind_boot::texts(&c.volume)? == c.texts,
            "original or known rewritten loader texts changed",
        )?;
        self.barrier()
    }
    fn persist(&mut self, next: Value) -> Result<()> {
        self.verify()?;
        let id = enzimos_platform::json::string(&self.intent["id"])?;
        crate::retirement_journal::validate(&next, id)?;
        require(
            next["intent"] == self.intent,
            "original immutable retirement intent changed",
        )?;
        let references = self.references;
        let generation = self.context.generation.clone();
        let guard = self.context.guard;
        let lock = self.context.lock;
        let authorize = &mut self.authorize;
        self.registry.publish(&json::canonical(&next)?, &mut || {
            guard.recheck()?;
            lock.recheck()?;
            references.require_unmentioned(&generation)?;
            authorize()
        })?;
        self.record = next;
        self.published = true;
        self.verify()
    }
    fn checkpoint(&mut self, next_step: usize, inflight: Option<usize>, phase: &str) -> Result<()> {
        let mut next = self.record.clone();
        next["phase"] = value!(phase);
        next["next_step"] = value!(next_step);
        next["inflight"] = value!(inflight);
        self.persist(next)
    }
    fn remove_artifact(&mut self, relative: &str, signed: bool) -> Result<()> {
        self.verify()?;
        let artifact = if signed {
            self.context.signed_inventory.images.get(relative)
        } else {
            self.context.artifacts.get(relative)
        }
        .ok_or_else(|| Error("original retirement artifact missing".into()))?;
        artifact.recheck()?;
        let path = artifact.path.clone();
        let rel = path
            .strip_prefix("/boot")
            .map_err(|_| Error("retirement artifact outside ESP".into()))?;
        let parent_relative = rel
            .parent()
            .ok_or_else(|| enzimos_platform::Error("missing parent".into()))?;
        let parent = self.context.volume.directory(parent_relative)?;
        let references = self.references;
        let generation = self.context.generation.clone();
        let guard = self.context.guard;
        let lock = self.context.lock;
        let authorize = &mut self.authorize;
        let mut fresh = || {
            guard.recheck()?;
            lock.recheck()?;
            references.require_unmentioned(&generation)?;
            authorize()
        };
        let artifact = if signed {
            self.context.signed_inventory.images.get(relative)
        } else {
            self.context.artifacts.get(relative)
        }
        .ok_or_else(|| Error("original retirement artifact missing before mutation".into()))?;
        let quarantined = artifact.quarantine_original(&parent, 256 * 1024 * 1024, &mut fresh)?;
        let removed = quarantined.unlink(&mut fresh)?;
        let artifact = if signed {
            self.context.signed_inventory.images.remove(relative)
        } else {
            self.context.artifacts.remove(relative)
        }
        .ok_or_else(|| Error("original artifact retirement cannot replay".into()))?;
        let retired = artifact.into_retired(removed)?;
        let leaf = path
            .file_name()
            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?;
        if signed {
            let directory = self
                .context
                .signed_inventory
                .directory
                .as_mut()
                .ok_or_else(|| Error("original signed directory missing".into()))?;
            require(
                directory.names.remove(leaf),
                "owned UKI directory original member missing",
            )?;
        } else {
            let parent = parent_relative
                .to_str()
                .ok_or_else(|| enzimos_platform::Error("path encoding".into()))?;
            let directory = self
                .context
                .directories
                .iter_mut()
                .find(|d| d.relative == parent)
                .ok_or_else(|| Error("original owned artifact directory missing".into()))?;
            require(
                directory.names.remove(leaf),
                "owned original directory member missing",
            )?;
            self.context.texts.remove(relative);
        }
        require(
            self.retired.insert(path, retired).is_none(),
            "original artifact cannot retire twice",
        )?;
        self.verify()
    }
    fn rewrite_bios(&mut self) -> Result<()> {
        self.verify()?;
        require(self.bios.is_none(), "original BIOS rewrite cannot replay")?;
        let name = "limine/limine.conf";
        let text = plan::without_bios(&self.context.texts[name], &self.context.generation)?;
        let original = self.context.artifacts[name].file.try_clone()?;
        let path = self.context.volume.path(Path::new(name))?;
        let references = self.references;
        let generation = self.context.generation.clone();
        let guard = self.context.guard;
        let lock = self.context.lock;
        let authorize = &mut self.authorize;
        let mut fresh = || {
            guard.recheck()?;
            lock.recheck()?;
            references.require_unmentioned(&generation)?;
            authorize()
        };
        let pending =
            publication::Prepared::write_authorized(&path, text.as_bytes(), 0, &mut fresh)?;
        pending.require_original(&original)?;
        self.context.artifacts[name].require_original_publication(&pending)?;
        let committed = pending.commit_retained_authorized(true, &mut fresh)?;
        let artifact = self
            .context
            .artifacts
            .remove(name)
            .ok_or_else(|| Error("original BIOS artifact missing".into()))?;
        self.bios = Some(artifact.into_replaced(committed)?);
        self.context.texts.insert(name.into(), text);
        self.verify()
    }
    fn remove_directory(&mut self) -> Result<()> {
        self.verify()?;
        require(
            self.directory.is_none(),
            "original empty directory retirement cannot replay",
        )?;
        let relative = format!("enzimos/generations/{}", self.context.generation);
        let index = self
            .context
            .directories
            .iter()
            .position(|d| d.relative == relative)
            .ok_or_else(|| Error("original candidate directory missing".into()))?;
        let directory = &self.context.directories[index];
        require(
            directory.names.is_empty() && files::directory_is_empty(&directory.file)?,
            "candidate directory has unowned remaining members",
        )?;
        let file = directory.file.try_clone()?;
        let before = files::identity(&file.metadata()?);
        let parent = self
            .context
            .volume
            .directory(Path::new("enzimos/generations"))?;
        let references = self.references;
        let generation = self.context.generation.clone();
        let guard = self.context.guard;
        let lock = self.context.lock;
        let authorize = &mut self.authorize;
        let mut fresh = || {
            guard.recheck()?;
            lock.recheck()?;
            references.require_unmentioned(&generation)?;
            authorize()
        };
        let removed = Quarantined::enter_original(
            &parent,
            &file,
            Path::new(&generation),
            0,
            65536,
            before,
            &mut fresh,
        )?
        .unlink(&mut fresh)?;
        require(
            removed.before_epoch()? == before
                && files::identity(&file.metadata()?)
                    == files::identity(&removed.descriptor()?.metadata()?),
            "directory retirement differs from original empty description",
        )?;
        let directory = self.context.directories.remove(index);
        let parent_directory = self
            .context
            .directories
            .iter_mut()
            .find(|d| d.relative == "enzimos/generations")
            .ok_or_else(|| Error("original generations parent missing".into()))?;
        require(
            parent_directory.names.remove(&generation),
            "original generations member missing",
        )?;
        self.directory = Some((directory, removed));
        self.verify()
    }
    fn state(&self, step: &Value) -> Result<String> {
        let id = enzimos_platform::json::string(&step["id"])?;
        let absent = json::fingerprint(&value!({"absent":true}))?;
        match enzimos_platform::json::string(&step["kind"])? {
            "uefi-entry" => {
                let flavor = id
                    .strip_prefix("uefi-")
                    .ok_or_else(|| Error("fixed retirement UEFI role".into()))?;
                require(
                    matches!(flavor, "linux" | "linux-lts"),
                    "fixed retirement UEFI flavor",
                )?;
                let relative = format!(
                    "loader/entries/enzimos-{}-{flavor}.conf",
                    self.context.generation
                );
                if let Some(a) = self.context.artifacts.get(&relative) {
                    a.recheck()?;
                    plan::file_state(&a.sha)
                } else {
                    require(
                        self.retired
                            .contains_key(&self.context.volume.path(Path::new(&relative))?),
                        "UEFI absence lacks original retirement proof",
                    )?;
                    Ok(absent)
                }
            }
            "bios-menu" => Ok(plan::file_state(&json::sha256(
                self.context.texts["limine/limine.conf"].as_bytes(),
            ))?),
            "boot-file" => {
                let (relative, signed) = file_role(&self.context.generation, id)?;
                let a = if signed {
                    self.context.signed_inventory.images.get(&relative)
                } else {
                    self.context.artifacts.get(&relative)
                };
                if let Some(a) = a {
                    a.recheck()?;
                    plan::file_state(&a.sha)
                } else {
                    require(
                        self.retired.contains_key(
                            &self
                                .context
                                .volume
                                .path(Path::new(relative.trim_start_matches('/')))?,
                        ),
                        "file absence lacks original retirement proof",
                    )?;
                    Ok(absent)
                }
            }
            "boot-directory" => {
                if self.directory.is_some() {
                    Ok(absent)
                } else {
                    let relative = format!("enzimos/generations/{}", self.context.generation);
                    let d = self
                        .context
                        .directories
                        .iter()
                        .find(|d| d.relative == relative)
                        .ok_or_else(|| {
                            Error("original empty candidate directory missing".into())
                        })?;
                    d.recheck(&self.context.volume)?;
                    require(
                        d.names.is_empty(),
                        "candidate directory not empty at retirement step",
                    )?;
                    json::fingerprint(&value!({"absent":false,"members":[]}))
                }
            }
            "catalog" => json::fingerprint(&self.context.transaction.data),
            _ => Err(Error("non-boot retirement resource refused".into())),
        }
    }
    fn apply(&mut self, step: &Value) -> Result<()> {
        let id = enzimos_platform::json::string(&step["id"])?;
        match enzimos_platform::json::string(&step["kind"])? {
            "uefi-entry" => {
                let flavor = id
                    .strip_prefix("uefi-")
                    .ok_or_else(|| Error("fixed UEFI retirement role".into()))?;
                require(
                    matches!(flavor, "linux" | "linux-lts"),
                    "fixed UEFI retirement flavor",
                )?;
                self.remove_artifact(
                    &format!(
                        "loader/entries/enzimos-{}-{flavor}.conf",
                        self.context.generation
                    ),
                    false,
                )
            }
            "bios-menu" => self.rewrite_bios(),
            "boot-file" => {
                let (relative, signed) = file_role(&self.context.generation, id)?;
                self.remove_artifact(&relative, signed)
            }
            "boot-directory" => self.remove_directory(),
            "catalog" => {
                self.verify()?;
                require(
                    !self.catalog_done && self.directory.is_some(),
                    "catalog tombstone requires original completed resource retirement",
                )?;
                self.context.transaction.owned_mut()?.data = self.after.clone();
                self.barrier()?;
                let references = self.references;
                let generation = self.context.generation.clone();
                let guard = self.context.guard;
                let lock = self.context.lock;
                let authorize = &mut self.authorize;
                self.context
                    .transaction
                    .owned_mut()?
                    .commit_owned_authorized(&mut || {
                        guard.recheck()?;
                        lock.recheck()?;
                        references.require_unmentioned(&generation)?;
                        authorize()
                    })?;
                self.catalog_done = true;
                self.verify()
            }
            _ => Err(Error("non-boot retirement resource refused".into())),
        }
    }
}
fn file_role(generation: &str, id: &str) -> Result<(String, bool)> {
    if let Some(digest) = id.strip_prefix("uki-") {
        identity::sha(digest)?;
        return Ok((format!("/enzimos/secure-boot/{digest}.efi"), true));
    }
    let name = id
        .strip_prefix("file-")
        .ok_or_else(|| Error("fixed owned payload retirement role".into()))?;
    require(
        plan::MEMBERS.contains(&name),
        "unowned retirement payload refused",
    )?;
    Ok((format!("enzimos/generations/{generation}/{name}"), false))
}
pub(super) fn retire<'a, 'g: 'a>(
    mut context: Context<'a, 'g>,
    references: &dyn References,
    expected: &str,
    authorize: &mut dyn FnMut() -> Result<()>,
    progress: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Value> {
    identity::sha(expected)?;
    references.require_unmentioned(&context.generation)?;
    let (intent, after) = context.planned_intent(&mut || {
        references.require_unmentioned(&context.generation)?;
        authorize()
    })?;
    require(
        intent["intent_sha256"] == expected,
        "original reviewed retirement intent changed",
    )?;
    context.recheck(authorize)?;
    let index = context
        .reference_registries
        .iter()
        .position(|r| r.folder() == "boot-retirements")
        .ok_or_else(|| Error("original retirement registry missing".into()))?;
    let absent = context.reference_registries[index].originally_absent()?;
    let folder = Path::new(operation::CONTROL).join("boot-retirements");
    let leaf = format!("{}.json", enzimos_platform::json::string(&intent["id"])?);
    let registry = if absent {
        let created = created_directory::Created::create(
            context.guard.control(),
            Path::new("boot-retirements"),
            0,
            &mut || {
                references.require_unmentioned(&context.generation)?;
                authorize()
            },
        )?;
        created.require_parent(context.guard.control(), Path::new("boot-retirements"))?;
        created.into_receipt_registry(&folder, &leaf, &mut || {
            context.guard.recheck()?;
            context.lock.recheck()?;
            references.require_unmentioned(&context.generation)?;
            authorize()
        })?
    } else {
        let parent = files::directory_relative(
            context.guard.control(),
            Path::new("boot-retirements"),
            Some(0),
        )?;
        let registry = Registry::observe(&folder, &parent, &leaf, 0)?;
        context.bind_existing_receipt_registry(&registry, authorize)?;
        registry
    };
    context.reference_registries.remove(index);
    let record = value!({"intent":intent,"phase":"prepared","next_step":0,"inflight":null});
    let mut runtime = Runtime {
        context,
        references,
        authorize,
        registry,
        record: record.clone(),
        intent,
        after,
        published: false,
        catalog_done: false,
        retired: BTreeMap::new(),
        bios: None,
        directory: None,
    };
    runtime.persist(record)?;
    let steps = enzimos_platform::json::array(&runtime.intent["steps"])?.clone();
    for (index, step) in steps.iter().enumerate() {
        runtime.verify()?;
        require(
            runtime.state(step)? == step["before"],
            "original retirement before state differs; no replay",
        )?;
        runtime.checkpoint(index, Some(index), "executing")?;
        progress("finishing")?;
        runtime.barrier()?;
        runtime.apply(step)?;
        runtime.verify()?;
        require(
            runtime.state(step)? == step["after"],
            "owned retirement step did not reach exact planned state",
        )?;
        runtime.checkpoint(index + 1, None, "executing")?;
    }
    require(runtime.catalog_done, "retirement catalog tombstone missing")?;
    runtime.checkpoint(steps.len(), None, "complete")?;
    runtime.verify()?;
    Ok(
        value!({"generation":runtime.context.generation,"status":"retirement-complete","root_subvolume_retained":true,
        "disclosed_unobservable":if runtime.context.firmware["observable"]==false{vec!["EFI-loader-state-not-observable-on-this-boot"]}else{Vec::<&str>::new()}}),
    )
}
