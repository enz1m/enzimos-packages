// SPDX-License-Identifier: MIT
//! Consume a complete original ESP context for exact online coordinator cleanup.
//! No decoded output, existing retired path or destructor supplies mutation authority.
use super::*;
use crate::boot_volume::{ReplacedArtifact, RetiredArtifact};
use crate::{
    control_record::Observation,
    root_retirement_boot_contract::{self, Finish},
    root_retirement_online_inventory::Inventory,
    root_retirement_online_journal::Journal,
};
use enzimos_platform::publication::Prepared;

pub struct Cleanup<'a, 'g> {
    context: Context<'a, 'g>,
    receipt: Observation,
    record: Value,
    plan: Finish,
    completed: bool,
    retiring_entry: bool,
    namespace: crate::root_retirement_signed_namespace::Original<'a>,
    replacements: BTreeMap<String, ReplacedArtifact>,
    entry: Option<RetiredArtifact>,
    retired_directory_epoch: Option<files::FileIdentity>,
    firmware: Option<crate::root_retirement_firmware_publication::finish::Completed<'a>>,
    entry_name: String,
    original_entry_epoch: Option<files::FileIdentity>,
}
impl<'a, 'g: 'a> Cleanup<'a, 'g> {
    pub fn observe(
        context: Context<'a, 'g>,
        journal: &Journal<'_>,
        inventory: &Inventory<'_>,
        firmware: Option<crate::root_retirement_firmware_publication::finish::Completed<'a>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        context.recheck(authorize)?;
        let namespace = crate::root_retirement_signed_namespace::Original::observe(
            context.guard,
            context.lock,
            authorize,
        )?;
        journal.require_original_source(context.guard, context.lock)?;
        inventory.require_deleted(journal, authorize)?;
        let receipt = journal.duplicate_observation()?;
        let record = receipt.value()?.clone();
        let coordinator = &record["coordinator"];
        let entry_name = format!(
            "loader/entries/{}",
            crate::recovery_records::text(coordinator, "uefi_entry")?
        );
        match &firmware {
            Some(actor) => actor.require_source(context.guard, context.lock, &record, authorize)?,
            None => require(
                !crate::recovery_activation_runtime::efi_guard()?,
                "actual retained firmware cleanup required",
            )?,
        }
        let plan = root_retirement_boot_contract::finish(
            &record,
            context
                .texts
                .get("loader/loader.conf")
                .ok_or_else(|| Error("original UEFI defaults absent".into()))?,
            context
                .texts
                .get("limine/limine.conf")
                .ok_or_else(|| Error("original BIOS menu absent".into()))?,
            context.texts.get(&entry_name).map(String::as_str),
            None,
        )?;
        let original_entry_epoch = context.root_loader_directory.map(|row| row.0);
        let result = Self {
            context,
            receipt,
            record,
            plan,
            completed: false,
            retiring_entry: false,
            namespace,
            replacements: BTreeMap::new(),
            entry: None,
            retired_directory_epoch: None,
            entry_name,
            firmware,
            original_entry_epoch,
        };
        result.recheck(authorize)?;
        Ok(result)
    }
    fn source_barrier(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.source_barrier_inner(None, None, authorize)
    }
    fn source_barrier_inner(
        &self,
        origin: Option<&crate::root_retirement_online_finish_origin::Published<'_>>,
        completed: Option<&crate::root_retirement_online_journal::Completed<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.context.guard.recheck()?;
        self.context.lock.recheck()?;
        self.namespace.recheck(authorize)?;
        match completed {
            Some(receipt) => {
                receipt.require_source(self.context.guard, self.context.lock)?;
                receipt.require_original_observation(&self.receipt)?;
                require(
                    receipt.before()? == &self.record,
                    "finish loader completed predecessor differs",
                )?;
            }
            None => {
                self.receipt.recheck()?;
                require(
                    self.receipt.value()? == &self.record,
                    "finish loader deleted receipt changed",
                )?;
            }
        }
        match (&self.firmware, completed) {
            (Some(actor), Some(receipt)) => actor.recheck_completed(receipt, authorize)?,
            (Some(actor), None) => actor.require_source(
                self.context.guard,
                self.context.lock,
                &self.record,
                authorize,
            )?,
            (None, _) => require(
                !crate::recovery_activation_runtime::efi_guard()?,
                "originally absent firmware became observable",
            )?,
        }
        self.context.transaction.recheck()?;
        for registry in &self.context.reference_registries {
            if let Some(receipt) = completed
                && registry.folder() == "root-retirements"
            {
                registry.recheck_completed_root(receipt)?;
                continue;
            }
            if let Some(origin) = origin
                && registry.folder() == origin.folder()
            {
                registry.recheck_finished_origin(origin)?;
                continue;
            }
            registry.recheck()?;
        }
        for journal in &self.context.reference_journals {
            if let Some(origin) = origin
                && journal.folder() == origin.folder()
            {
                journal.recheck_finished_origin(origin)?;
                continue;
            }
            journal.checkpoint()?;
        }
        match (origin, completed) {
            (Some(origin), Some(receipt)) => self
                .context
                .idle
                .recheck_finished_completion(origin, receipt)?,
            (Some(origin), None) => self.context.idle.recheck_finished_origin(origin)?,
            (None, None) => self.context.idle.recheck()?,
            (None, Some(_)) => {
                return Err(Error("completion missing original origin producer".into()));
            }
        }
        self.context.pins.recheck()?;
        self.context.volume.writable()?;
        require(
            self.context.guard.backup_root_binding()? == self.context.original["source"]
                && self.context.transaction.data == self.context.original["catalog"]
                && self.context.transaction.evidence()? == self.context.original["catalog_epoch"]
                && command_line()? == self.context.command_line
                && firmware()? == self.context.firmware,
            "finish original catalog/source/boot state changed",
        )?;
        for artifact in self.context.artifacts.values() {
            artifact.recheck()?;
        }
        for artifact in self.replacements.values() {
            artifact.recheck()?;
        }
        for directory in &self.context.directories {
            if directory.relative != "loader/entries" || !self.retiring_entry {
                directory.recheck(&self.context.volume)?;
            }
        }
        self.context
            .signed_inventory
            .recheck(&self.context.volume, authorize)?;
        authorize()
    }
    pub fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_after_retired_entry(authorize)
    }
    fn replace(
        &mut self,
        name: &str,
        next: &str,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if self.context.texts.get(name).map(String::as_str) == Some(next) {
            return self.recheck(authorize);
        }
        self.recheck(authorize)?;
        let original = self
            .context
            .artifacts
            .remove(name)
            .ok_or_else(|| Error("finish original loader descriptor absent".into()))?;
        let pending = Prepared::write_authorized(&original.path, next.as_bytes(), 0, &mut || {
            self.source_barrier(authorize)
        })?;
        original.require_original_publication(&pending)?;
        original.recheck()?;
        self.source_barrier(authorize)?;
        let committed =
            pending.commit_retained_authorized(true, &mut || self.source_barrier(authorize))?;
        let replaced = original.into_replaced(committed)?;
        require(
            files::read_file(replaced.file()?, boot_entries::MAX_TEXT, Some(0), true)?
                == next.as_bytes(),
            "finish exact loader successor readback differs",
        )?;
        self.replacements.insert(name.into(), replaced);
        self.context.texts.insert(name.into(), next.into());
        self.recheck(authorize)
    }
    pub fn run(
        mut self,
        inventory: &Inventory<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        self.recheck(authorize)?;
        inventory.require_deleted_record(&self.receipt, authorize)?;
        let defaults = self.plan.defaults.clone();
        let bios = self.plan.bios.clone();
        self.replace("loader/loader.conf", &defaults, authorize)?;
        self.replace("limine/limine.conf", &bios, authorize)?;
        if self.plan.remove_uefi {
            self.recheck(authorize)?;
            inventory.require_deleted_record(&self.receipt, authorize)?;
            let original = self
                .context
                .artifacts
                .remove(&self.entry_name)
                .ok_or_else(|| {
                    Error("finish original coordinator entry descriptor absent".into())
                })?;
            let parent = self.context.volume.directory(Path::new("loader/entries"))?;
            require(
                self.original_entry_epoch == Some(files::identity(&parent.metadata()?)),
                "finish original entry directory epoch differs",
            )?;
            self.retiring_entry = true;
            let pending = original.quarantine_original(
                &parent,
                boot_entries::MAX_TEXT as u64,
                &mut || self.source_barrier(authorize),
            )?;
            let removed = pending.unlink(&mut || self.source_barrier(authorize))?;
            // RetiredArtifact consumes the actual removal; an equal filename or
            // serialized epoch cannot construct its original predecessor join.
            self.entry = Some(original.into_retired(removed)?);
            self.retired_directory_epoch = Some(files::identity(&parent.metadata()?));
            self.context.texts.remove(&self.entry_name);
            // The retained retired artifact owns the Removed proof. The next
            // barrier joins that same private producer, not a reopened filename.
            self.recheck_after_retired_entry(authorize)?;
        }
        inventory.require_deleted_record(&self.receipt, authorize)?;
        self.recheck_after_retired_entry(authorize)?;
        self.completed = true;
        Ok(self)
    }
    fn recheck_after_retired_entry(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.recheck_after_origin_inner(None, None, authorize)
    }
    pub(crate) fn require_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        record: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            self.completed
                && std::ptr::eq(self.context.guard, guard)
                && std::ptr::eq(self.context.lock, lock)
                && &self.record == record,
            "actual completed loader cleanup belongs to another receipt/guard/lock",
        )?;
        self.recheck(authorize)
    }
    pub(crate) fn recheck_after_origin(
        &self,
        origin: &crate::root_retirement_online_finish_origin::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(self.completed, "actual consumed loader cleanup required")?;
        origin.require_source(self.context.guard, self.context.lock)?;
        self.recheck_after_origin_inner(Some(origin), None, authorize)
    }
    pub(crate) fn recheck_completed(
        &self,
        origin: &crate::root_retirement_online_finish_origin::Published<'_>,
        receipt: &crate::root_retirement_online_journal::Completed<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(self.completed, "actual consumed loader cleanup required")?;
        origin.require_source(self.context.guard, self.context.lock)?;
        receipt.require_source(self.context.guard, self.context.lock)?;
        self.recheck_after_origin_inner(Some(origin), Some(receipt), authorize)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn recheck_after_origin_inner(
        &self,
        origin: Option<&crate::root_retirement_online_finish_origin::Published<'_>>,
        completed: Option<&crate::root_retirement_online_journal::Completed<'_>>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.source_barrier_inner(origin, completed, authorize)?;
        if let Some(entry) = &self.entry {
            entry.recheck()?;
        }
        for artifact in self.context.artifacts.values() {
            artifact.recheck()?;
        }
        for artifact in self.replacements.values() {
            artifact.recheck()?;
        }
        for directory in &self.context.directories {
            if directory.relative == "loader/entries" && self.entry.is_some() {
                let named = self.context.volume.directory(Path::new("loader/entries"))?;
                let mut expected = directory.names.clone();
                expected.remove(
                    self.entry_name
                        .rsplit('/')
                        .next()
                        .ok_or_else(|| enzimos_platform::Error("missing element".into()))?,
                );
                require(shape(&directory.file)? == directory.shape && shape(&named)? == directory.shape
                    && Some(files::identity(&directory.file.metadata()?)) == self.retired_directory_epoch
                    && Some(files::identity(&named.metadata()?)) == self.retired_directory_epoch
                    && mount_identity::id(directory.file.as_fd(),true)? == self.context.volume.unique
                    && mount_identity::id(named.as_fd(),true)? == self.context.volume.unique
                    && self.context.root_loader_directory.is_some_and(|(_,flags)| unsafe {libc::fcntl(directory.file.as_raw_fd(),libc::F_GETFL)} == flags)
                    && names(&directory.file,256)? == expected && names(&named,256)? == expected,
                    "finish removed entry changed original directory/unrelated members")?;
            } else {
                directory.recheck(&self.context.volume)?;
            }
        }
        if self.entry.is_none() {
            self.context.recheck_root_loader_directory()?;
        }
        self.source_barrier_inner(origin, completed, authorize)
    }
}
