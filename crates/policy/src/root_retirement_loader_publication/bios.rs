use super::*;

impl<'a> PendingBios<'a> {
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.entry.recheck_body(authorize)?;
        let original = &self.entry.original;
        original.default_directories["loader"].recheck(&original.volume, "loader")?;
        let directory = &original.default_directories["limine"];
        let named = original.volume.directory(Path::new("limine"))?;
        let mut expected = directory.members.clone();
        expected.insert("limine.conf.new".into());
        require(
            files::identity(&directory.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&directory.file)? == directory.flags
                && mount_identity::id(directory.file.as_fd(), true)? == original.volume.unique
                && mount_identity::id(named.as_fd(), true)? == original.volume.unique
                && names(&directory.file)? == expected,
            "actual pending BIOS directory changed/replaced/covered",
        )?;
        let artifact = &original.defaults["limine/limine.conf"].0;
        artifact.recheck()?;
        artifact.require_original_publication(&self.prepared)?;
        self.entry.recheck_body(authorize)
    }
    /// Consume the actual pending BIOS write through one checked replacement.
    pub(crate) fn commit(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<CommittedBios<'a>> {
        self.recheck(authorize)?;
        self.entry.original.protected.recheck_pending_bios(
            self.entry.original.receipt,
            self.entry.original.signer,
            &self,
            authorize,
        )?;
        let entry = self.entry;
        let authorization = std::cell::RefCell::new(authorize);
        let committed = self.prepared.commit_checked(
            true,
            &mut || entry.recheck_body(&mut **authorization.borrow_mut()),
            &mut |actual| {
                entry.recheck_body_with(Some(actual), None, &mut **authorization.borrow_mut())
            },
        )?;
        let directory = &entry.original.default_directories["limine"];
        let epoch = files::identity(&directory.file.metadata()?);
        require(
            same_directory(directory.epoch, epoch),
            "owned BIOS commit changed original directory identity/protection",
        )?;
        let result = CommittedBios {
            entry,
            committed,
            epoch,
        };
        result.recheck(&mut **authorization.borrow_mut())?;
        result.entry.original.protected.recheck_committed_bios(
            result.entry.original.receipt,
            result.entry.original.signer,
            &result,
            &mut **authorization.borrow_mut(),
        )?;
        Ok(result)
    }
    /// JSON evidence for the pending BIOS entry.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed or `authorize` fails.
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.entry.original.entry,"bios_directory_epoch":self.epoch,
            "bios_sha256":enzimos_platform::json::sha256(self.entry.original.next_bios.as_bytes()),
            "bios_committed":false,"execution_authorized":false}),
        )
    }
}

impl<'a> CommittedBios<'a> {
    pub(crate) fn recheck(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.entry.original.default_directories["loader"]
            .recheck(&self.entry.original.volume, "loader")?;
        self.recheck_body(None, authorize)
    }
    pub(super) fn recheck_body(
        &self,
        loader: Option<&enzimos_platform::publication::Committed>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.entry
            .recheck_body_with(Some(&self.committed), loader, authorize)?;
        let original = &self.entry.original;
        let directory = &original.default_directories["limine"];
        let named = original.volume.directory(Path::new("limine"))?;
        require(
            files::identity(&directory.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && flags(&directory.file)? == directory.flags
                && mount_identity::id(directory.file.as_fd(), true)? == original.volume.unique
                && mount_identity::id(named.as_fd(), true)? == original.volume.unique
                && names(&directory.file)? == directory.members,
            "actual committed BIOS directory changed/replaced/covered",
        )?;
        self.committed
            .require_destination(&directory.file, Path::new("limine.conf"))?;
        require(
            files::read_file(
                self.committed.file()?,
                crate::boot_entries::MAX_TEXT,
                Some(0),
                true,
            )? == original.next_bios.as_bytes(),
            "actual BIOS bytes differ from original derived selection",
        )?;
        self.entry
            .recheck_body_with(Some(&self.committed), loader, authorize)
    }
    pub(crate) fn require_firmware_source(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<&str> {
        let original = &self.entry.original;
        require(
            std::ptr::eq(original.guard, guard)
                && std::ptr::eq(original.lock, lock)
                && original.receipt.record()?["coordinator"]["uefi_mode"] == "one-shot",
            "firmware selection belongs to another original source or reviewed mode",
        )?;
        self.recheck(authorize)?;
        original.protected.recheck_committed_bios(
            original.receipt,
            original.signer,
            self,
            authorize,
        )?;
        Ok(&original.entry)
    }
    pub(crate) fn recheck_firmware_publication(
        &self,
        published: &crate::root_retirement_firmware_publication::Published<'_>,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let original = &self.entry.original;
        original.protected.recheck_firmware_publication(
            original.receipt,
            original.signer,
            published,
            authorize,
        )
    }
    /// Default mode consumes the actual BIOS commit into one pending UEFI selection.
    /// One-shot mode requires a separate original firmware actor and cannot use this path.
    pub(crate) fn prepare_defaults(
        self,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<PendingDefaults<'a>> {
        self.recheck(authorize)?;
        let original = &self.entry.original;
        require(
            original.receipt.record()?["coordinator"]["uefi_mode"] == "default",
            "UEFI default publication requires reviewed default mode",
        )?;
        original.protected.recheck_committed_bios(
            original.receipt,
            original.signer,
            &self,
            authorize,
        )?;
        let path = original.volume.path(Path::new("loader/loader.conf"))?;
        let prepared = enzimos_platform::publication::Prepared::write_authorized(
            &path,
            original.next_defaults.as_bytes(),
            0,
            &mut || self.recheck_body(None, authorize),
        )?;
        original.defaults["loader/loader.conf"]
            .0
            .require_original_publication(&prepared)?;
        let directory = &original.default_directories["loader"];
        let epoch = files::identity(&directory.file.metadata()?);
        require(
            same_directory(directory.epoch, epoch),
            "owned pending defaults changed original directory identity/protection",
        )?;
        let result = PendingDefaults {
            bios: self,
            prepared,
            epoch,
        };
        result.recheck(authorize)?;
        let original = &result.bios.entry.original;
        original.protected.recheck_pending_defaults(
            original.receipt,
            original.signer,
            &result,
            authorize,
        )?;
        Ok(result)
    }
    /// JSON evidence for the committed BIOS entry.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed or `authorize` fails.
    pub fn evidence(&self, authorize: &mut dyn FnMut() -> Result<()>) -> Result<Value> {
        self.recheck(authorize)?;
        Ok(
            json!({"entry":self.entry.original.entry,"bios_directory_epoch":self.epoch,
            "bios_sha256":enzimos_platform::json::sha256(self.entry.original.next_bios.as_bytes()),
            "bios_committed":true,"execution_authorized":false}),
        )
    }
}
