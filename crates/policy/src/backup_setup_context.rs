// SPDX-License-Identifier: MIT
//! Only a newly published original outer intent permits coordinator-owned input storage.
use crate::{backup_setup_plan::Plan, storage_runtime::Guard};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const NAME: &str = "backup-initial-setup.json";
const LIMIT: usize = 32768;
pub(crate) fn validate(v: &Value) -> Result<()> {
    json::fields(v, "schema phase plan")?;
    require(
        v["schema"].as_u64() == Some(1) && v["phase"] == "prepared",
        "original prepared initial setup intent required",
    )?;
    crate::backup_setup_plan::validate(&v["plan"])
}
#[derive(Clone, Copy)]
pub(crate) enum Step {
    SecretInput,
    Configuration,
    Repository,
}
/// The published outer setup intent, retained for the setup body.
pub struct Prepared<'p, 'a, 'r, 'd> {
    plan: &'p Plan<'a, 'r, 'd>,
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    steps: std::cell::Cell<u8>,
}
impl<'p, 'a, 'r, 'd> Prepared<'p, 'a, 'r, 'd> {
    /// Replace only this original prepared intent after native provision, pin,
    /// worker and normal mount closure. Interrupted receipts are never adopted.
    ///
    /// # Errors
    ///
    /// Fails when the provisioned result does not match the plan or the record cannot be written.
    pub fn complete<'g>(
        self,
        provisioned: crate::backup_provisioned::Provisioned<'g>,
        lock: &files::Lock,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Completed<'p, 'a, 'r, 'd, 'g>> {
        self.recheck()?;
        provisioned.recheck()?;
        lock.recheck()?;
        authorize()?;
        require(
            provisioned.plan()? == self.plan.original()
                && self.steps.get()
                    == if self.plan.original()["mode"] == "initialize" {
                        7
                    } else {
                        3
                    },
            "outer completion requires original plan and exactly its entered publication steps",
        )?;
        let result = provisioned.public_result()?;
        let value = value!({"schema":1,"phase":"complete","plan":self.plan.original(),"result":result,"mount_closed":true});
        let bytes = json::canonical(&value)?;
        self.recheck()?;
        provisioned.recheck()?;
        lock.recheck()?;
        authorize()?;
        let file = files::atomic_replace_original(
            self.plan.guard().control(),
            Path::new(NAME),
            &bytes,
            0o600,
            Some(0),
            LIMIT,
            &self.file,
        )?;
        let this = Completed {
            plan: self.plan,
            identity: files::identity(&file.metadata()?),
            file,
            bytes,
            result,
            provisioned,
        };
        this.recheck()?;
        lock.recheck()?;
        authorize()?;
        Ok(this)
    }
    /// Publish the outer setup intent for `plan`.
    ///
    /// # Errors
    ///
    /// Fails when the plan changed, a record exists, or `authorize` fails.
    pub fn begin(
        plan: &'p Plan<'a, 'r, 'd>,
        review_sha: &str,
        lock: &files::Lock,
        authorize: &dyn Fn() -> Result<()>,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::identity::sha(review_sha)?;
        lock.recheck()?;
        authorize()?;
        plan.recheck_initial()?;
        require(
            plan.digest()? == review_sha,
            "initial setup reviewed plan changed",
        )?;
        let v = value!({"schema":1,"phase":"prepared","plan":plan.original()});
        validate(&v)?;
        let bytes = json::canonical(&v)?;
        let file = files::atomic_relative_retained(
            plan.guard().control(),
            Path::new(NAME),
            &bytes,
            0o600,
            Some(0),
            false,
            LIMIT,
        )?;
        let this = Self {
            plan,
            identity: files::identity(&file.metadata()?),
            file,
            bytes,
            steps: std::cell::Cell::new(0),
        };
        this.recheck()?;
        lock.recheck()?;
        authorize()?;
        Ok(this)
    }
    /// No cold-load constructor: an existing receipt is an interrupted outcome,
    /// not authority to repeat publication or adopt a completed child operation.
    pub(crate) fn recheck(&self) -> Result<()> {
        self.plan.recheck_identity()?;
        let guard = self.plan.guard();
        let named = files::open_relative(guard.control(), Path::new(NAME))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && self.file.metadata()?.uid() == 0
                && self.file.metadata()?.mode() & 0o7777 == 0o600
                && self.file.metadata()?.nlink() == 1
                && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id()
                && mount_identity::id(self.file.as_fd(), true)? == guard.control_mount_id()
                && files::read_file(&self.file, LIMIT, Some(0), true)? == self.bytes,
            "original outer setup intent changed or replaced",
        )
    }
    /// True once repository creation was entered on the destination. After
    /// that the device may hold a (partial) repository and rollback must not
    /// guess; the state stays for inspection/reset.
    pub fn repository_entered(&self) -> bool {
        self.steps.get() & 4 != 0
    }
    /// Failure rollback: remove this original prepared intent so a fresh,
    /// reviewed attempt is possible. Never used after completion.
    ///
    /// # Errors
    ///
    /// Fails when the intent changed or cannot be removed.
    pub fn retract(&self, lock: &files::Lock) -> Result<()> {
        lock.recheck()?;
        self.recheck()?;
        crate::backup_publication_identity::retract(
            self.plan.guard().control(),
            c"backup-initial-setup.json",
        )?;
        lock.recheck()
    }
    pub(crate) fn claim(&self, step: Step) -> Result<()> {
        self.recheck()?;
        let mask = match step {
            Step::SecretInput => 1,
            Step::Configuration => 2,
            Step::Repository => 4,
        };
        require(
            self.steps.get() & mask == 0,
            "setup step already entered; no replay within active context",
        )?;
        self.steps.set(self.steps.get() | mask);
        Ok(())
    }
    pub(crate) fn filesystem(&self) -> &str {
        self.plan.original()["destination"]["filesystem_uuid"]
            .as_str()
            .expect("setup plans are validated with a destination UUID string")
    }
    /// The intent record file.
    ///
    /// # Errors
    ///
    /// Fails when the intent changed.
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        Ok(&self.file)
    }
    pub(crate) fn plan_value(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(self.plan.original())
    }
    pub(crate) fn check_source(&self, guard: &Guard, uid: Option<u32>) -> Result<()> {
        self.recheck()?;
        require(
            guard.backup_root_binding()? == self.plan.original()["source"]
                && uid.is_none_or(|uid| self.plan.original()["owner_uid"] == uid),
            "setup input does not belong to original reviewed caller/Root",
        )
    }
}
/// Read-only original outer completion, retaining its newly published pin and
/// native provision witness. No constructor from JSON or a later pathname exists.
pub struct Completed<'p, 'a, 'r, 'd, 'g> {
    plan: &'p Plan<'a, 'r, 'd>,
    file: File,
    identity: files::FileIdentity,
    bytes: Vec<u8>,
    result: Value,
    provisioned: crate::backup_provisioned::Provisioned<'g>,
}
impl Completed<'_, '_, '_, '_, '_> {
    pub(crate) fn recheck(&self) -> Result<()> {
        self.plan.recheck_identity()?;
        self.provisioned.recheck()?;
        let guard = self.plan.guard();
        let named = files::open_relative(guard.control(), Path::new(NAME))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && self.file.metadata()?.uid() == 0
                && self.file.metadata()?.gid() == 0
                && self.file.metadata()?.mode() & 0o7777 == 0o600
                && self.file.metadata()?.nlink() == 1
                && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id()
                && mount_identity::id(self.file.as_fd(), true)? == guard.control_mount_id()
                && files::read_file(&self.file, LIMIT, Some(0), true)? == self.bytes
                && self.provisioned.public_result()? == self.result,
            "original completed outer setup receipt or native provision changed",
        )
    }
    /// Result document of the completed setup.
    ///
    /// # Errors
    ///
    /// Fails when the intent changed or is not complete.
    pub fn result(&self) -> Result<Value> {
        self.recheck()?;
        Ok(self.result.clone())
    }
}
