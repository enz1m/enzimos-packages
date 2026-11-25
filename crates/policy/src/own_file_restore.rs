// SPDX-License-Identifier: MIT
//! Original current recipient for one caller-owned export/grant/delivery chain.
use crate::{delivery_account::Recipient, delivery_grant::Registry, storage_runtime::Guard};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
/// Historical System1 filename: canonical SHA256 including job_store's newline.
/// This pure data helper never grants access to a home or backup path.
pub(crate) fn destination_name(path: &str, id: &str) -> Result<String> {
    enzimos_platform::delivery_name::restored(path, id)
}

pub struct Prepared<'g> {
    guard: &'g Guard,
    recipient: Recipient,
    registry: Registry,
    selection: Value,
    account: Value,
    filename: String,
    uid: u32,
}
impl<'g> Prepared<'g> {
    // UID comes from the Root service's authoritative caller and original ledger,
    // not selection JSON. The actual local account and home stay retained.
    pub fn observe(guard: &'g Guard, selection: &Value, uid: u32) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        crate::backup_selective_request::selection(selection)?;
        let recipient = Recipient::open(uid, guard)?;
        let account = recipient.account(guard)?;
        require(
            enzimos_platform::json::string(&selection["path"])?.starts_with(&format!(
                "/backup-source{}/",
                enzimos_platform::json::string(&account["home"])?
            )),
            "job-plan-invalid",
        )?;
        let filename = destination_name(
            enzimos_platform::json::string(&selection["path"])?,
            enzimos_platform::json::string(&selection["id"])?,
        )?;
        let registry = Registry::open(guard)?;
        registry.vacant(guard, enzimos_platform::json::string(&selection["id"])?)?;
        let this = Self {
            guard,
            recipient,
            registry,
            selection: selection.clone(),
            account,
            filename,
            uid,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.recipient.recheck(self.guard)?;
        require(
            self.recipient.account(self.guard)? == self.account && self.account["uid"] == self.uid,
            "original caller account/home changed",
        )?;
        self.registry.vacant(
            self.guard,
            enzimos_platform::json::string(&self.selection["id"])?,
        )
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"uid":self.uid,"account":self.account,"filename":self.filename,
            "recipient":self.recipient.evidence(self.guard)?,"grant_registry_sha256":json::fingerprint(&self.registry.evidence(self.guard)?)?,"selection":self.selection}),
        )
    }
    pub fn grant(
        mut self,
        completed: &crate::backup_selective_export::Completed<'_, '_, 'g>,
        lock: &enzimos_platform::files::Lock,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<crate::delivery_control::Owned<'g>> {
        self.recheck()?;
        lock.recheck()?;
        authorize()?;
        let export = completed.original_export(self.guard, authorize)?;
        let binding = export.binding(self.guard)?;
        require(
            binding["export"] == self.selection["id"],
            "original own-file export differs",
        )?;
        self.recheck()?;
        completed.recheck(authorize)?;
        let id = enzimos_platform::json::string(&self.selection["id"])?;
        let mut record = value!({"schema":2,"id":id,"phase":"granted","boot_id":crate::operation::boot_id()?,
            "account":self.account,"export":binding,"filename":self.filename,"metadata_restored":false});
        record["grant_sha256"] = value!(json::fingerprint(&record)?);
        crate::delivery_cancel::validate(&record, id)?;
        self.registry.publish(self.guard, id, &record, &mut || {
            authorize()?;
            lock.recheck()?;
            self.recipient.recheck(self.guard)?;
            completed.recheck(authorize)
        })?;
        completed.recheck(authorize)?;
        self.recipient.recheck(self.guard)?;
        let (directory, receipt) = self.registry.into_published(self.guard, id)?;
        crate::delivery_control::Owned::from_original(
            self.guard,
            self.recipient,
            export,
            directory,
            receipt,
        )
    }
}
