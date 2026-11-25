// SPDX-License-Identifier: MIT
//! Existing recovery-copy attestation is retained; it never proves physical possession.
use crate::{
    backup_admission::{Document, Repository},
    backup_configuration::Configuration,
    backup_credential::Credential,
};
use enzimos_platform::{Result, json, require};
use serde_json::{Value, json as value};
use std::path::Path;
fn validate_record(v: &Value, confirmation: bool) -> Result<()> {
    json::fields(
        v,
        if confirmation {
            "schema phase owner_uid ticket binding repository_key_id user_attested_independent_copy physical_copy_verified"
        } else {
            "schema phase owner_uid ticket binding repository_key_id descriptor_scope_closed"
        },
    )?;
    require(
        v["schema"].as_u64() == Some(1)
            && v["phase"] == "complete"
            && v["owner_uid"]
                .as_u64()
                .is_some_and(|n| (1000..i32::MAX as u64).contains(&n)),
        "completed recovery-copy authority required",
    )?;
    for key in ["ticket", "repository_key_id"] {
        crate::identity::sha(
            v[key].as_str().ok_or_else(|| {
                enzimos_platform::Error("recovery-copy ticket/key required".into())
            })?,
        )?;
    }
    if v["binding"].get("destination").is_some() {
        json::fields(
            &v["binding"],
            "destination configuration_sha256 destination_pin_sha256 credential_identity",
        )?;
        require(
            v["binding"]["destination"] == "share",
            "closed recovery-copy destination",
        )?;
    } else {
        json::fields(
            &v["binding"],
            "destination_uuid configuration_sha256 destination_pin_sha256 credential_identity",
        )?;
        crate::identity::uuid(v["binding"]["destination_uuid"].as_str().ok_or_else(|| {
            enzimos_platform::Error("recovery-copy destination required".into())
        })?)?;
    }
    for key in ["configuration_sha256", "destination_pin_sha256"] {
        crate::identity::sha(v["binding"][key].as_str().ok_or_else(|| {
            enzimos_platform::Error("recovery-copy public digest required".into())
        })?)?;
    }
    let identity = &v["binding"]["credential_identity"];
    json::fields(identity, "dev ino size mtime_ns ctime_ns")?;
    require(
        identity["dev"].as_u64().is_some_and(|n| n > 0)
            && identity["ino"].as_u64().is_some_and(|n| n > 0)
            && identity["size"]
                .as_u64()
                .is_some_and(|n| (1..=4096).contains(&n))
            && identity["mtime_ns"].as_i64().is_some()
            && identity["ctime_ns"].as_i64().is_some(),
        "recovery-copy credential metadata required",
    )?;
    require(
        if confirmation {
            v["user_attested_independent_copy"] == true && v["physical_copy_verified"] == false
        } else {
            v["descriptor_scope_closed"] == true
        },
        "recovery-copy attestation/scope required",
    )
}
pub(crate) fn verify_pair(exported: &Value, confirmed: &Value, expected: &Value) -> Result<()> {
    validate_record(exported, false)?;
    validate_record(confirmed, true)?;
    require(
        ["owner_uid", "ticket", "binding", "repository_key_id"]
            .iter()
            .all(|k| exported[*k] == confirmed[*k])
            && confirmed["binding"] == *expected,
        "recovery copy needs fresh review; no automatic replay",
    )
}
/// Redacted existing attestation status, independent of destination presence.
/// Credential observation is metadata-only; no password byte or hash is read.
/// A malformed/stale/missing half of a pair never becomes a positive claim.
pub(crate) fn status(
    configuration: &Configuration,
    storage: &crate::storage_runtime::Guard,
) -> Result<Value> {
    configuration.recheck()?;
    storage.recheck()?;
    let before = enzimos_platform::files::identity(&storage.control().metadata()?);
    let observed = (|| -> Result<&'static str> {
        let exported = Document::optional(
            &Path::new(crate::operation::CONTROL).join("backup-recovery-export.json"),
            0,
        )?;
        let confirmed = Document::optional(
            &Path::new(crate::operation::CONTROL).join("backup-recovery-confirmation.json"),
            0,
        )?;
        if exported.is_none() && confirmed.is_none() {
            return Ok("missing");
        }
        let exported =
            exported.ok_or_else(|| enzimos_platform::Error("recovery export missing".into()))?;
        let confirmed = confirmed
            .ok_or_else(|| enzimos_platform::Error("recovery confirmation missing".into()))?;
        let pin = crate::backup_admission::StoredPin::open(configuration, storage)?;
        let credential = Credential::open()?;
        require(
            exported.mount() == pin.storage().control_mount_id()
                && confirmed.mount() == exported.mount(),
            "recovery status records left original control mount",
        )?;
        let expected = value!({"destination_uuid":configuration.value()["destination_uuid"],
            "configuration_sha256":json::sha256(configuration.public_bytes()?),
            "destination_pin_sha256":json::sha256(pin.public_bytes()?),
            "credential_identity":credential.binding(storage)?});
        verify_pair(
            &json::decode(exported.bytes()?, crate::backup_configuration::LIMIT)?,
            &json::decode(confirmed.bytes()?, crate::backup_configuration::LIMIT)?,
            &expected,
        )?;
        exported.recheck()?;
        confirmed.recheck()?;
        pin.recheck()?;
        credential.recheck()?;
        Ok("user-attested")
    })();
    configuration.recheck()?;
    storage.recheck()?;
    require(
        enzimos_platform::files::identity(&storage.control().metadata()?) == before,
        "backup recovery status control inventory changed",
    )?;
    Ok(status_value(observed.unwrap_or("needs-review")))
}
/// Attestation status of a setup without a backup drive, bound to the share
/// configuration, pin and share repository password metadata. Read-only; a
/// record pair that does not verify reads as `needs-review`.
///
/// # Errors
/// None in practice; the result type matches the drive status.
pub(crate) fn share_status(guard: &crate::storage_runtime::Guard) -> Result<Value> {
    let observed = (|| -> Result<&'static str> {
        let read =
            |name: &str| Document::optional(&Path::new(crate::operation::CONTROL).join(name), 0);
        let (exported, confirmed) = match (
            read("backup-recovery-export.json")?,
            read("backup-recovery-confirmation.json")?,
        ) {
            (None, None) => return Ok("missing"),
            (Some(exported), Some(confirmed)) => (exported, confirmed),
            _ => return Ok("needs-review"),
        };
        let inputs = crate::backup_remote_inputs::Inputs::observe(guard)?;
        let expected = crate::backup_restic_runtime::recovery_export::share_binding_of(
            inputs.binding(guard)?,
            &crate::backup_share_destination::pin(guard)?,
        )?;
        verify_pair(
            &json::decode(exported.bytes()?, crate::backup_configuration::LIMIT)?,
            &json::decode(confirmed.bytes()?, crate::backup_configuration::LIMIT)?,
            &expected,
        )?;
        Ok("user-attested")
    })();
    Ok(status_value(observed.unwrap_or("needs-review")))
}
fn status_value(state: &str) -> Value {
    value!({"state":state,"user_attested_independent_copy":state=="user-attested",
        "physical_copy_verified":false})
}
pub(crate) struct Confirmation<'a, 'd, 'g> {
    configuration: &'a Configuration,
    repository: &'a Repository<'d, 'g>,
    credential: &'a Credential,
    exported: Document,
    confirmed: Document,
    expected: Value,
    key: String,
}
impl<'a, 'd, 'g> Confirmation<'a, 'd, 'g> {
    pub(crate) fn open(
        configuration: &'a Configuration,
        repository: &'a Repository<'d, 'g>,
        credential: &'a Credential,
    ) -> Result<Self> {
        let expected = Self::binding(configuration, repository, credential)?;
        let read = |name: &str| {
            Document::optional(&Path::new(crate::operation::CONTROL).join(name), 0)?
                .ok_or_else(|| enzimos_platform::Error("recovery copy needs fresh review".into()))
        };
        let exported = read("backup-recovery-export.json")?;
        let confirmed = read("backup-recovery-confirmation.json")?;
        require(
            exported.mount() == repository.storage().control_mount_id()
                && confirmed.mount() == exported.mount(),
            "recovery-copy records left original control mount",
        )?;
        let export_value = json::decode(exported.bytes()?, crate::backup_configuration::LIMIT)?;
        let confirm_value = json::decode(confirmed.bytes()?, crate::backup_configuration::LIMIT)?;
        verify_pair(&export_value, &confirm_value, &expected)?;
        let this = Self {
            configuration,
            repository,
            credential,
            exported,
            confirmed,
            expected,
            key: enzimos_platform::json::string(&export_value["repository_key_id"])?.into(),
        };
        this.recheck()?;
        Ok(this)
    }
    fn binding(
        configuration: &Configuration,
        repository: &Repository<'_, '_>,
        credential: &Credential,
    ) -> Result<Value> {
        repository.recheck()?;
        configuration.recheck()?;
        credential.recheck()?;
        Ok(
            value!({"destination_uuid":configuration.value()["destination_uuid"],"configuration_sha256":json::sha256(configuration.public_bytes()?),
            "destination_pin_sha256":json::sha256(repository.public_bytes()?),"credential_identity":credential.binding(repository.storage())?}),
        )
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.exported.recheck()?;
        self.confirmed.recheck()?;
        require(
            Self::binding(self.configuration, self.repository, self.credential)? == self.expected,
            "recovery-copy binding changed",
        )?;
        self.exported.recheck()?;
        self.confirmed.recheck()
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"user_attested_independent_copy":true,"physical_copy_verified":false,"repository_key_id":self.key}),
        )
    }
    pub(crate) fn review_evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"attestation":self.evidence()?,"binding":self.expected,
            "export":self.exported.evidence()?,"confirmation":self.confirmed.evidence()?}),
        )
    }
}
/// Original metadata authority survives normal destination unmount. It retains
/// only Root documents and the actual Root credential, never a destination FD.
pub struct Stored<'a> {
    configuration: &'a Configuration,
    pin: &'a crate::backup_admission::StoredPin<'a>,
    credential: &'a Credential,
    exported: Document,
    confirmed: Document,
    original: Value,
}
impl<'a> Stored<'a> {
    /// Open the recovery copy confirmation of `configuration`.
    ///
    /// # Errors
    ///
    /// Fails when the copy needs a fresh review or a file is unsafe.
    pub fn open(
        configuration: &'a Configuration,
        pin: &'a crate::backup_admission::StoredPin<'a>,
        credential: &'a Credential,
    ) -> Result<Self> {
        let read = |name: &str| {
            Document::optional(&Path::new(crate::operation::CONTROL).join(name), 0)?
                .ok_or_else(|| enzimos_platform::Error("recovery copy needs fresh review".into()))
        };
        let mut this = Self {
            configuration,
            pin,
            credential,
            exported: read("backup-recovery-export.json")?,
            confirmed: read("backup-recovery-confirmation.json")?,
            original: Value::Null,
        };
        this.original = this.binding()?;
        this.recheck()?;
        Ok(this)
    }
    fn binding(&self) -> Result<Value> {
        self.configuration.recheck()?;
        self.pin.recheck()?;
        self.credential.recheck()?;
        require(
            self.exported.mount() == self.pin.storage().control_mount_id()
                && self.confirmed.mount() == self.exported.mount(),
            "stored recovery authority crossed original control mount",
        )?;
        Ok(
            value!({"destination_uuid":self.configuration.value()["destination_uuid"],"configuration_sha256":json::sha256(self.configuration.public_bytes()?),"destination_pin_sha256":json::sha256(self.pin.public_bytes()?),"credential_identity":self.credential.binding(self.pin.storage())?}),
        )
    }
    /// Verify the confirmation is unchanged.
    ///
    /// # Errors
    ///
    /// Fails when it changed.
    pub fn recheck(&self) -> Result<()> {
        self.exported.recheck()?;
        self.confirmed.recheck()?;
        let binding = self.binding()?;
        require(
            binding == self.original,
            "original stored recovery authority binding changed",
        )?;
        verify_pair(
            &json::decode(self.exported.bytes()?, crate::backup_configuration::LIMIT)?,
            &json::decode(self.confirmed.bytes()?, crate::backup_configuration::LIMIT)?,
            &binding,
        )?;
        self.exported.recheck()?;
        self.confirmed.recheck()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(binding: &Value) -> (Value, Value) {
        let common = value!({"schema":1,"phase":"complete","owner_uid":1000,"ticket":"a".repeat(64),
            "binding":binding,"repository_key_id":"b".repeat(64)});
        let mut exported = common.clone();
        exported["descriptor_scope_closed"] = value!(true);
        let mut confirmed = common;
        confirmed["user_attested_independent_copy"] = value!(true);
        confirmed["physical_copy_verified"] = value!(false);
        (exported, confirmed)
    }
    #[test]
    fn a_share_recovery_copy_binds_its_share_and_never_a_drive() {
        let share = crate::backup_restic_runtime::recovery_export::share_binding_of(
            &value!({"configuration_sha256":"c".repeat(64),"credentials":{
                "/etc/enzimos/backup-remote.password":[2049, 21, 32, 1_000_000_000_i64, 1_000_000_000_i64]}}),
            &value!({"schema":2,"repository_id":"d".repeat(64),"configuration_sha256":"c".repeat(64)}),
        )
        .unwrap();
        let (exported, confirmed) = pair(&share);
        verify_pair(&exported, &confirmed, &share).unwrap();
        let mut other_pin = share.clone();
        other_pin["destination_pin_sha256"] = value!("e".repeat(64));
        assert!(verify_pair(&exported, &confirmed, &other_pin).is_err());
        let mut foreign = share.clone();
        foreign["destination"] = value!("cloud");
        let (exported, confirmed) = pair(&foreign);
        assert!(verify_pair(&exported, &confirmed, &foreign).is_err());
        let mut both = share;
        both["destination_uuid"] = value!("00000000-0000-4000-8000-000000000001");
        let (exported, confirmed) = pair(&both);
        assert!(verify_pair(&exported, &confirmed, &both).is_err());
    }
}
