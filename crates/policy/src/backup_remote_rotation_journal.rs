// SPDX-License-Identifier: MIT
//! Original fixed Root journal, then only its actual retained publication chain.
//! Drop never repairs, deletes or resumes an interrupted publication.
use crate::{backup_remote_record as codec, control_record::Retained, storage_runtime::Guard};
use enzimos_platform::{
    Result, files, json,
    publication::{Chain, Prepared},
    require,
};
use serde_json::{Value, json as value};
use std::{fs::File, path::Path};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Rotation,
    Pin,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Rotation => "backup-remote-rotation.json",
            Self::Pin => "backup-remote-pin.json",
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::Rotation => codec::ROTATION_LIMIT,
            Self::Pin => 32768,
        }
    }
    fn validate(self, row: &Value) -> Result<()> {
        match self {
            Self::Rotation => {
                codec::rotation(row)?;
                Ok(())
            }
            Self::Pin => codec::pin(row),
        }
    }
}
pub struct Journal<'a> {
    guard: &'a Guard,
    lock: &'a files::Lock,
    source: Value,
    role: Role,
    original: Option<Retained>,
    owned: Option<Chain>,
    record: Value,
    schema: u64,
}
impl<'a> Journal<'a> {
    pub(crate) fn observe(guard: &'a Guard, lock: &'a files::Lock, role: Role) -> Result<Self> {
        Self::observe_schema(
            guard,
            lock,
            role,
            if role == Role::Rotation { 2 } else { 1 },
        )
    }
    pub(crate) fn observe_legacy(guard: &'a Guard, lock: &'a files::Lock) -> Result<Self> {
        Self::observe_schema(guard, lock, Role::Rotation, 1)
    }
    fn observe_schema(
        guard: &'a Guard,
        lock: &'a files::Lock,
        role: Role,
        schema: u64,
    ) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        lock.recheck()?;
        let original = Retained::open(
            guard.control(),
            Path::new(role.name()),
            role.limit(),
            guard.control_mount_id(),
        )?;
        let record = original.value()?.clone();
        role.validate(&record)?;
        require(
            record["schema"] == schema,
            "fixed original remote journal schema differs",
        )?;
        let this = Self {
            guard,
            lock,
            role,
            source: guard.backup_root_binding()?,
            original: Some(original),
            owned: None,
            record,
            schema,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        self.lock.recheck()?;
        require(
            self.guard.backup_root_binding()? == self.source,
            "original remote journal source root changed",
        )?;
        let file = match (&self.original, &self.owned) {
            (Some(original), None) => {
                require(
                    original.value()? == &self.record,
                    "original remote journal record changed",
                )?;
                original.descriptor()?
            }
            (None, Some(chain)) => {
                chain.require_destination(self.guard.control(), Path::new(self.role.name()))?;
                chain.file()?
            }
            _ => {
                return Err(enzimos_platform::Error(
                    "remote journal original/publication state incomplete".into(),
                ));
            }
        };
        require(
            json::decode(
                &files::read_file(file, self.role.limit(), Some(0), true)?,
                self.role.limit(),
            )? == self.record,
            "owned original remote journal bytes differ from admitted record",
        )?;
        self.role.validate(&self.record)?;
        require(
            self.record["schema"] == self.schema,
            "original remote journal schema changed outside owned migration",
        )?;
        self.lock.recheck()?;
        self.guard.recheck()
    }
    pub(crate) fn require_scope(
        &self,
        guard: &Guard,
        lock: &files::Lock,
        role: Role,
    ) -> Result<()> {
        self.recheck()?;
        require(
            std::ptr::eq(self.guard, guard) && std::ptr::eq(self.lock, lock) && self.role == role,
            "remote journal requires original actual guard/lock and fixed role",
        )
    }
    pub(crate) fn value(&self) -> Result<&Value> {
        self.recheck()?;
        Ok(&self.record)
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"role":self.role.name(),"record_sha256":json::fingerprint(&self.record)?,
        "original":self.original.as_ref().map(super::control_record::Retained::evidence).transpose()?,
        "owned":self.owned.as_ref().map(enzimos_platform::publication::Chain::evidence).transpose()?,"source":self.source}),
        )
    }
    /// Caller retains its original authority/objects and durably records the
    /// closed operation phase before any file movement. No record-data constructor.
    pub(crate) fn replace(
        &mut self,
        next: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        require(
            next["schema"] == self.schema,
            "implicit remote journal schema conversion refused",
        )?;
        self.replace_schema(next, self.schema, authorize)
    }
    pub(crate) fn migrate_metadata(
        &mut self,
        next: &Value,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck()?;
        require(
            self.role == Role::Rotation && self.schema == 1 && next["schema"] == 2,
            "original legacy rotation and metadata-v2 candidate required",
        )?;
        for key in [
            "phase",
            "created_boot",
            "old_identity",
            "new_identity",
            "old_config_sha256",
            "new_config_sha256",
            "points",
        ] {
            require(
                next[key] == self.record[key],
                "metadata migration changed original public journal fields",
            )?;
        }
        self.replace_schema(next, 2, authorize)
    }
    fn replace_schema(
        &mut self,
        next: &Value,
        schema: u64,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck()?;
        self.role.validate(next)?;
        let mut bytes = json::canonical(next)?;
        bytes.push(b'\n');
        require(
            bytes.len() <= self.role.limit(),
            "owned remote journal byte bound",
        )?;
        if let Some(chain) = &mut self.owned {
            chain.replace(&bytes, authorize)?;
        } else {
            let original = self
                .original
                .as_ref()
                .ok_or_else(|| enzimos_platform::Error("original remote journal missing".into()))?;
            let path = Path::new(crate::operation::CONTROL).join(self.role.name());
            let prepared = Prepared::write_authorized(&path, &bytes, 0, authorize)?;
            original.require_original_publication(&prepared)?;
            let committed = prepared.commit_retained_authorized(true, authorize)?;
            committed.require_destination(self.guard.control(), Path::new(self.role.name()))?;
            self.owned = Some(Chain::new(committed)?);
            self.original = None;
        }
        self.record = next.clone();
        self.schema = schema;
        self.recheck()?;
        authorize()
    }
    pub fn descriptor(&self) -> Result<&File> {
        self.recheck()?;
        match (&self.original, &self.owned) {
            (Some(r), None) => r.descriptor(),
            (None, Some(c)) => c.file(),
            _ => Err(enzimos_platform::Error(
                "original remote journal state incomplete".into(),
            )),
        }
    }
}
