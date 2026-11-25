// SPDX-License-Identifier: MIT
//! Actual fixed Root remote-rotation inputs; credentials are never read or hashed.
//! Public evidence cannot reconstruct a retained object or authorize mutation.
use crate::{
    backup_remote_endpoint as endpoint, backup_rotation_record as local_record,
    storage_runtime::Guard,
};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    CurrentConfiguration,
    StagedConfiguration,
    RetiredConfiguration,
    CurrentPassword,
    StagedPassword,
    RetiredPassword,
    /// The share password; rotation keeps the share and its account.
    SharePassword,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::CurrentConfiguration => "backup-remote.json",
            Self::StagedConfiguration => "backup-remote-rotation.json",
            Self::RetiredConfiguration => "backup-remote-retired.json",
            Self::CurrentPassword => "backup-remote.password",
            Self::StagedPassword => "backup-remote-rotation.password",
            Self::RetiredPassword => "backup-remote-retired.password",
            Self::SharePassword => "backup-remote.share-password",
        }
    }
    fn configuration(self) -> bool {
        matches!(
            self,
            Self::CurrentConfiguration | Self::StagedConfiguration | Self::RetiredConfiguration
        )
    }
    fn credential(self) -> bool {
        matches!(
            self,
            Self::CurrentPassword
                | Self::StagedPassword
                | Self::RetiredPassword
                | Self::SharePassword
        )
    }
    fn limit(self) -> usize {
        if self.configuration() { 32768 } else { 4096 }
    }
}
type Shape = (u64, u64, u32, u32, u32);
fn shape(parent: &File) -> Result<Shape> {
    let m = parent.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original remote rotation parent",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
pub struct Object {
    role: Role,
    parent: File,
    shape: Shape,
    file: File,
    epoch: files::FileIdentity,
    flags: i32,
    mount: u64,
    source: Value,
    public: Option<Vec<u8>>,
    decoded: Option<Value>,
    credential: Option<Value>,
}
impl Object {
    pub fn observe(guard: &Guard, role: Role) -> Result<Option<Self>> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let source = guard.backup_root_binding()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == guard.root_mount_id(),
            "remote rotation parent outside original live root",
        )?;
        let Some(file) = files::optional_relative(&parent, Path::new(role.name()))? else {
            return Ok(None);
        };
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && (role.configuration() || m.mode() & 0o077 == 0)
                && m.len() > 0
                && m.len() <= role.limit() as u64
                && m.dev() == guard.root_device()
                && mount_identity::id(file.as_fd(), true)? == mount,
            "protected single-link original remote rotation object",
        )?;
        let epoch = files::identity(&m);
        let flags = enzimos_platform::files::status_flags(&file);
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY && flags & libc::O_PATH == 0,
            "original remote object readonly description",
        )?;
        // Only public configuration has readable bytes.
        let public = if role.credential() {
            None
        } else {
            Some(files::read_file(&file, role.limit(), Some(0), true)?)
        };
        let decoded = if role.configuration() {
            let decoded = json::decode(
                public
                    .as_ref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                32768,
            )?;
            endpoint::validate(&decoded)?;
            Some(decoded)
        } else {
            None
        };
        let credential = if role.credential() {
            let nanos = m
                .mtime()
                .checked_mul(1_000_000_000)
                .and_then(|s| s.checked_add(m.mtime_nsec()))
                .ok_or_else(|| {
                    enzimos_platform::Error("remote rotation credential time overflow".into())
                })?;
            let v = value!({"inode":m.ino(),"size":m.len(),"mtime_ns":nanos,
                "filesystem_uuid":source["configuration"]["filesystem_uuid"],"root_uuid":source["root"]["uuid"],
                "root_id":source["root"]["id"],"root_path":source["root"]["path"]});
            local_record::credential_identity(&v)?;
            Some(v)
        } else {
            None
        };
        let this = Self {
            role,
            shape: shape(&parent)?,
            parent,
            file,
            epoch,
            flags,
            mount,
            source,
            public,
            decoded,
            credential,
        };
        this.recheck(guard)?;
        Ok(Some(this))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    pub fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let named = files::open_relative(&self.parent, Path::new(self.role.name()))?;
        require(
            guard.backup_root_binding()? == self.source
                && shape(&parent)? == self.shape
                && shape(&self.parent)? == self.shape
                && mount_identity::id(parent.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount
                && self.mount == guard.root_mount_id()
                && files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                // SAFETY: F_GETFL takes no pointers and `self.file` keeps the descriptor open.
                && unsafe {
                    libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::F_GETFL)
                } == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original remote rotation object changed/replaced/covered",
        )?;
        if let Some(bytes) = &self.public {
            require(
                files::read_file(&self.file, self.role.limit(), Some(0), true)? == *bytes,
                "original public remote rotation bytes changed",
            )?;
        }
        require(
            files::identity(&self.file.metadata()?) == self.epoch,
            "original remote rotation epoch changed during check",
        )
    }
    pub(crate) fn descriptor(&self, guard: &Guard) -> Result<&File> {
        self.recheck(guard)?;
        Ok(&self.file)
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn configuration(&self, guard: &Guard) -> Result<&Value> {
        self.recheck(guard)?;
        self.decoded.as_ref().ok_or_else(|| {
            enzimos_platform::Error("remote rotation configuration role required".into())
        })
    }
    pub fn credential_identity(&self, guard: &Guard) -> Result<&Value> {
        self.recheck(guard)?;
        self.credential.as_ref().ok_or_else(|| {
            enzimos_platform::Error("remote rotation credential role required".into())
        })
    }
    pub fn public_sha256(&self, guard: &Guard) -> Result<String> {
        self.recheck(guard)?;
        self.public
            .as_ref()
            .map(|bytes| json::sha256(bytes))
            .ok_or_else(|| enzimos_platform::Error("credential hashing refused".into()))
    }
    pub fn evidence(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        Ok(
            value!({"role":self.role.name(),"epoch":self.epoch,"parent":self.shape,"mount":self.mount,
            "source":self.source,"public_sha256":self.public.as_ref().map(|b|json::sha256(b)),
            "credential_identity":self.credential,"credential_bytes_read":false}),
        )
    }
    pub fn require_distinct(&self, other: &Self, guard: &Guard) -> Result<()> {
        self.recheck(guard)?;
        other.recheck(guard)?;
        require(
            (self.epoch.0, self.epoch.1) != (other.epoch.0, other.epoch.1),
            "remote rotation roles alias original inode",
        )
    }
}
/// Original complete fixed-name inventory, including each originally absent slot.
/// Registry data may classify these actors but never supplies a File constructor.
pub struct Inventory {
    parent: File,
    shape: Shape,
    mount: u64,
    source: Value,
    objects: Vec<(Role, Option<Object>)>,
    removed: Vec<RemovedObject>,
}
impl Inventory {
    pub fn observe(guard: &Guard) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        guard.recheck()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let mount = mount_identity::id(parent.as_fd(), true)?;
        require(
            mount == guard.root_mount_id(),
            "remote rotation inventory outside original live root",
        )?;
        let mut objects = Vec::new();
        for role in [
            Role::CurrentConfiguration,
            Role::StagedConfiguration,
            Role::RetiredConfiguration,
            Role::CurrentPassword,
            Role::StagedPassword,
            Role::RetiredPassword,
            Role::SharePassword,
        ] {
            objects.push((role, Object::observe(guard, role)?));
        }
        let this = Self {
            shape: shape(&parent)?,
            parent,
            mount,
            source: guard.backup_root_binding()?,
            objects,
            removed: Vec::new(),
        };
        this.recheck(guard)?;
        Ok(this)
    }
    pub fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let named = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            guard.backup_root_binding()? == self.source
                && self.mount == guard.root_mount_id()
                && shape(&named)? == self.shape
                && shape(&self.parent)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount,
            "original remote rotation inventory parent/source changed",
        )?;
        let mut identities = std::collections::BTreeSet::new();
        for (role, object) in &self.objects {
            if let Some(object) = object {
                object.recheck(guard)?;
                require(
                    identities.insert((object.epoch.0, object.epoch.1)),
                    "remote rotation inventory role alias",
                )?;
            } else {
                require(
                    files::optional_relative(&self.parent, Path::new(role.name()))?.is_none(),
                    "remote rotation object appeared in original absent slot",
                )?;
            }
        }
        for removed in &self.removed {
            removed.recheck(guard)?;
        }
        guard.recheck()
    }
    pub fn object(&self, role: Role, guard: &Guard) -> Result<Option<&Object>> {
        self.recheck(guard)?;
        Ok(self
            .objects
            .iter()
            .find(|(r, _)| *r == role)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?
            .1
            .as_ref())
    }
    pub fn evidence(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        let mut objects = serde_json::Map::new();
        for (role, object) in &self.objects {
            objects.insert(
                role.name().into(),
                match object {
                    Some(o) => o.evidence(guard)?,
                    None => Value::Null,
                },
            );
        }
        self.recheck(guard)?;
        Ok(
            value!({"objects":objects,"parent":self.shape,"mount":self.mount,
            "source":self.source,"credential_bytes_read":false}),
        )
    }
    /// Read-only candidate data derived from actual original fixed inputs. No
    /// publication/mutation authority follows; migration must also retain the
    /// original legacy journal/pin and independently authenticate vendor results.
    pub fn legacy_candidate(&self, legacy: &Value, pin: &Value, guard: &Guard) -> Result<Value> {
        crate::backup_remote_record::rotation(legacy)?;
        crate::backup_remote_record::pin(pin)?;
        require(
            legacy["schema"] == 1,
            "legacy remote rotation candidate requires schema1",
        )?;
        self.recheck(guard)?;
        require(
            !matches!(legacy["phase"].as_str(), Some("complete" | "abandoned")),
            "terminal legacy remote rotation needs no metadata mutation",
        )?;
        let mut state = [None; 7];
        for (i, role) in [
            Role::CurrentConfiguration,
            Role::StagedConfiguration,
            Role::RetiredConfiguration,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(object) = self.object(role, guard)? {
                let sha = object.public_sha256(guard)?;
                state[i] = Some(if legacy["old_config_sha256"] == sha {
                    "old"
                } else if legacy["new_config_sha256"] == sha {
                    "new"
                } else {
                    "foreign"
                });
            }
        }
        for (i, role) in [
            Role::CurrentPassword,
            Role::StagedPassword,
            Role::RetiredPassword,
        ]
        .into_iter()
        .enumerate()
        {
            if self.object(role, guard)?.is_some() {
                state[i + 3] = Some("present");
            }
        }
        state[6] = Some(if pin == &legacy["old_identity"] {
            "old"
        } else if pin == &legacy["new_identity"] {
            "new"
        } else {
            "foreign"
        });
        let patterns = crate::backup_remote_rotation_context::legacy_boundaries();
        let index = patterns
            .iter()
            .position(|pattern| {
                pattern.iter().enumerate().all(|(i, expected)| {
                    if (3..6).contains(&i) {
                        state[i] == expected.map(|_| "present")
                    } else {
                        state[i] == *expected
                    }
                })
            })
            .ok_or_else(|| {
                enzimos_platform::Error(
                    "legacy remote material outside exact public/presence boundary".into(),
                )
            })?;
        require(
            index <= 5,
            "legacy metadata migration requires both original credentials",
        )?;
        match enzimos_platform::json::string(&legacy["phase"])? {
            "initializing" | "copying" | "copied" => {
                require(index == 0, "legacy phase moved before switching")?;
            }
            "switching" => (),
            "switched" => require(index == 5, "legacy switched boundary differs")?,
            _ => return Err(enzimos_platform::Error("legacy migration phase".into())),
        }
        let mut old = None;
        let mut new = None;
        for (i, role) in [
            Role::CurrentPassword,
            Role::StagedPassword,
            Role::RetiredPassword,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(object) = self.object(role, guard)? {
                let identity = object.credential_identity(guard)?.clone();
                match patterns[index][i + 3] {
                    Some("old") => old = Some(identity),
                    Some("new") => new = Some(identity),
                    _ => {
                        return Err(enzimos_platform::Error(
                            "foreign legacy credential slot".into(),
                        ));
                    }
                }
            }
        }
        let mut candidate = enzimos_platform::json::object(legacy)?.clone();
        candidate.remove("old_password_sha256");
        candidate.remove("new_password_sha256");
        candidate.insert("schema".into(), value!(2));
        candidate.insert("credential_identity_kind".into(), value!("metadata-v2"));
        candidate.insert(
            "old_password_identity".into(),
            old.ok_or_else(|| enzimos_platform::Error("original old credential missing".into()))?,
        );
        candidate.insert(
            "new_password_identity".into(),
            new.ok_or_else(|| enzimos_platform::Error("original new credential missing".into()))?,
        );
        let candidate = Value::Object(candidate);
        crate::backup_remote_record::rotation(&candidate)?;
        self.recheck(guard)?;
        Ok(candidate)
    }
    pub fn state(&self, record: &Value, guard: &Guard) -> Result<[Option<&'static str>; 6]> {
        crate::backup_remote_record::rotation(record)?;
        require(
            record["schema"] == 2,
            "legacy password-digest rotation requires explicit metadata migration",
        )?;
        self.recheck(guard)?;
        let mut state = [None; 6];
        for (i, role) in [
            Role::CurrentConfiguration,
            Role::StagedConfiguration,
            Role::RetiredConfiguration,
            Role::CurrentPassword,
            Role::StagedPassword,
            Role::RetiredPassword,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(object) = self.object(role, guard)? {
                state[i] = Some(if i < 3 {
                    let sha = object.public_sha256(guard)?;
                    if record["old_config_sha256"] == sha {
                        "old"
                    } else if record["new_config_sha256"] == sha {
                        "new"
                    } else {
                        "foreign"
                    }
                } else {
                    let identity = object.credential_identity(guard)?;
                    if identity == &record["old_password_identity"] {
                        "old"
                    } else if identity == &record["new_password_identity"] {
                        "new"
                    } else {
                        "foreign"
                    }
                });
            }
        }
        self.recheck(guard)?;
        Ok(state)
    }
}
enum Removal {
    Credential(enzimos_platform::credential_retirement::Removed),
    Document(enzimos_platform::named_retirement::Removed),
}
struct RemovedObject {
    original: Object,
    proof: Removal,
}
impl RemovedObject {
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let (descriptor, before) = match &self.proof {
            Removal::Credential(p) => {
                p.recheck()?;
                (p.descriptor()?, p.before_epoch()?)
            }
            Removal::Document(p) => {
                p.recheck()?;
                (p.descriptor()?, p.before_epoch()?)
            }
        };
        let named = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            before == self.original.epoch
                && files::identity(&descriptor.metadata()?)
                    == files::identity(&self.original.file.metadata()?)
                && mount_identity::id(descriptor.as_fd(), true)? == self.original.mount
                && guard.backup_root_binding()? == self.original.source
                && shape(&named)? == self.original.shape
                && shape(&self.original.parent)? == self.original.shape
                && mount_identity::id(named.as_fd(), true)? == self.original.mount
                // SAFETY: F_GETFL takes no pointers and `self.original.file` keeps the descriptor
                // open.
                && unsafe {
                    libc::fcntl(
                        std::os::fd::AsRawFd::as_raw_fd(&self.original.file),
                        libc::F_GETFL,
                    )
                } == self.original.flags,
            "retired remote object differs from original actor or source",
        )
    }
}
impl Object {
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    fn relocate(
        mut self,
        guard: &Guard,
        target: Role,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        use std::{ffi::CString, os::fd::AsRawFd};
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        authorize()?;
        self.recheck(guard)?;
        require(
            matches!(
                (self.role, target),
                (Role::CurrentConfiguration, Role::RetiredConfiguration)
                    | (Role::StagedConfiguration, Role::CurrentConfiguration)
                    | (Role::CurrentPassword, Role::RetiredPassword)
                    | (Role::StagedPassword, Role::CurrentPassword)
            ),
            "closed remote rotation rename required",
        )?;
        require(
            files::optional_relative(&self.parent, Path::new(target.name()))?.is_none(),
            "remote rotation target must remain absent",
        )?;
        let entry = enzimos_platform::directory_entry::Entry::observe(
            &self.parent,
            Path::new(self.role.name()),
        )?;
        entry.matches(&self.file)?;
        let mut names = files::directory_names(&self.parent, 131072)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        require(
            names.remove(std::ffi::OsStr::new(self.role.name()))
                && names.insert(std::ffi::OsString::from(target.name())),
            "original remote rename membership",
        )?;
        let old = CString::new(self.role.name())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        let new = CString::new(target.name())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        authorize()?;
        self.recheck(guard)?;
        entry.recheck()?;
        require(
            // SAFETY: Both names are NUL-terminated and the parent descriptor stays open.
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    old.as_ptr(),
                    self.parent.as_raw_fd(),
                    new.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "remote rotation rename collision/failure; retain journal, no replay",
        )?;
        let after = files::identity(&self.file.metadata()?);
        crate::backup_rotation_epoch::renamed(self.epoch, after)?;
        require(
            (after.5, after.6) >= (self.epoch.5, self.epoch.6),
            "remote rename time regressed",
        )?;
        require(
            files::directory_names(&self.parent, 131072)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                == names,
            "remote rename parent changed outside owned step",
        )?;
        self.parent.sync_all()?;
        self.epoch = after;
        self.role = target;
        self.recheck(guard)?;
        authorize()?;
        Ok(self)
    }
    fn retire(
        self,
        guard: &Guard,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<RemovedObject> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        self.recheck(guard)?;
        require(
            matches!(
                self.role,
                Role::RetiredConfiguration | Role::RetiredPassword
            ),
            "only original retired remote material may be removed",
        )?;
        let mut boundary = || {
            authorize()?;
            guard.recheck()?;
            require(
                enzimos_platform::files::status_flags(&self.file) == self.flags,
                "original remote retirement description flags changed",
            )
        };
        let proof = if self.role.credential() {
            let q = enzimos_platform::credential_retirement::Quarantined::enter_original(
                &self.parent,
                &self.file,
                Path::new(self.role.name()),
                self.epoch,
                0,
                &mut boundary,
            )?;
            Removal::Credential(q.unlink(&mut boundary)?)
        } else {
            let q = enzimos_platform::named_retirement::Quarantined::enter_original(
                &self.parent,
                &self.file,
                Path::new(self.role.name()),
                0,
                self.role.limit() as u64,
                self.epoch,
                &mut boundary,
            )?;
            Removal::Document(q.unlink(&mut boundary)?)
        };
        let retired = RemovedObject {
            original: self,
            proof,
        };
        retired.recheck(guard)?;
        Ok(retired)
    }
}
impl Inventory {
    fn others(&self, guard: &Guard, skip: &[Role]) -> Result<()> {
        guard.recheck()?;
        require(
            guard.backup_root_binding()? == self.source
                && shape(&self.parent)? == self.shape
                && mount_identity::id(self.parent.as_fd(), true)? == self.mount,
            "original remote mutation inventory source/parent",
        )?;
        for (role, object) in &self.objects {
            if skip.contains(role) {
                continue;
            }
            if let Some(o) = object {
                o.recheck(guard)?;
            } else {
                require(
                    files::optional_relative(&self.parent, Path::new(role.name()))?.is_none(),
                    "original remote absent slot appeared during mutation",
                )?;
            }
        }
        for removed in &self.removed {
            removed.recheck(guard)?;
        }
        Ok(())
    }
    pub(crate) fn rename(
        &mut self,
        guard: &Guard,
        source: Role,
        target: Role,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(guard)?;
        let from = self
            .objects
            .iter()
            .position(|(r, _)| *r == source)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        let to = self
            .objects
            .iter()
            .position(|(r, _)| *r == target)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        require(
            from != to && self.objects[to].1.is_none(),
            "original remote rename destination slot occupied",
        )?;
        let object = self.objects[from].1.take().ok_or_else(|| {
            enzimos_platform::Error("original remote rename source missing".into())
        })?;
        let moved = object.relocate(guard, target, &mut || {
            authorize()?;
            self.others(guard, &[source, target])
        })?;
        self.objects[to].1 = Some(moved);
        self.recheck(guard)?;
        authorize()
    }
    pub(crate) fn retire(
        &mut self,
        guard: &Guard,
        role: Role,
        authorize: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.recheck(guard)?;
        let from = self
            .objects
            .iter()
            .position(|(r, _)| *r == role)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        let object = self.objects[from].1.take().ok_or_else(|| {
            enzimos_platform::Error("original retired remote slot missing".into())
        })?;
        let retired = object.retire(guard, &mut || {
            authorize()?;
            self.others(guard, &[role])
        })?;
        self.removed.push(retired);
        self.recheck(guard)?;
        authorize()
    }
    pub(crate) fn retired_pair(&self, guard: &Guard) -> Result<()> {
        self.recheck(guard)?;
        require(
            self.removed.len() == 2
                && self
                    .removed
                    .iter()
                    .any(|r| r.original.role == Role::RetiredConfiguration)
                && self
                    .removed
                    .iter()
                    .any(|r| r.original.role == Role::RetiredPassword),
            "two original actual retired remote actors required",
        )
    }
}
/// Endpoint syntax checks are pure data validation, never an actor constructor.
pub fn staged_endpoint(current: &Value, staged: &Value) -> Result<()> {
    endpoint::validate(current)?;
    endpoint::validate(staged)?;
    for key in ["server", "share", "user", "domain"] {
        require(
            current.get(key) == staged.get(key),
            "remote rotation must keep the share and its account",
        )?;
    }
    let old = enzimos_platform::json::string(&current["folder"])?;
    let new = enzimos_platform::json::string(&staged["folder"])?;
    require(
        old != new && !new.starts_with(&format!("{old}/")) && !old.starts_with(&format!("{new}/")),
        "remote rotation requires separate non-nested repositories",
    )
}
