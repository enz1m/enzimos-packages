// SPDX-License-Identifier: MIT
//! Online fixed-name control registries retain mount and directory identity.
use crate::{
    catalog, control_record, identity, operation,
    recovery_journal::Records,
    storage_runtime::{Guard, IndependentGuard},
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::Value;
use std::{
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub fn read<F: FnMut(&Value, &str) -> Result<()>>(
    guard: &Guard,
    folder: &str,
    maximum: usize,
    validate: F,
) -> Result<Records> {
    read_bounded(guard, folder, maximum, catalog::MAX_CATALOG, validate)
}
pub fn read_bounded<F: FnMut(&Value, &str) -> Result<()>>(
    guard: &Guard,
    folder: &str,
    maximum: usize,
    limit: usize,
    validate: F,
) -> Result<Records> {
    read_control(
        guard.control(),
        guard.control_mount_id(),
        folder,
        maximum,
        limit,
        validate,
        || guard.recheck(),
    )
}
/// Read through the actual independently mounted guard, without consulting an
/// installed-root configuration file that is absent from the RAM environment.
pub fn read_independent<F: FnMut(&Value, &str) -> Result<()>>(
    guard: &IndependentGuard,
    folder: &str,
    maximum: usize,
    validate: F,
) -> Result<Records> {
    read_control(
        guard.control(),
        guard.control_mount_id(),
        folder,
        maximum,
        catalog::MAX_CATALOG,
        validate,
        || guard.recheck(),
    )
}
fn read_control<F: FnMut(&Value, &str) -> Result<()>>(
    control: &std::fs::File,
    control_mount: u64,
    folder: &str,
    maximum: usize,
    limit: usize,
    mut validate: F,
    mut recheck: impl FnMut() -> Result<()>,
) -> Result<Records> {
    identity::safe_id(folder)?;
    require(maximum <= 256, "control registry record bound")?;
    require(
        limit > 0 && limit <= catalog::MAX_CATALOG,
        "control record byte bound",
    )?;
    recheck()?;
    let path = Path::new(operation::CONTROL).join(folder);
    let Some(directory) = files::optional_directory_relative(control, Path::new(folder), Some(0))?
    else {
        recheck()?;
        return Ok(Records::new());
    };
    let original = files::identity(&directory.metadata()?);
    require(
        directory.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(directory.as_fd(), true)? == control_mount,
        "unsafe control registry",
    )?;
    let entries = files::directory_names(&directory, maximum.max(1))?;
    require(entries.len() <= maximum, "control registry count bound")?;
    let mut records = Records::new();
    for entry in entries {
        let name = entry
            .into_string()
            .map_err(|_| Error("control registry filename encoding".into()))?;
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| Error("unknown or interrupted control record".into()))?;
        identity::safe_id(id)?;
        let record = control_record::read(&directory, Path::new(&name), limit, control_mount)?;
        validate(&record, id)?;
        records.insert(id.into(), record);
    }
    let current = files::directory(&path, Some(0))?;
    let a = directory.metadata()?;
    let b = current.metadata()?;
    require(
        files::identity(&a) == original
            && files::identity(&b) == original
            && (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
                == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode())
            && mount_identity::id(current.as_fd(), true)? == control_mount,
        "control registry replaced",
    )?;
    recheck()?;
    Ok(records)
}

/// One observed record of a [`Folder`], retained for exact-inode retirement.
pub(crate) struct Member {
    pub(crate) value: Option<Value>,
    pub(crate) mtime: (i64, i64),
    identity: files::FileIdentity,
    bytes: Vec<u8>,
}
/// A private control registry observed for bounded history retirement. Only
/// `<id>.json` regular files are members; any other entry is left untouched.
pub(crate) struct Folder {
    directory: std::fs::File,
    mount: u64,
    owner: u32,
    limit: usize,
    pub(crate) members: std::collections::BTreeMap<String, Member>,
    /// Entries that are not `<safe id>.json` (interrupted or foreign files).
    pub(crate) foreign: usize,
}
impl Folder {
    /// Observe `folder` under `control`; None when absent. Records that fail
    /// `validate` keep `value: None` and are never offered for retirement.
    pub(crate) fn open(
        control: &std::fs::File,
        mount: u64,
        owner: u32,
        folder: &str,
        limit: usize,
        mut validate: impl FnMut(&Value, &str) -> Result<()>,
    ) -> Result<Option<Self>> {
        identity::safe_id(folder)?;
        let Some(directory) =
            files::optional_directory_relative(control, Path::new(folder), Some(owner))?
        else {
            return Ok(None);
        };
        let m = directory.metadata()?;
        require(
            m.mode() & 0o7777 == 0o700 && mount_identity::id(directory.as_fd(), true)? == mount,
            "unsafe control registry for retirement",
        )?;
        let mut this = Self {
            directory,
            mount,
            owner,
            limit,
            members: Default::default(),
            foreign: 0,
        };
        for name in files::directory_names(&this.directory, 4096)? {
            let Some(id) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .filter(|id| identity::safe_id(id).is_ok())
                .map(str::to_owned)
            else {
                this.foreign += 1;
                continue;
            };
            let Some((file, identity)) = this.member(&id)? else {
                this.foreign += 1;
                continue;
            };
            let bytes = files::read_file(&file, limit, Some(owner), true)?;
            let value = json::decode(&bytes, limit)
                .ok()
                .filter(|v| validate(v, &id).is_ok());
            let m = file.metadata()?;
            require(
                files::identity(&m) == identity,
                "control record changed during retirement read",
            )?;
            this.members.insert(
                id,
                Member {
                    value,
                    mtime: (m.mtime(), m.mtime_nsec()),
                    identity,
                    bytes,
                },
            );
        }
        Ok(Some(this))
    }
    fn member(&self, id: &str) -> Result<Option<(std::fs::File, files::FileIdentity)>> {
        let Some(file) =
            files::optional_relative(&self.directory, Path::new(&format!("{id}.json")))?
        else {
            return Ok(None);
        };
        let m = file.metadata()?;
        if !(m.is_file()
            && m.uid() == self.owner
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && mount_identity::id(file.as_fd(), true)? == self.mount)
        {
            return Ok(None);
        }
        Ok(Some((file, files::identity(&m))))
    }
    pub(crate) fn value(&self, id: &str) -> Option<&Value> {
        self.members.get(id).and_then(|m| m.value.as_ref())
    }
    pub(crate) fn len(&self) -> usize {
        self.members.len() + self.foreign
    }
    /// The observed registry directory, for removing a record's own data
    /// directory (`<id>/`) before the record itself.
    pub(crate) fn directory(&self) -> &std::fs::File {
        &self.directory
    }
    /// Unlink one observed record only while its name still holds the exact
    /// observed inode and bytes. Returns false when it was already absent.
    #[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
    pub(crate) fn retire(&mut self, id: &str) -> Result<bool> {
        let Some(member) = self.members.get(id) else {
            return Ok(false);
        };
        let (file, identity) = self
            .member(id)?
            .ok_or_else(|| Error("retired control record changed".into()))?;
        require(
            identity == member.identity
                && files::read_file(&file, self.limit, Some(self.owner), true)? == member.bytes
                && files::identity(&file.metadata()?) == member.identity,
            "retired control record changed",
        )?;
        let name = std::ffi::CString::new(format!("{id}.json"))
            .map_err(|_| Error("control record filename encoding".into()))?;
        require(
            unsafe {
                libc::unlinkat(
                    std::os::fd::AsRawFd::as_raw_fd(&self.directory),
                    name.as_ptr(),
                    0,
                )
            } == 0,
            "control record retirement failed",
        )?;
        self.members.remove(id);
        Ok(true)
    }
    pub(crate) fn sync(&self) -> Result<()> {
        Ok(self.directory.sync_all()?)
    }
    /// Members as (modification time, id, retirable) for [`select`].
    pub(crate) fn rows(&self, mut retirable: impl FnMut(&str, &Value) -> bool) -> Vec<Row> {
        self.members
            .iter()
            .map(|(id, m)| Row {
                order: m.mtime,
                id: id.clone(),
                retirable: m.value.as_ref().is_some_and(|v| retirable(id, v)),
            })
            .collect()
    }
}
/// One registry member offered to [`select`].
#[derive(Clone, Debug)]
pub(crate) struct Row {
    pub(crate) order: (i64, i64),
    pub(crate) id: String,
    pub(crate) retirable: bool,
}
/// Records to retire: once at least `trigger` members exist, every retirable
/// record outside the newest `keep` members (by order, then id), oldest first.
/// Non-retirable records are never selected and still count toward `keep`.
pub(crate) fn select(mut rows: Vec<Row>, keep: usize, trigger: usize) -> Vec<String> {
    if rows.len() < trigger {
        return Vec::new();
    }
    rows.sort_by(|a, b| (a.order, &a.id).cmp(&(b.order, &b.id)));
    let older = rows.len().saturating_sub(keep);
    rows.into_iter()
        .take(older)
        .filter(|row| row.retirable)
        .map(|row| row.id)
        .collect()
}
/// Retire finished records of one Root-private control registry so a bounded
/// registry never refuses forever. Only records that `retirable` accepts (it
/// must reject unfinished rows and rows other state still references) and
/// that are older than the newest `keep` members are unlinked, by exact inode,
/// once the registry holds at least `trigger` members. The caller holds the
/// operation lock and has not yet retained any observation of this folder.
pub(crate) fn retire_terminal(
    guard: &Guard,
    folder: &str,
    keep: usize,
    trigger: usize,
    limit: usize,
    validate: impl FnMut(&Value, &str) -> Result<()>,
    retirable: impl FnMut(&str, &Value) -> bool,
) -> Result<Vec<String>> {
    guard.recheck()?;
    let retired = retire_in(
        guard.control(),
        guard.control_mount_id(),
        0,
        folder,
        keep,
        trigger,
        limit,
        validate,
        retirable,
    )?;
    guard.recheck()?;
    Ok(retired)
}
pub(crate) fn retire_in(
    control: &std::fs::File,
    mount: u64,
    owner: u32,
    folder: &str,
    keep: usize,
    trigger: usize,
    limit: usize,
    validate: impl FnMut(&Value, &str) -> Result<()>,
    retirable: impl FnMut(&str, &Value) -> bool,
) -> Result<Vec<String>> {
    require(keep > 0, "retirement must keep recent history")?;
    let Some(mut registry) = Folder::open(control, mount, owner, folder, limit, validate)? else {
        return Ok(Vec::new());
    };
    if registry.len() < trigger {
        return Ok(Vec::new());
    }
    let selected = select(registry.rows(retirable), keep, 0);
    let mut retired = Vec::new();
    for id in selected {
        if registry.retire(&id)? {
            retired.push(id);
        }
    }
    if !retired.is_empty() {
        registry.sync()?;
    }
    Ok(retired)
}

/// Original private registry descriptions retained for destructive preflight.
/// Expected data is a comparison with the already validated idle observation;
/// it cannot construct a record or a filesystem mutation actor.
pub(crate) struct Snapshot<'g> {
    guard: &'g Guard,
    folder: String,
    parent: Option<std::fs::File>,
    original: Option<files::FileIdentity>,
    names: std::collections::BTreeSet<String>,
    records: std::collections::BTreeMap<String, control_record::Retained>,
    expected: Value,
}
impl<'g> Snapshot<'g> {
    pub(crate) fn observe(guard: &'g Guard, folder: &str, expected: &Value) -> Result<Self> {
        crate::operation::root_only()?;
        crate::namespaces::initial()?;
        require(
            matches!(
                folder,
                "boot-publications"
                    | "update-workers"
                    | "module-views"
                    | "authority-refresh"
                    | "root-births"
                    | "root-rebind-journal"
                    | "retirement-journals"
                    | "boot-retirements"
                    | "root-retirements"
            ),
            "fixed retirement reference registry required",
        )?;
        require(
            expected.as_object().is_some_and(|v| v.len() <= 256),
            "complete bounded original reference map required",
        )?;
        guard.recheck()?;
        let parent =
            files::optional_directory_relative(guard.control(), Path::new(folder), Some(0))?;
        let mut this = Self {
            guard,
            folder: folder.into(),
            parent,
            original: None,
            names: Default::default(),
            records: Default::default(),
            expected: expected.clone(),
        };
        if let Some(parent) = &this.parent {
            let m = parent.metadata()?;
            require(
                m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7777 == 0o700
                    && mount_identity::id(parent.as_fd(), true)? == guard.control_mount_id(),
                "original private reference registry protection/mount",
            )?;
            this.original = Some(files::identity(&m));
            for name in files::directory_names(parent, 256)? {
                let name = name
                    .into_string()
                    .map_err(|_| Error("reference record filename encoding".into()))?;
                let id = name.strip_suffix(".json").ok_or_else(|| {
                    Error("unknown/interrupted retirement reference member".into())
                })?;
                identity::safe_id(id)?;
                require(
                    expected.get(id).is_some(),
                    "original idle reference membership changed",
                )?;
                let record = control_record::Retained::open(
                    parent,
                    Path::new(&name),
                    catalog::MAX_CATALOG,
                    guard.control_mount_id(),
                )?;
                require(
                    record.value()? == &expected[id],
                    "original idle reference record changed before retention",
                )?;
                this.records.insert(id.into(), record);
                this.names.insert(name);
            }
        }
        require(
            this.records.len() == expected.as_object().unwrap().len(),
            "missing original idle reference record",
        )?;
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let named = files::optional_directory_relative(
            self.guard.control(),
            Path::new(&self.folder),
            Some(0),
        )?;
        match (&self.parent, named, self.original) {
            (None, None, None) => (),
            (Some(parent), Some(named), Some(epoch)) => {
                require(
                    files::identity(&parent.metadata()?) == epoch
                        && files::identity(&named.metadata()?) == epoch
                        && mount_identity::id(parent.as_fd(), true)?
                            == self.guard.control_mount_id()
                        && mount_identity::id(named.as_fd(), true)?
                            == self.guard.control_mount_id(),
                    "original reference registry replaced/changed/covered",
                )?;
                let current = files::directory_names(parent, 256)?
                    .into_iter()
                    .map(|v| {
                        v.into_string()
                            .map_err(|_| Error("reference filename encoding".into()))
                    })
                    .collect::<Result<std::collections::BTreeSet<_>>>()?;
                require(
                    current == self.names,
                    "original reference registry membership changed",
                )?;
                for (id, record) in &self.records {
                    require(
                        record.value()? == &self.expected[id],
                        "original retained reference bytes/epoch changed",
                    )?;
                }
            }
            _ => {
                return Err(Error(
                    "original reference registry appeared/disappeared".into(),
                ));
            }
        }
        self.guard.recheck()
    }
    /// Only this actual owned continuation chain may replace its original selected
    /// receipt. Every other original record and named directory member stays exact.
    pub(crate) fn recheck_boot_continuation(
        &self,
        journal: &crate::boot_retirement_continuation::ContinuationJournal,
    ) -> Result<()> {
        self.guard.recheck()?;
        require(
            self.folder == "boot-retirements",
            "fixed continuation registry required",
        )?;
        let original = self
            .records
            .get(journal.id())
            .ok_or_else(|| Error("original continuation registry member missing".into()))?;
        journal.require_original_retained(original)?;
        require(
            self.expected.get(journal.id()) == Some(journal.before()),
            "continuation initial row differs from original registry",
        )?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| Error("actual original continuation folder missing".into()))?;
        let epoch = self
            .original
            .ok_or_else(|| Error("actual original continuation folder epoch missing".into()))?;
        let named = files::directory_relative(
            self.guard.control(),
            Path::new("boot-retirements"),
            Some(0),
        )?;
        for directory in [parent, &named] {
            let m = directory.metadata()?;
            require(
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid(), m.nlink())
                    == (epoch.0, epoch.1, epoch.7, epoch.8, epoch.9, epoch.10)
                    && mount_identity::id(directory.as_fd(), true)?
                        == self.guard.control_mount_id(),
                "owned continuation folder identity/protection changed",
            )?;
            let names = files::directory_names(directory, 256)?
                .into_iter()
                .map(|s| {
                    s.into_string()
                        .map_err(|_| Error("continuation registry filename encoding".into()))
                })
                .collect::<Result<std::collections::BTreeSet<_>>>()?;
            require(
                names == self.names,
                "independent continuation registry membership changed",
            )?;
        }
        for (id, record) in &self.records {
            if id != journal.id() {
                require(
                    record.value()? == &self.expected[id],
                    "independent original continuation registry member changed",
                )?;
            }
        }
        let selected = files::open_relative(parent, Path::new(&format!("{}.json", journal.id())))?;
        require(
            files::identity(&selected.metadata()?)
                == files::identity(&journal.descriptor()?.metadata()?)
                && mount_identity::id(selected.as_fd(), true)? == self.guard.control_mount_id(),
            "owned current continuation row differs from actual named publication",
        )?;
        journal.recheck()?;
        self.guard.recheck()
    }
    /// Recheck an original Root registry across exactly this owned staging rename.
    pub(crate) fn recheck_staged_root(
        &self,
        published: &crate::root_retirement_online_journal::Published<'_>,
    ) -> Result<()> {
        require(
            self.folder == "root-retirements",
            "staging requires original Root registry",
        )?;
        self.guard.recheck()?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| Error("staging cannot adopt absent registry".into()))?;
        let original = self
            .original
            .ok_or_else(|| Error("staging requires original registry epoch".into()))?;
        published.require_original_directory(parent, original)?;
        let before = published.before()?;
        let id = crate::recovery_records::text(before, "id")?;
        require(
            self.expected[id] == *before,
            "staging producer differs from original registry selection",
        )?;
        let names = files::directory_names(parent, 256)?
            .into_iter()
            .map(|name| {
                name.into_string()
                    .map_err(|_| Error("Root registry filename encoding".into()))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        require(
            names == self.names,
            "staging changed original Root registry membership",
        )?;
        for (member, record) in &self.records {
            if member == id {
                published.require_original_member(record)?;
            } else {
                require(
                    record.value()? == &self.expected[member],
                    "unrelated original Root registry receipt changed",
                )?;
            }
        }
        require(
            self.records.contains_key(id),
            "original selected Root registry descriptor missing",
        )?;
        published.require_original_directory(parent, original)?;
        self.guard.recheck()
    }
    pub(crate) fn recheck_completed_root(
        &self,
        published: &crate::root_retirement_online_journal::Completed<'_>,
    ) -> Result<()> {
        require(
            self.folder == "root-retirements",
            "staging requires original Root registry",
        )?;
        self.guard.recheck()?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| Error("staging cannot adopt absent registry".into()))?;
        let original = self
            .original
            .ok_or_else(|| Error("staging requires original registry epoch".into()))?;
        published.require_original_directory(parent, original)?;
        let before = published.before()?;
        let id = crate::recovery_records::text(before, "id")?;
        require(
            self.expected[id] == *before,
            "staging producer differs from original registry selection",
        )?;
        let names = files::directory_names(parent, 256)?
            .into_iter()
            .map(|name| {
                name.into_string()
                    .map_err(|_| Error("Root registry filename encoding".into()))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        require(
            names == self.names,
            "staging changed original Root registry membership",
        )?;
        for (member, record) in &self.records {
            if member == id {
                published.require_original_member(record)?;
            } else {
                require(
                    record.value()? == &self.expected[member],
                    "unrelated original Root registry receipt changed",
                )?;
            }
        }
        require(
            self.records.contains_key(id),
            "original selected Root registry descriptor missing",
        )?;
        published.require_original_directory(parent, original)?;
        self.guard.recheck()
    }
    pub(crate) fn recheck_finished_origin(
        &self,
        published: &crate::root_retirement_online_finish_origin::Published<'_>,
    ) -> Result<()> {
        require(
            self.folder == "root-births" && published.folder() == self.folder,
            "original birth registry required",
        )?;
        self.guard.recheck()?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| Error("original birth registry absent".into()))?;
        published.require_original_directory(
            parent,
            self.original
                .ok_or_else(|| Error("original birth directory epoch absent".into()))?,
        )?;
        require(
            self.expected.get(published.id()) == Some(published.before()),
            "finish differs from original birth selection",
        )?;
        for (id, row) in &self.records {
            if id == published.id() {
                published.require_original_member(row)?;
            } else {
                require(
                    row.value()? == &self.expected[id],
                    "unrelated birth changed",
                )?;
            }
        }
        require(
            self.records.contains_key(published.id()),
            "original finish birth descriptor missing",
        )?;
        self.guard.recheck()
    }
    /// Transfer independently held original members before any own publication.
    /// An absent registry requires a separate exclusive-created directory proof.
    pub(crate) fn originally_absent(&self) -> Result<bool> {
        self.recheck()?;
        Ok(self.parent.is_none())
    }
    pub(crate) fn folder(&self) -> &str {
        &self.folder
    }
    pub(crate) fn bind_existing_receipt_registry(
        &self,
        registry: &enzimos_platform::receipt_registry::Registry,
        own_leaf: &str,
    ) -> Result<()> {
        self.recheck()?;
        require(
            matches!(
                self.folder.as_str(),
                "boot-retirements" | "root-retirements"
            ),
            "fixed original retirement source registry required",
        )?;
        let parent = self.parent.as_ref().ok_or_else(|| {
            Error("absent original registry requires exclusive creation proof".into())
        })?;
        registry.require_directory(parent, own_leaf)?;
        let records = self
            .records
            .iter()
            .map(|(id, record)| Ok((format!("{id}.json"), record.descriptor()?)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        registry.require_original_members(&records)?;
        self.recheck()
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        let epochs = self
            .records
            .iter()
            .map(|(id, r)| Ok((id.clone(), r.evidence()?)))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        Ok(
            serde_json::json!({"folder":self.folder,"directory":self.original,"records":epochs,"mount":self.guard.control_mount_id()}),
        )
    }
}
