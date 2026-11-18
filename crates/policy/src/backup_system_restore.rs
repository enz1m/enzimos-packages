// SPDX-License-Identifier: MIT
//! System data staging into one explicit empty non-snapshot subvolume.
//! No boot activation, live-home replacement or authority/worker restoration.
use super::{Image, Runtime};
use crate::{
    backup_admission::Repository,
    backup_configuration::Configuration,
    backup_credential::Credential,
    backup_destination::Destination,
    backup_repository_header::Header,
    filesystem, operation,
    storage_runtime::{self, Guard},
    subvolume,
};
use enzimos_platform::{
    Error, Result, files, json,
    local_restic::{self, RotationTask},
    mount_identity, mountinfo, publication, require,
};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
#[path = "backup_complete_boot.rs"]
pub mod boot_complete;
#[path = "backup_complete_prepare.rs"]
pub mod complete;
#[path = "backup_complete_fat.rs"]
mod complete_fat;
#[path = "backup_complete_tree.rs"]
mod complete_tree;
// Sealed original-source alternatives. RAM never constructs the installed Guard.
#[derive(Clone, Copy)]
enum Source<'a> {
    Live(&'a Guard),
    Ram(&'a crate::backup_ram_source::Source),
}
impl Source<'_> {
    fn recheck(&self) -> Result<()> {
        match self {
            Self::Live(s) => s.recheck(),
            Self::Ram(s) => s.recheck(),
        }
    }
    fn configuration(&self) -> &Value {
        match self {
            Self::Live(s) => &s.configuration,
            Self::Ram(s) => s.configuration(),
        }
    }
    fn control(&self) -> &File {
        match self {
            Self::Live(s) => s.control(),
            Self::Ram(s) => s.control(),
        }
    }
    fn control_mount_id(&self) -> u64 {
        match self {
            Self::Live(s) => s.control_mount_id(),
            Self::Ram(s) => s.control_mount_id(),
        }
    }
}
enum Backup<'a> {
    Live(Destination<'a>),
    Ram(crate::backup_destination::ram::Destination<'a>),
}
impl<'a> Backup<'a> {
    fn open(config: &'a Configuration, source: &Source<'a>) -> Result<Self> {
        Ok(match source {
            Source::Live(s) => Self::Live(Destination::open(config, s)?),
            Source::Ram(s) => Self::Ram(crate::backup_destination::ram::Destination::open(
                config, s,
            )?),
        })
    }
    fn recheck(&self) -> Result<()> {
        match self {
            Self::Live(d) => d.recheck(),
            Self::Ram(d) => d.recheck(),
        }
    }
    fn repository(&self) -> Result<File> {
        Ok(File::from(
            match self {
                Self::Live(d) => d.repository_descriptor()?,
                Self::Ram(d) => d.repository_descriptor()?,
            }
            .try_clone_to_owned()?,
        ))
    }
}
enum Pin<'a, 'g> {
    Live(Repository<'a, 'g>),
    Ram(crate::backup_admission::ram::Repository<'a, 'g>),
}
impl<'a, 'g> Pin<'a, 'g> {
    fn open(backup: &'a Backup<'g>) -> Result<Self> {
        Ok(match backup {
            Backup::Live(d) => Self::Live(Repository::open(d)?),
            Backup::Ram(d) => Self::Ram(crate::backup_admission::ram::Repository::open(d)?),
        })
    }
    fn recheck(&self) -> Result<()> {
        match self {
            Self::Live(p) => p.recheck(),
            Self::Ram(p) => p.recheck(),
        }
    }
}
enum Quiet {
    Live(
        crate::backup_rotation_context::Quiet,
        crate::transition_idle::Snapshot,
    ),
    Ram(crate::backup_ram_quiet::Quiet),
}
impl Quiet {
    fn observe(source: &Source<'_>) -> Result<Self> {
        Ok(match source {
            Source::Live(s) => Self::Live(
                crate::backup_rotation_context::Quiet::observe(s)?,
                crate::transition_idle::Snapshot::online()?,
            ),
            Source::Ram(s) => Self::Ram(crate::backup_ram_quiet::Quiet::observe(s)?),
        })
    }
    fn recheck(&self, source: &Source<'_>) -> Result<()> {
        match (self, source) {
            (Self::Live(q, i), Source::Live(s)) => {
                q.recheck(s)?;
                i.recheck()
            }
            (Self::Ram(q), Source::Ram(s)) => q.recheck(s),
            _ => Err(Error("restore original source kind differs".into())),
        }
    }
}
const TARGET: &str = "/restore-target";

fn target_name(row: &mountinfo::Row, configuration: &Value) -> Result<String> {
    require(
        row.target == TARGET && row.filesystem == "btrfs",
        "explicit Btrfs restore mount required",
    )?;
    let name = row
        .root
        .strip_prefix('/')
        .ok_or_else(|| Error("restore FSROOT required".into()))?;
    crate::identity::safe_id(name)?;
    require(
        name.len() <= 81
            && !name.contains('/')
            && [
                "root_subvol",
                "home_subvol",
                "authority_subvol",
                "control_subvol",
            ]
            .iter()
            .all(|k| configuration[*k] != name),
        "restore target overlaps protected storage",
    )?;
    crate::backup_destination::writable(row)?;
    Ok(name.into())
}
struct Target {
    path: &'static str,
    readonly: std::cell::Cell<bool>,
    copying: std::cell::Cell<Option<u32>>,
    final_mode: std::cell::Cell<bool>,
    directory: File,
    shape: (u64, u64, u32, u32, u32),
    flags: i32,
    mount: u64,
    row: mountinfo::Row,
    name: String,
    filesystem: Value,
    object: Value,
}
impl Target {
    fn observe(guard: &Source<'_>, uuid: &str) -> Result<Self> {
        Self::observe_at(guard, uuid, TARGET, None, true)
    }
    fn observe_at(
        guard: &Source<'_>,
        uuid: &str,
        path: &'static str,
        expected: Option<&str>,
        empty: bool,
    ) -> Result<Self> {
        Self::observe_at_state(guard, uuid, path, expected, empty, false)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn observe_at_state(
        guard: &Source<'_>,
        uuid: &str,
        path: &'static str,
        expected: Option<&str>,
        empty: bool,
        readonly_expected: bool,
    ) -> Result<Self> {
        crate::identity::uuid(uuid)?;
        guard.recheck()?;
        let directory = files::directory(Path::new(path), Some(0))?;
        let m = directory.metadata()?;
        require(
            m.ino() == 256
                && m.uid() == 0
                && m.gid() == 0
                && (m.mode() & 0o7777 == 0o700
                    || (!empty && expected.is_some() && m.mode() & 0o7777 == 0o755)),
            "private new restore subvolume required",
        )?;
        let shape = (m.dev(), m.ino(), m.mode(), m.uid(), m.gid());
        let flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0 && flags & (libc::O_ACCMODE | libc::O_PATH) == libc::O_RDONLY,
            "restore descriptor role",
        )?;
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let normal = mount_identity::id(directory.as_fd(), false)?;
        let rows = storage_runtime::rows()?;
        let matching = rows.iter().filter(|r| r.target == path).collect::<Vec<_>>();
        require(
            matching.len() == 1
                && matching[0].id == normal
                && !rows
                    .iter()
                    .any(|r| r.target.starts_with(&format!("{path}/"))),
            "restore mount missing, covered or nested",
        )?;
        let row = matching[0].clone();
        require(
            !rows.iter().any(|other| {
                other.id != row.id
                    && (other.major, other.minor, other.root.as_str())
                        == (row.major, row.minor, row.root.as_str())
            }),
            "restore object has another mounted alias; live data must remain untouched",
        )?;
        let name = if let Some(expected) = expected {
            require(
                matches!(
                    (path, expected),
                    ("/restore-system", "enzimos-root") | ("/restore-home", "enzimos-home")
                ),
                "closed replacement role required",
            )?;
            require(
                row.filesystem == "btrfs" && row.root == format!("/{expected}"),
                "replacement mount name differs",
            )?;
            crate::backup_destination::writable(&row)?;
            expected.to_owned()
        } else {
            target_name(&row, guard.configuration())?
        };
        let filesystem = filesystem::observe(directory.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == guard.configuration()["filesystem_uuid"],
            "restore filesystem differs from configured protected storage",
        )?;
        let (object, readonly) = subvolume::observe(directory.as_fd(), &name)?;
        require(
            object["uuid"] == uuid
                && object["parent_uuid"].is_null()
                && readonly == readonly_expected,
            "restore object differs, is a snapshot or readonly",
        )?;
        require(
            !empty || files::directory_names(&directory, 1)?.is_empty(),
            "restore target must be empty; no partial-stage replay",
        )?;
        let this = Self {
            path,
            readonly: std::cell::Cell::new(readonly_expected),
            copying: std::cell::Cell::new(None),
            final_mode: std::cell::Cell::new(false),
            directory,
            shape,
            flags,
            mount,
            row,
            name,
            filesystem,
            object,
        };
        this.recheck(guard)?;
        Ok(this)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn recheck(&self, guard: &Source<'_>) -> Result<()> {
        guard.recheck()?;
        let path = self.path;
        let named = files::directory(Path::new(path), Some(0))?;
        for directory in [&self.directory, &named] {
            let m = directory.metadata()?;
            require(
                (m.dev(), m.ino(), m.uid(), m.gid())
                    == (self.shape.0, self.shape.1, self.shape.3, self.shape.4)
                    && if self.final_mode.get() {
                        m.mode() & 0o7777 == 0o755
                    } else {
                        m.mode() == self.shape.2 || (self.copying.get() == Some(m.mode() & 0o7777))
                    }
                    && mount_identity::id(directory.as_fd(), true)? == self.mount
                    && filesystem::observe(directory.as_fd())? == self.filesystem,
                "original restore mount/object replaced or changed",
            )?;
            require(
                subvolume::observe(directory.as_fd(), &self.name)?
                    == (self.object.clone(), self.readonly.get()),
                "original restore subvolume identity or readonly state changed",
            )?;
        }
        require(
            unsafe { libc::fcntl(self.directory.as_raw_fd(), libc::F_GETFL) } == self.flags,
            "restore shared description flags changed",
        )?;
        let rows = storage_runtime::rows()?;
        let matching = rows.iter().filter(|r| r.target == path).collect::<Vec<_>>();
        require(
            matching == [&self.row]
                && !rows
                    .iter()
                    .any(|r| r.target.starts_with(&format!("{path}/"))),
            "restore mount changed during staging",
        )?;
        require(
            !rows.iter().any(|other| {
                other.id != self.row.id
                    && (other.major, other.minor, other.root.as_str())
                        == (self.row.major, self.row.minor, self.row.root.as_str())
            }),
            "another restore alias appeared",
        )?;
        if self.path == TARGET {
            target_name(&self.row, guard.configuration())?;
        } else {
            crate::backup_destination::writable(&self.row)?;
        }
        Ok(())
    }
    fn evidence(&self, guard: &Source<'_>) -> Result<Value> {
        self.recheck(guard)?;
        Ok(
            value!({"filesystem_uuid":self.filesystem["filesystem_uuid"],"mount":{"mount_id":self.row.id,"unique_mount_id":self.mount,
            "device":format!("{}:{}",self.row.major,self.row.minor),"root":self.row.root,"target":self.path,"fstype":"btrfs"},"object":self.object}),
        )
    }
}
fn selected(code: Option<i32>, bytes: &[u8], snapshot: &str) -> Result<String> {
    require(code == Some(0), "restore snapshot authentication failed")?;
    let rows = json::decode(bytes, 4 * 1024 * 1024)?;
    let rows = rows
        .as_array()
        .ok_or_else(|| Error("restore inventory array".into()))?;
    require(rows.len() <= 10000, "restore inventory count")?;
    let mut ids = std::collections::BTreeSet::new();
    let mut selected = None;
    for row in rows {
        let id = crate::recovery_records::text(row, "id")?;
        crate::identity::sha(id)?;
        require(ids.insert(id), "duplicate restore snapshot ID")?;
        if id == snapshot {
            crate::backup_points::scope(row, id)?;
            selected = Some(json::fingerprint(row)?);
        }
    }
    selected.ok_or_else(|| Error("explicit restore snapshot not found".into()))
}
fn validate(v: &Value, id: &str) -> Result<()> {
    json::fields(v, "schema phase snapshot target_uuid target")?;
    crate::identity::uuid(id)?;
    require(
        v["schema"] == 1
            && v["target_uuid"] == id
            && matches!(v["phase"].as_str(), Some("prepared" | "staged")),
        "system stage receipt schema/identity/phase",
    )?;
    crate::identity::sha(crate::recovery_records::text(v, "snapshot")?)?;
    json::fields(&v["target"], "filesystem_uuid mount object")?;
    crate::identity::uuid(crate::recovery_records::text(
        &v["target"],
        "filesystem_uuid",
    )?)?;
    require(
        v["target"]["object"]["uuid"] == id && v["target"]["object"]["parent_uuid"].is_null(),
        "system stage object receipt differs",
    )?;
    Ok(())
}
fn validate_complete(v: &Value, id: &str) -> Result<()> {
    let phase = v["phase"]
        .as_str()
        .ok_or_else(|| Error("complete stage phase required".into()))?;
    let fields = match phase {
        "prepared" | "staged" => "schema phase snapshot target_uuid target",
        "publishing" | "data-prepared-not-bootable" => {
            "schema phase snapshot target_uuid target replacement"
        }
        "boot-preparing" | "uefi-boot-prepared" => {
            "schema phase snapshot target_uuid target replacement boot_mount"
        }
        _ => return Err(Error("unknown complete stage phase".into())),
    };
    json::fields(v, fields)?;
    let mut base = v.clone();
    base.as_object_mut().unwrap().remove("replacement");
    base.as_object_mut().unwrap().remove("boot_mount");
    base["phase"] = value!("staged");
    validate(&base, id)?;
    if let Some(replacement) = v.get("replacement") {
        json::fields(replacement, "root home layout")?;
        for role in ["root", "home"] {
            json::fields(&replacement[role], "object mount")?;
            let object = &replacement[role]["object"];
            json::fields(object, "path id uuid parent_uuid")?;
            crate::identity::uuid(crate::recovery_records::text(object, "uuid")?)?;
            require(
                object["path"] == format!("enzimos-{role}")
                    && object["id"].as_u64().is_some_and(|id| id >= 256)
                    && object["parent_uuid"].is_null(),
                "complete replacement receipt object differs",
            )?;
        }
        require(
            replacement["root"]["object"]["uuid"] != replacement["home"]["object"]["uuid"]
                && replacement["root"]["object"]["uuid"] != id
                && replacement["home"]["object"]["uuid"] != id,
            "complete replacement receipt aliases another object",
        )?;
        require(
            replacement["layout"]["schema"] == 1
                && replacement["layout"]["authority_replayed"] == false
                && replacement["layout"]["automatic_backup_enabled"] == false,
            "complete layout receipt differs",
        )?;
    }
    Ok(())
}
pub fn stage_locked(
    guard: &Guard,
    lock: &files::Lock,
    snapshot: &str,
    uuid: &str,
) -> Result<Value> {
    stage(&Source::Live(guard), lock, snapshot, uuid, false)
}
/// Select actual root filesystem type; complete staging admits RAM only.
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatfs).")]
pub fn stage_auto_locked(
    lock: &files::Lock,
    snapshot: &str,
    uuid: &str,
    complete: bool,
) -> Result<Value> {
    operation::root_only()?;
    crate::namespaces::initial()?;
    lock.recheck()?;
    let root = files::directory(Path::new("/"), Some(0))?;
    let mut status: libc::statfs = unsafe { std::mem::zeroed() };
    require(
        unsafe { libc::fstatfs(root.as_raw_fd(), &mut status) } == 0,
        "actual restore root type unavailable",
    )?;
    if matches!(status.f_type, 0x01021994 | 0x858458f6) {
        let original = crate::backup_ram_source::Source::observe()?;
        stage(&Source::Ram(&original), lock, snapshot, uuid, complete)
    } else {
        require(
            !complete,
            "complete restore requires independent RAM recovery",
        )?;
        let original = Guard::observe()?;
        stage_locked(&original, lock, snapshot, uuid)
    }
}
fn stage(
    guard: &Source<'_>,
    lock: &files::Lock,
    snapshot: &str,
    uuid: &str,
    complete: bool,
) -> Result<Value> {
    let folder = if complete {
        "backup-complete-stages"
    } else {
        "backup-system-stages"
    };
    let capacity = if complete { 16 } else { 32 };
    operation::root_only()?;
    crate::namespaces::initial()?;
    guard.recheck()?;
    lock.recheck()?;
    let recipe = local_restic::RestoreSystem::new(snapshot)?;
    let complete_recipe = local_restic::RestoreComplete::new(snapshot)?;
    crate::identity::uuid(uuid)?;
    let parent = files::ensure_directory_relative(guard.control(), Path::new(folder), 0o700, 0)?;
    require(
        parent.metadata()?.mode() & 0o7777 == 0o700
            && mount_identity::id(parent.as_fd(), true)? == guard.control_mount_id(),
        "private system stage registry required",
    )?;
    let parent_shape = {
        let m = parent.metadata()?;
        (m.dev(), m.ino(), m.mode(), m.uid(), m.gid())
    };
    let mut old = BTreeMap::new();
    let mut originals = BTreeMap::new();
    for leaf in files::directory_names(&parent, capacity)? {
        let leaf = leaf
            .into_string()
            .map_err(|_| Error("stage registry filename encoding".into()))?;
        let id = leaf
            .strip_suffix(".json")
            .ok_or_else(|| Error("unknown/interrupted stage registry member".into()))?;
        crate::identity::uuid(id)?;
        let original = crate::control_record::Observation::open(
            &parent,
            Path::new(&leaf),
            256 * 1024,
            guard.control_mount_id(),
        )?;
        if complete {
            validate_complete(original.value()?, id)?;
        } else {
            validate(original.value()?, id)?;
        }
        require(
            matches!(
                original.value()?["phase"].as_str(),
                Some("staged" | "data-prepared-not-bootable" | "uefi-boot-prepared")
            ) && id != uuid,
            "existing or uncertain stage requires review; no replay",
        )?;
        old.insert(id.to_owned(), original.value()?.clone());
        originals.insert(id.to_owned(), original);
    }
    require(old.len() < capacity, "stage registry capacity exhausted")?;
    let family = |selected: bool| {
        let mut expected = old
            .keys()
            .map(|id| format!("{id}.json"))
            .collect::<std::collections::BTreeSet<_>>();
        if selected {
            expected.insert(format!("{uuid}.json"));
        }
        let actual = files::directory_names(&parent, capacity + 1)?
            .into_iter()
            .map(|n| {
                n.into_string()
                    .map_err(|_| Error("system stage registry encoding".into()))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        require(
            actual == expected,
            "system stage registry namespace changed",
        )
    };
    family(false)?;
    let quiet = Quiet::observe(guard)?;
    let config = Configuration::open()?;
    let destination = Backup::open(&config, guard)?;
    let pin = Pin::open(&destination)?;
    let credential = Credential::open()?;
    let image = Image::open()?;
    let target = Target::observe(guard, uuid)?;
    require(
        target.filesystem["filesystem_uuid"] != config.value()["destination_uuid"],
        "restore target overlaps backup filesystem",
    )?;
    let repository = destination.repository()?;
    let password = File::from(credential.descriptor()?.try_clone_to_owned()?);
    let header = Header::observe(&repository)?;
    let source = || {
        operation::root_only()?;
        crate::namespaces::initial()?;
        lock.recheck()?;
        guard.recheck()?;
        quiet.recheck(guard)?;
        config.recheck()?;
        destination.recheck()?;
        pin.recheck()?;
        credential.recheck()?;
        image.evidence()?;
        header.recheck(&repository)?;
        target.recheck(guard)?;
        let named = files::directory_relative(guard.control(), Path::new(folder), Some(0))?;
        require(
            {
                let m = named.metadata()?;
                (m.dev(), m.ino(), m.mode(), m.uid(), m.gid())
            } == parent_shape
                && {
                    let m = parent.metadata()?;
                    (m.dev(), m.ino(), m.mode(), m.uid(), m.gid())
                } == parent_shape
                && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
            "system stage registry replaced/covered",
        )?;
        for original in originals.values() {
            original.recheck()?;
        }
        Ok(())
    };
    let runtime = Runtime::create(&files::random_hex(16)?, &mut || source())?;
    require(
        runtime.image_evidence()? == image.evidence()?,
        "system staging original image changed",
    )?;
    let ongoing = || {
        source()?;
        runtime.recheck()
    };
    let query = local_restic::rotation_read(
        RotationTask::Points,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || ongoing(),
    )?;
    ongoing()?;
    runtime.empty()?;
    let snapshot_binding = selected(query.status.code(), &query.stdout, snapshot)?;
    let mut record = value!({"schema":1,"phase":"prepared","snapshot":snapshot,"target_uuid":uuid,"target":target.evidence(guard)?});
    validate(&record, uuid)?;
    let path = Path::new(operation::CONTROL)
        .join(folder)
        .join(format!("{uuid}.json"));
    let pending =
        publication::Prepared::write_authorized(&path, &json::canonical(&record)?, 0, &mut || {
            ongoing()
        })?;
    let mut receipt =
        publication::Chain::new(pending.commit_retained_authorized(false, &mut || ongoing())?)?;
    let entered = || {
        ongoing()?;
        receipt.recheck()?;
        family(true)
    };
    require(
        files::directory_names(&target.directory, 1)?.is_empty(),
        "restore target changed before sole vendor entry",
    )?;
    let output = if complete {
        local_restic::restore_complete(
            &complete_recipe,
            image.descriptor()?,
            &repository,
            &password,
            &target.directory,
            &runtime.scratch,
            &mut || entered(),
        )?
    } else {
        local_restic::restore_system(
            &recipe,
            image.descriptor()?,
            &repository,
            &password,
            &target.directory,
            &runtime.scratch,
            &mut || entered(),
        )?
    };
    entered()?;
    runtime.empty()?;
    require(
        output.status.code() == Some(0),
        "system staging failed or uncertain; prepared receipt retained",
    )?;
    let after = local_restic::rotation_read(
        RotationTask::Points,
        image.descriptor()?,
        &repository,
        &password,
        &runtime.scratch,
        &mut || entered(),
    )?;
    entered()?;
    runtime.empty()?;
    require(
        selected(after.status.code(), &after.stdout, snapshot)? == snapshot_binding,
        "original authenticated restore snapshot changed",
    )?;
    subvolume::sync(target.directory.as_fd())?;
    entered()?;
    record["phase"] = value!("staged");
    receipt.replace(&json::canonical(&record)?, &mut || ongoing())?;
    receipt.recheck()?;
    ongoing()?;
    family(true)?;
    Ok(
        value!({"status":if complete { "restored-staged-complete-not-activated" } else { "restored-staged-system-not-activated" },"snapshot":snapshot,"target_uuid":uuid,"home_staged":complete,
        "home_overwritten":false,"authority_overwritten":false,"workers_enabled":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_snapshot_must_authenticate_exact_whole_system_scope() {
        let id = "a".repeat(64);
        let mut row = value!({"id":id,"hostname":"enzimos","tags":["enzimos-whole-linux"],"paths":["/backup-source/system","/backup-source/home","/backup-source/boot","/backup-source/inventory"]});
        selected(Some(0), &json::canonical(&value!([row])).unwrap(), &id).unwrap();
        assert!(selected(Some(12), b"[]", &id).is_err());
        row["paths"] = value!([
            "/backup-source/system",
            "/backup-source/home",
            "/backup-source/boot",
            "/root"
        ]);
        assert!(selected(Some(0), &json::canonical(&value!([row])).unwrap(), &id).is_err());
    }
}
