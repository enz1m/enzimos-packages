// SPDX-License-Identifier: MIT
//! New image publication checkpoints origin before exclusive artifact creation.
use crate::{
    boot_entries,
    boot_volume::Volume,
    native_policy_files, operation, recovery_boot, recovery_image as images,
    recovery_journal::{Journal, Kind},
    recovery_records as records, signed_entry, subvolume,
    transition_idle::Snapshot,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
pub(crate) const INPUT: &str = "/run/enzimos/recovery-image-input";
struct Input {
    directory: File,
    identity: files::FileIdentity,
    unique: u64,
    manifest: Value,
    files: BTreeMap<String, (File, files::FileIdentity)>,
}
impl Input {
    fn observe() -> Result<Self> {
        let directory = files::directory(Path::new(INPUT), Some(0))?;
        require(
            directory.metadata()?.mode() & 0o7777 == 0o700,
            "private recovery input required",
        )?;
        let identity = files::identity(&directory.metadata()?);
        let unique = mount_identity::id(directory.as_fd(), true)?;
        let members = files::directory_names(&directory, 3)?
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        require(
            members
                == ["kernel", "initrd.img", "manifest.json"]
                    .map(std::ffi::OsString::from)
                    .into_iter()
                    .collect(),
            "unexpected recovery input members",
        )?;
        let manifest_file = files::open_relative(&directory, Path::new("manifest.json"))?;
        let manifest = json::decode(
            &files::read_file(&manifest_file, 2 * 1024 * 1024, Some(0), true)?,
            2 * 1024 * 1024,
        )?;
        images::manifest(&manifest)?;
        require(
            manifest["identity"]["schema"] == 2,
            "new publication requires native recovery image",
        )?;
        let mut files = BTreeMap::new();
        for name in ["kernel", "initrd.img", "manifest.json"] {
            let file = files::open_relative(&directory, Path::new(name))?;
            let identity = files::identity(&file.metadata()?);
            files.insert(name.into(), (file, identity));
        }
        let input = Self {
            directory,
            identity,
            unique,
            manifest,
            files,
        };
        input.recheck()?;
        Ok(input)
    }
    fn recheck(&self) -> Result<()> {
        let named = files::directory(Path::new(INPUT), Some(0))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.directory.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.unique
                && mount_identity::id(self.directory.as_fd(), true)? == self.unique,
            "recovery input directory changed",
        )?;
        for (name, (file, identity)) in &self.files {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&named.metadata()?) == *identity
                    && files::identity(&file.metadata()?) == *identity
                    && mount_identity::id(named.as_fd(), true)? == self.unique
                    && mount_identity::id(file.as_fd(), true)? == self.unique,
                "recovery input file changed",
            )?;
            if name != "manifest.json" {
                let body = files::read_file(file, images::MAX_IMAGE as usize, Some(0), true)?;
                let row = &self.manifest["files"][name];
                require(
                    row["bytes"] == body.len() && row["sha256"] == json::sha256(&body),
                    "recovery input digest differs",
                )?;
            } else {
                require(
                    json::decode(
                        &files::read_file(file, 2 * 1024 * 1024, Some(0), true)?,
                        2 * 1024 * 1024,
                    )? == self.manifest,
                    "recovery input manifest changed",
                )?;
            }
        }
        Ok(())
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
    fn archive(&self, id: &str) -> Result<()> {
        self.recheck()?;
        let parent = files::directory(Path::new("/run/enzimos"), Some(0))?;
        let old = c"recovery-image-input";
        let name = format!("recovery-image-input-published-{id}");
        let new = CString::new(name.as_str())
            .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
        require(
            // SAFETY: Both names are NUL-terminated and the parent descriptor stays open.
            unsafe {
                libc::renameat2(
                    parent.as_raw_fd(),
                    old.as_ptr(),
                    parent.as_raw_fd(),
                    new.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "published input archival uncertain; no replay",
        )?;
        parent.sync_all()?;
        let archived = files::directory(&Path::new("/run/enzimos").join(&name), Some(0))?;
        let after = files::identity(&archived.metadata()?);
        let mut expected = self.identity;
        expected.5 = after.5;
        expected.6 = after.6;
        require(
            after == expected && files::identity(&self.directory.metadata()?) == after,
            "archived publication input replaced; retained",
        )?;
        for (name, (_, identity)) in &self.files {
            require(
                files::identity(&files::open_relative(&archived, Path::new(name))?.metadata()?)
                    == *identity,
                "archived publication member replaced; retained",
            )?;
        }
        Ok(())
    }
}
fn text(volume: &Volume, name: &str) -> Result<String> {
    let file = volume.artifact(Path::new(name), boot_entries::MAX_TEXT as u64)?;
    let body = files::read_file(&file.file, boot_entries::MAX_TEXT, Some(0), true)?;
    file.recheck()?;
    String::from_utf8(body).map_err(|_| Error("recovery publication loader encoding".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
fn space(volume: &Volume, needed: u64) -> Result<()> {
    // SAFETY: `libc::statvfs` is a plain C struct, for which all-zero bytes are a valid value.
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    require(
        // SAFETY: `info` is a writable `libc::statvfs` and `volume.directory` keeps the descriptor
        // open.
        unsafe { libc::fstatvfs(volume.directory.as_raw_fd(), &mut info) } == 0
            && (info.f_bavail as u64)
                .checked_mul(info.f_frsize as u64)
                .is_some_and(|n| n >= needed),
        "recovery publication ESP headroom",
    )
}
fn folder(volume: &Volume, name: &str, create: bool) -> Result<File> {
    let path = volume.path(Path::new(name))?;
    let file = if create {
        // The protected FAT volume synthesizes private directory permissions.
        // Derive that mode from the retained volume, keeping exact mode checks.
        let mode = files::public_directory_mode(&volume.directory)?;
        files::ensure_directory(&path, mode, 0)?
    } else {
        files::directory(&path, Some(0))?
    };
    require(
        mount_identity::id(file.as_fd(), true)? == volume.unique,
        "recovery image folder crosses another mount",
    )?;
    volume.recheck()?;
    Ok(file)
}
pub fn publish_locked(options: &str, lock: &files::Lock) -> Result<Value> {
    records::command_line(options)?;
    require(
        !options
            .split_whitespace()
            .any(|w| w.starts_with("enzimos.")),
        "caller must not supply a recovery family marker",
    )?;
    let input = Input::observe()?;
    let id = images::image_id(&input.manifest["identity"])?;
    let mut idle = Snapshot::publication(&id)?;
    require(
        matches!(std::fs::symlink_metadata("/var/lib/pacman/db.lck"),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "package transaction prevents recovery publication",
    )?;
    require(
        native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?
            == input.manifest["identity"]["policy_files"],
        "native image policy differs from publisher",
    )?;
    let volume = Volume::observe()?;
    volume.writable()?;
    let config = &idle.guard.configuration;
    let control = subvolume::observe(
        idle.guard.control().as_fd(),
        records::text(config, "control_subvol")?,
    )?
    .0;
    let options = format!("{} enzimos.recovery={id}", options.trim());
    let mut record = value!({"schema":1,"id":id,"phase":"intent","created_boot":operation::boot_id()?,
        "filesystem_uuid":config["filesystem_uuid"],"control":control,"boot_uuid":volume.uuid,
        "inputs":input.manifest,"options":options,"observations":{}});
    images::validate(&record, &id)?;
    let (entry, title) = images::entry_names(&id)?;
    let relative = format!("enzimos/recovery-images/{id}");
    let entry_path = format!("loader/entries/{entry}");
    for name in [&relative, &entry_path] {
        require(
            matches!(std::fs::symlink_metadata(volume.path(Path::new(name))?),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "existing recovery image or entry cannot be adopted",
        )?;
    }
    for name in ["loader", "loader/entries", "limine"] {
        folder(&volume, name, false)?;
    }
    let defaults = text(&volume, "loader/loader.conf")?;
    let bios = text(&volume, "limine/limine.conf")?;
    let selected = boot_entries::fields(&defaults, false)?
        .get("default")
        .cloned()
        .ok_or_else(|| Error("literal recovery publication default missing".into()))?;
    records::literal_entry(&selected)?;
    recovery_boot::replace_default(&defaults, "default ", &selected)?;
    require(
        boot_entries::menu(&bios)?
            .entries
            .iter()
            .all(|r| r.title != title),
        "existing BIOS recovery entry cannot be adopted",
    )?;
    let needed = input.manifest["files"]
        .as_object()
        .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
        .values()
        .map(|r| enzimos_platform::json::unsigned(&r["bytes"]))
        .sum::<Result<u64>>()?
        + 16 * 1024 * 1024;
    space(&volume, needed)?;
    let mut publications = Journal::open(Kind::Publications, true)?;
    let mut registry = Journal::open(Kind::Images, true)?;
    let mut publication =
        value!({"schema":1,"record":record,"bios_before":bios,"default_before":defaults});
    publication["journal_sha256"] = value!(json::fingerprint(&publication)?);
    idle.recheck()?;
    input.recheck()?;
    volume.recheck()?;
    publications.save(&id, publication.clone(), None, lock)?;
    idle.publication_checkpoint(&id, None, Some(&publication))?;
    registry.save(&id, record.clone(), None, lock)?;
    idle.publication_checkpoint(&id, Some(&record), None)?;
    folder(&volume, "enzimos", true)?;
    let parent = folder(&volume, "enzimos/recovery-images", true)?;
    std::fs::create_dir(volume.path(Path::new(&relative))?)?;
    let target = folder(&volume, &relative, false)?;
    let public_mode = files::public_file_mode(&target)?;
    for name in ["kernel", "initrd.img"] {
        idle.recheck()?;
        input.recheck()?;
        volume.writable()?;
        let row = &input.manifest["files"][name];
        let mut file = input.files[name].0.try_clone()?;
        stream_copy::verified(
            &mut file,
            &target,
            name,
            enzimos_platform::json::unsigned(&row["bytes"])?,
            records::text(row, "sha256")?,
            0,
        )?;
        volume.recheck()?;
        input.recheck()?;
    }
    let mut descriptor = json::canonical(&input.manifest["identity"])?;
    descriptor.push(b'\n');
    files::atomic(
        &volume.path(Path::new(&format!("{relative}/identity.json")))?,
        &descriptor,
        public_mode,
        Some(0),
        false,
    )?;
    target.sync_all()?;
    parent.sync_all()?;
    volume.directory.sync_all()?;
    images::verify_artifacts(&record)?;
    idle.recheck()?;
    let intent = record.clone();
    record["phase"] = value!("artifacts");
    registry.save(&id, record.clone(), Some(&intent), lock)?;
    idle.publication_checkpoint(&id, Some(&record), None)?;
    require(
        text(&volume, "loader/loader.conf")? == defaults
            && text(&volume, "limine/limine.conf")? == bios,
        "boot metadata changed during image creation",
    )?;
    let (uefi, addition) = images::entry_texts(&id, &options)?;
    let uefi = signed_entry::wrap_locked(&uefi, lock)?;
    idle.recheck()?;
    publications.unchanged()?;
    volume.writable()?;
    files::atomic(
        &volume.path(Path::new(&entry_path))?,
        uefi.as_bytes(),
        public_mode,
        Some(0),
        false,
    )?;
    idle.recheck()?;
    publications.unchanged()?;
    volume.writable()?;
    require(
        text(&volume, "limine/limine.conf")? == bios
            && text(&volume, "loader/loader.conf")? == defaults,
        "image loader baseline changed",
    )?;
    let next = format!("{}\n{addition}", bios.trim_end());
    boot_entries::menu(&next)?;
    files::atomic(
        &volume.path(Path::new("limine/limine.conf"))?,
        next.as_bytes(),
        public_mode,
        Some(0),
        true,
    )?;
    images::verify_published(&record)?;
    require(
        text(&volume, "loader/loader.conf")? == defaults,
        "image publication changed default",
    )?;
    idle.recheck()?;
    publications.unchanged()?;
    let artifacts = record.clone();
    record["phase"] = value!("ready");
    registry.save(&id, record.clone(), Some(&artifacts), lock)?;
    idle.publication_checkpoint(&id, Some(&record), None)?;
    input.archive(&id)?;
    Ok(
        value!({"id":id,"phase":"ready","boot_uuid":volume.uuid,"selection_changed":false,
        "retirement_enabled":false,"assurance":"publisher-origin-only-unconfirmed"}),
    )
}
