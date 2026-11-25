// SPDX-License-Identifier: MIT
//! Explicit journal-bound loader continuation; image and package creation never replay.
use crate::{
    boot_entries,
    boot_volume::{Artifact, ReplacedArtifact, Volume},
    native_policy_files, operation, recovery_image,
    recovery_journal::{Journal, Kind},
    recovery_publication::{self, State},
    recovery_records, signed_entry,
    transition_idle::Snapshot,
};
use enzimos_platform::{
    Error, Result, files, mount_identity,
    publication::{Committed, Prepared},
    require,
};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
struct Directory {
    file: File,
    relative: String,
    shape: (u64, u64, u32, u32, u32),
    flags: i32,
    names: BTreeSet<String>,
}
fn names(file: &File) -> Result<BTreeSet<String>> {
    files::directory_names(file, 1024)?
        .into_iter()
        .map(|n| {
            n.into_string()
                .map_err(|_| Error("loader directory name encoding".into()))
        })
        .collect()
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "protected original loader parent required",
    )?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
impl Directory {
    fn observe(volume: &Volume, relative: &str) -> Result<Self> {
        let file = volume.directory(Path::new(relative))?;
        Ok(Self {
            shape: shape(&file)?,
            flags: enzimos_platform::files::status_flags(&file),
            names: names(&file)?,
            file,
            relative: relative.into(),
        })
    }
    fn recheck(&self, volume: &Volume, pending: Option<&str>) -> Result<()> {
        let named = volume.directory(Path::new(&self.relative))?;
        let mut expected = self.names.clone();
        if let Some(p) = pending {
            require(
                expected.insert(p.into()),
                "pending loader name already present",
            )?;
        }
        require(
            shape(&self.file)? == self.shape
                && shape(&named)? == self.shape
                && enzimos_platform::files::status_flags(&self.file) == self.flags
                && mount_identity::id(self.file.as_fd(), true)? == volume.unique
                && mount_identity::id(named.as_fd(), true)? == volume.unique
                && names(&self.file)? == expected
                && names(&named)? == expected,
            "original loader parent or membership changed",
        )
    }
    fn advance_new(&mut self, volume: &Volume, leaf: &str, producer: &Committed) -> Result<()> {
        producer.require_destination(&self.file, Path::new(leaf))?;
        require(
            self.names.insert(leaf.into()),
            "loader member was not originally absent",
        )?;
        self.recheck(volume, None)
    }
}
enum Bios {
    Original(Artifact),
    Replaced(ReplacedArtifact),
}
impl Bios {
    fn recheck(&self) -> Result<()> {
        match self {
            Self::Original(a) => a.recheck(),
            Self::Replaced(a) => a.recheck(),
        }
    }
}
struct Admission {
    id: String,
    journal: Journal,
    images: Journal,
    idle: Snapshot,
    runtime: native_policy_files::Original,
    artifacts: recovery_image::Artifacts,
    volume: Volume,
    defaults: Artifact,
    bios: Option<Bios>,
    entry: Option<Artifact>,
    published_entry: Option<Committed>,
    entry_directory: Directory,
    bios_directory: Directory,
    signature: Option<signed_entry::Verification>,
    record: Value,
    intent: Value,
    uefi: String,
    bios_after: String,
    entry_name: String,
    uefi_state: State,
    bios_state: State,
}
fn body(artifact: &Artifact) -> Result<String> {
    String::from_utf8(files::read_file(
        &artifact.file,
        boot_entries::MAX_TEXT,
        Some(0),
        true,
    )?)
    .map_err(|_| Error("loader text encoding".into()))
}
fn legal_order(ready: bool, uefi: State, bios: State) -> Result<()> {
    require(
        !(bios == State::After && uefi == State::Before),
        "out-of-order loader publication",
    )?;
    require(
        !ready || (uefi == State::After && bios == State::After),
        "ready publication binding drift",
    )
}
impl Admission {
    fn observe(id: &str, lock: &files::Lock) -> Result<Self> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        recovery_image::identifier(id)?;
        lock.recheck()?;
        let journal = Journal::open(Kind::Publications, false)?;
        let intent = journal
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| Error("original publication intent missing".into()))?;
        recovery_publication::validate(&intent, id)?;
        let images = Journal::open(Kind::Images, false)?;
        let record = images
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| Error("original image checkpoint missing".into()))?;
        recovery_publication::expected_record(&intent, &record)?;
        let idle = Snapshot::publication_continuation(&journal, id)?;
        let runtime = native_policy_files::Original::retain()?;
        require(
            runtime.hashes()? == &record["inputs"]["identity"]["policy_files"],
            "original image policy differs from installed runtime",
        )?;
        let artifacts = recovery_image::retain_artifacts(&record)?;
        let volume = Volume::observe()?;
        require(
            volume.uuid == record["boot_uuid"],
            "publication boot filesystem differs",
        )?;
        let defaults = volume.artifact(
            Path::new("loader/loader.conf"),
            boot_entries::MAX_TEXT as u64,
        )?;
        require(
            body(&defaults)? == intent["default_before"],
            "selected default changed since intent",
        )?;
        let original_bios = volume.artifact(
            Path::new("limine/limine.conf"),
            boot_entries::MAX_TEXT as u64,
        )?;
        let (entry_name, _) = recovery_image::entry_names(id)?;
        let (plain, addition) =
            recovery_image::entry_texts(id, recovery_records::text(&record, "options")?)?;
        // Existing UKIs only: observation never invokes a signer or adopts an unrelated image.
        let uefi = signed_entry::render_existing(&plain)?;
        let signature = signed_entry::retain(&boot_entries::fields(&uefi, false)?)?;
        let bios_after = format!(
            "{}\n{addition}",
            recovery_records::text(&intent, "bios_before")?.trim_end()
        );
        boot_entries::menu(&bios_after)?;
        let entry_directory = Directory::observe(&volume, "loader/entries")?;
        let bios_directory = Directory::observe(&volume, "limine")?;
        for (directory, leaf) in [
            (&entry_directory, entry_name.as_str()),
            (&bios_directory, "limine.conf"),
        ] {
            require(
                !directory.names.contains(&format!("{leaf}.partial"))
                    && !directory.names.contains(&format!("{leaf}.new")),
                "interrupted loader publication requires review",
            )?;
        }
        let entry = if entry_directory.names.contains(&entry_name) {
            Some(volume.artifact(
                Path::new(&format!("loader/entries/{entry_name}")),
                boot_entries::MAX_TEXT as u64,
            )?)
        } else {
            None
        };
        let actual = entry.as_ref().map(body).transpose()?;
        let uefi_state =
            recovery_publication::classify(&value!(actual), &Value::Null, &value!(uefi))?;
        let bios_state = recovery_publication::classify(
            &value!(body(&original_bios)?),
            &intent["bios_before"],
            &value!(bios_after),
        )?;
        legal_order(record["phase"] == "ready", uefi_state, bios_state)?;
        let this = Self {
            id: id.into(),
            journal,
            images,
            idle,
            runtime,
            artifacts,
            volume,
            defaults,
            bios: Some(Bios::Original(original_bios)),
            entry,
            published_entry: None,
            entry_directory,
            bios_directory,
            signature,
            record,
            intent,
            uefi,
            bios_after,
            entry_name,
            uefi_state,
            bios_state,
        };
        this.recheck(lock, None, None)?;
        Ok(this)
    }
    fn recheck(
        &self,
        lock: &files::Lock,
        entry_pending: Option<&str>,
        bios_pending: Option<&str>,
    ) -> Result<()> {
        operation::root_only()?;
        crate::namespaces::initial()?;
        lock.recheck()?;
        self.idle.recheck()?;
        self.journal.unchanged()?;
        self.images.unchanged()?;
        self.runtime.recheck()?;
        self.artifacts.recheck()?;
        self.volume.recheck()?;
        self.defaults.recheck()?;
        self.bios
            .as_ref()
            .ok_or_else(|| Error("original BIOS actor missing".into()))?
            .recheck()?;
        if let Some(a) = &self.entry {
            a.recheck()?;
        }
        if let Some(a) = &self.published_entry {
            a.recheck()?;
        }
        if let Some(a) = &self.signature {
            a.recheck()?;
        }
        self.entry_directory.recheck(&self.volume, entry_pending)?;
        self.bios_directory.recheck(&self.volume, bios_pending)?;
        lock.recheck()
    }
    fn review(&self) -> Value {
        value!({"id":self.id,"journal_sha256":self.intent["journal_sha256"],"phase":self.record["phase"],"metadata_states":{"uefi":if self.uefi_state==State::Before{"before"}else{"after"},"bios":if self.bios_state==State::Before{"before"}else{"after"}},"resume_available":self.record["phase"]=="artifacts","artifact_replay_available":false,"selection_changes":false,"retirement_enabled":false})
    }
    fn execute(mut self, digest: &str, lock: &files::Lock) -> Result<Value> {
        crate::identity::sha(digest)?;
        require(
            self.intent["journal_sha256"] == digest,
            "stale publication journal digest",
        )?;
        self.recheck(lock, None, None)?;
        if self.record["phase"] == "ready" {
            return Ok(
                value!({"id":self.id,"status":"already-ready","retirement_enabled":false,"selection_changed":false}),
            );
        }
        if self.uefi_state == State::Before {
            self.volume.writable()?;
            let path = self
                .volume
                .path(Path::new(&format!("loader/entries/{}", self.entry_name)))?;
            let prepared = Prepared::write(&path, self.uefi.as_bytes(), 0)?;
            prepared
                .require_new_destination(&self.entry_directory.file, Path::new(&self.entry_name))?;
            let pending = prepared
                .pending_name(&self.entry_directory.file, Path::new(&self.entry_name))?
                .to_owned();
            self.recheck(lock, Some(&pending), None)?;
            self.volume.writable()?;
            let committed = prepared.commit_retained(false)?;
            self.entry_directory
                .advance_new(&self.volume, &self.entry_name, &committed)?;
            self.published_entry = Some(committed);
            self.uefi_state = State::After;
            self.recheck(lock, None, None)?;
        }
        if self.bios_state == State::Before {
            self.volume.writable()?;
            let prepared = Prepared::write(
                &self.volume.path(Path::new("limine/limine.conf"))?,
                self.bios_after.as_bytes(),
                0,
            )?;
            let Some(Bios::Original(original)) = self.bios.as_ref() else {
                return Err(Error("original BIOS publication actor required".into()));
            };
            original.require_original_publication(&prepared)?;
            let pending = prepared
                .pending_name(&self.bios_directory.file, Path::new("limine.conf"))?
                .to_owned();
            self.recheck(lock, None, Some(&pending))?;
            self.volume.writable()?;
            let committed = prepared.commit_retained(true)?;
            let Some(Bios::Original(original)) = self.bios.take() else {
                unreachable!()
            };
            self.bios = Some(Bios::Replaced(original.into_replaced(committed)?));
            self.bios_state = State::After;
            self.recheck(lock, None, None)?;
        }
        let published = recovery_image::Published::observe(&self.record)?;
        published.recheck()?;
        self.recheck(lock, None, None)?;
        let mut next = self.record.clone();
        next["phase"] = value!("ready");
        self.images
            .save(&self.id, next.clone(), Some(&self.record), lock)?;
        self.idle
            .publication_checkpoint(&self.id, Some(&next), None)?;
        self.record = next;
        self.recheck(lock, None, None)?;
        published.recheck()?;
        Ok(
            value!({"id":self.id,"status":"publication-resumed","artifact_bytes_replayed":false,"packages_replayed":false,"selection_changed":false,"retirement_enabled":false}),
        )
    }
}
pub fn review_locked(id: &str, lock: &files::Lock) -> Result<Value> {
    let original = Admission::observe(id, lock)?;
    let data = original.review();
    original.recheck(lock, None, None)?;
    Ok(data)
}
pub fn resume_locked(id: &str, digest: &str, lock: &files::Lock) -> Result<Value> {
    Admission::observe(id, lock)?.execute(digest, lock)
}
