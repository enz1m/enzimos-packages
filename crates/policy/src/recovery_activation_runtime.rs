// SPDX-License-Identifier: MIT
//! Offline activation publishes exact reviewed metadata with durable selection intent.
use crate::{
    boot_entries,
    boot_volume::Volume,
    identity, native_policy_files, operation,
    recovery_boot::{self as boot, Entries, Metadata, State},
    recovery_context::Context,
    recovery_journal::{Journal, Kind},
    recovery_records as records, recovery_stage, signed_entry,
    storage_runtime::IndependentGuard,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::path::Path;
pub(crate) const EFI: &str = "/sys/firmware/efi/efivars";
pub(crate) const GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
pub fn efi_guard() -> Result<bool> {
    match std::fs::symlink_metadata(EFI) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    files::directory(Path::new(EFI), Some(0))?;
    let suffix = format!("-{GUID}");
    let mut count = 0;
    for entry in std::fs::read_dir(EFI)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| Error("EFI variable name encoding".into()))?;
        if name.starts_with("LoaderEntry") && name.ends_with(&suffix) {
            count += 1;
            require(
                count <= 64
                    && matches!(
                        name.strip_suffix(&suffix),
                        Some("LoaderEntrySelected" | "LoaderEntryLastBooted")
                    ),
                "EFI selection override or unknown state requires review",
            )?;
            boot_entries::efi_string(&files::read_kernel(&entry.path(), 8192)?)?;
        }
    }
    Ok(true)
}
fn signed_entries(job: &Value, lock: &files::Lock) -> Result<Entries> {
    let mut entries = boot::entries(job)?;
    for text in entries.uefi.values_mut() {
        *text = signed_entry::wrap_locked(text, lock)?;
        signed_entry::verify(&boot_entries::fields(text, false)?)?;
    }
    Ok(entries)
}
pub(crate) fn metadata(volume: &Volume, entries: &Entries) -> Result<Metadata> {
    for relative in ["loader", "loader/entries", "limine"] {
        volume.directory(Path::new(relative))?;
        let children = std::fs::read_dir(volume.path(Path::new(relative))?)?
            .take(4097)
            .collect::<std::io::Result<Vec<_>>>()?;
        require(
            children.len() <= 4096
                && children.iter().all(|entry| {
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".enzimos-write-")
                }),
            "interrupted or excess boot metadata publication",
        )?;
    }
    let mut names = entries.sequence.clone();
    names.push("loader/loader.conf".into());
    let mut result = Metadata::new();
    for name in names {
        let path = volume.path(Path::new(&name))?;
        for suffix in [".partial", ".new"] {
            require(
                matches!(std::fs::symlink_metadata(path.with_file_name(format!("{}{suffix}",path.file_name().ok_or_else(|| enzimos_platform::Error("missing filename".into()))?.to_str().ok_or_else(|| enzimos_platform::Error("path encoding".into()))?))),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "interrupted activation metadata",
            )?;
        }
        let body = match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
            Ok(_) => {
                let held = volume.artifact(Path::new(&name), boot_entries::MAX_TEXT as u64)?;
                let bytes = files::read_file(&held.file, boot_entries::MAX_TEXT, Some(0), true)?;
                held.recheck()?;
                Some(
                    String::from_utf8(bytes)
                        .map_err(|_| Error("activation loader text encoding".into()))?,
                )
            }
        };
        require(
            body.is_some() || name.starts_with("loader/entries/"),
            "activation loader configuration absent",
        )?;
        result.insert(name, body);
    }
    volume.recheck()?;
    Ok(result)
}
fn idle(journal: &Journal, id: &str) -> Result<()> {
    require(
        journal.records.iter().all(|(name, v)| {
            name == id
                || matches!(
                    v["phase"].as_str(),
                    Some("published" | "selected" | "adopted")
                )
        }),
        "another unfinished activation requires review",
    )
}
fn compatible(context: &Context, expected: Option<&Value>) -> Result<Value> {
    let hashes = native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?;
    let target = Path::new(IndependentGuard::TOP)
        .join(records::text(&context.plan, "target_name")?)
        .join("usr/lib/enzimos-native");
    require(
        native_policy_files::observe(&target)? == hashes && expected.is_none_or(|v| *v == hashes),
        "restored native policy is incompatible; injection refused",
    )?;
    context.recheck()?;
    Ok(hashes)
}
fn verified(
    context: &Context,
    journal: &Journal,
    jobs: &Journal,
    record: &Value,
    entries: &Entries,
) -> Result<(Metadata, std::collections::BTreeMap<String, State>)> {
    let id = records::text(&record["intent"], "id")?;
    journal.unchanged()?;
    jobs.unchanged()?;
    idle(journal, id)?;
    require(
        jobs.records.get(id) == Some(&record["intent"]["job"])
            && jobs.records.values().all(|v| v["phase"] == "staged"),
        "activation staging record changed or incomplete",
    )?;
    require(
        recovery_stage::verify_staged(context, &record["intent"]["job"])?
            == record["intent"]["material"],
        "activation restored material changed",
    )?;
    compatible(context, Some(&record["intent"]["policy_files"]))?;
    let actual = metadata(&context.volume, entries)?;
    let states = boot::classify(record, entries, &actual)?;
    Ok((actual, states))
}
pub fn prepare_locked(id: &str, job_sha: &str, lock: &files::Lock) -> Result<Value> {
    identity::sha(job_sha)?;
    let job = recovery_stage::load_job(id)?;
    require(
        json::fingerprint(&job)? == job_sha,
        "stale staged job review",
    )?;
    let context = Context::observe(&job["plan"])?;
    let jobs = Journal::open_independent(Kind::Jobs, false, &job["plan"])?;
    let mut journal = Journal::open_independent(Kind::Activations, true, &job["plan"])?;
    idle(&journal, id)?;
    require(
        !journal.records.contains_key(id)
            && jobs.records.get(id) == Some(&job)
            && jobs.records.values().all(|v| v["phase"] == "staged"),
        "existing activation or unfinished staging cannot be adopted",
    )?;
    let material = recovery_stage::verify_staged(&context, &job)?;
    let policies = compatible(&context, None)?;
    let entries = signed_entries(&job, lock)?;
    let actual = metadata(&context.volume, &entries)?;
    require(
        actual
            .iter()
            .filter(|(name, _)| name.starts_with("loader/entries/"))
            .all(|(_, body)| body.is_none()),
        "existing staged entry cannot be adopted",
    )?;
    let default = boot::default_guard(
        actual["loader/loader.conf"]
            .as_deref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
        &entries,
    )?;
    context
        .volume
        .artifact(
            Path::new(&format!("loader/entries/{default}")),
            boot_entries::MAX_TEXT as u64,
        )?
        .recheck()?;
    efi_guard()?;
    let mut intent = value!({"schema":2,"id":id,"created_boot":operation::boot_id()?,"job":job,"material":material,"policy_files":policies,"bios_before":actual["limine/limine.conf"],"default_before":actual["loader/loader.conf"]});
    intent["intent_sha256"] = value!(json::fingerprint(&intent)?);
    let record = value!({"intent":intent,"phase":"prepared","selection":null,"observations":{}});
    boot::classify(&record, &entries, &actual)?;
    jobs.unchanged()?;
    journal.unchanged()?;
    context.recheck()?;
    require(
        metadata(&context.volume, &entries)? == actual,
        "activation metadata changed during preparation",
    )?;
    journal.save(id, record, None, lock)?;
    Ok(
        value!({"id":id,"intent_sha256":intent["intent_sha256"],"status":"activation-publication-prepared","selection_changed":false}),
    )
}
pub(crate) fn existing_entries(job: &Value) -> Result<Entries> {
    let mut entries = boot::entries(job)?;
    for text in entries.uefi.values_mut() {
        *text = signed_entry::render_existing(text)?;
    }
    Ok(entries)
}
fn load(
    id: &str,
    digest: &str,
    lock: &files::Lock,
) -> Result<(Context, Journal, Journal, Value, Entries)> {
    identity::sha(digest)?;
    let job = recovery_stage::load_job(id)?;
    let context = Context::observe(&job["plan"])?;
    let jobs = Journal::open_independent(Kind::Jobs, false, &job["plan"])?;
    let journal = Journal::open_independent(Kind::Activations, false, &job["plan"])?;
    let record = journal
        .records
        .get(id)
        .cloned()
        .ok_or_else(|| Error("activation not found".into()))?;
    require(
        record["intent"]["intent_sha256"] == digest,
        "stale activation intent",
    )?;
    let _ = lock;
    let entries = existing_entries(&record["intent"]["job"])?;
    verified(&context, &journal, &jobs, &record, &entries)?;
    Ok((context, journal, jobs, record, entries))
}
fn write(
    context: &Context,
    name: &str,
    text: &str,
    entries: &Entries,
    record: &Value,
    states: &std::collections::BTreeMap<String, State>,
) -> Result<()> {
    require(
        states.get(name) == Some(&State::Before),
        "activation write lacks exact before state",
    )?;
    context.volume.writable()?;
    let expected = boot::expected(
        &record["intent"],
        entries,
        (!record["selection"].is_null()).then_some(&record["selection"]),
    )?;
    require(
        expected.get(name).and_then(|v| v.as_deref()) == Some(text),
        "activation write differs from intent",
    )?;
    let path = context.volume.path(Path::new(name))?;
    files::atomic(
        &path,
        text.as_bytes(),
        files::public_file_mode(&context.volume.directory)?,
        Some(0),
        !name.starts_with("loader/entries/"),
    )?;
    context.volume.recheck()?;
    let actual = metadata(&context.volume, entries)?;
    require(
        actual.get(name).and_then(|v| v.as_deref()) == Some(text),
        "activation write readback differs",
    )?;
    boot::classify(record, entries, &actual)?;
    Ok(())
}
pub fn publish_locked<F: FnMut(&str) -> Result<()>>(
    id: &str,
    digest: &str,
    lock: &files::Lock,
    mut observer: F,
) -> Result<Value> {
    let (context, mut journal, jobs, mut record, entries) = load(id, digest, lock)?;
    require(
        matches!(record["phase"].as_str(), Some("prepared" | "published")),
        "activation already selecting",
    )?;
    if record["phase"] == "published" {
        return Ok(
            value!({"status":"already-published","selection_changed":false,"retirement_enabled":false}),
        );
    }
    let expected = boot::expected(&record["intent"], &entries, None)?;
    for name in &entries.sequence {
        let (_, states) = verified(&context, &journal, &jobs, &record, &entries)?;
        if states[name] == State::Before {
            write(
                &context,
                name,
                expected[name]
                    .as_deref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                &entries,
                &record,
                &states,
            )?;
        }
        observer(name)?;
    }
    require(
        verified(&context, &journal, &jobs, &record, &entries)?.0 == expected,
        "activation publication incomplete",
    )?;
    let previous = record.clone();
    record["phase"] = value!("published");
    journal.save(id, record, Some(&previous), lock)?;
    observer("published")?;
    Ok(
        value!({"status":"staged-entries-published","selection_changed":false,"artifacts_copied":false,"retirement_enabled":false}),
    )
}
pub fn select_locked<F: FnMut(&str) -> Result<()>>(
    id: &str,
    digest: &str,
    flavor: &str,
    lock: &files::Lock,
    mut observer: F,
) -> Result<Value> {
    records::flavor(flavor)?;
    let (context, mut journal, jobs, mut record, entries) = load(id, digest, lock)?;
    require(
        matches!(
            record["phase"].as_str(),
            Some("published" | "selecting" | "selected")
        ),
        "publish activation before selection",
    )?;
    let observable = efi_guard()?;
    require(
        record["selection"].is_null() || record["selection"]["flavor"] == flavor,
        "different selection requires new reviewed operation",
    )?;
    if record["phase"] == "selected" {
        return Ok(
            value!({"status":"already-selected-disk-defaults","efi_observable":observable,"retirement_enabled":false}),
        );
    }
    if record["phase"] == "published" {
        let previous = record.clone();
        let mut selection = value!({"flavor":flavor,"created_boot":operation::boot_id()?,"efi_observable":observable});
        selection["selection_sha256"] = value!(json::fingerprint(&selection)?);
        record["selection"] = selection;
        record["phase"] = value!("selecting");
        journal.save(id, record.clone(), Some(&previous), lock)?;
        observer("selection-intent")?;
    }
    let expected = boot::expected(&record["intent"], &entries, Some(&record["selection"]))?;
    for name in ["loader/loader.conf", "limine/limine.conf"] {
        let (_, states) = verified(&context, &journal, &jobs, &record, &entries)?;
        efi_guard()?;
        if states[name] == State::Before {
            write(
                &context,
                name,
                expected[name]
                    .as_deref()
                    .ok_or_else(|| enzimos_platform::Error("missing value".into()))?,
                &entries,
                &record,
                &states,
            )?;
        }
        observer(name)?;
    }
    require(
        verified(&context, &journal, &jobs, &record, &entries)?.0 == expected,
        "activation selection incomplete",
    )?;
    let previous = record.clone();
    record["phase"] = value!("selected");
    journal.save(id, record, Some(&previous), lock)?;
    observer("selected")?;
    Ok(
        value!({"status":"staged-disk-defaults-selected","efi_observable":observable,"firmware_override_state":if observable {"observed-no-override"} else {"unobservable-not-empty"},"effective_boot_confirmed":false,"retirement_enabled":false}),
    )
}
