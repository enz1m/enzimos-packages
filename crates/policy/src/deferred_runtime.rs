// SPDX-License-Identifier: MIT
//! Independent control storage and a dedicated lock serialize owed-run markers.
use crate::{control_record, control_registry, deferred, operation, storage_runtime::Guard};
use enzimos_platform::{Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn lock() -> Result<files::Lock> {
    operation::root_only()?;
    crate::storage_runtime::initial_namespace()?;
    files::ensure_directory(Path::new("/run/enzimos"), 0o700, 0)?;
    files::Lock::acquire(Path::new("/run/enzimos/deferred.lock"), 0)
}
fn markers(guard: &Guard) -> Result<std::collections::BTreeMap<String, Value>> {
    let records = control_registry::read_bounded(
        guard,
        "deferred",
        deferred::ACTIONS.len(),
        4096,
        deferred::validate,
    )?;
    // The legacy wire limit is 4096 bytes, even though the shared reader permits more.
    for record in records.values() {
        require(
            json::canonical(record)?.len() <= 4096,
            "deferred marker wire bound",
        )?;
    }
    Ok(records)
}
fn directory(guard: &Guard) -> Result<std::fs::File> {
    guard.recheck()?;
    let directory =
        files::ensure_directory(&Path::new(operation::CONTROL).join("deferred"), 0o700, 0)?;
    require(
        mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
        "deferred storage mount changed",
    )?;
    guard.recheck()?;
    Ok(directory)
}
fn original_directory(guard: &Guard, held: &std::fs::File, folder: &str) -> Result<()> {
    guard.recheck()?;
    let named = files::optional_directory_relative(guard.control(), Path::new(folder), Some(0))?
        .ok_or_else(|| enzimos_platform::Error("original deferred directory disappeared".into()))?;
    let a = held.metadata()?;
    let b = named.metadata()?;
    require(
        (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
            == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode())
            && mount_identity::id(held.as_fd(), true)? == guard.control_mount_id()
            && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
        "original deferred directory replaced or covered",
    )?;
    guard.recheck()
}
pub fn status() -> Result<Value> {
    let _lock = lock()?;
    let guard = Guard::observe()?;
    let records = markers(&guard)?;
    guard.recheck()?;
    Ok(value!({"owed":records}))
}
pub(crate) fn contended(action: &str) -> Result<Value> {
    deferred::unit(action)?;
    let _lock = lock()?;
    let guard = Guard::observe()?;
    let records = markers(&guard)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| enzimos_platform::Error("deferred clock unavailable".into()))?
        .as_secs();
    let record = deferred::next(records.get(action), action, &operation::boot_id()?, now)?;
    let held = directory(&guard)?;
    let name = format!("{action}.json");
    let mut original = if let Some(previous) = records.get(action) {
        let retained = control_record::Retained::open(
            &held,
            Path::new(&name),
            4096,
            guard.control_mount_id(),
        )?;
        require(
            retained.value()? == previous,
            "original deferred marker differs",
        )?;
        Some(retained)
    } else {
        None
    };
    guard.recheck()?;
    _lock.recheck()?;
    require(
        markers(&guard)? == records,
        "deferred markers changed before publication",
    )?;
    if let Some(retained) = &mut original {
        retained.replace(&record)?;
    } else {
        original = Some(control_record::Retained::create(
            &held,
            Path::new(&name),
            &record,
            4096,
            guard.control_mount_id(),
        )?);
    }
    let named = directory(&guard)?;
    let a = held.metadata()?;
    let b = named.metadata()?;
    require(
        (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
            == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode()),
        "original deferred directory replaced",
    )?;
    require(
        original
            .as_ref()
            .ok_or_else(|| enzimos_platform::Error("missing value".into()))?
            .value()?
            == &record,
        "deferred original publication changed",
    )?;
    _lock.recheck()?;
    guard.recheck()?;
    Ok(record)
}
pub fn clear(action: &str) -> Result<bool> {
    deferred::unit(action)?;
    let _lock = lock()?;
    let guard = Guard::observe()?;
    let records = markers(&guard)?;
    let Some(record) = records.get(action) else {
        return Ok(false);
    };
    let held = directory(&guard)?;
    let name = format!("{action}.json");
    let original =
        control_record::Retained::open(&held, Path::new(&name), 4096, guard.control_mount_id())?;
    require(
        original.value()? == record,
        "original deferred marker differs before clear",
    )?;
    // Retain cleared bytes for review; removal never loses evidence of an owed run.
    let archive = Path::new(operation::CONTROL).join("deferred-cleared");
    let target = files::ensure_directory(&archive, 0o700, 0)?;
    require(
        mount_identity::id(target.as_fd(), true)? == guard.control_mount_id(),
        "deferred archive mount changed",
    )?;
    guard.recheck()?;
    _lock.recheck()?;
    let destination = format!("{action}-{}.json", files::random_hex(16)?);
    let archived = original.archive(&target, Path::new(&destination))?;
    require(
        archived.value()? == record,
        "original cleared deferred marker changed; archive retained",
    )?;
    original_directory(&guard, &held, "deferred")?;
    original_directory(&guard, &target, "deferred-cleared")?;
    archived.recheck()?;
    _lock.recheck()?;
    guard.recheck()?;
    Ok(true)
}
/// Whether deferred start `id` no longer guards a still-owed marker.
fn start_finished(
    id: &str,
    start: &Value,
    markers: &std::collections::BTreeMap<String, Value>,
) -> bool {
    start["action"].as_str().is_some_and(|action| {
        markers.get(action).is_none_or(|marker| {
            crate::deferred_start::id(action, marker).ok().as_deref() != Some(id)
        })
    })
}
pub fn resume() -> Result<Value> {
    let _lock = lock()?;
    let guard = Guard::observe()?;
    let boot = operation::boot_id()?;
    let records = markers(&guard)?;
    // A start record only prevents restarting its exact owed marker; once that
    // marker was cleared or replaced, the record is history. Best effort.
    let _ = control_registry::retire_terminal(
        &guard,
        "deferred-starts",
        8,
        crate::deferred_start::MAXIMUM * 3 / 4,
        4096,
        crate::deferred_start::validate,
        |id, start| start_finished(id, start, &records),
    );
    let starts = control_registry::read_bounded(
        &guard,
        "deferred-starts",
        crate::deferred_start::MAXIMUM,
        4096,
        crate::deferred_start::validate,
    )?;
    let actions = deferred::previous_boot_actions(&records, &boot)?;
    let provider = crate::settings_command::Command::open("/usr/bin/systemctl")?;
    let held_markers = directory(&guard)?;
    let mut started = Vec::new();
    let mut retained = Vec::new();
    for action in actions {
        let marker = &records[&action];
        let original_marker = control_record::Retained::open(
            &held_markers,
            Path::new(&format!("{action}.json")),
            4096,
            guard.control_mount_id(),
        )?;
        require(
            original_marker.value()? == marker,
            "original owed marker differs before start",
        )?;
        let id = crate::deferred_start::id(&action, marker)?;
        if starts.contains_key(&id) {
            retained.push(action);
            continue;
        }
        require(
            starts.len() + started.len() < crate::deferred_start::MAXIMUM,
            "deferred start archive full; review required",
        )?;
        let path = Path::new(operation::CONTROL).join("deferred-starts");
        let directory = files::ensure_directory(&path, 0o700, 0)?;
        require(
            mount_identity::id(directory.as_fd(), true)? == guard.control_mount_id(),
            "deferred start directory changed mount",
        )?;
        let name = format!("{id}.json");
        let mut record = value!({"schema":1,"id":id,"action":action,"boot_id":boot,
            "marker":marker,"phase":"intent"});
        crate::deferred_start::transition(None, &record, &id)?;
        guard.recheck()?;
        require(
            markers(&guard)?.get(&action) == Some(marker),
            "owed marker changed before start",
        )?;
        _lock.recheck()?;
        let mut intent = control_record::Retained::create(
            &directory,
            Path::new(&name),
            &record,
            4096,
            guard.control_mount_id(),
        )?;
        require(
            intent.value()? == &record,
            "original deferred start intent changed",
        )?;
        _lock.recheck()?;
        guard.recheck()?;
        original_directory(&guard, &held_markers, "deferred")?;
        original_marker.recheck()?;
        intent.recheck()?;
        let named = files::optional_directory_relative(
            guard.control(),
            Path::new("deferred-starts"),
            Some(0),
        )?
        .ok_or_else(|| enzimos_platform::Error("deferred start directory disappeared".into()))?;
        let a = directory.metadata()?;
        let b = named.metadata()?;
        require(
            (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
                == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode())
                && mount_identity::id(named.as_fd(), true)? == guard.control_mount_id(),
            "original deferred start directory replaced",
        )?;
        _lock.recheck()?;
        let result = provider.run(
            &["start", "--no-block", deferred::unit(&action)?],
            &[0],
            65536,
        );
        original_directory(&guard, &directory, "deferred-starts")?;
        let before = record.clone();
        record["phase"] = value!(if result.is_ok() {
            "requested"
        } else {
            "uncertain"
        });
        crate::deferred_start::transition(Some(&before), &record, &id)?;
        guard.recheck()?;
        _lock.recheck()?;
        require(
            intent.value()? == &before,
            "original deferred start journal changed; intent retained",
        )?;
        original_directory(&guard, &directory, "deferred-starts")?;
        intent.replace(&record)?;
        require(
            intent.value()? == &record,
            "original deferred start publication changed",
        )?;
        _lock.recheck()?;
        guard.recheck()?;
        original_directory(&guard, &directory, "deferred-starts")?;
        result?;
        started.push(action);
    }
    Ok(
        value!({"status":"deferred-work-resumed","started":started,"retained":retained,
        "bypassed_guards":false}),
    )
}
