// SPDX-License-Identifier: MIT
//! Loader detachment retains the ESP, each before state, and renamed entry inode.
use crate::{
    boot_entries, boot_volume::Volume, recovery_detachment, recovery_records as records,
    recovery_run_parameters::Parameters,
};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use std::{
    ffi::CString,
    fs::File,
    os::fd::{AsFd, AsRawFd},
    path::Path,
};
struct Text {
    artifact: crate::boot_volume::Artifact,
    body: String,
}
impl Text {
    fn observe(volume: &Volume, name: &str) -> Result<Self> {
        let artifact = volume.artifact(Path::new(name), boot_entries::MAX_TEXT as u64)?;
        let body = String::from_utf8(files::read_file(
            &artifact.file,
            boot_entries::MAX_TEXT,
            Some(0),
            true,
        )?)
        .map_err(|_| Error("run loader text encoding".into()))?;
        artifact.recheck()?;
        Ok(Self { artifact, body })
    }
    fn replace(&self, volume: &Volume, body: &str) -> Result<()> {
        volume.writable()?;
        self.artifact.recheck()?;
        if body == self.body {
            return Ok(());
        }
        files::atomic(
            &self.artifact.path,
            body.as_bytes(),
            files::public_file_mode(&volume.directory)?,
            Some(0),
            true,
        )?;
        volume.recheck()?;
        require(
            files::read(&self.artifact.path, boot_entries::MAX_TEXT, Some(0), true)?
                == body.as_bytes(),
            "run loader replacement readback differs",
        )
    }
}
fn directory_unchanged(volume: &Volume, parent: &File, relative: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let current = volume.directory(Path::new(relative))?;
    let a = parent.metadata()?;
    let b = current.metadata()?;
    require(
        (a.dev(), a.ino(), a.mode()) == (b.dev(), b.ino(), b.mode())
            && mount_identity::id(parent.as_fd(), true)? == volume.unique,
        "run loader directory replaced",
    )?;
    volume.recheck()
}
#[allow(unsafe_code, reason = "Linux syscall ABI (renameat2, unlinkat).")]
fn remove_owned(volume: &Volume, entry: &Text) -> Result<()> {
    let parent = volume.directory(Path::new("loader/entries"))?;
    let old = CString::new(
        entry
            .artifact
            .path
            .file_name()
            .ok_or_else(|| enzimos_platform::Error("missing filename".into()))?
            .as_encoded_bytes(),
    )
    .map_err(|_| Error("run entry filename".into()))?;
    // An unexpected object moved by a race remains at a private random name for
    // inspection. It is never deleted on a failed identity or content check.
    let name = format!(".enzimos-write-detached-{}", files::random_hex(16)?);
    let new = CString::new(name.as_str())
        .map_err(|_| enzimos_platform::Error("invalid C string".into()))?;
    directory_unchanged(volume, &parent, "loader/entries")?;
    volume.writable()?;
    entry.artifact.recheck()?;
    let before = files::identity(&entry.artifact.file.metadata()?);
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
        "run entry quarantine failed; outcome requires inspection",
    )?;
    parent.sync_all()?;
    directory_unchanged(volume, &parent, "loader/entries")?;
    let moved = files::open_relative(&parent, Path::new(&name))?;
    let after = files::identity(&moved.metadata()?);
    let mut expected = before;
    expected.5 = after.5;
    expected.6 = after.6;
    require(
        after == expected
            && files::identity(&entry.artifact.file.metadata()?) == after
            && files::read_file(&moved, boot_entries::MAX_TEXT, Some(0), true)?
                == entry.body.as_bytes()
            && mount_identity::id(moved.as_fd(), true)? == volume.unique,
        "quarantined run entry differs; retained for review",
    )?;
    let named = files::open_relative(&parent, Path::new(&name))?;
    require(
        files::identity(&named.metadata()?) == after,
        "quarantined run entry replaced; retained",
    )?;
    directory_unchanged(volume, &parent, "loader/entries")?;
    require(
        // SAFETY: `new` is a NUL-terminated CString and `parent` keeps the descriptor open.
        unsafe { libc::unlinkat(parent.as_raw_fd(), new.as_ptr(), 0) } == 0,
        "owned run entry unlink failed",
    )?;
    parent.sync_all()?;
    volume.recheck()
}
pub(crate) fn detach(p: &Parameters) -> Result<String> {
    crate::recovery_bootstrap::quiet()?;
    let volume = Volume::observe()?;
    require(volume.uuid == p.esp, "actual run ESP differs")?;
    let defaults = Text::observe(&volume, "loader/loader.conf")?;
    let bios = Text::observe(&volume, "limine/limine.conf")?;
    let (name, _) = records::run_entry_names(&p.id)?;
    let relative = format!("loader/entries/{name}");
    let entry = match std::fs::symlink_metadata(volume.path(Path::new(&relative))?) {
        Ok(_) => Some(Text::observe(&volume, &relative)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let plan = recovery_detachment::plan(
        p,
        &defaults.body,
        &bios.body,
        entry.as_ref().map(|e| e.body.as_str()),
    )?;
    let image = plan
        .image
        .ok_or_else(|| Error("no actual run entry remains; automatic adoption refused".into()))?;
    // Prove the previous default exists before modifying either loader.
    volume
        .artifact(
            Path::new(&format!("loader/entries/{}", p.uefi_previous)),
            boot_entries::MAX_TEXT as u64,
        )?
        .recheck()?;
    defaults.artifact.recheck()?;
    bios.artifact.recheck()?;
    if let Some(entry) = &entry {
        entry.artifact.recheck()?;
    }
    defaults.replace(&volume, &plan.defaults)?;
    if let Some(entry) = &entry {
        remove_owned(&volume, entry)?;
    }
    bios.replace(&volume, &plan.bios)?;
    for folder in ["loader", "loader/entries", "limine"] {
        volume.directory(Path::new(folder))?.sync_all()?;
    }
    let next_defaults = Text::observe(&volume, "loader/loader.conf")?;
    let next_bios = Text::observe(&volume, "limine/limine.conf")?;
    let absent = std::fs::symlink_metadata(volume.path(Path::new(&relative))?);
    require(
        matches!(absent,Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "run UEFI entry still present",
    )?;
    let after = recovery_detachment::plan(p, &next_defaults.body, &next_bios.body, None)?;
    require(
        after.defaults == plan.defaults && after.bios == plan.bios && after.image.is_none(),
        "run loader detachment readback differs",
    )?;
    volume.recheck()?;
    Ok(image)
}
