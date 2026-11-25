// SPDX-License-Identifier: MIT
//! Rebinding changes boot references only after current and retained roots agree.
use crate::{
    authority_identity, filesystem, root_rebind_record,
    storage_runtime::{Guard, TopMount},
    subvolume,
};
use enzimos_platform::{Error, Result, files, json, mount_identity, process, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
    time::Duration,
};
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    crate::recovery_records::text(v, key)
}
fn retained(parent: &File, path: &Path, mount: u64, filesystem: &str) -> Result<File> {
    let file = files::directory_relative(parent, path, Some(0))?;
    let metadata = file.metadata()?;
    require(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && mount_identity::id(file.as_fd(), true)? == mount
            && filesystem::observe(file.as_fd())?["filesystem_uuid"] == filesystem,
        "rebind root crosses a foreign filesystem or mount",
    )?;
    Ok(file)
}
pub(crate) fn roots(journal: &Value, guard: &Guard) -> Result<()> {
    root_rebind_record::validate(journal, text(journal, "id")?)?;
    guard.recheck()?;
    require(
        guard.configuration["filesystem_uuid"] == journal["filesystem_uuid"]
            && authority_identity::observe(guard)? == journal["authority"],
        "rebind filesystem or current authority changed",
    )?;
    let mut top = TopMount::open(guard)?;
    let result = (|| {
        let mount = mount_identity::id(top.directory()?.as_fd(), true)?;
        let fs = text(journal, "filesystem_uuid")?;
        for role in ["source", "target"] {
            top.recheck()?;
            let expected = &journal[role];
            let name = text(expected, "path")?;
            let file = retained(top.directory()?, Path::new(name), mount, fs)?;
            let (identity, _) = subvolume::observe(file.as_fd(), name)?;
            require(
                value!({"path":name,"id":identity["id"],"uuid":identity["uuid"],"ownership":"not-established"})
                    == *expected,
                "rebind source or retained root identity changed",
            )?;
            let inventory = process::run_with_fds(
                "/usr/bin/pacman",
                &["--root", "@fd:0", "-Q"],
                &[],
                Duration::from_secs(30),
                2 * 1024 * 1024,
                &[file.as_fd()],
            )?;
            require(
                inventory.status.success(),
                "rebind package inventory refused",
            )?;
            let inventory = std::str::from_utf8(&inventory.stdout)
                .map_err(|_| Error("rebind package inventory encoding".into()))?
                .trim();
            require(
                !inventory.is_empty()
                    && json::sha256(inventory.as_bytes()) == journal["inventory_sha256"],
                "rebind source/retained inventory changed",
            )?;
            let storage = files::open_relative(&file, Path::new("etc/enzimos/storage.json"))?;
            require(
                mount_identity::id(storage.as_fd(), true)? == mount,
                "rebind storage record crosses foreign mount",
            )?;
            let storage = json::decode(&files::read_file(&storage, 65536, Some(0), true)?, 65536)?;
            require(
                storage["root_subvol"] == name
                    && storage["filesystem_uuid"] == fs
                    && storage["control_subvol"] == guard.configuration["control_subvol"],
                "rebind retained storage configuration changed",
            )?;
            for flavor in ["linux", "linux-lts"] {
                let version = text(&journal["kernels"], flavor)?;
                let kernel = files::open_relative(
                    &file,
                    Path::new(&format!("usr/lib/modules/{version}/vmlinuz")),
                )?;
                require(
                    mount_identity::id(kernel.as_fd(), true)? == mount
                        && json::sha256(&files::read_file(
                            &kernel,
                            128 * 1024 * 1024,
                            Some(0),
                            true,
                        )?) == journal["kernel_hashes"][flavor],
                    "rebind retained root/kernel bytes changed",
                )?;
            }
            if role == "source" {
                let relative = format!(
                    ".snapshots/{}/snapshot",
                    enzimos_platform::json::unsigned(&journal["snapshot"]["number"])?
                );
                let snapshot = retained(&file, Path::new(&relative), mount, fs)?;
                let (identity, readonly) =
                    subvolume::observe(snapshot.as_fd(), &format!("{name}/{relative}"))?;
                require(
                    readonly
                        && identity["uuid"] == journal["snapshot"]["uuid"]
                        && identity["parent_uuid"] == journal["source"]["uuid"],
                    "rebind source snapshot lineage or readonly state changed",
                )?;
            } else {
                require(
                    identity["parent_uuid"] == journal["snapshot"]["uuid"],
                    "rebind retained root is not derived from source snapshot",
                )?;
            }
            let current = retained(top.directory()?, Path::new(name), mount, fs)?;
            require(
                subvolume::observe(current.as_fd(), name)?.0 == identity,
                "rebind root changed during inspection",
            )?;
            top.recheck()?;
        }
        guard.recheck()
    })();
    // Every inspection descriptor above has left scope before normal unmount.
    let closed = top.close();
    result?;
    closed
}
