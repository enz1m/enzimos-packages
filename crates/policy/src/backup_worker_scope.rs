// SPDX-License-Identifier: MIT
//! Read-only checks of a borrowed original mount; never mounting or adoption authority.
use enzimos_platform::{Result, files, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
pub(crate) fn directory(file: &File) -> Result<Value> {
    let m = file.metadata()?;
    let value = value!({"device":m.dev(),"inode":m.ino(),"mount":mount_identity::id(file.as_fd(),true)?,
        "mode":m.mode(),"uid":m.uid(),"gid":m.gid()});
    crate::backup_worker_request::directory(&value)?;
    Ok(value)
}
/// The receiver first proves every borrowed open description with the original
/// caller's pidfd/image and KCMP. This function cannot infer mount ownership
/// from a path or JSON, and cannot create a writable mount or completion receipt.
#[allow(unsafe_code, reason = "Linux syscall ABI (ioctl).")]
pub(crate) fn recheck(
    request: &Value,
    source: &crate::storage_runtime::Guard,
    root: &File,
    repository: &File,
) -> Result<()> {
    crate::namespaces::initial()?;
    crate::backup_worker_request::request(request)?;
    source.recheck()?;
    require(
        source.backup_root_binding()? == request["plan"]["source"],
        "worker source changed",
    )?;
    require(
        directory(root)? == request["root"] && directory(repository)? == request["repository"],
        "borrowed original root/repository changed",
    )?;
    let named = files::directory(Path::new("/backup-repository"), Some(0))?;
    let named_repository = files::directory_relative(root, Path::new("restic"), Some(0))?;
    require(
        directory(&named)? == request["root"]
            && directory(&named_repository)? == request["repository"],
        "worker destination named directory differs from original descriptor",
    )?;
    let normal = mount_identity::id(root.as_fd(), false)?;
    let unique = mount_identity::id(root.as_fd(), true)?;
    require(
        request["mount"]["mount_id"] == normal && request["mount"]["unique_mount_id"] == unique,
        "worker owned mount IDs changed",
    )?;
    let rows = crate::storage_runtime::rows()?;
    require(
        !rows
            .iter()
            .any(|row| row.target.starts_with("/backup-repository/")),
        "nested worker destination mount refused",
    )?;
    let row = &crate::backup_destination::mount(&rows, normal)?;
    crate::backup_destination::writable(row)?;
    // An attached scope must not have been propagated to a namespace peer.
    require(row.optional.is_empty(), "worker mount propagation changed")?;
    let filesystem = crate::filesystem::observe(root.as_fd())?;
    let uuid = request["mount"]["filesystem_uuid"].as_str().unwrap();
    require(
        filesystem["filesystem_uuid"] == uuid && filesystem["members"] == 1,
        "worker filesystem/member scope differs from reviewed destination",
    )?;
    let mut info = [0u64; 63];
    require(
        unsafe {
            libc::ioctl(
                root.as_raw_fd(),
                0x81f8943c as libc::c_ulong,
                info.as_mut_ptr(),
            )
        } == 0
            && info[0] == 5
            && info[36] & 1 == 0
            && root.metadata()?.ino() == 256,
        "whole writable original Btrfs top level required",
    )?;
    let device = &request["plan"]["destination"]["device"];
    let expected = (
        device["major"].as_u64().unwrap() as u32,
        device["minor"].as_u64().unwrap() as u32,
    );
    require(
        crate::topology::btrfs_roots(uuid)? == vec![expected],
        "worker filesystem member differs from original selected device",
    )?;
    let graph = crate::topology::mounted_btrfs(uuid)?;
    require(
        graph.json() == request["plan"]["destination"]["topology"],
        "worker destination topology changed",
    )?;
    let source_uuid = source.configuration["filesystem_uuid"].as_str().unwrap();
    let source_graph = crate::topology::mounted_btrfs(source_uuid)?.json();
    let destination_graph = graph.json();
    let leaves = |graph: &Value| -> Result<Vec<Value>> {
        let rows = graph["leaves"]
            .as_array()
            .ok_or_else(|| enzimos_platform::Error("worker topology leaves required".into()))?;
        require(!rows.is_empty(), "worker topology leaves required")?;
        Ok(rows.clone())
    };
    let protected = leaves(&source_graph)?;
    require(
        leaves(&destination_graph)?
            .iter()
            .all(|leaf| !protected.contains(leaf)),
        "worker destination overlaps a protected system disk",
    )?;
    source.recheck()?;
    let final_root = files::directory(Path::new("/backup-repository"), Some(0))?;
    let final_repository = files::directory_relative(root, Path::new("restic"), Some(0))?;
    let final_rows = crate::storage_runtime::rows()?;
    require(
        &crate::backup_destination::mount(&final_rows, normal)? == row
            && !final_rows
                .iter()
                .any(|row| row.target.starts_with("/backup-repository/")),
        "worker mount record changed during observation",
    )?;
    require(
        directory(root)? == request["root"]
            && directory(repository)? == request["repository"]
            && crate::filesystem::observe(root.as_fd())? == filesystem
            && directory(&named)? == request["root"]
            && directory(&named_repository)? == request["repository"]
            && directory(&final_root)? == request["root"]
            && directory(&final_repository)? == request["repository"]
            && crate::topology::mounted_btrfs(uuid)?.json() == destination_graph
            && crate::topology::mounted_btrfs(source_uuid)?.json() == source_graph,
        "worker scope changed during observation",
    )?;
    Ok(())
}
