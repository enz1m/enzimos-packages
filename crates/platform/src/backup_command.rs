// SPDX-License-Identifier: MIT
//! Closed archive command data; this module grants no mount or execution authority.
use crate::{Result, require};
use std::collections::BTreeSet;
/// Derive every operand from the closed target set, never caller options/globs.
///
/// # Errors
/// A target set that [`validate`] refuses.
pub fn arguments(targets: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut sources = vec![
        "/backup-source/system".to_owned(),
        "/backup-source/home".to_owned(),
    ];
    sources.extend(
        targets
            .iter()
            .filter(|s| s.starts_with("/backup-source/additional/"))
            .cloned(),
    );
    sources.extend([
        "/backup-source/boot".to_owned(),
        "/backup-source/inventory".to_owned(),
    ]);
    let mut args = [
        "backup",
        "--json",
        "--tag",
        "enzimos-whole-linux",
        "--host",
        "enzimos",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for pattern in EXCLUDES {
        args.extend(["--exclude".to_owned(), (*pattern).to_owned()]);
    }
    for source in &sources[2..sources.len() - 2] {
        args.extend(["--exclude".to_owned(), format!("{source}/.snapshots/**")]);
    }
    args.extend(skipped_arguments());
    args.extend(sources);
    validate(&args, targets)?;
    Ok(args)
}
/// Folders skipped by rule (build output, caches, games, Trash, a person's
/// exclusions), listed in the inventory of every backup.
pub const SKIPPED: &str = "/backup-source/inventory/skipped.txt";
/// The fixed `--exclude-file` operand pair that follows the exclusions.
#[must_use]
pub fn skipped_arguments() -> [String; 2] {
    ["--exclude-file".to_owned(), SKIPPED.to_owned()]
}
/// Paths every backup leaves out and every restore skips: runtime trees,
/// nested snapshots, staging areas and backup credentials.
pub const EXCLUDES: &[&str] = &[
    "/backup-source/system/dev/**",
    "/backup-source/system/proc/**",
    "/backup-source/system/sys/**",
    "/backup-source/system/run/**",
    "/backup-source/system/tmp/**",
    "/backup-source/system/var/tmp/**",
    "/backup-source/system/home/**",
    "/backup-source/system/boot/**",
    "/backup-source/system/.snapshots/**",
    "/backup-source/system/backup-source/**",
    "/backup-source/system/backup-repository/**",
    "/backup-source/system/restore-target/**",
    "/backup-source/system/swap/**",
    "/backup-source/system/var/lib/enzimos/module-views/**",
    "/backup-source/system/var/lib/enzimos/boot-stage/**",
    "/backup-source/system/var/lib/enzimos/backup-stage/**",
    "/backup-source/system/var/lib/enzimos-control/**",
    "/backup-source/system/etc/pacman.d/gnupg/**",
    "/backup-source/home/.snapshots/**",
    "/backup-source/system/etc/enzimos/backup.password",
    "/backup-source/system/etc/enzimos/backup.json",
    "/backup-source/system/etc/enzimos/backup.next-password",
    "/backup-source/system/etc/enzimos/backup.rotation-password",
    "/backup-source/system/etc/enzimos/backup.retired-password",
    "/backup-source/system/etc/enzimos/backup-remote.password",
    "/backup-source/system/etc/enzimos/backup-remote.identity",
    "/backup-source/system/etc/enzimos/backup-remote.hosts",
    "/backup-source/system/etc/enzimos/backup-remote.share-password",
    "/backup-source/system/etc/enzimos/backup-remote.json",
    "/backup-source/system/etc/enzimos/backup-remote-rotation.password",
    "/backup-source/system/etc/enzimos/backup-remote-retired.password",
    "/backup-source/system/etc/enzimos/backup-remote-rotation.json",
    "/backup-source/system/etc/enzimos/backup-remote-retired.json",
    "/backup-source/system/etc/enzimos/backup-remote-setup.json",
    "/backup-source/system/etc/enzimos/backup-remote-setup.password",
    "/backup-source/system/etc/enzimos/backup-remote-setup.share-password",
    "/backup-source/system/var/lib/pacman/db.lck",
    "/backup-source/system/payload/**",
    "/backup-source/system/var/lib/systemd/coredump/**",
];
/// Shape validation only. This never constructs an execution or mount permit.
///
/// # Errors
/// Arguments that differ from the closed prefix, exclusions, skipped-folder
/// list or source set derived from `targets`.
pub fn validate(args: &[String], targets: &BTreeSet<String>) -> Result<()> {
    const PREFIX: &[&str] = &[
        "backup",
        "--json",
        "--tag",
        "enzimos-whole-linux",
        "--host",
        "enzimos",
    ];
    require(
        (10..=320).contains(&args.len())
            && args.iter().all(|a| a.len() <= 4096 && !a.contains('\0'))
            && args
                .iter()
                .take(PREFIX.len())
                .map(String::as_str)
                .eq(PREFIX.iter().copied()),
        "closed backup command prefix or bounds",
    )?;
    let mut index = PREFIX.len();
    let mut exclusions = Vec::new();
    while args.get(index).is_some_and(|a| a == "--exclude") {
        exclusions.push(
            args.get(index + 1)
                .ok_or_else(|| crate::Error("backup exclusion operand missing".into()))?
                .as_str(),
        );
        index += 2;
    }
    require(
        args.get(index).is_some_and(|a| a == "--exclude-file")
            && args.get(index + 1).is_some_and(|a| a == SKIPPED),
        "backup skipped-folder list required",
    )?;
    index += 2;
    let sources = &args[index..];
    require(
        (4..=34).contains(&sources.len())
            && sources[0] == "/backup-source/system"
            && sources[1] == "/backup-source/home"
            && sources[sources.len() - 2] == "/backup-source/boot"
            && sources[sources.len() - 1] == "/backup-source/inventory"
            && sources.iter().cloned().collect::<BTreeSet<_>>() == *targets
            && sources.len() == targets.len(),
        "complete fixed backup source command set required",
    )?;
    let mut expected = EXCLUDES.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    for source in &sources[2..sources.len() - 2] {
        let name = source
            .strip_prefix("/backup-source/additional/")
            .ok_or_else(|| crate::Error("closed additional backup source required".into()))?;
        require(
            !name.is_empty()
                && name.len() <= 32
                && name.as_bytes()[0].is_ascii_lowercase()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "closed additional backup source name",
        )?;
        expected.push(format!("{source}/.snapshots/**"));
    }
    require(
        exclusions
            .iter()
            .copied()
            .eq(expected.iter().map(String::as_str)),
        "backup exclusion set differs from original closed scope",
    )
}
