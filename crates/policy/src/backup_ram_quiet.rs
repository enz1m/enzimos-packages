// SPDX-License-Identifier: MIT
//! Original RAM control families retained across one data-stage producer.
use crate::{backup_ram_source::Source, control_record::Observation};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
struct Family {
    name: &'static str,
    directory: Option<(File, files::FileIdentity)>,
    records: Vec<Observation>,
    names: BTreeSet<String>,
}
pub(crate) struct Quiet {
    control: files::FileIdentity,
    families: Vec<Family>,
}
fn completed(name: &str, row: &Value, id: &str) -> Result<()> {
    match name {
        "backup-attempts" => {
            // The RAM environment is a later boot: no attempt process of the
            // installed system survives, so a running row was interrupted.
            crate::backup_attempt::validate(row, id)?;
            require(
                !crate::backup_attempt::blocks(row, &crate::operation::boot_id()?),
                "running RAM backup requires review",
            )
        }
        "backup-credentials" => {
            crate::backup_credential_record::validate(row, id)?;
            require(
                row["phase"] == "complete",
                "uncertain RAM enrollment requires review",
            )
        }
        "backup-rotation" => {
            crate::backup_rotation_record::validate(row, id)?;
            require(
                matches!(row["phase"].as_str(), Some("complete" | "abandoned")),
                "uncertain RAM rotation requires review",
            )
        }
        _ => Err(Error("closed RAM quiescence family required".into())),
    }
}
impl Quiet {
    pub(crate) fn observe(source: &Source) -> Result<Self> {
        source.recheck()?;
        require(
            files::optional_relative(source.control(), Path::new("backup.enabled"))?.is_none(),
            "disable automatic backup before RAM restore",
        )?;
        let control = files::identity(&source.control().metadata()?);
        let mut families = Vec::new();
        for (name, maximum, limit) in [
            ("backup-attempts", 128, 8192),
            (
                "backup-credentials",
                crate::backup_credential_record::CAPACITY,
                crate::backup_credential_record::LIMIT,
            ),
            ("backup-rotation", 128, crate::catalog::MAX_CATALOG),
        ] {
            let directory =
                files::optional_directory_relative(source.control(), Path::new(name), Some(0))?;
            let mut records = Vec::new();
            let mut names = BTreeSet::new();
            if let Some(parent) = &directory {
                let m = parent.metadata()?;
                require(
                    m.uid() == 0
                        && m.gid() == 0
                        && m.mode() & 0o7777 == 0o700
                        && mount_identity::id(parent.as_fd(), true)? == source.control_mount_id(),
                    "private original RAM control family required",
                )?;
                for leaf in files::directory_names(parent, maximum.max(1))? {
                    let leaf = leaf
                        .into_string()
                        .map_err(|_| Error("RAM control filename encoding".into()))?;
                    let id = leaf
                        .strip_suffix(".json")
                        .ok_or_else(|| Error("unknown/interrupted RAM control member".into()))?;
                    crate::identity::safe_id(id)?;
                    let original = Observation::open(
                        parent,
                        Path::new(&leaf),
                        limit,
                        source.control_mount_id(),
                    )?;
                    completed(name, original.value()?, id)?;
                    records.push(original);
                    names.insert(leaf);
                }
            }
            let directory = directory
                .map(|f| Ok::<_, Error>((f.try_clone()?, files::identity(&f.metadata()?))))
                .transpose()?;
            families.push(Family {
                name,
                directory,
                records,
                names,
            });
        }
        let this = Self { control, families };
        this.recheck(source)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, source: &Source) -> Result<()> {
        source.recheck()?;
        require(
            files::identity(&source.control().metadata()?) == self.control
                && files::optional_relative(source.control(), Path::new("backup.enabled"))?
                    .is_none(),
            "original RAM control/schedule epoch changed",
        )?;
        for family in &self.families {
            let named = files::optional_directory_relative(
                source.control(),
                Path::new(family.name),
                Some(0),
            )?;
            match (&family.directory, named) {
                (None, None) => (),
                (Some((original, epoch)), Some(named)) => {
                    require(
                        files::identity(&original.metadata()?) == *epoch
                            && files::identity(&named.metadata()?) == *epoch
                            && mount_identity::id(original.as_fd(), true)?
                                == source.control_mount_id()
                            && mount_identity::id(named.as_fd(), true)?
                                == source.control_mount_id(),
                        "original RAM family replaced/changed/covered",
                    )?;
                    let names = files::directory_names(original, 256)?
                        .into_iter()
                        .map(|n| {
                            n.into_string()
                                .map_err(|_| Error("RAM family filename encoding".into()))
                        })
                        .collect::<Result<BTreeSet<_>>>()?;
                    require(names == family.names, "RAM family membership changed")?;
                    for record in &family.records {
                        record.recheck()?;
                    }
                }
                _ => return Err(Error("RAM family appeared/disappeared".into())),
            }
        }
        source.recheck()
    }
}
