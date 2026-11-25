// SPDX-License-Identifier: MIT
//! Complete, bounded nested-source inventory precedes snapshot capture admission.
use crate::{
    backup_configuration::SourceScope,
    backup_source::Source,
    backup_source_layout::Dataset,
    birth_runtime::parse_inventory,
    settings_command::Command,
    storage_runtime::{self, Guard},
};
use enzimos_platform::{Result, mountinfo, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::Mutex,
    time::{Duration, Instant},
};
const EXCLUDED: &[&str] = &[
    ".snapshots",
    "swap",
    "backup-source",
    "backup-repository",
    "restore-target",
    "payload",
    "var/lib/enzimos-control",
    "etc/pacman.d/gnupg",
];
fn beneath(path: &str, parent: &str) -> bool {
    path == parent || path.starts_with(&format!("{parent}/"))
}
fn persistent_mounts(rows: Vec<mountinfo::Row>) -> Vec<mountinfo::Row> {
    // These runtime trees are excluded from the archive. New service sandboxes,
    // device mounts and desktop sockets below them cannot change captured data.
    // Keep their top-level mounts and every persistent mount identity unchanged.
    rows.into_iter()
        .filter(|row| !crate::backup_source_layout::runtime_mount(&row.target))
        .collect()
}
fn qualify_nested(body: &str, physical: &str, source: &Dataset, all: &[Dataset]) -> Result<Value> {
    let mut rows = parse_inventory(body)?;
    require(
        !physical.is_empty() && physical.split('/').all(|p| !matches!(p, "" | "." | "..")),
        "explicit source filesystem path required",
    )?;
    // `-o` filters by one immediate parent root ID and omits snapshots beneath
    // the nested .snapshots subvolume. Parse the complete filesystem inventory
    // first, then select this original dataset by component boundary. This keeps
    // recursive descendants while never treating a sibling/prefix alias as data.
    rows.retain(|path, _| beneath(path, physical));
    for path in rows.keys() {
        if path == physical {
            continue;
        }
        let relative = path.strip_prefix(&format!("{physical}/")).ok_or_else(|| {
            enzimos_platform::Error("nested source inventory escaped dataset".into())
        })?;
        let absolute = format!("{}/{}", source.path.trim_end_matches('/'), relative);
        let separately_captured = all
            .iter()
            .any(|s| s.path != "/" && s.path != source.path && beneath(&absolute, &s.path));
        require(
            separately_captured || EXCLUDED.iter().any(|p| beneath(relative, p)),
            "unconfigured nested backup subvolume refused",
        )?;
    }
    Ok(json!(rows))
}
fn qualify_mounts(rows: &[mountinfo::Row], datasets: &[Dataset], filesystem: &str) -> Result<()> {
    for row in rows {
        if row.target == "/swap" {
            require(
                row.filesystem == "btrfs" && row.root == "/enzimos-swap",
                "system swap mount identity changed",
            )?;
            let file = enzimos_platform::files::directory(std::path::Path::new("/swap"), Some(0))?;
            require(
                crate::filesystem::observe(std::os::fd::AsFd::as_fd(&file))?["filesystem_uuid"]
                    == filesystem,
                "system swap filesystem changed",
            )?;
            continue;
        }
        let known = datasets.iter().any(|s| s.path == row.target)
            || [
                "/dev",
                "/proc",
                "/sys",
                "/run",
                "/tmp",
                "/var/tmp",
                "/boot",
                "/backup-repository",
                "/backup-source",
                "/restore-target",
                "/payload",
                "/patches",
                "/etc/pacman.d/gnupg",
                "/var/lib/enzimos-control",
            ]
            .iter()
            .any(|p| beneath(&row.target, p));
        require(known, "unconfigured persistent backup mount refused")?;
    }
    Ok(())
}
/// Whether `path` is a Snapper snapshot of the source at `parent`
/// (`<parent>/.snapshots/<number>/snapshot`). Snapper timeline and cleanup and
/// home history add and remove these at any time; `.snapshots` is never
/// archived, so they are qualified but not part of the stable inventory.
fn snapper_snapshot(path: &str, parent: &str) -> bool {
    path.strip_prefix(&format!("{parent}/"))
        .and_then(|relative| relative.strip_prefix(".snapshots/"))
        .and_then(|relative| relative.strip_suffix("/snapshot"))
        .is_some_and(|number| {
            !number.is_empty()
                && number.bytes().all(|b| b.is_ascii_digit())
                && !number.starts_with('0')
        })
}
/// The nested inventory without Snapper snapshot rows.
fn stable(rows: &[Value], physical: &[String]) -> Result<Vec<Value>> {
    require(
        rows.len() == physical.len(),
        "nested inventory source count differs",
    )?;
    rows.iter()
        .zip(physical)
        .map(|(rows, parent)| {
            let rows = rows.as_object().ok_or_else(|| {
                enzimos_platform::Error("original nested inventory object required".into())
            })?;
            Ok(Value::Object(
                rows.iter()
                    .filter(|(path, _)| !snapper_snapshot(path, parent))
                    .map(|(path, row)| (path.clone(), row.clone()))
                    .collect(),
            ))
        })
        .collect()
}
/// The subvolume UUIDs of a full nested inventory.
fn subvolume_uuids(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .filter_map(Value::as_object)
        .flat_map(|rows| rows.values())
        .filter_map(|row| row["uuid"].as_str().map(str::to_owned))
        .collect()
}
/// The backup's own new snapshot: a Snapper snapshot of exactly one source,
/// listed with exactly its row now, and a subvolume absent when the sources
/// were reviewed. Snapper reuses the number of a removed newest snapshot, so
/// the path alone does not tell a new snapshot from a reviewed one.
fn created_row(
    current: &[Value],
    physical: &[String],
    reviewed: &BTreeSet<String>,
    path: &str,
    row: &Value,
) -> Result<()> {
    enzimos_platform::json::fields(row, "path id uuid parent_uuid")?;
    require(
        current.len() == physical.len() && row["path"] == path,
        "created inventory row shape differs",
    )?;
    require(
        row["uuid"]
            .as_str()
            .is_some_and(|uuid| !reviewed.contains(uuid)),
        "created snapshot already recorded; no replay",
    )?;
    let owners = current
        .iter()
        .zip(physical)
        .filter(|(_, parent)| snapper_snapshot(path, parent))
        .collect::<Vec<_>>();
    require(
        owners.len() == 1 && owners[0].0[path] == *row,
        "created snapshot escaped original source inventory",
    )
}
pub struct Inventory<'a, 'g> {
    configuration: &'a dyn SourceScope,
    guard: &'g Guard,
    sources: Vec<Source<'g>>,
    vendor: Command,
    mounts: Vec<mountinfo::Row>,
    nested: Mutex<Vec<Value>>,
    reviewed: BTreeSet<String>,
}
impl<'a, 'g> Inventory<'a, 'g> {
    pub fn observe(configuration: &'a dyn SourceScope, guard: &'g Guard) -> Result<Self> {
        configuration.recheck()?;
        guard.recheck()?;
        let datasets = configuration.datasets()?;
        let sources = datasets
            .iter()
            .cloned()
            .map(|d| Source::open(d, guard))
            .collect::<Result<Vec<_>>>()?;
        let mut objects = std::collections::BTreeSet::new();
        for source in &sources {
            let evidence = source.evidence()?;
            require(
                objects.insert(evidence["object"]["uuid"].as_str().unwrap().to_owned()),
                "backup dataset aliases another configured source",
            )?;
        }
        let mounts = storage_runtime::rows()?;
        qualify_mounts(
            &mounts,
            &datasets,
            guard.configuration["filesystem_uuid"].as_str().unwrap(),
        )?;
        let vendor = Command::open("/usr/bin/btrfs")?;
        let full = Self::sample(&sources, &datasets, &vendor)?;
        let physical = sources
            .iter()
            .map(Source::filesystem_path)
            .collect::<Vec<_>>();
        let this = Self {
            configuration,
            guard,
            sources,
            vendor,
            mounts: persistent_mounts(mounts),
            nested: Mutex::new(stable(&full, &physical)?),
            reviewed: subvolume_uuids(&full),
        };
        this.recheck()?;
        Ok(this)
    }
    fn sample(
        sources: &[Source<'g>],
        datasets: &[Dataset],
        vendor: &Command,
    ) -> Result<Vec<Value>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut result = Vec::new();
        for source in sources {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let body = vendor.run_fds(
                &["subvolume", "list", "-a", "-u", "-q", "@fd-dir:0"],
                &[0],
                1024 * 1024,
                remaining,
                &[source.descriptor()?],
            )?;
            source.recheck()?;
            let body = std::str::from_utf8(&body).map_err(|_| {
                enzimos_platform::Error("backup subvolume inventory encoding".into())
            })?;
            result.push(qualify_nested(
                body,
                &source.filesystem_path(),
                source.dataset(),
                datasets,
            )?);
        }
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        enzimos_platform::recheck_scope::once(self, "source-inventory", || self.recheck_fresh())
    }
    fn recheck_fresh(&self) -> Result<()> {
        self.configuration.recheck()?;
        self.guard.recheck()?;
        self.vendor.recheck()?;
        let datasets = self.configuration.datasets()?;
        require(
            persistent_mounts(storage_runtime::rows()?) == self.mounts
                && stable(
                    &Self::sample(&self.sources, &datasets, &self.vendor)?,
                    &self.physical(),
                )? == self.nested_value()?,
            "original backup source inventory changed; new review required",
        )?;
        self.configuration.recheck()?;
        self.guard.recheck()?;
        require(
            persistent_mounts(storage_runtime::rows()?) == self.mounts,
            "backup mounts changed during source inventory",
        )
    }
    fn physical(&self) -> Vec<String> {
        self.sources.iter().map(Source::filesystem_path).collect()
    }
    fn nested_value(&self) -> Result<Vec<Value>> {
        self.nested
            .lock()
            .map(|value| value.clone())
            .map_err(|_| enzimos_platform::Error("backup source inventory lock poisoned".into()))
    }
    /// Admit only the known creation proven by an original retained actor.
    /// A decoded row or an independently opened old snapshot cannot invoke this.
    pub(crate) fn advance_created(
        &self,
        created: &crate::backup_snapshot_creation::Created<'_, '_, 'g>,
    ) -> Result<()> {
        self.configuration.recheck()?;
        self.guard.recheck()?;
        self.vendor.recheck()?;
        let (source, path, row) = created.inventory_addition()?;
        require(
            self.sources
                .iter()
                .any(|actual| std::ptr::eq(actual, source)),
            "created snapshot is not from an original inventory source actor",
        )?;
        require(
            persistent_mounts(storage_runtime::rows()?) == self.mounts,
            "backup mounts changed during snapshot creation",
        )?;
        let datasets = self.configuration.datasets()?;
        let physical = self.physical();
        let original = self
            .nested
            .lock()
            .map_err(|_| enzimos_platform::Error("backup source inventory lock poisoned".into()))?;
        let current = Self::sample(&self.sources, &datasets, &self.vendor)?;
        created_row(&current, &physical, &self.reviewed, &path, &row)?;
        require(
            stable(&current, &physical)? == *original,
            "backup source inventory has unowned changes; no adoption",
        )?;
        created.recheck()?;
        self.configuration.recheck()?;
        self.guard.recheck()?;
        self.vendor.recheck()?;
        require(
            persistent_mounts(storage_runtime::rows()?) == self.mounts,
            "backup mount closure changed",
        )?;
        drop(original);
        self.recheck()
    }
    pub(crate) fn require_pair(
        &self,
        configuration: &dyn SourceScope,
        guard: &Guard,
    ) -> Result<()> {
        require(
            std::ptr::addr_eq(self.configuration, configuration) && std::ptr::eq(self.guard, guard),
            "review requires original source configuration and storage actors",
        )?;
        self.recheck()
    }
    pub(crate) fn guard(&self) -> &'g Guard {
        self.guard
    }
    pub fn sources(&self) -> &[Source<'g>] {
        &self.sources
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"configuration":self.configuration.evidence()?,"sources":self.sources.iter().map(Source::evidence).collect::<Result<Vec<_>>>()?,"nested":self.nested_value()?,"provider":self.vendor.evidence()?}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(path: &str, id: u64) -> Value {
        json!({"path":path,"id":id,"uuid":format!("00000000-0000-4000-8000-{id:012}"),"parent_uuid":null})
    }
    fn rows(paths: &[(&str, u64)]) -> Value {
        Value::Object(
            paths
                .iter()
                .map(|(path, id)| ((*path).to_owned(), row(path, *id)))
                .collect(),
        )
    }
    fn physical() -> Vec<String> {
        vec!["enzimos-root".into(), "enzimos-home".into()]
    }

    #[test]
    fn only_exact_snapper_snapshots_leave_the_stable_inventory() {
        for path in [
            "enzimos-root/.snapshots/1/snapshot",
            "enzimos-root/.snapshots/4711/snapshot",
        ] {
            assert!(snapper_snapshot(path, "enzimos-root"), "{path}");
        }
        for path in [
            "enzimos-root/.snapshots",
            "enzimos-root/.snapshots/01/snapshot",
            "enzimos-root/.snapshots/x/snapshot",
            "enzimos-root/.snapshots/1/snapshot/nested",
            "enzimos-root/.snapshots/1/other",
            "enzimos-root/var/lib/machines",
            "enzimos-home/.snapshots/1/snapshot",
            "enzimos-rooted/.snapshots/1/snapshot",
        ] {
            assert!(!snapper_snapshot(path, "enzimos-root"), "{path}");
        }
    }
    #[test]
    fn snapper_churn_keeps_the_inventory_but_a_new_data_subvolume_does_not() {
        let before = vec![
            rows(&[
                ("enzimos-root/.snapshots", 300),
                ("enzimos-root/.snapshots/7/snapshot", 301),
            ]),
            rows(&[("enzimos-home/.snapshots", 400)]),
        ];
        let churned = vec![
            rows(&[
                ("enzimos-root/.snapshots", 300),
                ("enzimos-root/.snapshots/8/snapshot", 302),
            ]),
            rows(&[
                ("enzimos-home/.snapshots", 400),
                ("enzimos-home/.snapshots/12/snapshot", 401),
            ]),
        ];
        assert_eq!(
            stable(&before, &physical()).unwrap(),
            stable(&churned, &physical()).unwrap()
        );
        let mut data = churned.clone();
        data[0]["enzimos-root/var/lib/machines"] = row("enzimos-root/var/lib/machines", 500);
        assert_ne!(
            stable(&before, &physical()).unwrap(),
            stable(&data, &physical()).unwrap()
        );
        let mut nested = churned;
        nested[0]["enzimos-root/.snapshots/8/snapshot/inner"] =
            row("enzimos-root/.snapshots/8/snapshot/inner", 501);
        assert_ne!(
            stable(&before, &physical()).unwrap(),
            stable(&nested, &physical()).unwrap()
        );
    }
    #[test]
    fn the_backup_snapshot_must_be_a_new_subvolume_listed_with_exactly_its_row() {
        let path = "enzimos-home/.snapshots/13/snapshot";
        let created = row(path, 402);
        let current = vec![
            rows(&[("enzimos-root/.snapshots", 300)]),
            rows(&[("enzimos-home/.snapshots", 400), (path, 402)]),
        ];
        let reused_number = vec![
            rows(&[("enzimos-root/.snapshots", 300)]),
            rows(&[("enzimos-home/.snapshots", 400), (path, 401)]),
        ];
        let reviewed = subvolume_uuids(&reused_number);
        created_row(&current, &physical(), &reviewed, path, &created).unwrap();
        let replay = subvolume_uuids(&current);
        assert!(created_row(&current, &physical(), &replay, path, &created).is_err());
        let mut other = created.clone();
        other["id"] = json!(403);
        assert!(created_row(&current, &physical(), &reviewed, path, &other).is_err());
        let missing = vec![
            current[0].clone(),
            rows(&[("enzimos-home/.snapshots", 400)]),
        ];
        assert!(created_row(&missing, &physical(), &reviewed, path, &created).is_err());
        let data = "enzimos-home/var/data";
        assert!(created_row(&current, &physical(), &reviewed, data, &row(data, 402)).is_err());
    }
}
