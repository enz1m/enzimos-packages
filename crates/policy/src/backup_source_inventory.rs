// SPDX-License-Identifier: MIT
//! Complete, bounded nested-source inventory precedes snapshot capture admission.
use crate::{
    backup_configuration::Configuration,
    backup_source::Source,
    backup_source_layout::{Dataset, layout},
    birth_runtime::parse_inventory,
    settings_command::Command,
    storage_runtime::{self, Guard},
};
use enzimos_platform::{Result, mountinfo, require};
use serde_json::{Value, json};
use std::{
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
fn creation_rows(
    before: &[Value],
    physical: &[String],
    path: &str,
    row: &Value,
) -> Result<Vec<Value>> {
    require(
        before.len() == physical.len() && row["path"] == path,
        "created inventory row shape differs",
    )?;
    enzimos_platform::json::fields(row, "path id uuid parent_uuid")?;
    let mut expected = before.to_vec();
    let mut affected = false;
    for (rows, parent) in expected.iter_mut().zip(physical) {
        if path.starts_with(&format!("{parent}/")) {
            let rows = rows.as_object_mut().ok_or_else(|| {
                enzimos_platform::Error("original nested inventory object required".into())
            })?;
            require(
                rows.insert(path.into(), row.clone()).is_none(),
                "created snapshot already recorded; no replay",
            )?;
            affected = true;
        }
    }
    require(
        affected,
        "created snapshot escaped original source inventory",
    )?;
    Ok(expected)
}
pub struct Inventory<'a, 'g> {
    configuration: &'a Configuration,
    guard: &'g Guard,
    sources: Vec<Source<'g>>,
    vendor: Command,
    mounts: Vec<mountinfo::Row>,
    nested: Mutex<Vec<Value>>,
}
impl<'a, 'g> Inventory<'a, 'g> {
    pub fn observe(configuration: &'a Configuration, guard: &'g Guard) -> Result<Self> {
        configuration.recheck()?;
        guard.recheck()?;
        let datasets = layout(configuration.value())?;
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
        let nested = Self::sample(&sources, &datasets, &vendor)?;
        let this = Self {
            configuration,
            guard,
            sources,
            vendor,
            mounts: persistent_mounts(mounts),
            nested: Mutex::new(nested),
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
        self.configuration.recheck()?;
        self.guard.recheck()?;
        self.vendor.recheck()?;
        let datasets = layout(self.configuration.value())?;
        require(
            persistent_mounts(storage_runtime::rows()?) == self.mounts
                && Self::sample(&self.sources, &datasets, &self.vendor)? == self.nested_value()?,
            "original backup source inventory changed; new review required",
        )?;
        self.configuration.recheck()?;
        self.guard.recheck()?;
        require(
            persistent_mounts(storage_runtime::rows()?) == self.mounts,
            "backup mounts changed during source inventory",
        )
    }
    fn nested_value(&self) -> Result<Vec<Value>> {
        self.nested
            .lock()
            .map(|value| value.clone())
            .map_err(|_| enzimos_platform::Error("backup source inventory lock poisoned".into()))
    }
    /// Advance only the known creation proven by an original retained actor.
    /// A decoded row or an independently opened old snapshot cannot invoke this.
    pub fn advance_created(
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
        let datasets = layout(self.configuration.value())?;
        let physical = self
            .sources
            .iter()
            .map(Source::filesystem_path)
            .collect::<Vec<_>>();
        let mut original = self
            .nested
            .lock()
            .map_err(|_| enzimos_platform::Error("backup source inventory lock poisoned".into()))?;
        let expected = creation_rows(&original, &physical, &path, &row)?;
        let current = Self::sample(&self.sources, &datasets, &self.vendor)?;
        require(
            current == expected,
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
        *original = expected;
        drop(original);
        self.recheck()
    }
    pub(crate) fn require_pair(&self, configuration: &Configuration, guard: &Guard) -> Result<()> {
        require(
            std::ptr::eq(self.configuration, configuration) && std::ptr::eq(self.guard, guard),
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
