// SPDX-License-Identifier: MIT
//! Original current loader and other publisher-generation closure for fresh review.
use super::*;
use crate::{boot_entries, boot_retirement_plan as plan};
fn independent_loader_closure(
    texts: &BTreeMap<String, String>,
    generation: &str,
    ukis: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let (entries, titles) = plan::entry_names(generation)?;
    let loader = boot_entries::fields(
        texts
            .get("loader/loader.conf")
            .ok_or_else(|| Error("original loader defaults required".into()))?,
        false,
    )?;
    let default = loader
        .get("default")
        .ok_or_else(|| Error("explicit original UEFI default required".into()))?;
    identity::safe_id(default)?;
    require(
        default.ends_with(".conf") && texts.contains_key(&format!("loader/entries/{default}")),
        "ambiguous or missing actual UEFI default",
    )?;
    require(
        !entries.contains(default),
        "UEFI default protects continuation candidate",
    )?;
    for (path, text) in texts
        .iter()
        .filter(|(p, _)| p.starts_with("loader/entries/"))
    {
        if entries
            .iter()
            .any(|n| path == &format!("loader/entries/{n}"))
        {
            continue;
        }
        let fields = boot_entries::fields(text, false)?;
        require(
            !plan::mentions(&value!(fields), generation)?
                && !fields.get("uki").is_some_and(|p| ukis.contains(p)),
            "independent UEFI entry protects continuation candidate",
        )?;
    }
    let menu = boot_entries::menu(
        texts
            .get("limine/limine.conf")
            .ok_or_else(|| Error("original BIOS menu required".into()))?,
    )?;
    let selected = menu.entries[menu.selected - 1].title.clone();
    require(
        !titles.contains(&selected),
        "BIOS default protects continuation candidate",
    )?;
    for entry in &menu.entries {
        if titles.contains(&entry.title) {
            continue;
        }
        let fields = boot_entries::fields(&entry.text, true)?;
        require(
            !plan::mentions(&value!(fields), generation)?,
            "independent BIOS entry protects continuation candidate",
        )?;
    }
    Ok(BTreeSet::from([default.clone(), selected]))
}
pub(super) struct Loaders {
    texts: BTreeMap<String, String>,
    artifacts: BTreeMap<PathBuf, Artifact>,
    directories: BTreeMap<PathBuf, Directory>,
    firmware: Value,
    command_line: String,
    selected: BTreeSet<String>,
    generation: String,
    ukis: BTreeSet<String>,
}
impl Loaders {
    pub(super) fn observe(admission: &Admission<'_>) -> Result<Self> {
        let volume = &admission.volume;
        let generation = admission.record.value()?["intent"]["id"]
            .as_str()
            .unwrap()
            .strip_prefix("boot-")
            .unwrap()
            .to_owned();
        let texts = crate::root_rebind_boot::texts(volume)?;
        let mut artifacts = BTreeMap::new();
        let mut directories = BTreeMap::new();
        for path in ["loader/entries", "enzimos/generations"] {
            directories.insert(path.into(), Directory::observe(volume, Path::new(path))?);
        }
        for (path, text) in &texts {
            let artifact = volume.artifact(Path::new(path), boot_entries::MAX_TEXT as u64)?;
            require(
                files::read_file(&artifact.file, boot_entries::MAX_TEXT, Some(0), true)?
                    == text.as_bytes(),
                "original continuation loader changed during retention",
            )?;
            artifacts.insert(path.into(), artifact);
        }
        let mut ukis = BTreeSet::new();
        for role in &admission.roles {
            if let Role::File(path) = role
                && path.starts_with("enzimos/secure-boot")
            {
                ukis.insert(format!("/{}", path.display()));
            }
        }
        let mut selected = independent_loader_closure(&texts, &generation, &ukis)?;
        let firmware = crate::boot_retirement_context::firmware()?;
        for variable in firmware["variables"].as_object().unwrap().values() {
            selected.insert(variable.as_str().unwrap().into());
        }
        let command_line = crate::boot_retirement_context::command_line()?;
        let uefi: BTreeMap<_, _> = texts
            .iter()
            .filter_map(|(p, t)| {
                p.strip_prefix("loader/entries/")
                    .map(|n| (n.to_owned(), t.clone()))
            })
            .collect();
        let mut expected_generation_names = BTreeSet::new();
        for (id, row) in admission.catalog.data["generations"].as_object().unwrap() {
            if id == &generation {
                if directories[Path::new("enzimos/generations")]
                    .names
                    .contains(id)
                {
                    expected_generation_names.insert(id.clone());
                }
                continue;
            }
            expected_generation_names.insert(id.clone());
            require(
                boot_entries::fingerprint_entries(row, &uefi, &texts["limine/limine.conf"])?
                    == row["entry_fingerprints"],
                "independent publisher loader fingerprints drifted",
            )?;
            let path = PathBuf::from(format!("enzimos/generations/{id}"));
            let directory = Directory::observe(volume, &path)?;
            require(
                directory.names == plan::MEMBERS.iter().map(|n| (*n).into()).collect(),
                "independent publisher generation membership drifted",
            )?;
            for leaf in plan::MEMBERS {
                let relative = path.join(leaf);
                let limit = if leaf.ends_with(".json") {
                    catalog::MAX_CATALOG
                } else {
                    128 * 1024 * 1024
                };
                let artifact = volume.artifact(&relative, limit as u64)?;
                if let Some(expected) = row["material"]["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["name"] == leaf)
                {
                    require(
                        expected["bytes"] == artifact.bytes && expected["sha256"] == artifact.sha,
                        "independent publisher material drifted",
                    )?;
                }
                if leaf == "READY.json" {
                    let ready = json::decode(
                        &files::read_file(&artifact.file, catalog::MAX_CATALOG, Some(0), true)?,
                        catalog::MAX_CATALOG,
                    )?;
                    require(
                        ready
                            == value!({"generation":id,"kernels":row["material"]["kernels"],"files":row["material"]["files"]}),
                        "independent ready manifest differs",
                    )?;
                }
                if leaf == "PUBLISHED.json" {
                    let published = json::decode(
                        &files::read_file(&artifact.file, catalog::MAX_CATALOG, Some(0), true)?,
                        catalog::MAX_CATALOG,
                    )?;
                    json::fields(&published, "generation bios_first_entry flavors")?;
                    require(
                        published["generation"] == *id
                            && published["flavors"] == value!(["linux", "linux-lts"])
                            && published["bios_first_entry"]
                                .as_u64()
                                .is_some_and(|n| (1..=255).contains(&n)),
                        "independent publisher marker invalid",
                    )?;
                }
                artifacts.insert(relative, artifact);
            }
            directories.insert(path, directory);
        }
        require(
            directories[Path::new("enzimos/generations")].names == expected_generation_names,
            "unknown or missing independent publisher generation directory",
        )?;
        let this = Self {
            texts,
            artifacts,
            directories,
            firmware,
            command_line,
            selected,
            generation,
            ukis,
        };
        this.recheck(admission)?;
        Ok(this)
    }
    pub(super) fn retire_original(
        &mut self,
        volume: &Volume,
        relative: &Path,
        retired: &crate::boot_volume::RetiredArtifact,
    ) -> Result<()> {
        if let Some(original) = self.artifacts.get(relative) {
            retired.require_original(original)?;
            let parent = relative
                .parent()
                .ok_or_else(|| Error("original loader artifact parent required".into()))?;
            if let Some(directory) = self.directories.get_mut(parent) {
                directory.advance_removed(
                    volume,
                    retired.removal()?,
                    relative.file_name().unwrap().to_str().unwrap(),
                )?;
            }
            self.artifacts.remove(relative);
            self.texts.remove(
                relative
                    .to_str()
                    .ok_or_else(|| Error("original loader path encoding".into()))?,
            );
        }
        retired.recheck()
    }
    pub(super) fn replace_bios(
        &mut self,
        volume: &Volume,
        replaced: &crate::boot_volume::ReplacedArtifact,
        text: &str,
    ) -> Result<()> {
        let path = Path::new("limine/limine.conf");
        let held = self
            .artifacts
            .get(path)
            .ok_or_else(|| Error("original loader BIOS artifact missing".into()))?;
        replaced.require_original(held)?;
        let actual = files::read_file(
            replaced.file()?,
            crate::boot_entries::MAX_TEXT,
            Some(0),
            true,
        )?;
        require(
            actual == text.as_bytes(),
            "actual owned BIOS replacement bytes differ",
        )?;
        replaced.require_parent_member(
            &volume.directory(Path::new("limine"))?,
            Path::new("limine.conf"),
        )?;
        self.artifacts.remove(path);
        self.texts.insert("limine/limine.conf".into(), text.into());
        replaced.recheck()
    }
    pub(super) fn retire_directory(
        &mut self,
        volume: &Volume,
        relative: &Path,
        removed: &enzimos_platform::named_retirement::Removed,
    ) -> Result<()> {
        let parent = relative
            .parent()
            .ok_or_else(|| Error("original generation directory parent required".into()))?;
        self.directories
            .get_mut(parent)
            .ok_or_else(|| Error("original loader generations parent missing".into()))?
            .advance_removed(
                volume,
                removed,
                relative.file_name().unwrap().to_str().unwrap(),
            )?;
        self.directories.remove(relative);
        removed.recheck()
    }
    // Safe during our own rename/unlink: unlike named-file checks, these
    // independent live selections cannot be changed by the owned mutation.
    pub(super) fn recheck_live_boot(&self) -> Result<()> {
        require(
            crate::boot_retirement_context::firmware()? == self.firmware
                && crate::boot_retirement_context::command_line()? == self.command_line,
            "actual firmware/current boot changed at continuation mutation boundary",
        )
    }
    pub(super) fn texts(&self) -> &BTreeMap<String, String> {
        &self.texts
    }
    pub(super) fn recheck_owned(
        &self,
        admission: &Admission<'_>,
        journal: &ContinuationJournal,
        bios: Option<&crate::boot_volume::ReplacedArtifact>,
    ) -> Result<()> {
        admission.guard.recheck()?;
        admission.lock.recheck()?;
        journal.recheck()?;
        admission.catalog.recheck()?;
        for directory in self.directories.values() {
            directory.recheck(&admission.volume)?;
        }
        for artifact in self.artifacts.values() {
            artifact.recheck()?;
        }
        if let Some(bios) = bios {
            bios.recheck()?;
            require(
                files::read_file(bios.file()?, crate::boot_entries::MAX_TEXT, Some(0), true)?
                    == self.texts["limine/limine.conf"].as_bytes(),
                "known owned loader rewrite bytes changed",
            )?;
        }
        require(
            crate::boot_retirement_context::firmware()? == self.firmware
                && crate::boot_retirement_context::command_line()? == self.command_line,
            "actual original firmware/current boot changed during owned continuation",
        )?;
        let mut selected = independent_loader_closure(&self.texts, &self.generation, &self.ukis)?;
        for variable in self.firmware["variables"].as_object().unwrap().values() {
            selected.insert(variable.as_str().unwrap().into());
        }
        require(
            selected == self.selected,
            "owned continuation changed actual boot selections",
        )?;
        let (entries, titles) = plan::entry_names(&self.generation)?;
        require(
            entries
                .iter()
                .chain(titles.iter())
                .all(|name| !selected.contains(name)),
            "actual selected entry protects owned continuation",
        )?;
        if admission.catalog.data["generations"]
            .get(&self.generation)
            .is_some()
        {
            let markers: Vec<_> = self
                .command_line
                .split_whitespace()
                .filter_map(|s| s.strip_prefix("enzimos.generation="))
                .collect();
            require(
                markers.len() == 1,
                "actual running-generation marker changed",
            )?;
            plan::retention(
                &admission.catalog.data,
                &self.generation,
                &operation::boot_id()?,
                Some(markers[0]),
                &self.selected,
                &admission
                    .references
                    .as_ref()
                    .ok_or_else(|| Error("actual original pin protection absent".into()))?
                    .pins()?,
            )?;
        } else {
            require(
                admission.catalog.data["retired"]
                    .get(&self.generation)
                    .is_some()
                    && json::fingerprint(&admission.catalog.data)?
                        == journal.current()?["intent"]["steps"]
                            .as_array()
                            .unwrap()
                            .last()
                            .unwrap()["after"],
                "known terminal owned publisher tombstone differs",
            )?;
        }
        journal.recheck()?;
        admission.guard.recheck()?;
        admission.lock.recheck()
    }
    pub(super) fn recheck(&self, admission: &Admission<'_>) -> Result<()> {
        admission.guard.recheck()?;
        admission.lock.recheck()?;
        admission.catalog.recheck()?;
        for directory in self.directories.values() {
            directory.recheck(&admission.volume)?;
        }
        for artifact in self.artifacts.values() {
            artifact.recheck()?;
        }
        require(
            crate::boot_retirement_context::firmware()? == self.firmware
                && crate::boot_retirement_context::command_line()? == self.command_line,
            "actual firmware/current boot changed during continuation review",
        )?;
        let mut selected = independent_loader_closure(&self.texts, &self.generation, &self.ukis)?;
        for variable in self.firmware["variables"].as_object().unwrap().values() {
            selected.insert(variable.as_str().unwrap().into());
        }
        require(
            selected == self.selected,
            "original continuation loader selection changed",
        )?;
        let (entries, titles) = plan::entry_names(&self.generation)?;
        require(
            entries
                .iter()
                .chain(titles.iter())
                .all(|n| !selected.contains(n)),
            "actual firmware/default protects continuation candidate",
        )?;
        if admission.catalog.data["generations"]
            .get(&self.generation)
            .is_some()
        {
            let markers: Vec<_> = self
                .command_line
                .split_whitespace()
                .filter_map(|s| s.strip_prefix("enzimos.generation="))
                .collect();
            require(
                markers.len() == 1,
                "one actual running-generation marker required for continuation",
            )?;
            plan::retention(
                &admission.catalog.data,
                &self.generation,
                &operation::boot_id()?,
                Some(markers[0]),
                &self.selected,
                &admission
                    .references
                    .as_ref()
                    .ok_or_else(|| Error("original continuation pins absent".into()))?
                    .pins()?,
            )?;
        } else {
            require(
                admission.catalog.data["retired"]
                    .get(&self.generation)
                    .is_some()
                    && admission.states.last().is_some_and(|s| {
                        admission.record.value().is_ok_and(|r| {
                            r["intent"]["steps"].as_array().unwrap().last().unwrap()["after"]
                                == s.as_str()
                        })
                    })
                    && admission
                        .states
                        .iter()
                        .zip(
                            admission.record.value()?["intent"]["steps"]
                                .as_array()
                                .unwrap(),
                        )
                        .all(|(s, r)| r["after"] == s.as_str()),
                "retired publisher reconciliation requires every actual resource already after",
            )?;
        }
        admission.guard.recheck()?;
        admission.lock.recheck()
    }
    pub(super) fn evidence(&self, admission: &Admission<'_>) -> Result<Value> {
        self.recheck(admission)?;
        let mut artifacts = BTreeMap::new();
        for (path, a) in &self.artifacts {
            artifacts.insert(path.to_string_lossy().into_owned(),value!({"epoch":files::identity(&a.file.metadata()?),"sha256":a.sha,"bytes":a.bytes}));
        }
        Ok(
            value!({"selected":self.selected,"firmware":self.firmware,"command_line":self.command_line,"original_artifacts":artifacts,"execution_authorized":false}),
        )
    }
}
