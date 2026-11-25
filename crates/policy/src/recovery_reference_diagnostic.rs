// SPDX-License-Identifier: MIT
//! Diagnostic protected-reference graph. No graph node or edge is execution authority.
use crate::{boot_entries, identity, recovery_records as records};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json as value};
use std::collections::{BTreeMap, BTreeSet};
type Rows = BTreeMap<String, Value>;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    records::text(v, key)
}
fn boot_path(path: &str, bios: bool) -> Result<String> {
    let path = if bios {
        path.strip_prefix("boot():")
            .ok_or_else(|| Error("fixed BIOS artifact origin required".into()))?
    } else {
        path
    };
    require(
        path.starts_with('/')
            && path.len() <= 4096
            && !path.contains('\\')
            && !path.chars().any(|c| c.is_control() || c.is_whitespace())
            && path[1..].split('/').all(|p| !matches!(p, "" | "." | "..")),
        "canonical boot reference path required",
    )?;
    Ok(path.into())
}
#[derive(Default)]
struct Graph {
    nodes: Rows,
    edges: BTreeSet<(String, String, String)>,
    blockers: BTreeSet<String>,
}
impl Graph {
    fn node(&mut self, key: &str, kind: &str, fields: Value) -> Result<()> {
        require(
            key.len() <= 8192 && fields.is_object(),
            "bounded graph node required",
        )?;
        if !self.nodes.contains_key(key) {
            require(self.nodes.len() < 8192, "recovery reference node bound")?;
            let mut row = fields;
            require(
                row.get("kind").is_none() && row.get("deletion_authorized").is_none(),
                "fixed diagnostic node flags required",
            )?;
            row["kind"] = value!(kind);
            row["deletion_authorized"] = value!(false);
            self.nodes.insert(key.into(), row);
        }
        require(
            self.nodes[key]["kind"] == kind,
            "ambiguous recovery reference kind",
        )
    }
    fn link(&mut self, source: &str, target: &str, reason: &str) -> Result<()> {
        require(
            self.nodes.contains_key(source) && self.nodes.contains_key(target),
            "unknown recovery reference endpoint",
        )?;
        let edge = (source.into(), target.into(), reason.into());
        if !self.edges.contains(&edge) {
            require(self.edges.len() < 32768, "recovery reference edge bound")?;
            self.edges.insert(edge);
        }
        Ok(())
    }
    fn artifact(&mut self, path: &str, expected: Option<Value>) -> Result<String> {
        let path = boot_path(path, false)?;
        let key = format!("boot:{path}");
        self.node(&key, "boot-artifact", value!({"path":path,"expected":[]}))?;
        if let Some(expected) = expected {
            enzimos_platform::json::fields(&expected, "bytes sha256")?;
            require(
                expected["bytes"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= crate::recovery_image::MAX_IMAGE),
                "reference artifact size bound",
            )?;
            identity::sha(text(&expected, "sha256")?)?;
            let values = enzimos_platform::json::array_mut(
                &mut self
                    .nodes
                    .get_mut(&key)
                    .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["expected"],
            )?;
            if !values.contains(&expected) {
                values.push(expected);
            }
            if values.len() > 1 {
                self.blockers
                    .insert(format!("conflicting-artifact-records:{path}"));
            }
        }
        Ok(key)
    }
    fn root(&mut self, identity: &Value, inventory: &Rows) -> Result<String> {
        let uuid = identity::uuid(text(identity, "uuid")?)?;
        let path = text(identity, "path")?;
        require(
            identity["id"].as_u64().is_some_and(|n| n >= 256),
            "root graph filesystem ID required",
        )?;
        let key = format!("root:{uuid}");
        self.node(
            &key,
            "root-resource",
            value!({"identity":identity,"identity_matches":null}),
        )?;
        let matches = inventory.get(path).is_some_and(|actual| {
            identity.as_object().is_some_and(|r| {
                r.iter()
                    .filter(|(k, _)| *k != "ownership")
                    .all(|(k, v)| actual.get(k) == Some(v))
            })
        });
        let row = self
            .nodes
            .get_mut(&key)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?;
        require(
            ["path", "id", "uuid"]
                .iter()
                .all(|k| row["identity"][*k] == identity[*k]),
            "conflicting root reference identity",
        )?;
        row["identity_matches"] = value!(
            matches && (row["identity_matches"].is_null() || row["identity_matches"] == true)
        );
        if !matches {
            self.blockers
                .insert(format!("recovery-root-identity-drift:{path}"));
        }
        Ok(key)
    }
    fn material(
        &mut self,
        key: &str,
        name: &str,
        material: &Value,
        inventory: &Rows,
        root_reason: &str,
        file_reason: &str,
    ) -> Result<()> {
        let target = self.root(&material["root_identity"], inventory)?;
        self.link(key, &target, root_reason)?;
        for item in material["files"]
            .as_array()
            .ok_or_else(|| Error("graph material files required".into()))?
        {
            let target = self.artifact(
                &format!("/enzimos/generations/{name}/{}", text(item, "name")?),
                Some(value!({"bytes":item["bytes"],"sha256":item["sha256"]})),
            )?;
            self.link(key, &target, file_reason)?;
        }
        Ok(())
    }
    fn loader(
        &mut self,
        kind: &str,
        name: &str,
        fields: &BTreeMap<String, String>,
        inventory: &Rows,
    ) -> Result<String> {
        let bios = kind != "uefi";
        let key = format!("entry:{kind}:{name}");
        self.node(&key, "loader-entry", value!({"loader":kind,"name":name}))?;
        let known: &[&str] = if bios {
            &["protocol", "path", "module_path", "cmdline"]
        } else {
            &[
                "title",
                "version",
                "machine-id",
                "sort-key",
                "architecture",
                "linux",
                "initrd",
                "options",
                "uki",
            ]
        };
        if fields.keys().any(|k| !known.contains(&k.as_str())) {
            self.blockers
                .insert(format!("unparsed-loader-fields:{kind}:{name}"));
        }
        if bios && fields.get("protocol").map(String::as_str) != Some("linux") {
            self.blockers
                .insert(format!("unqualified-loader-protocol:{name}"));
        }
        let paths: &[&str] = if bios {
            &["path", "module_path"]
        } else if fields.contains_key("uki") {
            &["linux", "initrd", "uki"]
        } else {
            &["linux", "initrd"]
        };
        for field in paths {
            let Some(path) = fields.get(*field) else {
                self.blockers
                    .insert(format!("missing-loader-artifact:{kind}:{name}:{field}"));
                continue;
            };
            match boot_path(path, bios) {
                Ok(path) => {
                    let target = self.artifact(&path, None)?;
                    self.link(&key, &target, "loader-artifact")?;
                }
                Err(_) => {
                    self.blockers
                        .insert(format!("unresolved-loader-artifact:{kind}:{name}:{field}"));
                }
            }
        }
        let options = fields
            .get(if bios { "cmdline" } else { "options" })
            .map_or("", String::as_str);
        if options
            .split_whitespace()
            .any(|w| w.starts_with("rootflags=") || w.starts_with("root="))
        {
            match crate::boot_options::subvolume_from_options(options) {
                Ok(path) => {
                    if let Some(actual) = inventory.get(&path) {
                        let target = self.root(actual, inventory)?;
                        self.link(&key, &target, "loader-root")?;
                    } else {
                        self.blockers.insert(format!("missing-loader-root:{path}"));
                    }
                }
                Err(_) => {
                    self.blockers
                        .insert(format!("unresolved-loader-root:{kind}:{name}"));
                }
            }
        }
        Ok(key)
    }
    fn select(&mut self, source: &str, kind: &str, name: &str, reason: &str) -> Result<()> {
        let key = format!("entry:{kind}:{name}");
        if self.nodes.contains_key(&key) {
            self.link(source, &key, reason)
        } else {
            self.blockers
                .insert(format!("unresolved-boot-selection:{kind}:{name}"));
            Ok(())
        }
    }
    fn before_menu(
        &mut self,
        owner: &str,
        kind: &str,
        text: &str,
        inventory: &Rows,
        reason: &str,
    ) -> Result<()> {
        let menu = boot_entries::menu(text)?;
        for entry in menu.entries {
            let fields = boot_entries::fields(&entry.text, true)?;
            let target = self.loader(kind, &entry.title, &fields, inventory)?;
            self.link(owner, &target, reason)?;
        }
        Ok(())
    }
    fn finish(mut self) -> Value {
        for row in self.nodes.values() {
            if row["kind"] == "boot-artifact" && row["expected"].as_array().unwrap().is_empty() {
                self.blockers.insert(format!(
                    "unowned-boot-reference:{}",
                    row["path"].as_str().unwrap()
                ));
            }
        }
        value!({"schema":1,"status":"OBSERVED-recovery-reference-graph-retirement-blocked","complete":false,"execution_available":false,
            "nodes":self.nodes,"edges":self.edges.iter().map(|(a,b,c)|value!({"source":a,"target":b,"reason":c})).collect::<Vec<_>>(),"blockers":self.blockers,
            "scope":"diagnostic protected references; explicit generation pins only, incomplete namespace/foreign-loader support; no ownership or deletion authority"})
    }
}

fn rows(v: &Value, maximum: usize) -> Result<Rows> {
    require(
        v.as_object().is_some_and(|r| r.len() <= maximum),
        "bounded diagnostic record map required",
    )?;
    serde_json::from_value(v.clone()).map_err(Into::into)
}
fn fields(v: &Value) -> Result<BTreeMap<String, String>> {
    if v.get("unparsed") == Some(&value!(true)) {
        return Ok(BTreeMap::from([("unparsed".into(), "true".into())]));
    }
    serde_json::from_value(v.clone()).map_err(Into::into)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fnmatch).")]
pub(crate) fn candidates(config: &str, uefi: &Rows, variables: &Rows) -> Result<BTreeSet<String>> {
    let config = boot_entries::fields(config, false)?;
    let default = config
        .get("default")
        .ok_or_else(|| Error("explicit before default required".into()))?;
    let pattern = if default == "@saved" {
        variables
            .get("LoaderEntryLastBooted")
            .and_then(Value::as_str)
            .ok_or_else(|| Error("saved UEFI selection unavailable".into()))?
    } else {
        default
    };
    require(
        !pattern.starts_with('@') && pattern.len() <= 256,
        "bounded supported UEFI default pattern required",
    )?;
    let pattern =
        std::ffi::CString::new(pattern).map_err(|_| Error("UEFI pattern encoding".into()))?;
    let mut matches = BTreeSet::new();
    for name in uefi.keys() {
        require(name.len() <= 256, "bounded UEFI entry name required")?;
        let name_c = std::ffi::CString::new(name.as_str())
            .map_err(|_| Error("UEFI entry encoding".into()))?;
        let result =
            // SAFETY: Both strings are NUL-terminated CStrings.
            unsafe { libc::fnmatch(pattern.as_ptr(), name_c.as_ptr(), libc::FNM_NOESCAPE) };
        require(
            result == 0 || result == libc::FNM_NOMATCH,
            "UEFI pattern match unavailable",
        )?;
        if result == 0 {
            matches.insert(name.clone());
        }
    }
    require(!matches.is_empty(), "UEFI default has no observed entry")?;
    Ok(matches)
}
/// Internal data join only; original observers remain held by its collector.
pub(crate) fn join(input: &Value) -> Result<Value> {
    let catalog = &input["catalog"];
    let roots = &input["root_references"];
    let fs = text(catalog, "filesystem_uuid")?;
    crate::catalog::validate(catalog, fs)?;
    require(
        roots["filesystem_uuid"] == fs
            && roots["complete"] == false
            && roots["execution_available"] == false,
        "blocked root diagnostic source required",
    )?;
    let image_records = rows(&input["images"], crate::recovery_image::MAX_IMAGES)?;
    let journals = rows(&input["publications"], crate::recovery_image::MAX_IMAGES)?;
    let jobs = rows(&input["jobs"], records::MAX_JOBS)?;
    let activations = rows(&input["activations"], records::MAX_JOBS)?;
    let pins = rows(&input["pins"], crate::generation_pins::MAXIMUM)?;
    let rebinds = rows(&input["rebinds"], 32)?;
    let operations = rows(&input["operations"], 128)?;
    let retirements = rows(&input["retirements"], 128)?;
    let uefi = rows(&input["uefi"], 256)?;
    let variables = rows(&input["variables"], 64)?;
    let bios = input["bios"]
        .as_array()
        .ok_or_else(|| Error("diagnostic BIOS entries required".into()))?;
    let defaults = input["defaults"]
        .as_array()
        .ok_or_else(|| Error("diagnostic default candidates required".into()))?;
    require(
        bios.len() <= 256 && defaults.len() <= 256 && input["efi_observable"].is_boolean(),
        "bounded boot reference observations required",
    )?;
    let cmdline = text(input, "command_line")?;
    require(cmdline.len() <= 8192, "boot command line bound")?;
    let boot_uuid = text(input, "boot_uuid")?;
    records::fat_uuid(boot_uuid)?;
    let root_rows = rows(&roots["resources"], 4096)?;
    let inventory: Rows = root_rows
        .values()
        .map(|r| Ok((text(&r["identity"], "path")?.into(), r["identity"].clone())))
        .collect::<Result<_>>()?;
    require(
        inventory.len() == root_rows.len(),
        "ambiguous diagnostic root paths",
    )?;
    crate::root_reference_diagnostic::validate_inventory(&inventory)?;
    let mut graph = Graph::default();
    graph.blockers.extend(
        [
            "recovery-workflow-retirement-not-qualified",
            "complete-retirement-inventory-not-implemented",
            "retirement-executor-not-implemented",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    for blocker in roots["blockers"]
        .as_array()
        .ok_or_else(|| Error("root reference blockers required".into()))?
    {
        graph.blockers.insert(
            blocker
                .as_str()
                .ok_or_else(|| Error("root blocker text required".into()))?
                .into(),
        );
    }
    for row in root_rows.values() {
        graph.root(&row["identity"], &inventory)?;
    }
    for (uuid, row) in &root_rows {
        let key = format!("root:{uuid}");
        for (field, reason) in [
            ("children", "contains"),
            ("birth_dependencies", "birth-dependency"),
        ] {
            for target in row[field]
                .as_array()
                .ok_or_else(|| Error("root dependency array required".into()))?
            {
                graph.link(
                    &key,
                    &format!(
                        "root:{}",
                        target
                            .as_str()
                            .ok_or_else(|| Error("root dependency UUID required".into()))?
                    ),
                    reason,
                )?;
            }
        }
        graph
            .nodes
            .get_mut(&key)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["observed_mounts"] =
            row["mount_references"].clone();
    }
    for (name, row) in enzimos_platform::json::object(&catalog["generations"])? {
        let key = format!("system:{name}");
        graph.node(&key, "system-generation", value!({"state":row["state"]}))?;
        graph.material(&key, name, &row["material"], &inventory, "root", "artifact")?;
    }
    graph.blockers.remove("user-pin-inventory-unavailable");
    for (id, row) in &pins {
        crate::generation_pins::validate(row, id, fs)?;
        let name = text(row, "generation")?;
        let key = format!("pin:{id}");
        graph.node(
            &key,
            "generation-keep-pin",
            value!({"generation":name,"material_sha256":row["material_sha256"]}),
        )?;
        let source = format!("system:{name}");
        graph.node(
            &source,
            "system-generation",
            value!({"state":"record-missing"}),
        )?;
        graph.link(&key, &source, "keep-generation")?;
        if catalog["generations"]
            .get(name)
            .is_none_or(|r| r["material"] != row["material"])
        {
            graph
                .blockers
                .insert(format!("pinned-generation-missing-or-drift:{id}"));
        }
        graph.material(
            &key,
            name,
            &row["material"],
            &inventory,
            "keep-root",
            "keep-artifact",
        )?;
    }
    for (id, row) in &rebinds {
        crate::root_rebind_record::validate(row, id)?;
        require(
            row["filesystem_uuid"] == fs,
            "rebind graph filesystem mismatch",
        )?;
        let key = format!("rebind:{id}");
        graph.node(&key, "root-rebind-journal", value!({"phase":row["phase"]}))?;
        if row["phase"] != "complete" {
            graph
                .blockers
                .insert(format!("pending-rebind-journal:{id}"));
        }
        for role in ["source", "target"] {
            let target = graph.root(&row[role], &inventory)?;
            graph.link(&key, &target, &format!("rebind-{role}"))?;
        }
        for phase in ["before_catalog", "after_catalog"] {
            for (name, generation) in enzimos_platform::json::object(&row[phase]["generations"])? {
                graph.material(
                    &key,
                    name,
                    &generation["material"],
                    &inventory,
                    &format!("rebind-{phase}-root"),
                    &format!("rebind-{phase}-artifact"),
                )?;
            }
        }
        let path = format!(
            "{}/.snapshots/{}/snapshot",
            text(&row["source"], "path")?,
            enzimos_platform::json::unsigned(&row["snapshot"]["number"])?
        );
        if let Some(actual) = inventory
            .get(&path)
            .filter(|r| r["uuid"] == row["snapshot"]["uuid"])
        {
            let target = graph.root(actual, &inventory)?;
            graph.link(&key, &target, "rebind-source-snapshot")?;
        } else {
            graph
                .blockers
                .insert(format!("rebind-source-snapshot-missing-or-drift:{id}"));
        }
    }
    let concluded: BTreeSet<_> = activations
        .iter()
        .filter(|(_, r)| r["phase"] == "adopted" && r["superseded"]["legacy_detached"] == true)
        .map(|(id, _)| id.as_str())
        .collect();
    for (id, row) in &operations {
        crate::boot_backend_references::validate(row, id)?;
        let key = format!("operation:{id}");
        let operation = text(row, "operation")?;
        graph.node(
            &key,
            "backend-operation",
            value!({"operation":operation,"state":row["state"],"plan_sha256":row["plan_sha256"]}),
        )?;
        graph
            .blockers
            .insert(format!("backend-operation-retirement-not-qualified:{id}"));
        if operation == "recovery-prepare" {
            if concluded.contains(format!("api-{id}").as_str()) {
                continue;
            }
            let selection = &row["plan"]["selection"];
            enzimos_platform::json::fields(selection, "birth generation")?;
            for field in ["birth", "generation"] {
                identity::safe_id(text(selection, field)?)?;
            }
            let source = format!("system:{}", text(selection, "generation")?);
            graph.node(
                &source,
                "system-generation",
                value!({"state":"record-missing"}),
            )?;
            graph.link(&key, &source, "backend-recovery-source")?;
            let target = format!("stage:api-{id}");
            graph.node(&target,"staging-job",value!({"phase":"record-missing","target_name":format!("enzimos-recovered-api-{id}")}))?;
            graph.link(&key, &target, "backend-recovery-result-or-reservation")?;
        } else if operation == "update-apply" {
            for name in [format!("api-{id}"), format!("old-api-{id}")] {
                let target = format!("system:{name}");
                graph.node(
                    &target,
                    "system-generation",
                    value!({"state":"record-missing"}),
                )?;
                graph.link(&key, &target, "backend-update-result-or-fallback")?;
            }
        }
    }
    for (id, row) in &retirements {
        crate::retirement_journal::validate(row, id)?;
        require(
            row["intent"]["filesystem_uuid"] == fs,
            "retirement graph source mismatch",
        )?;
        graph.node(
            &format!("retirement:{id}"),
            "retirement-journal",
            value!({"phase":row["phase"],"intent_sha256":row["intent"]["intent_sha256"]}),
        )?;
        graph.blockers.insert(format!(
            "retirement-concrete-resource-references-unavailable:{id}"
        ));
    }
    let mut expected_entries: BTreeMap<(String, String), String> = BTreeMap::new();
    for (id, row) in &image_records {
        crate::recovery_image::validate(row, id)?;
        require(row["filesystem_uuid"] == fs, "image graph source mismatch")?;
        let key = format!("recovery:{id}");
        let modes: Vec<_> = enzimos_platform::json::object(&row["observations"])?
            .keys()
            .collect();
        graph.node(
            &key,
            "recovery-image",
            value!({"phase":row["phase"],"software_observed_modes":modes}),
        )?;
        if row["phase"] != "ready" {
            graph
                .blockers
                .insert(format!("pending-recovery-image:{id}"));
        }
        if row["boot_uuid"] != boot_uuid {
            graph
                .blockers
                .insert(format!("recovery-boot-volume-drift:{id}"));
        }
        let target = graph.root(&row["control"], &inventory)?;
        graph.link(&key, &target, "control-storage")?;
        for (name, item) in enzimos_platform::json::object(&row["inputs"]["files"])? {
            let target = graph.artifact(
                &format!("/enzimos/recovery-images/{id}/{name}"),
                Some(item.clone()),
            )?;
            graph.link(&key, &target, "artifact")?;
        }
        let (uefi, bios) = crate::recovery_image::entry_names(id)?;
        expected_entries.insert(("uefi".into(), uefi), key.clone());
        expected_entries.insert(("bios".into(), bios), key);
    }
    for (id, row) in &journals {
        crate::recovery_publication::validate(row, id)?;
        let record = &row["record"];
        require(
            record["filesystem_uuid"] == fs,
            "publication graph source mismatch",
        )?;
        let key = format!("publication:{id}");
        graph.node(
            &key,
            "publication-journal",
            value!({"journal_sha256":row["journal_sha256"]}),
        )?;
        let target = format!("recovery:{id}");
        graph.node(
            &target,
            "recovery-image",
            value!({"phase":"record-missing","software_observed_modes":[]}),
        )?;
        graph.link(&key, &target, "publication-intent")?;
        if let Some(current) = image_records.get(id) {
            let mut normalized = current.clone();
            normalized["phase"] = value!("intent");
            normalized["observations"] = value!({});
            if normalized != *record {
                graph
                    .blockers
                    .insert(format!("publication-image-record-drift:{id}"));
            }
        } else {
            graph
                .blockers
                .insert(format!("publication-image-record-missing:{id}"));
        }
        if image_records.get(id).is_none_or(|r| r["phase"] != "ready") {
            graph
                .blockers
                .insert(format!("pending-publication-journal:{id}"));
        }
        if record["boot_uuid"] != boot_uuid {
            graph
                .blockers
                .insert(format!("publication-boot-volume-drift:{id}"));
        }
        let target = graph.root(&record["control"], &inventory)?;
        graph.link(&key, &target, "control-storage")?;
        for (name, item) in enzimos_platform::json::object(&record["inputs"]["files"])? {
            let target = graph.artifact(
                &format!("/enzimos/recovery-images/{id}/{name}"),
                Some(item.clone()),
            )?;
            graph.link(&key, &target, "journal-artifact")?;
        }
        let menu = boot_entries::menu(text(row, "bios_before")?)?;
        graph
            .nodes
            .get_mut(&key)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["bios_default_before"] =
            value!(menu.entries[menu.selected - 1].title);
        graph
            .nodes
            .get_mut(&key)
            .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["uefi_config_before"] =
            value!(boot_entries::fields(text(row, "default_before")?, false)?);
        graph.before_menu(
            &key,
            &format!("journal-bios:{id}"),
            text(row, "bios_before")?,
            &inventory,
            "before-entry",
        )?;
        match candidates(text(row, "default_before")?, &uefi, &variables) {
            Ok(candidates) => {
                for candidate in candidates {
                    let target = format!("entry:uefi:{candidate}");
                    graph.node(
                        &target,
                        "loader-entry",
                        value!({"loader":"uefi","name":candidate}),
                    )?;
                    graph.link(&key, &target, "default-before")?;
                }
            }
            Err(_) => {
                if image_records.get(id).is_none_or(|r| r["phase"] != "ready") {
                    graph
                        .blockers
                        .insert(format!("unresolved-publication-default-before:{id}"));
                }
            }
        }
    }
    finish_active_graph(
        graph,
        input,
        &inventory,
        catalog,
        &jobs,
        &activations,
        &uefi,
        &variables,
        bios,
        defaults,
        expected_entries,
        &concluded,
    )
}

mod completion;
use completion::finish_active_graph;
pub(crate) use completion::finish_observation;
