use super::*;

pub(super) fn finish_active_graph(
    mut graph: Graph,
    input: &Value,
    inventory: &Rows,
    catalog: &Value,
    jobs: &Rows,
    activations: &Rows,
    uefi: &Rows,
    variables: &Rows,
    bios: &[Value],
    defaults: &[Value],
    mut expected: BTreeMap<(String, String), String>,
    concluded: &BTreeSet<&str>,
) -> Result<Value> {
    let fs = text(catalog, "filesystem_uuid")?;
    let boot_uuid = text(input, "boot_uuid")?;
    for (id, row) in jobs {
        records::job(row, id)?;
        let plan = &row["plan"];
        require(
            plan["filesystem_uuid"] == fs,
            "staging graph filesystem mismatch",
        )?;
        let key = format!("stage:{id}");
        if concluded.contains(id.as_str()) && row["phase"] == "staged" {
            graph.node(
                &key,
                "staging-job",
                value!({"phase":"concluded","target_name":plan["target_name"]}),
            )?;
            for role in ["root", "history"] {
                let target = graph.root(&row[role], inventory)?;
                graph.link(&key, &target, "staging-root-dependency")?;
            }
            continue;
        }
        graph.node(
            &key,
            "staging-job",
            value!({"phase":row["phase"],"target_name":plan["target_name"]}),
        )?;
        let destination = format!("root-path:{}", text(plan, "target_name")?);
        graph.node(
            &destination,
            "reserved-root-path",
            value!({"path":plan["target_name"]}),
        )?;
        graph.link(&key, &destination, "reserved-destination-not-ownership")?;
        if row["phase"] != "staged" {
            graph
                .blockers
                .insert(format!("pending-recovery-stage:{id}"));
        }
        if plan["boot_uuid"] != boot_uuid {
            graph
                .blockers
                .insert(format!("staging-boot-volume-drift:{id}"));
        }
        let generation = text(plan, "generation")?;
        let source = format!("system:{generation}");
        graph.node(
            &source,
            "system-generation",
            value!({"state":"record-missing"}),
        )?;
        graph.link(&key, &source, "source-generation")?;
        if catalog["generations"]
            .get(generation)
            .is_none_or(|r| r["material"] != plan["material"])
        {
            graph
                .blockers
                .insert(format!("staging-generation-material-drift:{id}"));
        }
        let birth = &plan["source_birth"];
        let mut identities = vec![
            &birth["source"],
            &birth["snapshot"]["object"],
            &birth["root"],
            &birth["history"],
        ];
        identities.extend(enzimos_platform::json::object(&plan["protected"])?.values());
        identities.extend(
            [&row["root"], &row["history"]]
                .into_iter()
                .filter(|v| !v.is_null()),
        );
        for identity in identities {
            let target = graph.root(identity, inventory)?;
            graph.link(&key, &target, "staging-root-dependency")?;
        }
        for item in enzimos_platform::json::array(&plan["material"]["files"])? {
            let target = graph.artifact(
                &format!("/enzimos/generations/{generation}/{}", text(item, "name")?),
                Some(value!({"bytes":item["bytes"],"sha256":item["sha256"]})),
            )?;
            graph.link(&key, &target, "staging-artifact")?;
        }
    }
    for (id, row) in activations {
        crate::recovery_activation::validate(row, id)?;
        let intent = &row["intent"];
        let job = &intent["job"];
        let plan = &job["plan"];
        require(
            plan["filesystem_uuid"] == fs,
            "activation graph source mismatch",
        )?;
        let key = format!("activation:{id}");
        graph.node(
            &key,
            "activation-journal",
            value!({"phase":row["phase"],"intent_sha256":intent["intent_sha256"]}),
        )?;
        let target = format!("stage:{id}");
        graph.node(
            &target,
            "staging-job",
            value!({"phase":"record-missing","target_name":plan["target_name"]}),
        )?;
        graph.link(&key, &target, "activation-job")?;
        if jobs.get(id) != Some(job) {
            graph
                .blockers
                .insert(format!("activation-staging-record-drift:{id}"));
        }
        if !matches!(
            row["phase"].as_str(),
            Some("published" | "selected" | "adopted")
        ) {
            graph
                .blockers
                .insert(format!("pending-staged-activation:{id}"));
        }
        for role in ["root", "history"] {
            let target = graph.root(&job[role], inventory)?;
            graph.link(&key, &target, "activation-root")?;
        }
        if concluded.contains(id.as_str()) {
            graph
                .nodes
                .get_mut(&key)
                .ok_or_else(|| enzimos_platform::Error("missing element".into()))?["phase"] =
                value!("concluded");
            continue;
        }
        let birth = &plan["source_birth"];
        let mut identities = vec![
            &birth["source"],
            &birth["root"],
            &birth["snapshot"]["object"],
            &birth["history"],
        ];
        identities.extend(enzimos_platform::json::object(&plan["protected"])?.values());
        for identity in identities {
            let target = graph.root(identity, inventory)?;
            graph.link(&key, &target, "activation-source-dependency")?;
        }
        let generation = text(plan, "generation")?;
        for item in enzimos_platform::json::array(&plan["material"]["files"])? {
            let target = graph.artifact(
                &format!("/enzimos/generations/{generation}/{}", text(item, "name")?),
                Some(value!({"bytes":item["bytes"],"sha256":item["sha256"]})),
            )?;
            graph.link(&key, &target, "activation-artifact")?;
        }
        for flavor in ["linux", "linux-lts"] {
            let (uefi, bios) = crate::recovery_activation::entry_names(id, flavor)?;
            expected.insert(("uefi".into(), uefi), key.clone());
            expected.insert(("bios".into(), bios), key.clone());
        }
        graph.before_menu(
            &key,
            &format!("activation-bios:{id}"),
            text(intent, "bios_before")?,
            inventory,
            "activation-before-entry",
        )?;
        match candidates(text(intent, "default_before")?, uefi, variables) {
            Ok(candidates) => {
                for candidate in candidates {
                    let target = format!("entry:uefi:{candidate}");
                    graph.node(
                        &target,
                        "loader-entry",
                        value!({"loader":"uefi","name":candidate}),
                    )?;
                    graph.link(&key, &target, "activation-default-before")?;
                }
            }
            Err(_) => {
                if row["phase"] != "adopted" {
                    graph
                        .blockers
                        .insert(format!("unresolved-activation-default-before:{id}"));
                }
            }
        }
    }
    for (name, row) in uefi {
        graph.loader("uefi", name, &fields(row)?, inventory)?;
    }
    let mut titles = BTreeSet::new();
    for entry in bios {
        let title = text(entry, "title")?;
        require(titles.insert(title), "duplicate BIOS graph title")?;
        let fields = boot_entries::fields(text(entry, "text")?, true)
            .unwrap_or_else(|_| BTreeMap::from([("unparsed".into(), "true".into())]));
        graph.loader("bios", title, &fields, inventory)?;
    }
    for ((kind, name), target) in expected {
        let entry = format!("entry:{kind}:{name}");
        if graph.nodes.contains_key(&entry) {
            graph.link(&target, &entry, "published-entry")?;
        } else {
            graph
                .blockers
                .insert(format!("recovery-entry-missing:{kind}:{name}"));
        }
    }
    let selection = "selection:current";
    graph.node(selection, "boot-selection", value!({}))?;
    for name in defaults {
        graph.select(
            selection,
            "uefi",
            name.as_str()
                .ok_or_else(|| Error("UEFI candidate text required".into()))?,
            "uefi-default",
        )?;
    }
    graph.select(
        selection,
        "bios",
        text(input, "bios_default_title")?,
        "bios-default",
    )?;
    if input["efi_observable"] != true {
        graph
            .blockers
            .insert("EFI-loader-state-not-observable-on-this-boot".into());
    }
    for (key, name) in variables {
        if ![
            "LoaderEntrySelected",
            "LoaderEntryDefault",
            "LoaderEntryOneShot",
            "LoaderEntryLastBooted",
        ]
        .contains(&key.as_str())
        {
            graph
                .blockers
                .insert(format!("unrecognized-EFI-loader-state:{key}"));
        }
        graph.select(
            selection,
            "uefi",
            name.as_str()
                .ok_or_else(|| Error("firmware entry text required".into()))?,
            key,
        )?;
    }
    for (prefix, kind) in [
        ("enzimos.generation=", "system:"),
        ("enzimos.recovery=", "recovery:"),
        ("enzimos.staged=", "activation:"),
    ] {
        let markers: Vec<_> = text(input, "command_line")?
            .split_whitespace()
            .filter_map(|w| w.strip_prefix(prefix))
            .collect();
        if markers.len() > 1 {
            graph
                .blockers
                .insert(format!("ambiguous-running-marker:{prefix}"));
        }
        for name in markers {
            let target = format!("{kind}{name}");
            if graph.nodes.contains_key(&target) {
                graph.link(selection, &target, "running-marker-not-authority")?;
            } else {
                graph
                    .blockers
                    .insert(format!("unresolved-running-marker:{name}"));
            }
        }
    }
    Ok(graph.finish())
}

fn terminal_before(nodes: &serde_json::Map<String, Value>, source: &str, reason: &str) -> bool {
    if reason != "loader-artifact" {
        return false;
    }
    for (prefix, owner, phase) in [
        ("entry:journal-bios:", "recovery:", "ready"),
        ("entry:activation-bios:", "activation:", "adopted"),
    ] {
        if let Some(tail) = source.strip_prefix(prefix) {
            let id = tail.split(':').next().unwrap();
            return nodes
                .get(&format!("{owner}{id}"))
                .is_some_and(|r| r["phase"] == phase || r["phase"] == "concluded");
        }
    }
    false
}
/// Join only measured hashes and actual original records supplied by the observer.
/// Historical diagnostics never supply a deletion exemption to an execution actor.
pub(crate) fn finish_observation(
    mut report: Value,
    catalog: &Value,
    births: &Rows,
    measured: &Rows,
) -> Result<Value> {
    let nodes = report["nodes"]
        .as_object()
        .ok_or_else(|| Error("diagnostic graph nodes required".into()))?
        .clone();
    let edges = report["edges"]
        .as_array()
        .ok_or_else(|| Error("diagnostic graph edges required".into()))?;
    let mut incoming: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for edge in edges {
        incoming
            .entry(text(edge, "target")?.into())
            .or_default()
            .push((text(edge, "source")?.into(), text(edge, "reason")?.into()));
    }
    let mut tombstones = BTreeMap::new();
    for row in births.values().filter(|r| r["phase"] == "retired") {
        for role in ["root", "history"] {
            tombstones.insert(text(&row[role], "uuid")?.to_owned(), row[role].clone());
        }
    }
    let mut blockers: BTreeSet<String> = enzimos_platform::json::array(&report["blockers"])?
        .iter()
        .map(|b| {
            b.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error("graph blocker text required".into()))
        })
        .collect::<Result<_>>()?;
    for (key, node) in &nodes {
        let incoming = incoming.get(key);
        let nonempty = incoming.is_some_and(|r| !r.is_empty());
        let edges = incoming.map(Vec::as_slice).unwrap_or(&[]);
        let completed_rebind = |source: &str| {
            nodes
                .get(source)
                .is_some_and(|r| r["kind"] == "root-rebind-journal" && r["phase"] == "complete")
        };
        if node["kind"] == "boot-artifact" {
            let path = text(node, "path")?;
            let parts: Vec<_> = path.split('/').collect();
            let retired = parts.len() >= 4
                && parts[1] == "enzimos"
                && parts[2] == "generations"
                && catalog["retired"].get(parts[3]).is_some();
            let historical = retired
                && nonempty
                && edges.iter().all(|(s, r)| {
                    (completed_rebind(s)
                        && matches!(
                            r.as_str(),
                            "rebind-before_catalog-artifact" | "rebind-after_catalog-artifact"
                        ))
                        || terminal_before(&nodes, s, r)
                });
            if historical {
                report["nodes"][key]["retired_historical"] = value!(true);
                continue;
            }
            let expected = enzimos_platform::json::array(&node["expected"])?;
            if expected.is_empty() {
                continue;
            }
            let matched =
                expected.len() == 1 && measured.get(path).is_some_and(|r| r == &expected[0]);
            report["nodes"][key]["bytes_match"] = value!(matched);
            if !matched {
                blockers.insert(format!("referenced-artifact-missing-or-drift:{path}"));
            }
        } else if node["kind"] == "root-resource" && node["identity_matches"] == false {
            let identity = &node["identity"];
            let uuid = text(identity, "uuid")?;
            let historical = tombstones
                .get(uuid)
                .is_some_and(|t| ["path", "id", "uuid"].iter().all(|f| identity[*f] == t[*f]))
                && nonempty
                && edges.iter().all(|(s, r)| {
                    completed_rebind(s)
                        && matches!(
                            r.as_str(),
                            "rebind-before_catalog-root"
                                | "rebind-after_catalog-root"
                                | "rebind-target"
                        )
                });
            if historical {
                report["nodes"][key]["retired_historical"] = value!(true);
                blockers.remove(&format!(
                    "recovery-root-identity-drift:{}",
                    text(identity, "path")?
                ));
            }
        }
    }
    report["blockers"] = value!(blockers);
    Ok(report)
}
