// SPDX-License-Identifier: MIT
//! Archive scope review data. This module grants no process or mount authority.
use crate::{
    backup_source_capture::Released,
    backup_source_layout::{Dataset, validate_dataset},
};
use enzimos_platform::backup_command::EXCLUDES;
use enzimos_platform::{Result, require};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn scope(datasets: &[Dataset]) -> Result<(Vec<String>, Vec<String>)> {
    require(
        (2..=32).contains(&datasets.len()),
        "closed backup dataset count required",
    )?;
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut slots = BTreeSet::new();
    let mut excludes = EXCLUDES.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let mut sources = Vec::new();
    for (index, dataset) in datasets.iter().enumerate() {
        validate_dataset(dataset)?;
        require(
            names.insert(dataset.name.clone())
                && paths.insert(dataset.path.clone())
                && slots.insert(dataset.archive.clone()),
            "duplicate backup scope dataset",
        )?;
        require(
            (index != 0 || dataset.archive == "system")
                && (index != 1 || dataset.archive == "home")
                && (index < 2 || dataset.archive.starts_with("additional/")),
            "backup scope differs from configured root/home/additional layout",
        )?;
        let source = format!("/backup-source/{}", dataset.archive);
        if index >= 2 {
            excludes.push(format!("{source}/.snapshots/**"));
        }
        sources.push(source);
    }
    sources.extend([
        "/backup-source/boot".into(),
        "/backup-source/inventory".into(),
    ]);
    Ok((sources, excludes))
}
/// Validate only the shared closed command contract; no execution authority.
pub(crate) fn validate_arguments_for_targets(
    args: &[String],
    targets: &BTreeSet<String>,
) -> Result<()> {
    enzimos_platform::backup_command::validate(args, targets)
}
/// Original released capture supplies the datasets; no caller-provided globs,
/// source roots, options or alternate tag/host can enter the scope. Actual source
/// mounts and boot/inventory stage actors are still required before execution.
pub fn review(capture: &Released<'_, '_, '_>) -> Result<Value> {
    enzimos_platform::recheck_scope::evaluation(|| {
        capture.recheck()?;
        let datasets = capture
            .snapshots()?
            .iter()
            .map(|snapshot| Ok(snapshot.dataset()?.clone()))
            .collect::<Result<Vec<_>>>()?;
        let (sources, excludes) = scope(&datasets)?;
        let evidence = capture.evidence()?;
        capture.recheck()?;
        Ok(
            json!({"schema":1,"role":"backup-archive-scope-review","sources":sources,
        "excludes":excludes,"tag":"enzimos-whole-linux","host":"enzimos",
        "capture":evidence,"global_atomicity":false,"source_mounts_admitted":false,
        "boot_inventory_staged":false,"transfer_entered":false,"backup_complete":false}),
        )
    })
}
