// SPDX-License-Identifier: MIT
//! Explicit boot-redirection recovery accepts only a completely bound before/after prefix.
use crate::{
    recovery_publication::{self, State},
    root_rebind_plan::Texts,
    root_rebind_record,
};
use enzimos_platform::{Result, require};
use serde_json::{Value, json as value};
/// Internal runtime adapters must retain storage, authority, root lineage and boot artifacts.
/// No callback, executable or filesystem path is accepted from IPC.
pub trait Adapter {
    fn verify(&mut self, journal: &Value) -> Result<()>;
    fn files(&mut self) -> Result<Texts>;
    fn catalog(&mut self) -> Result<Value>;
    fn write_file(&mut self, name: &str, body: &str) -> Result<()>;
    fn write_catalog(&mut self, body: &Value) -> Result<()>;
    fn finish(&mut self, journal: &Value) -> Result<()>;
    fn boundary(&mut self, _name: &str, _journal: &Value) -> Result<()> {
        Ok(())
    }
}
fn observed(adapter: &mut impl Adapter, journal: &Value) -> Result<Texts> {
    let actual = adapter.files()?;
    let before = journal["before_files"].as_object().unwrap();
    require(
        actual.len() == before.len() && before.keys().all(|key| actual.contains_key(key)),
        "rebind boot metadata membership changed",
    )?;
    for (name, original) in before {
        let replacement = journal["replacements"].get(name).unwrap_or(original);
        recovery_publication::classify(&value!(actual[name]), original, replacement)?;
    }
    recovery_publication::classify(
        &adapter.catalog()?,
        &journal["before_catalog"],
        &journal["after_catalog"],
    )?;
    Ok(actual)
}
pub fn apply(journal: &Value, adapter: &mut impl Adapter) -> Result<Value> {
    let id = crate::recovery_records::text(journal, "id")?;
    root_rebind_record::validate(journal, id)?;
    if journal["phase"] == "complete" {
        return Ok(value!({"status":"already-complete","id":id,"packages_replayed":false}));
    }
    adapter.verify(journal)?;
    observed(adapter, journal)?;
    let mut names = journal["replacements"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|name| name.as_str() != "limine/limine.conf")
        .cloned()
        .collect::<Vec<_>>();
    names.sort();
    if journal["replacements"].get("limine/limine.conf").is_some() {
        names.push("limine/limine.conf".into());
    }
    for name in names {
        let actual = observed(adapter, journal)?;
        let replacement = journal["replacements"][&name].as_str().unwrap();
        if actual[&name] != replacement {
            adapter.write_file(&name, replacement)?;
        }
        adapter.boundary(&format!("file:{name}"), journal)?;
    }
    adapter.verify(journal)?;
    let mut expected = journal["before_files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, body)| (name.clone(), body.as_str().unwrap().to_owned()))
        .collect::<Texts>();
    expected.extend(
        journal["replacements"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, body)| (name.clone(), body.as_str().unwrap().to_owned())),
    );
    require(
        adapter.files()? == expected,
        "rebind boot rewrites incomplete",
    )?;
    if recovery_publication::classify(
        &adapter.catalog()?,
        &journal["before_catalog"],
        &journal["after_catalog"],
    )? == State::Before
    {
        adapter.write_catalog(&journal["after_catalog"])?;
    }
    adapter.boundary("catalog", journal)?;
    require(
        adapter.catalog()? == journal["after_catalog"] && adapter.files()? == expected,
        "rebind final boot/catalog state changed",
    )?;
    adapter.finish(journal)?;
    adapter.boundary("complete", journal)?;
    Ok(
        value!({"status":"rebind-complete","id":id,"affected":journal["affected"],"packages_replayed":false,"retirement_enabled":false}),
    )
}
