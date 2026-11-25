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
    /// Verify the journal still matches the system.
    ///
    /// # Errors
    ///
    /// Fails when the context changed.
    fn verify(&mut self, journal: &Value) -> Result<()>;
    /// Current loader files by name.
    ///
    /// # Errors
    ///
    /// Fails when a file cannot be read.
    fn files(&mut self) -> Result<Texts>;
    /// Current generation registry.
    ///
    /// # Errors
    ///
    /// Fails when the registry cannot be read.
    fn catalog(&mut self) -> Result<Value>;
    /// Write loader file `name`.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    fn write_file(&mut self, name: &str, body: &str) -> Result<()>;
    /// Write the generation registry.
    ///
    /// # Errors
    ///
    /// Fails when the write fails.
    fn write_catalog(&mut self, body: &Value) -> Result<()>;
    /// Record that the journal completed.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be written.
    fn finish(&mut self, journal: &Value) -> Result<()>;
    /// Check point called before each write.
    ///
    /// # Errors
    ///
    /// Fails to stop before the write.
    fn boundary(&mut self, _name: &str, _journal: &Value) -> Result<()> {
        Ok(())
    }
}
fn observed(adapter: &mut impl Adapter, journal: &Value) -> Result<Texts> {
    let actual = adapter.files()?;
    let before = enzimos_platform::json::object(&journal["before_files"])?;
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
/// Apply the boot redirection described by `journal`, resuming from whatever part already matches.
///
/// # Errors
///
/// Fails when the journal is invalid, the current files match neither the before nor the after
/// state, or a write fails.
pub fn apply(journal: &Value, adapter: &mut impl Adapter) -> Result<Value> {
    let id = crate::recovery_records::text(journal, "id")?;
    root_rebind_record::validate(journal, id)?;
    if journal["phase"] == "complete" {
        return Ok(value!({"status":"already-complete","id":id,"packages_replayed":false}));
    }
    adapter.verify(journal)?;
    observed(adapter, journal)?;
    let mut names = enzimos_platform::json::object(&journal["replacements"])?
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
        let replacement = enzimos_platform::json::string(&journal["replacements"][&name])?;
        if actual[&name] != replacement {
            adapter.write_file(&name, replacement)?;
        }
        adapter.boundary(&format!("file:{name}"), journal)?;
    }
    adapter.verify(journal)?;
    let mut expected = journal["before_files"]
        .as_object()
        .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
        .iter()
        .map(|(name, body)| {
            Ok((
                name.clone(),
                enzimos_platform::json::string(body)?.to_owned(),
            ))
        })
        .collect::<Result<Texts>>()?;
    expected.extend(
        journal["replacements"]
            .as_object()
            .ok_or_else(|| enzimos_platform::Error("unexpected JSON value type".into()))?
            .iter()
            .map(|(name, body)| {
                Ok((
                    name.clone(),
                    enzimos_platform::json::string(body)?.to_owned(),
                ))
            })
            .collect::<Result<Texts>>()?,
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
