// SPDX-License-Identifier: MIT
//! Public backup configuration is retained separately from credential material.
use enzimos_platform::{Result, json, require};
use serde_json::Value;

pub const PATH: &str = "/etc/enzimos/backup.json";
pub(crate) const REPOSITORY: &str = "/backup-repository/restic";
pub(crate) const PASSWORD: &str = "/etc/enzimos/backup.password";
pub(crate) const LIMIT: usize = 32768;

pub fn validate(value: &Value) -> Result<()> {
    let row = value
        .as_object()
        .ok_or_else(|| enzimos_platform::Error("backup configuration object required".into()))?;
    require(
        ["repository", "destination_uuid", "password_file"]
            .iter()
            .all(|key| row.contains_key(*key))
            && row.keys().all(|key| {
                [
                    "repository",
                    "destination_uuid",
                    "password_file",
                    "minimum_free_bytes",
                    "keep_last",
                    "additional_sources",
                ]
                .contains(&key.as_str())
            }),
        "invalid backup configuration fields",
    )?;
    require(
        value["repository"] == REPOSITORY && value["password_file"] == PASSWORD,
        "fixed managed backup paths required",
    )?;
    crate::identity::uuid(
        value["destination_uuid"]
            .as_str()
            .ok_or_else(|| enzimos_platform::Error("invalid backup destination UUID".into()))?,
    )?;
    for (key, minimum, maximum) in [
        ("minimum_free_bytes", 0, 1u64 << 50),
        ("keep_last", 1, 10000),
    ] {
        if let Some(number) = row.get(key) {
            require(
                number
                    .as_u64()
                    .is_some_and(|n| (minimum..=maximum).contains(&n)),
                "invalid backup space/retention policy",
            )?;
        }
    }
    if let Some(extra) = row.get("additional_sources") {
        let rows = extra.as_array().ok_or_else(|| {
            enzimos_platform::Error("invalid additional backup source list".into())
        })?;
        require(rows.len() <= 8, "invalid additional backup source list")?;
        for source in rows {
            require(
                source.as_object().is_some_and(|r| {
                    r.len() == 2
                        && r.get("path").is_some_and(Value::is_string)
                        && r.get("snapper_config").is_some_and(Value::is_string)
                }),
                "invalid additional backup source fields",
            )?;
        }
    }
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<Value> {
    let value = json::decode(bytes, LIMIT)?;
    validate(&value)?;
    Ok(value)
}

/// The configuration that decides what a backup captures: the backup drive's
/// `backup.json`, or the NAS share's configuration in setups without a drive
/// (see `backup_share_scope`).
pub trait SourceScope {
    /// The original configuration file is still the one observed.
    ///
    /// # Errors
    /// The file was changed, replaced or remounted.
    fn recheck(&self) -> Result<()>;
    /// The datasets to capture, in archive order.
    ///
    /// # Errors
    /// An invalid source selection.
    fn datasets(&self) -> Result<Vec<crate::backup_source_layout::Dataset>>;
    /// Identity and content evidence of the original configuration file.
    ///
    /// # Errors
    /// As for [`SourceScope::recheck`].
    fn evidence(&self) -> Result<Value>;
}
pub struct Configuration {
    original: crate::settings_file::Config,
    value: Value,
}
impl Configuration {
    /// This observes public configuration only; it neither reads credentials nor
    /// qualifies a mounted repository or an additional source.
    pub fn open() -> Result<Self> {
        crate::namespaces::initial()?;
        let original = crate::settings_file::Config::open(PATH, LIMIT)?;
        let value = decode(&original.body)?;
        original.recheck()?;
        Ok(Self { original, value })
    }
    pub fn recheck(&self) -> Result<()> {
        self.original.recheck()
    }
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn evidence(&self) -> Result<Value> {
        self.original.evidence()
    }
    pub fn public_bytes(&self) -> Result<&[u8]> {
        self.recheck()?;
        Ok(&self.original.body)
    }
    pub(crate) fn descriptor(&self) -> Result<&std::fs::File> {
        self.original.descriptor()
    }
    pub(crate) fn minimum_free_bytes(&self) -> u64 {
        self.value["minimum_free_bytes"]
            .as_u64()
            .unwrap_or(64 * 1024 * 1024)
    }
}
impl SourceScope for Configuration {
    fn recheck(&self) -> Result<()> {
        Configuration::recheck(self)
    }
    fn datasets(&self) -> Result<Vec<crate::backup_source_layout::Dataset>> {
        crate::backup_source_layout::layout(&self.value)
    }
    fn evidence(&self) -> Result<Value> {
        Configuration::evidence(self)
    }
}
