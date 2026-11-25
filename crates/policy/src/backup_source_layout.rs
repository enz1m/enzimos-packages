// SPDX-License-Identifier: MIT
//! Explicit source selections never infer additional datasets from the filesystem.
use enzimos_platform::{Result, require};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dataset {
    pub name: String,
    pub path: String,
    pub archive: String,
}
/// Runtime descendants excluded from the system archive, never additional sources.
pub(crate) fn runtime_mount(path: &str) -> bool {
    ["/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp"]
        .iter()
        .any(|parent| path.starts_with(&format!("{parent}/")))
}
pub(crate) fn additional(name: &str, path: &str) -> Result<()> {
    require(
        !name.is_empty()
            && name.len() <= 32
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "unqualified additional source name",
    )?;
    require(
        path.starts_with("/var/lib/")
            && path.len() < 4096
            && path[9..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
            && !path[9..].is_empty()
            && !path.split('/').any(|p| p == ".." || p == ".")
            && !path.contains("//")
            && !path.ends_with('/')
            && !path.starts_with("/var/lib/enzimos-control")
            && !path.starts_with("/var/lib/enzimos/"),
        "unqualified additional source path",
    )
}
/// The system and home datasets every backup captures.
pub(crate) fn base() -> Vec<Dataset> {
    vec![
        Dataset {
            name: "root".into(),
            path: "/".into(),
            archive: "system".into(),
        },
        Dataset {
            name: "home".into(),
            path: "/home".into(),
            archive: "home".into(),
        },
    ]
}
pub(crate) fn layout(config: &Value) -> Result<Vec<Dataset>> {
    crate::backup_configuration::validate(config)?;
    let mut sources = base();
    if let Some(rows) = config.get("additional_sources") {
        for row in enzimos_platform::json::array(rows)? {
            let name = enzimos_platform::json::string(&row["snapper_config"])?;
            let path = enzimos_platform::json::string(&row["path"])?;
            additional(name, path)?;
            require(
                !sources.iter().any(|s| {
                    s.name == name
                        || s.path == path
                        || (s.path != "/"
                            && s.path != "/home"
                            && (path.starts_with(&format!("{}/", s.path))
                                || s.path.starts_with(&format!("{path}/"))))
                }),
                "overlapping additional sources",
            )?;
            sources.push(Dataset {
                name: name.into(),
                path: path.into(),
                archive: format!("additional/{name}"),
            });
        }
    }
    Ok(sources)
}
pub(crate) fn validate_dataset(row: &Dataset) -> Result<()> {
    if (row.name.as_str(), row.path.as_str(), row.archive.as_str()) == ("root", "/", "system")
        || (row.name.as_str(), row.path.as_str(), row.archive.as_str()) == ("home", "/home", "home")
    {
        return Ok(());
    }
    additional(&row.name, &row.path)?;
    require(
        row.name != "root"
            && row.name != "home"
            && row.archive == format!("additional/{}", row.name),
        "backup source archive binding mismatch",
    )
}
