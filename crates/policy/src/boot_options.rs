// SPDX-License-Identifier: MIT
//! Kernel command line options that bind a root subvolume and enzimOS markers.
use crate::identity::safe_id;
use enzimos_platform::{Error, Result, require};
/// Kernel options `options` bound to root `subvolume`.
///
/// # Errors
///
/// Fails when the options are invalid or already bind another subvolume ambiguously.
pub fn root_options(options: &str, subvolume: &str) -> Result<String> {
    safe_id(subvolume)?;
    require(
        options.len() <= 4096 && !options.chars().any(char::is_control),
        "invalid root boot options",
    )?;
    let mut found = 0;
    let mut words = Vec::new();
    for word in options.split_whitespace() {
        if let Some(flags) = word.strip_prefix("rootflags=") {
            found += 1;
            let mut flags = flags
                .split(',')
                .filter(|s| !s.starts_with("subvol=") && !s.starts_with("subvolid="))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            require(
                flags.iter().all(|s| !s.is_empty()),
                "empty root mount option",
            )?;
            flags.push(format!("subvol={subvolume}"));
            words.push(format!("rootflags={}", flags.join(",")));
        } else {
            words.push(word.to_owned());
        }
    }
    require(found == 1, "one explicit rootflags value required")?;
    Ok(words.join(" "))
}
pub(crate) fn generation_options(options: &str, generation: &str) -> Result<String> {
    safe_id(generation)?;
    require(
        options.len() <= 4096 && !options.chars().any(char::is_control),
        "invalid boot options",
    )?;
    let mut words = options
        .split_whitespace()
        .filter(|w| !w.starts_with("enzimos.generation="))
        .collect::<Vec<_>>();
    let marker = format!("enzimos.generation={generation}");
    words.push(&marker);
    Ok(words.join(" "))
}
/// The root subvolume named by `options`.
///
/// # Errors
///
/// Fails without exactly one named root subvolume.
pub fn subvolume_from_options(options: &str) -> Result<String> {
    let values = options
        .split_whitespace()
        .filter_map(|word| word.strip_prefix("rootflags="))
        .collect::<Vec<_>>();
    require(values.len() == 1, "one explicit rootflags value required")?;
    let flags = values[0].split(',').collect::<Vec<_>>();
    require(
        !flags.iter().any(|s| s.starts_with("subvolid=")),
        "named root binding required",
    )?;
    let roots = flags
        .iter()
        .filter_map(|s| s.strip_prefix("subvol="))
        .collect::<Vec<_>>();
    require(roots.len() == 1, "one named root subvolume required")?;
    Ok(safe_id(roots[0])?.into())
}
/// Value of the enzimOS boot marker `key` in `cmdline`.
///
/// # Errors
///
/// Fails for unknown keys or without exactly one marker.
pub fn marker(cmdline: &str, key: &str) -> Result<String> {
    require(
        cmdline.len() <= 65536
            && matches!(key, "enzimos.generation" | "enzimos.staged" | "enzimos.run"),
        "boot marker key/bound",
    )?;
    let prefix = format!("{key}=");
    let found = cmdline
        .split_whitespace()
        .filter_map(|s| s.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    if found.len() != 1 {
        return Err(Error("one actual boot marker required".into()));
    }
    Ok(safe_id(found[0])?.into())
}
