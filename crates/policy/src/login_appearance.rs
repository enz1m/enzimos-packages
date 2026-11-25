// SPDX-License-Identifier: MIT
//! Explicit public login appearance; no user paths or private home traversal.
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
};
/// Protected public presentation store, separate from private OS state and homes.
pub(crate) const DIRECTORY: &str = "/var/lib/enzimos-login-appearance";
const PUBLIC_LIMIT: usize = 4 * 1024 * 1024;

/// Validate only public presentation settings. Session, lock and power policy
/// cannot be changed or disclosed by this operation.
///
/// # Errors
/// Refuses unknown fields, private paths, unsupported values or missing consent.
pub fn request(body: &Value) -> Result<()> {
    let publish = body["action"] == "publish";
    json::fields(
        body,
        if publish {
            "schema action allow_interaction public_consent appearance"
        } else {
            "schema action allow_interaction"
        },
    )?;
    require(
        body["schema"].as_u64() == Some(1) && (publish || body["action"] == "clear"),
        "login-appearance-invalid",
    )?;
    require(
        body["allow_interaction"].is_boolean(),
        "login-appearance-invalid",
    )?;
    if !publish {
        return Ok(());
    }
    require(
        body["public_consent"] == true,
        "login-appearance-public-consent-required",
    )?;
    let appearance = &body["appearance"];
    json::fields(
        appearance,
        "show_time show_date clock_24h reduced_motion material layout size font weight hide_wallpaper_clock hide_wallpaper_date background",
    )?;
    for key in [
        "show_time",
        "show_date",
        "clock_24h",
        "reduced_motion",
        "hide_wallpaper_clock",
        "hide_wallpaper_date",
    ] {
        require(appearance[key].is_boolean(), "login-appearance-invalid")?;
    }
    for (key, choices) in [
        ("material", &["glass", "frosted_glass", "simple"][..]),
        ("layout", &["centered", "split", "stacked", "corner"][..]),
        ("size", &["small", "medium", "large"][..]),
    ] {
        require(
            appearance[key]
                .as_str()
                .is_some_and(|s| choices.contains(&s)),
            "login-appearance-invalid",
        )?;
    }
    require(
        appearance["font"].as_str().is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 128
                && !s.chars().any(|c| c.is_control() || matches!(c, '/' | '\\'))
        }) && appearance["weight"]
            .as_u64()
            .is_some_and(|n| (1..=1000).contains(&n)),
        "login-appearance-invalid",
    )?;
    let background = &appearance["background"];
    if background["kind"] == "scene" {
        json::fields(background, "kind id")?;
        require(
            background["id"].as_str().is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }),
            "login-appearance-invalid",
        )?;
    } else {
        json::fields(background, "kind")?;
        require(
            matches!(background["kind"].as_str(), Some("default" | "image")),
            "login-appearance-invalid",
        )?;
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Inspect immutable anonymous input with fcntl; never follow a user path."
)]
fn input(file: &File, uid: u32) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: fcntl only inspects the live received descriptor.
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    require(
        before.is_file()
            && before.uid() == uid
            && before.nlink() == 0
            && before.mode() & 0o7077 == 0
            && before.len() <= super::login_image::LIMIT as u64
            && actual >= 0
            && actual & seals == seals,
        "login-image-input-refused",
    )?;
    let mut bytes = vec![0; before.len() as usize];
    file.read_exact_at(&mut bytes, 0)?;
    require(
        files::identity(&before) == files::identity(&file.metadata()?),
        "login-image-input-refused",
    )?;
    Ok(bytes)
}

/// Publish or revoke only the authenticated caller's appearance in one atomic
/// public document, including a canonical bounded PNG when explicitly selected.
///
/// # Errors
/// Refuses invalid requests, unsealed inputs, untrusted scenes or changed authority.
pub fn publish(
    uid: u32,
    body: &Value,
    file: &File,
    authorize: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    crate::operation::root_only()?;
    require((1000..i32::MAX as u32).contains(&uid), "not-authorized")?;
    let account = enzimos_platform::accounts::lookup_uid(uid)?;
    request(body)?;
    let bytes = input(file, uid)?;
    let clearing = body["action"] == "clear";
    let image = !clearing && body["appearance"]["background"]["kind"] == "image";
    require(image || bytes.is_empty(), "login-image-input-refused")?;
    let png = if image {
        Some(openssl::base64::encode_block(
            &super::login_image::canonical(&bytes)?,
        ))
    } else {
        None
    };
    if !clearing && body["appearance"]["background"]["kind"] == "scene" {
        let id = body["appearance"]["background"]["id"]
            .as_str()
            .ok_or_else(|| Error("login-appearance-invalid".into()))?;
        let root = Path::new("/usr/share/enzui/enzwall/scenes").join(id);
        let folder = files::directory(&root, Some(0))?;
        let scene = files::open_relative(&folder, Path::new("scene.toml"))?;
        let m = scene.metadata()?;
        require(
            m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.len() <= 256 * 1024,
            "login-scene-untrusted",
        )?;
    }
    files::ensure_directory(Path::new(DIRECTORY), 0o755, 0)?;
    let _lock = files::Lock::try_acquire(&Path::new(DIRECTORY).join(format!(".{uid}.lock")), 0)?
        .ok_or_else(|| Error("service-busy".into()))?;
    let result = value!({"schema":1,"uid":uid,"account":account.name,"published":!clearing,
        "appearance":if clearing {Value::Null} else {body["appearance"].clone()},"image_png_base64":png});
    authorize()?;
    require(
        enzimos_platform::accounts::lookup_uid(uid)? == account,
        "caller-session-changed",
    )?;
    // A clear is an atomic tombstone. The previous public image disappears with
    // the old inode; neither concurrent readers nor errors see a mixed pair.
    files::atomic_bounded(
        &Path::new(DIRECTORY).join(format!("{uid}.json")),
        &json::canonical(&result)?,
        0o644,
        Some(0),
        true,
        PUBLIC_LIMIT,
    )?;
    Ok(value!({"schema":1,"published":!clearing,"public":true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    #[test]
    #[allow(
        unsafe_code,
        reason = "An owned anonymous memfd fixture, never host policy or accounts."
    )]
    fn publication_requires_consent_allowlisted_settings_and_immutable_owner_input() {
        let good = value!({"schema":1,"action":"publish","allow_interaction":true,"public_consent":true,"appearance":{
            "show_time":true,"show_date":true,"clock_24h":true,"reduced_motion":false,
            "material":"glass","layout":"centered","size":"medium","font":"Fredoka","weight":600,
            "hide_wallpaper_clock":true,"hide_wallpaper_date":true,"background":{"kind":"default"}}});
        request(&good).unwrap();
        request(&value!({"schema":1,"action":"clear","allow_interaction":true})).unwrap();
        for (pointer, value) in [
            ("/public_consent", value!(false)),
            ("/appearance/uid", value!(1001)),
            (
                "/appearance/background",
                value!({"kind":"image","path":"/home/other/private.png"}),
            ),
            ("/appearance/font", value!("/home/user/private.ttf")),
            ("/appearance/show_time", value!(1)),
            (
                "/appearance/background",
                value!({"kind":"scene","id":"../private"}),
            ),
        ] {
            let mut bad = good.clone();
            if pointer == "/appearance/uid" {
                bad["appearance"]["uid"] = value;
            } else {
                *bad.pointer_mut(pointer).unwrap() = value;
            }
            assert!(request(&bad).is_err(), "{pointer}");
        }
        // SAFETY: the fixture owns the returned FD and closes it through File.
        let raw = unsafe {
            libc::memfd_create(
                c"login-appearance-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(raw >= 0);
        let file = unsafe { File::from_raw_fd(raw) };
        let uid = file.metadata().unwrap().uid();
        assert!(input(&file, uid).is_err());
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        // SAFETY: fchmod and fcntl affect only this fixture's anonymous file.
        assert_eq!(unsafe { libc::fchmod(raw, 0o600) }, 0);
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, seals) }, 0);
        assert!(input(&file, uid).unwrap().is_empty());
        assert!(input(&file, uid + 1).is_err());
        let ordinary = tempfile::tempfile().unwrap();
        assert!(input(&ordinary, uid).is_err());
    }
}
