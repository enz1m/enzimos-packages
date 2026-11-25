// SPDX-License-Identifier: MIT
//! Desktop PAM and device configuration, without reading credentials or starting services.
use enzimos_platform::mount_identity;
use enzimos_platform::{Error, Result, files, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
};
const LIMIT: usize = 128 * 1024;
const BEGIN: &str = "# BEGIN enzimOS desktop integration";
const END: &str = "# END enzimOS desktop integration";
pub fn pam(body: &str, service: &str) -> Result<String> {
    bounded(body)?;
    let rules: &[&str] = match service {
        "greetd" => &[
            "auth [success=1 default=ignore] pam_succeed_if.so user = greeter",
            "auth optional pam_oo7.so",
            "session [success=1 default=ignore] pam_succeed_if.so user = greeter",
            "session optional pam_oo7.so auto_start",
            "password optional pam_oo7.so",
        ],
        "sddm" | "gdm-password" | "login" => &[
            "auth optional pam_oo7.so",
            "session optional pam_oo7.so auto_start",
            "password optional pam_oo7.so",
        ],
        "enzui-lock" => &["auth optional pam_oo7.so", "session optional pam_oo7.so"],
        "passwd" => &["password optional pam_oo7.so"],
        _ => return Err(Error("fixed PAM service required".into())),
    };
    let mut rules = rules.to_vec();
    let mut lines: Vec<_> = body.lines().collect();
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| **l == BEGIN)
        .map(|(i, _)| i)
        .collect();
    let ends: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| **l == END)
        .map(|(i, _)| i)
        .collect();
    if !starts.is_empty() || !ends.is_empty() {
        require(
            starts.len() == 1 && ends.len() == 1 && starts[0] < ends[0],
            "invalid managed PAM section",
        )?;
        lines.drain(starts[0]..=ends[0]);
    }
    let active: Vec<Vec<_>> = lines
        .iter()
        .filter(|s| !s.trim_start().starts_with('#'))
        .map(|s| s.split_whitespace().collect())
        .collect();
    let group = if service == "passwd" {
        "password"
    } else {
        "auth"
    };
    require(
        active.iter().any(|r| {
            r.len() >= 3
                && r[0] == group
                && matches!(r[1], "include" | "required" | "requisite" | "substack")
        }),
        "existing distribution PAM authentication required",
    )?;
    let missing_password =
        service == "greetd" && !active.iter().any(|r| r.first() == Some(&"password"));
    if active.iter().any(|r| r.contains(&"pam_oo7.so")) {
        // Respect administrator keyring rules while still supplying the missing
        // distribution password stack needed by pam_chauthtok.
        rules.clear();
    }
    if missing_password {
        rules.insert(0, "password include system-local-login");
    }
    if rules.is_empty() {
        return Ok(body.into());
    }
    Ok(format!(
        "{}\n\n{BEGIN}\n{}\n{END}\n",
        lines.join("\n").trim_end(),
        rules.join("\n")
    ))
}
fn bounded(body: &str) -> Result<()> {
    require(
        body.len() <= LIMIT && !body.contains('\0'),
        "bounded desktop configuration required",
    )
}
const CUPS: &[(&str, &[&str])] = &[
    (
        "Listen",
        &["127.0.0.1:631", "[::1]:631", "/run/cups/cups.sock"],
    ),
    ("Browsing", &["No"]),
    ("WebInterface", &["No"]),
    ("DefaultShared", &["No"]),
    ("PreserveJobFiles", &["No"]),
    ("PreserveJobHistory", &["86400"]),
    ("MaxLogSize", &["1048576"]),
    ("MaxJobs", &["100"]),
    ("MaxJobsPerUser", &["20"]),
];
pub fn cups(body: &str) -> Result<String> {
    bounded(body)?;
    let mut depth = 0usize;
    let mut lines = Vec::new();
    for line in body.lines() {
        let s = line.trim();
        if s.starts_with("</") {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| Error("unbalanced CUPS section".into()))?;
        }
        if depth == 0 && !s.is_empty() && !s.starts_with(['#', '<']) {
            let key = s.split_whitespace().next().unwrap();
            if CUPS.iter().any(|(name, _)| name.eq_ignore_ascii_case(key)) {
                continue;
            }
            require(
                !matches!(key.to_ascii_lowercase().as_str(), "include" | "port"),
                "unexpected CUPS listener/configuration include",
            )?;
        }
        lines.push(line);
        if s.starts_with('<') && !s.starts_with("</") {
            depth += 1;
            require(depth <= 64, "CUPS section depth bound")?;
        }
    }
    require(depth == 0, "unbalanced CUPS section")?;
    require(
        body.contains("<Policy default>")
            && body.lines().any(|s| {
                let r: Vec<_> = s.split_whitespace().collect();
                r.windows(3).any(|r| r == ["Require", "user", "@SYSTEM"])
            }),
        "vendor CUPS authorization policy missing",
    )?;
    let mut out = format!("{}\n", lines.join("\n").trim_end());
    for (key, values) in CUPS {
        for value in *values {
            out.push_str(&format!("{key} {value}\n"));
        }
    }
    Ok(out)
}
/// Strict INI parser: preserve unrelated values, reject duplicate sections/options.
pub fn ini(body: &str, overrides: &[(&str, &[(&str, &str)])]) -> Result<String> {
    bounded(body)?;
    let mut sections: Vec<(String, Vec<(String, String)>)> = Vec::new();
    let mut seen = BTreeSet::new();
    for line in body.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with(['#', ';']) {
            continue;
        }
        if s.starts_with('[') {
            require(s.ends_with(']') && s.len() > 2, "invalid INI section")?;
            let name = &s[1..s.len() - 1];
            require(seen.insert(name.to_owned()), "duplicate INI section")?;
            sections.push((name.into(), Vec::new()));
            continue;
        }
        let index = s
            .find(['=', ':'])
            .ok_or_else(|| Error("invalid INI option".into()))?;
        let key = s[..index].trim().to_ascii_lowercase();
        require(!key.is_empty(), "empty INI option")?;
        let value = s[index + 1..].trim();
        let value = value
            .char_indices()
            .find(|(i, c)| {
                *i > 0 && matches!(c, '#' | ';') && value[..*i].ends_with(char::is_whitespace)
            })
            .map_or(value, |(i, _)| value[..i].trim_end());
        let options = &mut sections
            .last_mut()
            .ok_or_else(|| Error("INI section required".into()))?
            .1;
        require(
            !options.iter().any(|(k, _)| k == &key),
            "duplicate INI option",
        )?;
        options.push((key, value.into()));
    }
    for (name, values) in overrides {
        let i = sections
            .iter()
            .position(|(n, _)| n == name)
            .unwrap_or_else(|| {
                sections.push(((*name).into(), Vec::new()));
                sections.len() - 1
            });
        for (key, value) in *values {
            if let Some((_, old)) = sections[i].1.iter_mut().find(|(k, _)| k == key) {
                *old = (*value).into();
            } else {
                sections[i].1.push(((*key).into(), (*value).into()));
            }
        }
    }
    let mut output = String::new();
    for (name, options) in sections {
        output.push_str(&format!("[{name}]\n"));
        for (k, v) in options {
            output.push_str(&format!("{k}={v}\n"));
        }
        output.push('\n');
    }
    Ok(output)
}
const CONNECTIVITY: &str = "# SPDX-License-Identifier: MIT\n# Existing Arch connectivity endpoint; no identifiers or credentials are sent.\n# HTTP is intentional: a captive network must be detectable without TLS bypass.\n# The desktop offers explicit browser sign-in and the NM privacy toggle.\n[connectivity]\nenabled=true\nuri=http://ping.archlinux.org/nm-check.txt\nresponse=NetworkManager is online\ninterval=300\ntimeout=5\n";
fn environment(body: &str) -> Result<String> {
    bounded(body)?;
    let mut present = BTreeSet::new();
    for line in body.lines() {
        let s = line
            .trim_start()
            .strip_prefix("export ")
            .unwrap_or_else(|| line.trim_start());
        if let Some((k, _)) = s.split_once('=') {
            let k = k.trim();
            if !k.is_empty()
                && k.chars().enumerate().all(|(i, c)| {
                    c == '_' || c.is_ascii_alphabetic() || i > 0 && c.is_ascii_digit()
                })
            {
                present.insert(k);
            }
        }
    }
    let missing: Vec<_> = [
        ("XMODIFIERS", "@im=fcitx"),
        ("QT_IM_MODULE", "fcitx"),
        ("SDL_IM_MODULE", "fcitx"),
    ]
    .into_iter()
    .filter(|(k, _)| !present.contains(k))
    .map(|(k, v)| format!("{k}={v}"))
    .collect();
    Ok(if missing.is_empty() {
        body.into()
    } else {
        format!(
            "{}\n\n# enzimOS input method defaults (GTK uses native Wayland text input)\n{}\n",
            body.trim_end(),
            missing.join("\n")
        )
    })
}
type DirectoryShape = (u64, u64, u32, u32, u32);
fn directory_shape(f: &File) -> Result<DirectoryShape> {
    let m = f.metadata()?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
struct Target {
    file: File,
    path: PathBuf,
    shape: DirectoryShape,
    mount: u64,
}
impl Target {
    fn recheck(&self) -> Result<()> {
        let named = files::directory(&self.path, None)?;
        require(
            directory_shape(&named)? == self.shape
                && directory_shape(&self.file)? == self.shape
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount,
            "fresh target identity/mount changed",
        )
    }
    fn parent(&self, relative: &Path, parent: &File) -> Result<()> {
        self.recheck()?;
        let named = files::directory_relative(&self.file, relative, None)?;
        require(
            directory_shape(&named)? == directory_shape(parent)?
                && mount_identity::id(named.as_fd(), true)?
                    == mount_identity::id(parent.as_fd(), true)?,
            "fresh target configuration parent changed",
        )
    }
}
struct Edit {
    target: Arc<Target>,
    relative_parent: PathBuf,
    parent: File,
    name: String,
    original: Option<File>,
    bytes: Vec<u8>,
    result: String,
    label: String,
    mode: u32,
}
impl Edit {
    fn check(&self) -> Result<()> {
        self.target.parent(&self.relative_parent, &self.parent)?;
        let named = files::optional_relative(&self.parent, Path::new(&self.name))?;
        match (&self.original, named) {
            (None, None) => Ok(()),
            (Some(old), Some(now)) => {
                require(
                    files::identity(&old.metadata()?) == files::identity(&now.metadata()?),
                    "desktop configuration identity changed",
                )?;
                require(
                    files::read_file(old, LIMIT, None, true)? == self.bytes,
                    "desktop configuration bytes changed",
                )
            }
            _ => Err(Error("desktop configuration membership changed".into())),
        }
    }
}
pub fn configure(root: &Path, everyday: bool) -> Result<Value> {
    configure_mode(root, everyday, false)
}
/// Configure the installed login stacks that exist on an Arch-based system.
pub fn configure_keyring(root: &Path) -> Result<Value> {
    configure_mode(root, false, true)
}
fn configure_mode(root: &Path, everyday: bool, keyring_only: bool) -> Result<Value> {
    require(
        // Keyring PAM setup also runs from the oo7 pacman hook on the
        // installed system; everyday service defaults only configure fresh targets.
        root.is_absolute() && (!everyday || root != Path::new("/")),
        "explicit fresh target required; host root refused",
    )?;
    let target = files::directory(root, None)?;
    let host = std::fs::metadata("/")?;
    let target_meta = target.metadata()?;
    require(
        !everyday || (host.dev(), host.ino()) != (target_meta.dev(), target_meta.ino()),
        "host root alias refused",
    )?;
    require(
        target.metadata()?.uid() == enzimos_platform::process_identity::effective_uid(),
        "target owner required",
    )?;
    let target = Arc::new(Target {
        shape: directory_shape(&target)?,
        mount: mount_identity::id(target.as_fd(), true)?,
        file: target,
        path: root.into(),
    });
    let mut edits = Vec::new();
    let paths: &[&str] = if keyring_only {
        &[
            "etc/pam.d/greetd",
            "etc/pam.d/sddm",
            "etc/pam.d/gdm-password",
            "etc/pam.d/login",
            "etc/pam.d/enzui-lock",
            "etc/pam.d/passwd",
        ]
    } else if everyday {
        &[
            "etc/cups/cupsd.conf",
            "etc/ipp-usb/ipp-usb.conf",
            "etc/avahi/avahi-daemon.conf",
            "etc/NetworkManager/conf.d/30-enzimos-connectivity.conf",
        ]
    } else {
        &[
            "etc/pam.d/greetd",
            "etc/pam.d/enzui-lock",
            "etc/pam.d/passwd",
            "etc/environment",
        ]
    };
    for relative in paths {
        let path = Path::new(relative);
        let parent = files::directory_relative(&target.file, path.parent().unwrap(), None)?;
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let original = files::optional_relative(&parent, Path::new(&name))?;
        if keyring_only && original.is_none() {
            continue;
        }
        require(
            original.is_some()
                || matches!(
                    *relative,
                    "etc/environment" | "etc/NetworkManager/conf.d/30-enzimos-connectivity.conf"
                ),
            "required signed service configuration missing",
        )?;
        if let Some(f) = &original {
            require(
                mount_identity::id(f.as_fd(), true)? == mount_identity::id(parent.as_fd(), true)?,
                "configuration member crosses parent mount",
            )?;
            let m = f.metadata()?;
            require(
                m.uid() == enzimos_platform::process_identity::effective_uid()
                    && m.gid() == target_meta.gid()
                    && m.mode() & 0o7022 == 0,
                "configuration owner/group/mode requires review",
            )?;
        }
        let bytes = original
            .as_ref()
            .map(|f| files::read_file(f, LIMIT, None, true))
            .transpose()?
            .unwrap_or_default();
        let body = std::str::from_utf8(&bytes)
            .map_err(|_| Error("UTF-8 desktop configuration required".into()))?;
        let mode = original
            .as_ref()
            .map(|f| f.metadata().map(|m| m.mode() & 0o777))
            .transpose()?
            .unwrap_or(0o644);
        require(
            matches!(mode, 0o600 | 0o644),
            "private conventional configuration mode required",
        )?;
        let result = match *relative {
            "etc/cups/cupsd.conf" => cups(body)?,
            "etc/ipp-usb/ipp-usb.conf" => ini(
                body,
                &[
                    (
                        "network",
                        &[
                            ("interface", "loopback"),
                            ("dns-sd", "enable"),
                            ("ipv6", "enable"),
                        ],
                    ),
                    (
                        "auth uid",
                        &[
                            ("print", "cups, @lp, root"),
                            ("config", "@wheel"),
                            ("scan", "root"),
                            ("fax", "root"),
                            ("all", "root"),
                        ],
                    ),
                    (
                        "logging",
                        &[
                            ("device-log", "error"),
                            ("main-log", "error"),
                            ("console-log", "error"),
                            ("max-file-size", "256K"),
                            ("max-backup-files", "2"),
                            ("console-color", "disable"),
                        ],
                    ),
                ],
            )?,
            "etc/avahi/avahi-daemon.conf" => ini(
                body,
                &[
                    ("wide-area", &[("enable-wide-area", "no")]),
                    (
                        "publish",
                        &[
                            ("publish-workstation", "no"),
                            ("publish-hinfo", "no"),
                            ("publish-domain", "no"),
                        ],
                    ),
                    ("reflector", &[("enable-reflector", "no")]),
                ],
            )?,
            "etc/NetworkManager/conf.d/30-enzimos-connectivity.conf" => CONNECTIVITY.into(),
            "etc/environment" => environment(body)?,
            _ => pam(body, &name)?,
        };
        edits.push(Edit {
            target: std::sync::Arc::clone(&target),
            relative_parent: path.parent().unwrap().into(),
            parent,
            name: name.clone(),
            original,
            bytes,
            result,
            label: if everyday { (*relative).into() } else { name },
            mode,
        });
    }
    let socket = if everyday {
        None
    } else {
        KeyringSocket::observe(target)?
    };
    // All inputs validate before the first write; each subsequent write rechecks all remaining originals.
    let mut changed = Vec::new();
    for i in 0..edits.len() {
        for edit in &edits[i..] {
            edit.check()?;
        }
        let e = &edits[i];
        if e.bytes == e.result.as_bytes() {
            continue;
        }
        if let Some(original) = &e.original {
            files::atomic_replace_original(
                &e.parent,
                Path::new(&e.name),
                e.result.as_bytes(),
                e.mode,
                None,
                LIMIT,
                original,
            )?;
        } else {
            files::atomic_relative(
                &e.parent,
                Path::new(&e.name),
                e.result.as_bytes(),
                e.mode,
                None,
                false,
                LIMIT,
            )?;
        }
        e.parent.sync_all()?;
        changed.push(e.label.clone());
    }
    if let Some(socket) = socket {
        socket.retire()?;
        changed.push("gnome-keyring-daemon.socket".into());
    }
    Ok(if everyday {
        json!({"schema":1,"changed":changed,"services_started":false,"printer_sharing":false,"phone_debugging":false,"connectivity_endpoint":"http://ping.archlinux.org/nm-check.txt"})
    } else {
        json!({"schema":1,"changed":changed,"provider":"oo7","password_handled":false})
    })
}

// Quarantine by a fresh exclusive name before unlinking the retained original link.
// A substituted member remains quarantined for review; never remove an unknown inode.
struct KeyringSocket {
    target: Arc<Target>,
    parent: File,
    original: File,
    before: std::fs::Metadata,
}
impl KeyringSocket {
    #[allow(unsafe_code, reason = "Linux syscall ABI (openat, readlinkat).")]
    fn observe(target: Arc<Target>) -> Result<Option<Self>> {
        use std::os::fd::{AsRawFd, FromRawFd};
        target.recheck()?;
        let mut parent = target.file.try_clone()?;
        for leaf in ["etc", "systemd", "user", "sockets.target.wants"] {
            let Some(next) = files::optional_directory_relative(&parent, Path::new(leaf), None)?
            else {
                return Ok(None);
            };
            parent = next;
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c"gnome-keyring-daemon.socket".as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error.into());
        }
        let original = unsafe { File::from_raw_fd(fd) };
        let before = original.metadata()?;
        require(
            before.file_type().is_symlink()
                && before.uid() == enzimos_platform::process_identity::effective_uid(),
            "administrator keyring activation requires review",
        )?;
        let mut link = [0u8; 4096];
        let n = unsafe {
            libc::readlinkat(
                original.as_raw_fd(),
                c"".as_ptr(),
                link.as_mut_ptr().cast(),
                link.len(),
            )
        };
        require(
            n > 0 && (n as usize) < link.len(),
            "bounded keyring activation link required",
        )?;
        require(
            matches!(
                &link[..n as usize],
                b"/usr/lib/systemd/user/gnome-keyring-daemon.socket"
                    | b"../../../../usr/lib/systemd/user/gnome-keyring-daemon.socket"
            ),
            "administrator keyring activation target requires review",
        )?;
        Ok(Some(Self {
            target,
            parent,
            original,
            before,
        }))
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (openat, renameat2, unlinkat)."
    )]
    fn retire(self) -> Result<()> {
        self.target.parent(
            Path::new("etc/systemd/user/sockets.target.wants"),
            &self.parent,
        )?;
        use std::os::fd::{AsRawFd, FromRawFd};
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                c"gnome-keyring-daemon.socket".as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "keyring activation disappeared")?;
        let named = unsafe { File::from_raw_fd(fd) };
        require(
            files::identity(&named.metadata()?) == files::identity(&self.before)
                && files::identity(&self.original.metadata()?) == files::identity(&self.before),
            "keyring activation changed",
        )?;
        let leaf = std::ffi::CString::new(format!(
            ".enzimos-keyring-retired-{}",
            files::random_hex(16)?
        ))
        .unwrap();
        require(
            unsafe {
                libc::renameat2(
                    self.parent.as_raw_fd(),
                    c"gnome-keyring-daemon.socket".as_ptr(),
                    self.parent.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "keyring quarantine refused",
        )?;
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        require(fd >= 0, "keyring quarantine unavailable")?;
        let moved = unsafe { File::from_raw_fd(fd) };
        let m = moved.metadata()?;
        let held = self.original.metadata()?;
        require(
            files::identity(&m) == files::identity(&held)
                && m.dev() == self.before.dev()
                && m.ino() == self.before.ino()
                && m.uid() == self.before.uid()
                && m.gid() == self.before.gid()
                && m.mode() == self.before.mode()
                && m.len() == self.before.len()
                && m.nlink() == 1,
            "keyring quarantine identity changed; retained for review",
        )?;
        require(
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), leaf.as_ptr(), 0) } == 0,
            "keyring quarantine retirement refused",
        )?;
        self.parent.sync_all()?;
        self.target.parent(
            Path::new("etc/systemd/user/sockets.target.wants"),
            &self.parent,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn whole_fresh_target_setup_is_idempotent_and_validates_before_writes() {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        let t = tempfile::Builder::new()
            .prefix("desktop-setup-")
            .tempdir_in(work)
            .unwrap();
        for dir in [
            "etc/pam.d",
            "etc/systemd/user/sockets.target.wants",
            "etc/cups",
            "etc/ipp-usb",
            "etc/avahi",
            "etc/NetworkManager/conf.d",
        ] {
            std::fs::create_dir_all(t.path().join(dir)).unwrap();
        }
        for name in ["greetd", "enzui-lock", "passwd"] {
            let body = if name == "passwd" {
                "password include system-auth\n"
            } else {
                "auth include system-local-login\n"
            };
            std::fs::write(t.path().join("etc/pam.d").join(name), body).unwrap();
        }
        let socket = t
            .path()
            .join("etc/systemd/user/sockets.target.wants/gnome-keyring-daemon.socket");
        symlink("/usr/lib/systemd/user/gnome-keyring-daemon.socket", &socket).unwrap();
        let first = configure(t.path(), false).unwrap();
        assert_eq!(first["changed"].as_array().unwrap().len(), 5);
        let greetd = std::fs::read_to_string(t.path().join("etc/pam.d/greetd")).unwrap();
        assert!(greetd.contains("password include system-local-login"));
        assert_eq!(greetd.matches("pam_oo7.so").count(), 3);
        let lock = std::fs::read_to_string(t.path().join("etc/pam.d/enzui-lock")).unwrap();
        assert!(lock.contains("session optional pam_oo7.so"));
        assert_eq!(first["provider"], "oo7");
        let old = "auth include system-local-login\n# BEGIN enzimOS desktop integration\nauth optional pam_gnome_keyring.so\n# END enzimOS desktop integration\n";
        let migrated = pam(old, "greetd").unwrap();
        assert!(migrated.contains("session optional pam_oo7.so auto_start"));
        assert!(!migrated.contains("pam_gnome_keyring.so"));
        let sddm = t.path().join("etc/pam.d/sddm");
        std::fs::write(
            &sddm,
            "auth include system-login\nsession include system-login\n",
        )
        .unwrap();
        configure_keyring(t.path()).unwrap();
        let installed = std::fs::read_to_string(&sddm).unwrap();
        assert!(installed.contains("session optional pam_oo7.so auto_start"));
        assert_eq!(configure_keyring(t.path()).unwrap()["changed"], json!([]));
        let custom = "auth include system-local-login\npassword requisite pam_custom.so\n";
        assert!(
            !pam(custom, "greetd")
                .unwrap()
                .contains("password include system-local-login")
        );
        assert!(!socket.exists());
        assert!(std::fs::symlink_metadata(&socket).is_err());
        assert_eq!(configure(t.path(), false).unwrap()["changed"], json!([]));
        let cups_path = t.path().join("etc/cups/cupsd.conf");
        let cups_body = "Listen *:631\n<Policy default>\n Require user @SYSTEM\n</Policy>\n";
        std::fs::write(&cups_path, cups_body).unwrap();
        std::fs::write(
            t.path().join("etc/ipp-usb/ipp-usb.conf"),
            "[network]\ninterface=all\n",
        )
        .unwrap();
        let avahi = t.path().join("etc/avahi/avahi-daemon.conf");
        std::fs::write(&avahi, "invalid").unwrap();
        assert!(configure(t.path(), true).is_err());
        assert_eq!(std::fs::read_to_string(&cups_path).unwrap(), cups_body);
        std::fs::write(&avahi, "[server]\nuse-ipv6=yes\n").unwrap();
        assert_eq!(
            configure(t.path(), true).unwrap()["changed"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(configure(t.path(), true).unwrap()["changed"], json!([]));
        std::fs::set_permissions(&cups_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(configure(t.path(), true).is_err());
    }
}
