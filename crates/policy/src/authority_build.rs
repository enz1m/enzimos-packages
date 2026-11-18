// SPDX-License-Identifier: MIT
//! Build a public-only authority aside. Input files remain pinned throughout review.
use crate::authority;
use enzimos_platform::{Error, Result, files, json, memfile, mount_identity, process, require};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
const MAX: usize = 8 * 1024 * 1024;
struct Input {
    file: File,
    path: PathBuf,
    identity: files::FileIdentity,
    mount: u64,
    bytes: Vec<u8>,
}
impl Input {
    fn open(path: &Path, owner: u32) -> Result<Self> {
        let parent = files::directory(
            path.parent()
                .ok_or_else(|| Error("authority source parent".into()))?,
            Some(owner),
        )?;
        let file = files::open_relative(
            &parent,
            Path::new(
                path.file_name()
                    .ok_or_else(|| Error("authority filename".into()))?,
            ),
        )?;
        let m = file.metadata()?;
        require(
            m.uid() == owner && m.nlink() == 1 && m.mode() & 0o022 == 0 && m.len() <= MAX as u64,
            "unsafe package authority source",
        )?;
        let bytes = files::read_file(&file, MAX, Some(owner), true)?;
        let this = Self {
            mount: mount_identity::id(file.as_fd(), true)?,
            identity: files::identity(&m),
            file,
            path: path.into(),
            bytes,
        };
        this.recheck(owner)?;
        Ok(this)
    }
    fn recheck(&self, owner: u32) -> Result<()> {
        let parent = files::directory(self.path.parent().unwrap(), Some(owner))?;
        let named = files::open_relative(&parent, Path::new(self.path.file_name().unwrap()))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && files::read_file(&self.file, MAX, Some(owner), true)? == self.bytes,
            "package authority input changed during build",
        )
    }
}
pub struct Prepared {
    pub directory: PathBuf,
    pub approved: Vec<String>,
    pub local: Vec<String>,
    pub summary: Value,
    inputs: Vec<(Input, u32)>,
    prepared: BTreeMap<String, Input>,
    owner: u32,
    source_authority: PathBuf,
}
impl Prepared {
    pub fn recheck_material(&self) -> Result<()> {
        for (input, owner) in &self.inputs {
            if !input.path.starts_with(&self.source_authority) {
                input.recheck(*owner)?;
            }
        }
        for input in self.prepared.values() {
            input.recheck(self.owner)?;
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<()> {
        for (input, owner) in &self.inputs {
            input.recheck(*owner)?;
        }
        for input in self.prepared.values() {
            input.recheck(self.owner)?;
        }
        Ok(())
    }
    pub fn files(&self) -> BTreeMap<String, Vec<u8>> {
        self.prepared
            .iter()
            .map(|(name, input)| (name.clone(), input.bytes.clone()))
            .collect()
    }
    pub fn hashes(&self) -> Value {
        value!(
            self.prepared
                .iter()
                .map(|(name, input)| (name.clone(), json::sha256(&input.bytes)))
                .collect::<BTreeMap<_, _>>()
        )
    }
}
pub fn gpg(home: &Path, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut all = vec![
        "--homedir",
        home.to_str()
            .ok_or_else(|| Error("authority home encoding".into()))?,
        "--batch",
        "--no-tty",
        "--no-autostart",
        "--no-options",
        "--no-auto-key-retrieve",
        "--auto-key-locate",
        "clear",
    ];
    all.extend_from_slice(args);
    let result = process::run("/usr/bin/gpg", &all, input, Duration::from_secs(120), MAX)?;
    require(
        result.status.success(),
        "isolated authority GnuPG operation failed",
    )?;
    Ok(result.stdout)
}
fn import(home: &Path, body: &[u8]) -> Result<()> {
    let ring = memfile::sealed("enzimos-authority-ring", body)?;
    let result = process::run_with_fds(
        "/usr/bin/gpg",
        &[
            "--homedir",
            home.to_str().unwrap(),
            "--batch",
            "--no-tty",
            "--no-autostart",
            "--no-options",
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "clear",
            "--import",
            "@fd:0",
        ],
        &[],
        Duration::from_secs(120),
        MAX,
        &[ring.as_fd()],
    )?;
    require(result.status.success(), "isolated authority import failed")
}
fn text(body: &[u8]) -> Result<&str> {
    std::str::from_utf8(body).map_err(|_| Error("authority listing encoding".into()))
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error("package authority clock before epoch".into()))?
        .as_secs())
}
fn public_only(path: &Path, owner: u32) -> Result<()> {
    let directory = files::directory(path, Some(owner))?;
    require(
        directory.metadata()?.uid() == owner && directory.metadata()?.mode() & 0o7777 == 0o700,
        "private package authority directory required",
    )?;
    for name in ["secring.gpg", "private-keys-v1.d"] {
        let p = path.join(name);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {
                files::directory(&p, Some(owner))?;
                require(
                    std::fs::read_dir(p)?.next().is_none(),
                    "private material in package authority",
                )?;
            }
            Ok(m) => require(
                m.is_file() && !m.file_type().is_symlink() && m.len() == 0,
                "private material in package authority",
            )?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn build(current: &Path, keyring: &Path, work: &Path, owner: u32) -> Result<Prepared> {
    require(
        unsafe { libc::geteuid() } == owner,
        "authority build owner mismatch",
    )?;
    public_only(current, owner)?;
    // No trust state is queried in the live authority: GPG sees a private copy.
    let mut inputs = Vec::new();
    let ring = Input::open(&keyring.join("archlinux.gpg"), 0)?;
    require(!ring.bytes.is_empty(), "Arch public keyring empty")?;
    let revocations = Input::open(&keyring.join("archlinux-revoked"), 0)?;
    let revoked = authority::revoked(text(&revocations.bytes)?)?;
    require(
        authority::MASTERS
            .iter()
            .all(|master| !revoked.contains(*master)),
        "a pinned Arch master key is revoked; review required",
    )?;
    files::create_directory(work, 0o700, owner)?;
    let saved = work.join("current");
    files::create_directory(&saved, 0o700, owner)?;
    for name in authority::FILES {
        let input = Input::open(&current.join(name), owner)?;
        files::atomic_bounded(
            &saved.join(name),
            &input.bytes,
            if name == "gpg.conf" { 0o644 } else { 0o600 },
            Some(owner),
            false,
            MAX,
        )?;
        inputs.push((input, owner));
    }
    let before = authority::trusted_local(
        text(&gpg(&saved, &["--export-ownertrust"], &[])?)?,
        &BTreeSet::new(),
    )?;
    let mut listings = BTreeMap::new();
    let mut arch = BTreeSet::new();
    for (index, master) in authority::MASTERS.iter().enumerate() {
        for (input, owner) in &inputs {
            input.recheck(*owner)?;
        }
        ring.recheck(0)?;
        revocations.recheck(0)?;
        let home = work.join(format!("master-{index}"));
        files::create_directory(&home, 0o700, owner)?;
        import(&home, &ring.bytes)?;
        gpg(
            &home,
            &["--import-ownertrust"],
            format!("{master}:6:\n").as_bytes(),
        )?;
        gpg(
            &home,
            &[
                "--trust-model",
                "classic",
                "--max-cert-depth",
                "1",
                "--check-trustdb",
            ],
            &[],
        )?;
        let bytes = gpg(
            &home,
            &[
                "--trust-model",
                "classic",
                "--max-cert-depth",
                "1",
                "--with-colons",
                "--fixed-list-mode",
                "--fingerprint",
                "--list-keys",
            ],
            &[],
        )?;
        let listing = text(&bytes)?.to_owned();
        authority::masters_usable(&listing, now()?)?;
        if index == 0 {
            arch = authority::fingerprints(&listing)?;
        }
        listings.insert(master.to_string(), listing);
    }
    let approved = authority::quorum(&listings, &revoked)?;
    require(
        approved.len() >= authority::MINIMUM_APPROVED,
        "implausibly few approved Arch packagers; review required",
    )?;
    let local = before
        .into_iter()
        .filter(|key| !arch.contains(key))
        .collect::<Vec<_>>();
    let selected = approved
        .iter()
        .chain(local.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    let new = work.join("authority");
    files::create_directory(&new, 0o700, owner)?;
    files::atomic(
        &new.join("gpg.conf"),
        authority::CONFIG.as_bytes(),
        0o644,
        Some(owner),
        false,
    )?;
    import(&new, &ring.bytes)?;
    if !local.is_empty() {
        let mut args = vec!["--export"];
        args.extend(local.iter().map(String::as_str));
        import(&new, &gpg(&saved, &args, &[])?)?;
    }
    let trust = authority::trust(selected.iter().cloned())?;
    gpg(&new, &["--import-ownertrust"], trust.as_bytes())?;
    require(
        gpg(&new, &["--list-secret-keys"], &[])?.is_empty(),
        "new authority contains private key material",
    )?;
    let mut args = vec!["--export"];
    args.extend(selected.iter().map(String::as_str));
    let exported = gpg(&new, &args, &[])?;
    let final_path = work.join("final");
    files::create_directory(&final_path, 0o700, owner)?;
    for (name, body, mode) in [
        ("gpg.conf", authority::CONFIG.as_bytes().to_vec(), 0o644),
        (
            "approved.trust",
            authority::trust(approved.iter().cloned())?.into_bytes(),
            0o600,
        ),
        ("pubring.gpg", Vec::new(), 0o600),
    ] {
        files::atomic(&final_path.join(name), &body, mode, Some(owner), false)?;
    }
    import(&final_path, &exported)?;
    gpg(&final_path, &["--import-ownertrust"], trust.as_bytes())?;
    let listed = gpg(
        &final_path,
        &["--with-colons", "--fingerprint", "--list-keys"],
        &[],
    )?;
    require(
        selected.is_subset(&authority::fingerprints(text(&listed)?)?),
        "refreshed authority lacks approved keys",
    )?;
    require(
        gpg(&final_path, &["--list-secret-keys"], &[])?.is_empty(),
        "final authority must remain public-only",
    )?;
    let final_trust = gpg(&final_path, &["--export-ownertrust"], &[])?;
    require(
        authority::trusted_local(text(&final_trust)?, &BTreeSet::new())?
            .into_iter()
            .collect::<BTreeSet<_>>()
            == selected,
        "final authority trust differs from reviewed keys",
    )?;
    let mut prepared = BTreeMap::new();
    for name in authority::FILES {
        prepared.insert(name.to_owned(), Input::open(&final_path.join(name), owner)?);
    }
    let previous = authority::revoked(
        text(
            &inputs
                .iter()
                .find(|(i, _)| i.path.file_name().is_some_and(|n| n == "approved.trust"))
                .unwrap()
                .0
                .bytes,
        )?
        .lines()
        .map(|s| {
            s.strip_suffix(":5:")
                .ok_or_else(|| Error("previous approved trust record refused".into()))
        })
        .collect::<Result<Vec<_>>>()?
        .join("\n")
        .as_str(),
    )?;
    let summary = value!({"status":"authority-refresh-dry-run","approved_packagers":approved.len(),"added":approved.iter().filter(|k|!previous.contains(*k)).count(),"removed":previous.iter().filter(|k|!approved.contains(*k)).count(),"local_keys_kept":local});
    inputs.push((ring, 0));
    inputs.push((revocations, 0));
    let result = Prepared {
        directory: final_path,
        approved,
        local,
        summary,
        inputs,
        prepared,
        owner,
        source_authority: current.into(),
    };
    result.recheck()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct FixtureAgent(PathBuf);
    impl Drop for FixtureAgent {
        fn drop(&mut self) {
            let _ = process::run(
                "/usr/bin/gpgconf",
                &["--homedir", self.0.to_str().unwrap(), "--kill", "gpg-agent"],
                &[],
                Duration::from_secs(5),
                65536,
            );
        }
    }
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn isolated_public_ring_import_and_direct_trust_match_real_gnupg_without_live_authority() {
        let work = Path::new(
            &std::env::var_os("ENZIMOS_TEST_TMPDIR")
                .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
        )
        .to_path_buf();
        let temporary = tempfile::Builder::new()
            .prefix("rust-authority-fixture-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(work)
            .unwrap();
        let owner = unsafe { libc::geteuid() };
        let private = temporary.path().join("signer");
        files::create_directory(&private, 0o700, owner).unwrap();
        let _agent = FixtureAgent(private.clone());
        let generated = process::run(
            "/usr/bin/gpg",
            &[
                "--no-options",
                "--homedir",
                private.to_str().unwrap(),
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Authority fixture <fixture@archlinux.org>",
                "ed25519",
                "cert",
                "1d",
            ],
            &[],
            Duration::from_secs(30),
            65536,
        )
        .unwrap();
        assert!(generated.status.success());
        let listing = gpg(
            &private,
            &["--with-colons", "--fingerprint", "--list-keys"],
            &[],
        )
        .unwrap();
        let fp = authority::fingerprints(text(&listing).unwrap())
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let exported = gpg(&private, &["--export", &fp], &[]).unwrap();
        let public = temporary.path().join("public");
        files::create_directory(&public, 0o700, owner).unwrap();
        files::atomic(&public.join("pubring.gpg"), &[], 0o600, Some(owner), false).unwrap();
        import(&public, &exported).unwrap();
        gpg(
            &public,
            &["--import-ownertrust"],
            format!("{fp}:6:\n").as_bytes(),
        )
        .unwrap();
        gpg(
            &public,
            &[
                "--trust-model",
                "classic",
                "--max-cert-depth",
                "1",
                "--check-trustdb",
            ],
            &[],
        )
        .unwrap();
        let listing = gpg(
            &public,
            &[
                "--trust-model",
                "classic",
                "--max-cert-depth",
                "1",
                "--with-colons",
                "--fixed-list-mode",
                "--fingerprint",
                "--list-keys",
            ],
            &[],
        )
        .unwrap();
        assert!(
            authority::identities(text(&listing).unwrap())
                .unwrap()
                .iter()
                .any(|(key, _)| key == &fp)
        );
        assert!(
            gpg(&public, &["--list-secret-keys"], &[])
                .unwrap()
                .is_empty()
        );
        let trust = gpg(&public, &["--export-ownertrust"], &[]).unwrap();
        assert_eq!(
            authority::trusted_local(text(&trust).unwrap(), &BTreeSet::new()).unwrap(),
            [fp]
        );
        public_only(&public, owner).unwrap();
        assert!(public_only(&private, owner).is_err());
    }
}
