// SPDX-License-Identifier: MIT
//! Installed account files are data. Password hashing runs in a confined child.
use enzimos_platform::{Error, Result, files, mount_identity, process, require};
use std::{
    fs::File,
    os::{
        fd::AsFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;
pub(crate) const CONSUMER: &str = "/usr/lib/enzimos-native/enzimos-media-auth";
pub(crate) const MAX_DATA: usize = 256 * 1024;
/// An installed account that can unlock the recovery media.
pub struct Account {
    /// Account name.
    pub name: String,
    /// User ID.
    pub uid: u32,
    /// Primary group ID.
    pub gid: u32,
    pub(crate) hash: Zeroizing<Vec<u8>>,
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && matches!(s.as_bytes()[0], b'a'..=b'z' | b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}
fn rows(bytes: &[u8]) -> Result<impl Iterator<Item = &str>> {
    require(
        bytes.len() <= MAX_DATA && !bytes.contains(&0),
        "offline account file bound",
    )?;
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| Error("offline account file encoding".into()))?
        .lines())
}
pub(crate) fn documents(
    passwd: &[u8],
    group: &[u8],
    shadow: &[u8],
    username: &str,
) -> Result<Account> {
    require(
        name(username) && username != "root",
        "ordinary administrator account required",
    )?;
    let wheel = rows(group)?
        .filter(|l| l.split(':').next() == Some("wheel"))
        .collect::<Vec<_>>();
    require(wheel.len() == 1, "exactly one wheel group required")?;
    let fields = wheel[0].split(':').collect::<Vec<_>>();
    require(
        fields.len() == 4
            && fields[2]
                .parse::<u32>()
                .ok()
                .is_some_and(|n| n > 0 && n < u32::MAX)
            && fields[3].split(',').any(|n| n == username),
        "explicit wheel administrator required",
    )?;
    let user = rows(passwd)?
        .filter(|l| l.split(':').next() == Some(username))
        .collect::<Vec<_>>();
    require(user.len() == 1, "exactly one installed account required")?;
    let fields = user[0].split(':').collect::<Vec<_>>();
    require(fields.len() == 7, "installed account fields refused")?;
    let uid = fields[2]
        .parse::<u32>()
        .map_err(|_| Error("installed UID refused".into()))?;
    let gid = fields[3]
        .parse::<u32>()
        .map_err(|_| Error("installed GID refused".into()))?;
    require(
        (1000..u32::MAX).contains(&uid)
            && gid > 0
            && gid < u32::MAX
            && fields[6].starts_with('/')
            && !fields[6].ends_with("/nologin")
            && !fields[6].ends_with("/false"),
        "ordinary installed login account required",
    )?;
    let secret = rows(shadow)?
        .filter(|l| l.split(':').next() == Some(username))
        .collect::<Vec<_>>();
    require(
        secret.len() == 1,
        "exactly one installed shadow account required",
    )?;
    let fields = secret[0].split(':').collect::<Vec<_>>();
    require(fields.len() == 9, "installed shadow fields refused")?;
    hash_setting(fields[1].as_bytes())?;
    Ok(Account {
        name: username.into(),
        uid,
        gid,
        hash: Zeroizing::new(fields[1].as_bytes().to_vec()),
    })
}
pub(crate) fn hash_setting(hash: &[u8]) -> Result<()> {
    require(
        hash.len() < 384
            && hash.len() >= 20
            && hash.iter().all(|b| b.is_ascii_graphic() && *b != b':')
            && [b"$y$".as_slice(), b"$6$", b"$5$"]
                .iter()
                .any(|p| hash.starts_with(p)),
        "supported nonlocked administrator password required",
    )
}
struct Data {
    name: &'static str,
    file: File,
    identity: files::FileIdentity,
}
fn private_bytes(file: &File) -> Result<Zeroizing<Vec<u8>>> {
    let before = files::identity(&file.metadata()?);
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_DATA));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let count = file.read_at(&mut *chunk, bytes.len() as u64)?;
        if count == 0 {
            break;
        }
        require(
            bytes.len() + count <= MAX_DATA,
            "offline account file bound",
        )?;
        bytes.extend_from_slice(&chunk[..count]);
    }
    require(
        files::identity(&file.metadata()?) == before,
        "installed account file changed during read",
    )?;
    Ok(bytes)
}
pub(crate) struct Observation {
    root: File,
    path: PathBuf,
    identity: files::FileIdentity,
    mount: u64,
    data: Vec<Data>,
    pub(crate) account: Account,
}
impl Observation {
    pub(crate) fn observe(root: &Path, username: &str) -> Result<Self> {
        crate::media_origin::current()?;
        require(
            root.starts_with(crate::storage_runtime::IndependentGuard::TOP)
                && root.parent() == Some(Path::new(crate::storage_runtime::IndependentGuard::TOP)),
            "installed top-level root required",
        )?;
        let directory = files::directory(root, Some(0))?;
        let identity = files::identity(&directory.metadata()?);
        let mount = mount_identity::id(directory.as_fd(), true)?;
        let etc = files::directory(&root.join("etc"), Some(0))?;
        require(
            mount_identity::id(etc.as_fd(), true)? == mount,
            "installed account folder crosses a mount",
        )?;
        let mut data = Vec::new();
        let mut bytes = Vec::new();
        for name in ["etc/passwd", "etc/group", "etc/shadow"] {
            let file = files::open_relative(&directory, Path::new(name))?;
            let m = file.metadata()?;
            require(
                m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o022 == 0
                    && (name != "etc/shadow" || m.mode() & 0o077 == 0)
                    && mount_identity::id(file.as_fd(), true)? == mount,
                "installed account file authority refused",
            )?;
            bytes.push(private_bytes(&file)?);
            data.push(Data {
                name,
                file,
                identity: files::identity(&m),
            });
        }
        let account = documents(&bytes[0], &bytes[1], &bytes[2], username)?;
        let observation = Self {
            root: directory,
            path: root.into(),
            identity,
            mount,
            data,
            account,
        };
        observation.recheck()?;
        Ok(observation)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        crate::media_origin::current()?;
        let named = files::directory(&self.path, Some(0))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.root.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "installed authentication root changed",
        )?;
        for data in &self.data {
            let etc = files::directory(&self.path.join("etc"), Some(0))?;
            require(
                mount_identity::id(etc.as_fd(), true)? == self.mount,
                "installed account folder crosses a mount",
            )?;
            let named = files::open_relative(&self.root, Path::new(data.name))?;
            require(
                files::identity(&data.file.metadata()?) == data.identity
                    && files::identity(&named.metadata()?) == data.identity
                    && mount_identity::id(named.as_fd(), true)? == self.mount,
                "installed account authority changed",
            )?;
        }
        Ok(())
    }
    pub(crate) fn authenticate(&self, password: &[u8]) -> Result<()> {
        require(
            !password.is_empty() && password.len() < 512 && !password.contains(&0),
            "administrator password size bound",
        )?;
        self.recheck()?;
        let policy = crate::native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))?;
        require(
            policy
                .as_object()
                .is_some_and(|p| p.contains_key("enzimos-media-auth")),
            "native media password consumer missing",
        )?;
        let mut input = Zeroizing::new(Vec::with_capacity(1024));
        input.extend_from_slice(password);
        input.push(0);
        input.extend_from_slice(&self.account.hash);
        input.push(0);
        let output = process::run(CONSUMER, &[], &input, Duration::from_secs(15), 4096)?;
        self.recheck()?;
        require(
            crate::native_policy_files::observe(Path::new("/usr/lib/enzimos-native"))? == policy,
            "native media password consumer changed",
        )?;
        require(
            output.status.success() && output.stdout.is_empty() && output.stderr.is_empty(),
            "administrator password incorrect or verifier refused",
        )
    }
}
