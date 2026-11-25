// SPDX-License-Identifier: MIT
//! Independent, retained inspection of the closed offline update publication.
use crate::{identity, package_archive, package_database, package_signature};
use enzimos_platform::{Error, Result, files, json, mount_identity, require, stream_copy};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
pub(crate) const PATH: &str = "/var/lib/enzimos-update-cohort";
pub const CONFIG: &str = "/etc/enzimos/update-pacman.conf";
pub fn configuration() -> String {
    format!(
        "[options]\nArchitecture = x86_64\nCacheDir = {PATH}/packages\nLogFile = /var/log/pacman-enzimos-api.log\nSigLevel = Required TrustedOnly DatabaseOptional\nLocalFileSigLevel = Required TrustedOnly\nCheckSpace\n[verified]\nServer = file://{PATH}/packages\n"
    )
}
pub(crate) fn expiry(text: &str, now: i64) -> Result<()> {
    require(text.len() <= 64, "cohort expiry bound")?;
    let expiry = chrono::DateTime::parse_from_rfc3339(text)
        .map_err(|_| Error("cohort expiry requires an explicit timezone".into()))?;
    let now = chrono::DateTime::from_timestamp(now, 0)
        .ok_or_else(|| Error("cohort clock out of range".into()))?;
    require(
        expiry.timestamp_subsec_nanos() < 1_000_000_000 && expiry > now,
        "admitted cohort expired",
    )
}
fn fresh_expiry(text: &str) -> Result<()> {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error("cohort clock predates epoch".into()))?;
    let seconds = at
        .as_secs()
        .try_into()
        .map_err(|_| Error("cohort clock overflow".into()))?;
    let at = chrono::DateTime::from_timestamp(seconds, at.subsec_nanos())
        .ok_or_else(|| Error("cohort clock out of range".into()))?;
    let expires = chrono::DateTime::parse_from_rfc3339(text)
        .map_err(|_| Error("cohort expiry timezone".into()))?;
    require(
        expires.timestamp_subsec_nanos() < 1_000_000_000 && expires > at,
        "admitted cohort expired",
    )
}
fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error("cohort clock predates epoch".into()))?
        .as_secs()
        .try_into()
        .map_err(|_| Error("cohort clock overflow".into()))
}
pub fn metadata(document: &Value, at: i64) -> Result<BTreeMap<String, Value>> {
    json::fields(document, "schema files expires_at signature_policy")?;
    require(
        document["schema"].as_u64() == Some(1)
            && document["signature_policy"] == "Required TrustedOnly",
        "cohort admission policy refused",
    )?;
    expiry(
        document["expires_at"]
            .as_str()
            .ok_or_else(|| Error("cohort expiry missing".into()))?,
        at,
    )?;
    let rows = document["files"]
        .as_object()
        .ok_or_else(|| Error("cohort files missing".into()))?;
    require(
        rows.len() >= 3 && rows.len() <= 1537,
        "cohort member count bound",
    )?;
    let mut expected = BTreeSet::from(["verified.db".to_owned()]);
    let mut total = 0u64;
    let mut archives = 0;
    for (name, row) in rows {
        require(
            name.len() <= 255
                && name
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._+:-".contains(&byte)),
            "cohort filename refused",
        )?;
        json::fields(row, "bytes sha256")?;
        let bound = if name == "verified.db" {
            32 * 1024 * 1024
        } else if name.ends_with(".sig") {
            65536
        } else {
            512 * 1024 * 1024
        };
        let bytes = row["bytes"]
            .as_u64()
            .ok_or_else(|| Error("cohort member byte type".into()))?;
        require(bytes > 0 && bytes <= bound, "cohort member byte bound")?;
        identity::sha(
            row["sha256"]
                .as_str()
                .ok_or_else(|| Error("cohort digest missing".into()))?,
        )?;
        total = total
            .checked_add(bytes)
            .ok_or_else(|| Error("cohort size overflow".into()))?;
        if name.ends_with(".pkg.tar.zst") {
            archives += 1;
            expected.insert(name.clone());
            expected.insert(format!("{name}.sig"));
        }
    }
    require(
        archives > 0
            && archives <= 768
            && total <= 4 * 1024 * 1024 * 1024
            && rows.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "cohort archive/signature/database set differs",
    )?;
    Ok(rows.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}
fn shape(file: &File, owner: u32) -> Result<Value> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == owner && m.mode() & 0o7777 == 0o700,
        "private cohort directory required",
    )?;
    Ok(
        value!({"device":m.dev(),"inode":m.ino(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),
        "mount":mount_identity::id(file.as_fd(),true)?}),
    )
}
fn names(directory: &File, limit: usize) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for item in files::directory_names(directory, limit)? {
        let name = item
            .into_string()
            .map_err(|_| Error("cohort filename encoding".into()))?;
        require(
            names.len() < limit && names.insert(name),
            "cohort name bound",
        )?;
    }
    Ok(names)
}
struct Member {
    file: File,
    identity: files::FileIdentity,
}
/// All inputs remain held; matching replacement bytes never authorize adoption.
pub struct Cohort {
    path: PathBuf,
    owner: u32,
    directory: File,
    directory_shape: Value,
    packages: File,
    packages_shape: Value,
    admission: Member,
    members: BTreeMap<String, Member>,
    document: Value,
    raw_sha256: String,
    packages_metadata: Vec<Value>,
    kernels: Value,
}
impl Cohort {
    pub fn observe() -> Result<Self> {
        Self::at(Path::new(PATH), 0)
    }
    pub fn document(&self) -> &Value {
        &self.document
    }
    pub(crate) fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }
    pub fn packages_metadata(&self) -> &[Value] {
        &self.packages_metadata
    }
    pub fn kernels(&self) -> &Value {
        &self.kernels
    }
    pub fn at(path: &Path, owner: u32) -> Result<Self> {
        let directory = files::directory(path, Some(owner))?;
        let directory_shape = shape(&directory, owner)?;
        require(
            names(&directory, 2)? == BTreeSet::from(["admission.json".into(), "packages".into()]),
            "unknown cohort root member",
        )?;
        let packages = files::directory_relative(&directory, Path::new("packages"), Some(owner))?;
        let packages_shape = shape(&packages, owner)?;
        require(
            packages_shape["mount"] == directory_shape["mount"],
            "cohort packages independently mounted",
        )?;
        let file = files::open_relative(&directory, Path::new("admission.json"))?;
        let admission = Self::member(file, owner, &directory_shape["mount"], 2 * 1024 * 1024)?;
        let body = files::read_file(&admission.file, 2 * 1024 * 1024, Some(owner), true)?;
        let document = json::decode(&body, 2 * 1024 * 1024)?;
        let expected = metadata(&document, now()?)?;
        require(
            names(&packages, 1537)? == expected.keys().cloned().collect(),
            "cohort package member set changed",
        )?;
        let mut members = BTreeMap::new();
        for (name, row) in &expected {
            let member = Self::member(
                files::open_relative(&packages, Path::new(name))?,
                owner,
                &packages_shape["mount"],
                enzimos_platform::json::unsigned(&row["bytes"])?,
            )?;
            let (bytes, digest) = stream_copy::hash_borrowed(
                &member.file,
                enzimos_platform::json::unsigned(&row["bytes"])?,
                Some(owner),
            )?;
            require(
                value!({"bytes":bytes,"sha256":digest}) == *row,
                "cohort member digest mismatch",
            )?;
            members.insert(name.clone(), member);
        }
        let mut packages_metadata = Vec::new();
        let mut unique = BTreeSet::new();
        let mut kernels = value!({});
        for (name, member) in &members {
            if !name.ends_with(".pkg.tar.zst") {
                continue;
            }
            let mut row = package_archive::identity(&member.file)?;
            let package = enzimos_platform::json::string(&row["name"])?.to_owned();
            require(
                unique.insert(package.clone())
                    && package_archive::filename_matches(
                        name,
                        &package,
                        enzimos_platform::json::string(&row["version"])?,
                    ),
                "cohort archive filename or package identity differs",
            )?;
            if matches!(package.as_str(), "linux" | "linux-lts") {
                kernels[&package] =
                    value!(package_archive::kernel_release(&member.file, &package)?);
            }
            row["file"] = value!(name);
            row["bytes"] = expected[name]["bytes"].clone();
            row["sha256"] = expected[name]["sha256"].clone();
            packages_metadata.push(row);
        }
        require(
            enzimos_platform::json::object(&kernels)?.len() == 2
                && kernels["linux"] != kernels["linux-lts"],
            "cohort requires separate actual dual kernel releases",
        )?;
        package_database::verify(&members["verified.db"].file, &packages_metadata)?;
        let source = Self {
            path: path.into(),
            owner,
            directory,
            directory_shape,
            packages,
            packages_shape,
            admission,
            members,
            document,
            raw_sha256: json::sha256(&body),
            packages_metadata,
            kernels,
        };
        source.recheck()?;
        Ok(source)
    }
    fn member(file: File, owner: u32, mount: &Value, bound: u64) -> Result<Member> {
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == owner
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && m.len() > 0
                && m.len() <= bound
                && value!(mount_identity::id(file.as_fd(), true)?) == *mount,
            "cohort member authority or mount refused",
        )?;
        Ok(Member {
            identity: files::identity(&m),
            file,
        })
    }
    fn original(&self, parent: &File, name: &str, member: &Member) -> Result<()> {
        let named = files::open_relative(parent, Path::new(name))?;
        for file in [&member.file, &named] {
            require(
                files::identity(&file.metadata()?) == member.identity
                    && value!(mount_identity::id(file.as_fd(), true)?)
                        == self.directory_shape["mount"],
                "original cohort file replaced or changed",
            )?;
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<()> {
        fresh_expiry(enzimos_platform::json::string(
            &self.document["expires_at"],
        )?)?;
        let named = files::directory(&self.path, Some(self.owner))?;
        let packages =
            files::directory_relative(&self.directory, Path::new("packages"), Some(self.owner))?;
        require(
            shape(&named, self.owner)? == self.directory_shape
                && shape(&self.directory, self.owner)? == self.directory_shape
                && shape(&packages, self.owner)? == self.packages_shape
                && shape(&self.packages, self.owner)? == self.packages_shape
                && names(&self.directory, 2)?
                    == BTreeSet::from(["admission.json".into(), "packages".into()])
                && names(&self.packages, 1537)? == self.members.keys().cloned().collect(),
            "original cohort directories or membership changed",
        )?;
        self.original(&self.directory, "admission.json", &self.admission)?;
        for (name, member) in &self.members {
            self.original(&self.packages, name, member)?;
        }
        Ok(())
    }
    pub(crate) fn verify_signatures(&self, home: &Path) -> Result<()> {
        self.recheck()?;
        for (name, member) in &self.members {
            if name.ends_with(".pkg.tar.zst") {
                package_signature::verify(
                    &member.file,
                    &self.members[&format!("{name}.sig")].file,
                    home,
                )?;
                // The verifier checks both held inputs before and after this
                // signature. Recheck the complete closed set once at the end,
                // retaining replacement refusal without quadratic FD walks.
            }
        }
        self.recheck()
    }
}
