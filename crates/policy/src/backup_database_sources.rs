// SPDX-License-Identifier: MIT
//! Explicit SQLite source metadata retains original files; it is not an export.
use crate::{settings_file::Config, storage_runtime::Guard};
use enzimos_platform::{Error, Result, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    fs::File,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
const PATH: &str = "/etc/enzimos/backup-databases.json";
const MAX_DATABASE: u64 = 64 * 1024 * 1024;
type Shape = (u64, u64, u32, u32, u32, u64);
fn shape(file: &File) -> Result<Shape> {
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
        "original protected database source parent required",
    )?;
    Ok((
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        mount_identity::id(file.as_fd(), true)?,
    ))
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Row {
    name: String,
    path: PathBuf,
}
fn decode(bytes: &[u8]) -> Result<Vec<Row>> {
    let v = json::decode(bytes, 32768)?;
    json::fields(&v, "schema sqlite")?;
    require(
        v["schema"].as_u64() == Some(1),
        "database configuration schema refused",
    )?;
    let rows = v["sqlite"]
        .as_array()
        .ok_or_else(|| Error("explicit database source array required".into()))?;
    require((1..=4).contains(&rows.len()), "database source count bound")?;
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut result = Vec::new();
    for row in rows {
        json::fields(row, "name path")?;
        let name = row["name"]
            .as_str()
            .ok_or_else(|| Error("database source name required".into()))?;
        let path = row["path"]
            .as_str()
            .ok_or_else(|| Error("database source path required".into()))?;
        require(
            !name.is_empty()
                && name.len() <= 32
                && name.as_bytes()[0].is_ascii_lowercase()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && names.insert(name.to_owned()),
            "invalid or repeated database source name",
        )?;
        let suffix = path
            .strip_prefix("/var/lib/")
            .ok_or_else(|| Error("qualified database path required".into()))?;
        let components = suffix.split('/').collect::<Vec<_>>();
        require(
            path.len() <= 240
                && components.len() >= 2
                && components.iter().all(|s| {
                    !s.is_empty()
                        && *s != "."
                        && *s != ".."
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                })
                && components[0]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && ![
                    "/var/lib/enzimos",
                    "/var/lib/enzimos-control",
                    "/var/lib/pacman",
                    "/var/lib/flatpak",
                ]
                .iter()
                .any(|p| path == *p || path.starts_with(&format!("{p}/")))
                && paths.insert(path.to_owned()),
            "database path conflicts with protected state or aliases another selection",
        )?;
        result.push(Row {
            name: name.into(),
            path: path.into(),
        });
    }
    Ok(result)
}
pub(crate) struct Configuration<'g> {
    guard: &'g Guard,
    parent: File,
    parent_shape: Shape,
    original: Option<Config>,
    rows: Vec<Row>,
}
impl<'g> Configuration<'g> {
    pub(crate) fn observe(guard: &'g Guard) -> Result<Self> {
        guard.recheck()?;
        crate::namespaces::initial()?;
        let parent = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        let parent_shape = shape(&parent)?;
        let original = Config::optional_database_configuration(&parent)?;
        let rows = original
            .as_ref()
            .map(|file| decode(&file.body))
            .transpose()?
            .unwrap_or_default();
        let this = Self {
            guard,
            parent,
            parent_shape,
            original,
            rows,
        };
        this.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.guard.recheck()?;
        let named = files::directory(Path::new("/etc/enzimos"), Some(0))?;
        require(
            shape(&self.parent)? == self.parent_shape && shape(&named)? == self.parent_shape,
            "database configuration parent changed or covered",
        )?;
        if let Some(original) = &self.original {
            original.recheck()?;
            require(
                decode(&original.body)? == self.rows,
                "database source selection changed",
            )?;
        } else {
            require(
                files::optional_relative(&self.parent, Path::new("backup-databases.json"))?
                    .is_none(),
                "database export configuration appeared after absent observation",
            )?;
        }
        Ok(())
    }
    pub(crate) fn sources(&self) -> Result<Vec<Source<'_, 'g>>> {
        self.recheck()?;
        self.rows
            .iter()
            .map(|row| Source::open(self, row))
            .collect()
    }
    pub(crate) fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"path":PATH,"configuration":self.original.as_ref().map(Config::evidence).transpose()?,"configured":self.original.is_some(),"rows":self.rows.iter().map(|r|value!({"name":r.name,"path":r.path})).collect::<Vec<_>>(),"global_atomicity":false}),
        )
    }
}
struct Member {
    file: File,
    epoch: files::FileIdentity,
    mount: u64,
    name: PathBuf,
}
impl Member {
    fn open(parent: &File, name: &Path, owner: u32) -> Result<Option<Self>> {
        files::optional_relative(parent, name)?
            .map(|file| {
                let m = file.metadata()?;
                require(
                    m.uid() == owner
                        && m.gid() == parent.metadata()?.gid()
                        && m.mode() & 0o7022 == 0
                        && m.nlink() == 1
                        && m.len() <= MAX_DATABASE,
                    "unsafe or oversized database member",
                )?;
                let this = Self {
                    epoch: files::identity(&m),
                    mount: mount_identity::id(file.as_fd(), true)?,
                    file,
                    name: name.into(),
                };
                this.recheck(parent)?;
                Ok(this)
            })
            .transpose()
    }
    fn recheck(&self, parent: &File) -> Result<()> {
        let named = files::open_relative(parent, &self.name)?;
        require(
            files::identity(&self.file.metadata()?) == self.epoch
                && files::identity(&named.metadata()?) == self.epoch
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && mount_identity::id(named.as_fd(), true)? == self.mount,
            "original database member changed, replaced or covered",
        )
    }
    fn evidence(&self, parent: &File) -> Result<Value> {
        self.recheck(parent)?;
        Ok(value!({"file":self.epoch,"mount":self.mount}))
    }
}
pub struct Source<'a, 'g> {
    configuration: &'a Configuration<'g>,
    row: &'a Row,
    parent: File,
    parent_shape: Shape,
    main: Member,
    sidecars: Vec<(PathBuf, Option<Member>)>,
}
impl<'a, 'g> Source<'a, 'g> {
    fn open(configuration: &'a Configuration<'g>, row: &'a Row) -> Result<Self> {
        configuration.recheck()?;
        let parent = files::directory(row.path.parent().unwrap(), Some(0))?;
        let parent_shape = shape(&parent)?;
        let name = Path::new(row.path.file_name().unwrap());
        let main = Member::open(&parent, name, 0)?
            .ok_or_else(|| Error("explicit database source missing".into()))?;
        require(main.epoch.2 > 0, "empty database source refused")?;
        let mut sidecars = Vec::new();
        for suffix in ["-wal", "-shm", "-journal"] {
            let name = PathBuf::from(format!("{}{suffix}", name.to_str().unwrap()));
            let original = Member::open(&parent, &name, 0)?;
            sidecars.push((name, original));
        }
        let this = Self {
            configuration,
            row,
            parent,
            parent_shape,
            main,
            sidecars,
        };
        this.recheck()?;
        Ok(this)
    }
    pub fn recheck(&self) -> Result<()> {
        self.configuration.recheck()?;
        let named = files::directory(self.row.path.parent().unwrap(), Some(0))?;
        require(
            shape(&self.parent)? == self.parent_shape && shape(&named)? == self.parent_shape,
            "original database parent changed or covered",
        )?;
        self.main.recheck(&self.parent)?;
        for (name, original) in &self.sidecars {
            if let Some(original) = original {
                original.recheck(&self.parent)?;
            } else {
                require(
                    files::optional_relative(&self.parent, name)?.is_none(),
                    "database sidecar appeared after absent observation",
                )?;
            }
        }
        Ok(())
    }
    pub(crate) fn path(&self) -> &Path {
        &self.row.path
    }
    pub(crate) fn name(&self) -> &str {
        &self.row.name
    }
    pub(crate) fn guard(&self) -> &'g Guard {
        self.configuration.guard
    }
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.recheck()?;
        Ok(self.main.file.as_fd())
    }
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            value!({"name":self.row.name,"path":self.row.path,"main":self.main.evidence(&self.parent)?,"sidecars":self.sidecars.iter().map(|(name,file)|Ok(value!({"name":name,"original":file.as_ref().map(|f|f.evidence(&self.parent)).transpose()?}))).collect::<Result<Vec<_>>>()?,"exported":false,"global_atomicity":false}),
        )
    }
}
