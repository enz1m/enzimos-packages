// SPDX-License-Identifier: MIT
//! An explicit local recipient is paired with NSS and retained original account/home files.
use crate::{filesystem, storage_runtime::Guard};
use enzimos_platform::{Error, Result, accounts, files, json, mount_identity, require};
use serde_json::{Value, json as value};
use std::{
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
const LIMIT: usize = 1024 * 1024;
struct Local {
    name: String,
    gid: u32,
    home: String,
    shell: String,
    row: String,
}
fn local(body: &[u8], uid: u32) -> Result<Local> {
    require(
        (1000..i32::MAX as u32).contains(&uid) && body.len() <= LIMIT,
        "explicit ordinary local recipient required",
    )?;
    let body = std::str::from_utf8(body).map_err(|_| Error("local account encoding".into()))?;
    let rows = body
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    require(
        rows.iter().all(|row| row.len() == 7),
        "malformed local account database",
    )?;
    let number = uid.to_string();
    let matches = rows
        .iter()
        .filter(|row| row[2] == number)
        .collect::<Vec<_>>();
    require(matches.len() == 1, "unique local recipient required")?;
    let row = matches[0];
    let name = row[0];
    require(
        !name.is_empty()
            && name.len() <= 32
            && (name.as_bytes()[0].is_ascii_lowercase() || name.starts_with('_'))
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            && rows.iter().filter(|other| other[0] == name).count() == 1,
        "unique ordinary local account name required",
    )?;
    let gid = row[3]
        .parse::<u32>()
        .ok()
        .filter(|n| (1..i32::MAX as u32).contains(n));
    require(
        !row[3].is_empty()
            && row[3].bytes().all(|b| b.is_ascii_digit())
            && gid.is_some()
            && row[5] == format!("/home/{name}")
            && !matches!(row[6], "/usr/bin/nologin" | "/bin/false" | "/sbin/nologin"),
        "unsupported local home/account",
    )?;
    Ok(Local {
        name: name.into(),
        gid: gid.ok_or_else(|| enzimos_platform::Error("unsupported local home/account".into()))?,
        home: row[5].into(),
        shell: row[6].into(),
        row: row.join(":"),
    })
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.uid(), m.gid(), m.mode()))
}
fn ns(seconds: i64, nanos: i64) -> Result<i64> {
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .ok_or_else(|| Error("account timestamp bound".into()))
}
pub(crate) struct Recipient {
    uid: u32,
    local: Local,
    etc: File,
    etc_shape: (u64, u64, u32, u32, u32),
    passwd: File,
    passwd_identity: files::FileIdentity,
    passwd_mount: u64,
    bytes: Vec<u8>,
    homes: File,
    homes_shape: (u64, u64, u32, u32, u32),
    homes_mount: u64,
    home: File,
    home_shape: (u64, u64, u32, u32, u32),
    home_mount: u64,
    filesystem: Value,
}
impl Recipient {
    pub(crate) fn home<'a>(&'a self, guard: &Guard) -> Result<&'a File> {
        self.recheck(guard)?;
        Ok(&self.home)
    }
    pub(crate) fn open(uid: u32, guard: &Guard) -> Result<Self> {
        guard.recheck()?;
        let etc = files::directory(Path::new("/etc"), Some(0))?;
        let passwd = files::open_relative(&etc, Path::new("passwd"))?;
        let passwd_identity = files::identity(&passwd.metadata()?);
        require(
            passwd_identity.8 == 0 && passwd_identity.9 == 0,
            "local passwd Root ownership required",
        )?;
        let bytes = files::read_file(&passwd, LIMIT, Some(0), true)?;
        let local = local(&bytes, uid)?;
        let homes = files::directory(Path::new("/home"), Some(0))?;
        let home = files::directory_relative(&homes, Path::new(&local.name), Some(uid))?;
        let home_shape = shape(&home)?;
        require(
            home_shape.2 == uid && home_shape.4 & 0o022 == 0,
            "unsafe recipient home",
        )?;
        let filesystem = filesystem::observe(home.as_fd())?;
        require(
            filesystem["filesystem_uuid"] == guard.configuration["filesystem_uuid"],
            "recipient home left qualified filesystem",
        )?;
        let this = Self {
            uid,
            local,
            etc_shape: shape(&etc)?,
            passwd_mount: mount_identity::id(passwd.as_fd(), true)?,
            homes_shape: shape(&homes)?,
            homes_mount: mount_identity::id(homes.as_fd(), true)?,
            home_mount: mount_identity::id(home.as_fd(), true)?,
            etc,
            passwd,
            passwd_identity,
            bytes,
            homes,
            home,
            home_shape,
            filesystem,
        };
        this.recheck(guard)?;
        Ok(this)
    }
    pub(crate) fn recheck(&self, guard: &Guard) -> Result<()> {
        guard.recheck()?;
        let etc = files::directory(Path::new("/etc"), Some(0))?;
        let named = files::open_relative(&etc, Path::new("passwd"))?;
        require(
            shape(&self.etc)? == self.etc_shape
                && shape(&etc)? == self.etc_shape
                && files::identity(&self.passwd.metadata()?) == self.passwd_identity
                && files::identity(&named.metadata()?) == self.passwd_identity
                && mount_identity::id(self.passwd.as_fd(), true)? == self.passwd_mount
                && mount_identity::id(named.as_fd(), true)? == self.passwd_mount
                && files::read_file(&self.passwd, LIMIT, Some(0), true)? == self.bytes,
            "original local account database changed",
        )?;
        let account = accounts::lookup_uid(self.uid)?;
        require(
            account.name == self.local.name
                && account.gid == self.local.gid
                && account.home == self.local.home
                && account.shell == self.local.shell,
            "local and NSS recipient differ",
        )?;
        let homes = files::directory(Path::new("/home"), Some(0))?;
        let home = files::directory_relative(&homes, Path::new(&self.local.name), Some(self.uid))?;
        require(
            shape(&self.homes)? == self.homes_shape
                && shape(&homes)? == self.homes_shape
                && mount_identity::id(self.homes.as_fd(), true)? == self.homes_mount
                && mount_identity::id(homes.as_fd(), true)? == self.homes_mount
                && shape(&self.home)? == self.home_shape
                && shape(&home)? == self.home_shape
                && mount_identity::id(self.home.as_fd(), true)? == self.home_mount
                && mount_identity::id(home.as_fd(), true)? == self.home_mount
                && filesystem::observe(self.home.as_fd())? == self.filesystem
                && filesystem::observe(home.as_fd())? == self.filesystem,
            "original recipient home changed, replaced or covered",
        )?;
        guard.recheck()
    }
    pub(crate) fn account(&self, guard: &Guard) -> Result<Value> {
        self.recheck(guard)?;
        let m = self.passwd.metadata()?;
        Ok(
            value!({"uid":self.uid,"gid":self.local.gid,"name":self.local.name,"home":self.local.home,
            "passwd_row_sha256":json::sha256(self.local.row.as_bytes()),"passwd_identity":[m.dev(),m.ino(),i128::from(ns(m.mtime(),m.mtime_nsec())?),i128::from(ns(m.ctime(),m.ctime_nsec())?)],
            "passwd_sha256":json::sha256(&self.bytes),"home_device":self.home_shape.0,"home_inode":self.home_shape.1,"home_mount_id":self.home_mount}),
        )
    }
    pub(crate) fn evidence(&self, guard: &Guard) -> Result<Value> {
        Ok(
            value!({"account":self.account(guard)?,"passwd_file":self.passwd_identity,"passwd_mount":self.passwd_mount,"home_shape":self.home_shape,"filesystem":self.filesystem}),
        )
    }
}
