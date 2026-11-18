// SPDX-License-Identifier: MIT
//! Newly created ESP members remain the original inodes through completion.
use crate::{boot_volume::Volume, generation_stage::NAMES};
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) struct Destination {
    pub directory: File,
    generation: String,
    shape: (u64, u64, u32, u32, u32),
    members: BTreeMap<String, (File, files::FileIdentity)>,
    publications: BTreeMap<String, enzimos_platform::publication::Committed>,
}
fn shape(file: &File) -> Result<(u64, u64, u32, u32, u32)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
}
impl Destination {
    pub(crate) fn capture(directory: &File, generation: &str, volume: &Volume) -> Result<Self> {
        let mut this = Self {
            directory: directory.try_clone()?,
            generation: generation.into(),
            shape: shape(directory)?,
            members: BTreeMap::new(),
            publications: BTreeMap::new(),
        };
        for name in NAMES {
            this.add(name, volume)?;
        }
        this.recheck(volume)?;
        Ok(this)
    }
    pub(crate) fn add(&mut self, name: &str, volume: &Volume) -> Result<()> {
        require(
            NAMES.contains(&name) && !self.members.contains_key(name),
            "generation destination member cannot be adopted or replaced",
        )?;
        let file = files::open_relative(&self.directory, Path::new(name))?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && mount_identity::id(file.as_fd(), true)? == volume.unique,
            "new generation member protection or mount differs",
        )?;
        self.members
            .insert(name.into(), (file, files::identity(&m)));
        Ok(())
    }
    pub(crate) fn add_published(
        &mut self,
        name: &str,
        volume: &Volume,
        publication: enzimos_platform::publication::Committed,
    ) -> Result<()> {
        require(
            matches!(name, "READY.json" | "PUBLISHED.json")
                && !self.members.contains_key(name)
                && !self.publications.contains_key(name),
            "new generation requires original owned publication",
        )?;
        publication.recheck()?;
        let file = publication.file()?.try_clone()?;
        let named = files::open_relative(&self.directory, Path::new(name))?;
        let epoch = files::identity(&file.metadata()?);
        require(
            files::identity(&named.metadata()?) == epoch
                && mount_identity::id(file.as_fd(), true)? == volume.unique
                && mount_identity::id(named.as_fd(), true)? == volume.unique,
            "published generation description differs from original named member",
        )?;
        self.members.insert(name.into(), (file, epoch));
        self.publications.insert(name.into(), publication);
        self.recheck(volume)
    }
    pub(crate) fn recheck(&self, volume: &Volume) -> Result<()> {
        let named = volume.directory(Path::new(&format!(
            "enzimos/generations/{}",
            self.generation
        )))?;
        require(
            shape(&self.directory)? == self.shape
                && shape(&named)? == self.shape
                && mount_identity::id(self.directory.as_fd(), true)? == volume.unique,
            "original new generation directory replaced or remounted",
        )?;
        let actual = files::directory_names(&self.directory, 8)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        require(
            actual == self.members.keys().map(std::ffi::OsString::from).collect(),
            "new generation contains an unexpected or interrupted member",
        )?;
        for (name, (file, before)) in &self.members {
            let named = files::open_relative(&self.directory, Path::new(name))?;
            require(
                files::identity(&file.metadata()?) == *before
                    && files::identity(&named.metadata()?) == *before
                    && mount_identity::id(file.as_fd(), true)? == volume.unique
                    && mount_identity::id(named.as_fd(), true)? == volume.unique,
                "original new generation member replaced or modified",
            )?;
        }
        for publication in self.publications.values() {
            publication.recheck()?;
        }
        volume.recheck()
    }
}
