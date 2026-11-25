// SPDX-License-Identifier: MIT
//! Original repository directory borrowed only while the owned mount remains live.
use enzimos_platform::{Result, files, require};
use serde_json::Value;
use std::{fs::File, path::Path};
/// The repository directory on the owned setup mount.
pub struct Repository {
    file: File,
    binding: Value,
    header: Option<crate::backup_repository_header::Header>,
}
impl Repository {
    /// Retain the existing repository directory on `scope`.
    ///
    /// # Errors
    ///
    /// Fails when the directory is missing or unsafe.
    pub fn adopt(scope: &crate::backup_setup_mount::Scope<'_, '_, '_>) -> Result<Self> {
        scope.recheck()?;
        let root = File::from(scope.descriptor()?.try_clone_to_owned()?);
        let file = files::directory_relative(&root, Path::new("restic"), Some(0))?;
        let binding = crate::backup_worker_scope::directory(&file)?;
        let header = Some(crate::backup_repository_header::Header::observe(&file)?);
        let this = Self {
            file,
            binding,
            header,
        };
        this.recheck(scope)?;
        Ok(this)
    }
    /// Initial directory creation is entered once under the original durable
    /// prepared outer context. Existing encrypted/nonempty repositories are refused.
    ///
    /// # Errors
    ///
    /// Fails when the plan is not an initialization or the repository cannot be created exactly as
    /// prepared.
    pub fn initialize(
        scope: &crate::backup_setup_mount::Scope<'_, '_, '_>,
        context: &crate::backup_setup_context::Prepared<'_, '_, '_, '_>,
    ) -> Result<Self> {
        scope.recheck()?;
        context.recheck()?;
        require(
            context.plan_value()?["mode"] == "initialize"
                && context.filesystem() == scope.evidence()?["filesystem_uuid"],
            "repository creation differs from original prepared initialization",
        )?;
        context.claim(crate::backup_setup_context::Step::Repository)?;
        let root = File::from(scope.descriptor()?.try_clone_to_owned()?);
        let file = files::ensure_directory_relative(&root, Path::new("restic"), 0o700, 0)?;
        require(
            files::directory_is_empty(&file)?,
            "initial repository directory is not empty; no adoption or overwrite",
        )?;
        let binding = crate::backup_worker_scope::directory(&file)?;
        let this = Self {
            file,
            binding,
            header: None,
        };
        this.recheck(scope)?;
        context.recheck()?;
        Ok(this)
    }
    pub(crate) fn recheck(
        &self,
        scope: &crate::backup_setup_mount::Scope<'_, '_, '_>,
    ) -> Result<()> {
        scope.recheck()?;
        let root = File::from(scope.descriptor()?.try_clone_to_owned()?);
        let named = files::directory_relative(&root, Path::new("restic"), Some(0))?;
        require(
            crate::backup_worker_scope::directory(&self.file)? == self.binding
                && crate::backup_worker_scope::directory(&named)? == self.binding
                && self.binding["mount"] == crate::backup_worker_scope::directory(&root)?["mount"],
            "original repository directory replaced or remounted",
        )?;
        if let Some(header) = &self.header {
            header.recheck(&self.file)?;
        }
        Ok(())
    }
    /// The repository directory while `scope` is live.
    ///
    /// # Errors
    ///
    /// Fails when the scope or directory changed.
    pub fn descriptor(
        &self,
        scope: &crate::backup_setup_mount::Scope<'_, '_, '_>,
    ) -> Result<&File> {
        self.recheck(scope)?;
        Ok(&self.file)
    }
    pub(crate) fn binding(
        &self,
        scope: &crate::backup_setup_mount::Scope<'_, '_, '_>,
    ) -> Result<&Value> {
        self.recheck(scope)?;
        Ok(&self.binding)
    }
    pub(crate) fn header(
        &self,
        scope: &crate::backup_setup_mount::Scope<'_, '_, '_>,
    ) -> Result<Value> {
        self.recheck(scope)?;
        self.header
            .as_ref()
            .map(|h| h.evidence(&self.file))
            .transpose()
            .map(|v| v.unwrap_or(Value::Null))
    }
}
