// SPDX-License-Identifier: MIT
use super::*;
impl Runtime {
    pub(crate) fn rotation_query(
        &self,
        task: local_restic::RotationTask,
        repository: &File,
        password: &File,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<enzimos_platform::process::Output> {
        self.recheck()?;
        self.empty()?;
        boundary()?;
        let mut ongoing = || {
            self.recheck()?;
            boundary()
        };
        let output = local_restic::rotation_read(
            task,
            self.image.descriptor()?,
            repository,
            password,
            &self.scratch,
            &mut ongoing,
        )?;
        ongoing()?;
        self.empty()?;
        Ok(output)
    }

    pub(crate) fn rotation_prepare(
        &self,
        task: local_restic::RotationPrepare,
        target: &File,
        next: &File,
        source: &File,
        current: &File,
        boundary: &mut dyn FnMut() -> Result<()>,
    ) -> Result<enzimos_platform::process::Output> {
        self.recheck()?;
        self.empty()?;
        boundary()?;
        let mut ongoing = || {
            self.recheck()?;
            boundary()
        };
        let output = local_restic::rotation_prepare(
            task,
            self.image.descriptor()?,
            target,
            next,
            source,
            current,
            &self.scratch,
            &mut ongoing,
        )?;
        ongoing()?;
        self.empty()?;
        Ok(output)
    }
}
