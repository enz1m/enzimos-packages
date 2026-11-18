// SPDX-License-Identifier: MIT
//! Known original rename validation. A successful syscall never permits object adoption.
use enzimos_platform::{Result, files, require};
pub(crate) fn renamed(before: files::FileIdentity, after: files::FileIdentity) -> Result<()> {
    require(
        before.0 == after.0
            && before.1 == after.1
            && before.2 == after.2
            && before.3 == after.3
            && before.4 == after.4
            && before.7 == after.7
            && before.8 == after.8
            && before.9 == after.9
            && before.10 == after.10,
        "original rename changed fields beyond ctime",
    )
}
pub(crate) fn parent_changed(
    before: files::FileIdentity,
    after: files::FileIdentity,
    removed_directory: bool,
) -> Result<()> {
    require(
        before.0 == after.0
            && before.1 == after.1
            && before.7 == after.7
            && before.8 == after.8
            && before.9 == after.9
            && if removed_directory {
                before.10 == after.10 || before.10.checked_sub(1) == Some(after.10)
            } else {
                before.10 == after.10
            },
        "original directory mutation changed protected parent identity",
    )
}
pub(crate) fn unlinked(before: files::FileIdentity, after: files::FileIdentity) -> Result<()> {
    require(
        before.0 == after.0
            && before.1 == after.1
            && before.2 == after.2
            && before.3 == after.3
            && before.4 == after.4
            && before.7 == after.7
            && before.8 == after.8
            && before.9 == after.9
            && before.10 == 1
            && after.10 == 0,
        "original unlink did not retire exact single-link inode",
    )
}
