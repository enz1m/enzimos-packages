// SPDX-License-Identifier: MIT
//! Reentrant NSS lookup. Returned names never become shell source.
use crate::{Error, Result, require};
#[derive(Clone, Debug, PartialEq, Eq)]
/// Owned account data from a bounded NSS lookup.
pub struct Account {
    /// Login name; validated against empty or control-character values.
    pub name: String,
    /// Exact UID requested by the caller.
    pub uid: u32,
    /// Primary group reported by NSS.
    pub gid: u32,
    /// Absolute home path; it does not establish filesystem ownership.
    pub home: String,
    /// Absolute login shell path, or empty when NSS supplies none.
    pub shell: String,
}
/// Looks up an exact UID without sharing libc's static account buffer.
///
/// # Errors
/// Rejects missing accounts, NSS failures, oversized or invalid text fields,
/// and a record whose UID differs from the requested identity.
#[allow(unsafe_code, reason = "Linux syscall ABI (getpwuid_r).")]
pub fn lookup_uid(uid: u32) -> Result<Account> {
    let mut buffer = vec![0u8; 65536];
    let mut row = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    // SAFETY: row and result are writable; buffer remains live with its exact capacity.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            row.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    require(rc == 0 && !result.is_null(), "account-unavailable")?;
    // SAFETY: a successful non-null getpwuid_r result initializes row.
    let row = unsafe { row.assume_init() };
    let text = |ptr: *const libc::c_char, max: usize| -> Result<String> {
        require(!ptr.is_null(), "account-field-unavailable")?;
        // SAFETY: NSS returns NUL-terminated fields in the still-live lookup buffer.
        let text = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .map_err(|_| Error("account-field-encoding".into()))?;
        require(
            text.len() <= max && !text.chars().any(char::is_control),
            "account-field-bound",
        )?;
        Ok(text.into())
    };
    let name = text(row.pw_name, 256)?;
    let home = text(row.pw_dir, 4096)?;
    let shell = text(row.pw_shell, 4096)?;
    require(
        row.pw_uid == uid
            && !name.is_empty()
            && home.starts_with('/')
            && (shell.is_empty() || shell.starts_with('/')),
        "account-identity-invalid",
    )?;
    Ok(Account {
        name,
        uid,
        gid: row.pw_gid,
        home,
        shell,
    })
}
