// SPDX-License-Identifier: MIT
use enzimos_platform::{Result, files, require};
use std::path::Path;
pub const STATE: &str = "/var/lib/enzimos";
pub const CONTROL: &str = "/var/lib/enzimos-control";
pub const BUSY: &str = "service-busy";
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
pub fn root_only() -> Result<()> {
    require(
        unsafe { libc::geteuid() } == 0,
        "root authorization required",
    )
}
pub fn lock() -> Result<files::Lock> {
    try_lock()?.ok_or_else(|| enzimos_platform::Error(BUSY.into()))
}
/// Wait a bounded time for other boot-time policy work to release the lock.
pub fn lock_wait(timeout: std::time::Duration) -> Result<files::Lock> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(lock) = try_lock()? {
            return Ok(lock);
        }
        require(std::time::Instant::now() < deadline, BUSY)?;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}
pub fn try_lock() -> Result<Option<files::Lock>> {
    root_only()?;
    let directory = Path::new("/run/enzimos");
    files::ensure_directory(directory, 0o700, 0)?;
    let lock = files::Lock::try_acquire(&directory.join("operation.lock"), 0)?;
    if lock.is_some() {
        crate::update_apply_pending::entry()?;
        crate::signed_entry::enable::pending_entry()?;
    }
    Ok(lock)
}
/// The operation lock for `secure-boot abandon` only: it skips the refusal of
/// an unfinished owner boot enablement (which it exists to end) and the update
/// apply review, so neither pending state can lock the other out.
pub fn lock_for_enable_abandon() -> Result<files::Lock> {
    root_only()?;
    let directory = Path::new("/run/enzimos");
    files::ensure_directory(directory, 0o700, 0)?;
    files::Lock::try_acquire(&directory.join("operation.lock"), 0)?
        .ok_or_else(|| enzimos_platform::Error(BUSY.into()))
}
/// Independent recovery uses its genuine mounted plan guard for pending work.
pub fn independent_lock(plan: &serde_json::Value) -> Result<files::Lock> {
    root_only()?;
    crate::recovery_bootstrap::quiet()?;
    let directory = Path::new("/run/enzimos");
    files::ensure_directory(directory, 0o700, 0)?;
    let lock = files::Lock::try_acquire(&directory.join("operation.lock"), 0)?
        .ok_or_else(|| enzimos_platform::Error(BUSY.into()))?;
    crate::update_apply_pending::independent_entry(plan)?;
    crate::signed_entry::enable::pending_entry()?;
    lock.recheck()?;
    Ok(lock)
}
pub fn boot_id() -> Result<String> {
    let bytes = files::read_kernel(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| enzimos_platform::Error("boot identity encoding".into()))?
        .trim();
    Ok(crate::identity::uuid(s)?.into())
}
pub fn query(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
    bound: usize,
    codes: &[i32],
) -> Result<Vec<u8>> {
    let result = enzimos_platform::process::run(program, args, &[], timeout, bound)?;
    if !result.status.code().is_some_and(|c| codes.contains(&c)) {
        return Err(enzimos_platform::Error(format!(
            "fixed command refused: {}",
            enzimos_platform::process::refusal(program, &result)
        )));
    }
    Ok(result.stdout)
}
