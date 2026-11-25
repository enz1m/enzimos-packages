// SPDX-License-Identifier: MIT
//! This API is entered only in the separately bounded, unprivileged consumer.
use enzimos_platform::{Result, require};
use zeroize::Zeroize;
#[link(name = "crypt")]
#[allow(
    unsafe_code,
    reason = "Declares libcrypt password hashing with caller-owned output storage."
)]
unsafe extern "C" {
    fn crypt_ra(
        phrase: *const libc::c_char,
        setting: *const libc::c_char,
        data: *mut *mut libc::c_void,
        size: *mut libc::c_int,
    ) -> *mut libc::c_char;
}
struct Scratch {
    pointer: *mut libc::c_void,
    size: libc::c_int,
}
impl Drop for Scratch {
    #[allow(unsafe_code, reason = "Linux syscall ABI (free).")]
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            if self.size > 0 {
                // SAFETY: crypt_ra allocated `size` bytes at `pointer`, owned by this guard.
                unsafe {
                    std::slice::from_raw_parts_mut(self.pointer.cast::<u8>(), self.size as usize)
                }
                .zeroize();
            }
            // SAFETY: `pointer` came from crypt_ra's malloc and is freed exactly once.
            unsafe { libc::free(self.pointer) };
        }
    }
}
#[allow(unsafe_code, reason = "libcrypt ABI.")]
pub fn verify(bytes: &[u8]) -> Result<()> {
    require(
        bytes.len() <= 1024 && bytes.last() == Some(&0),
        "password frame refused",
    )?;
    let parts = bytes[..bytes.len() - 1]
        .split(|b| *b == 0)
        .collect::<Vec<_>>();
    require(
        parts.len() == 2 && !parts[0].is_empty() && parts[0].len() < 512,
        "password frame refused",
    )?;
    crate::media_auth::hash_setting(parts[1])?;
    // Let libxcrypt allocate its own ABI-sized workspace. It is zeroed before
    // release, and the consumer's memory limit also bounds future workspaces.
    let mut scratch = Scratch {
        pointer: std::ptr::null_mut(),
        size: 0,
    };
    // SAFETY: Both strings are NUL-terminated within `bytes`, and the scratch pointers are
    // writable.
    let result = unsafe {
        crypt_ra(
            bytes.as_ptr().cast(),
            bytes.as_ptr().add(parts[0].len() + 1).cast(),
            &mut scratch.pointer,
            &mut scratch.size,
        )
    };
    require(
        !result.is_null() && !scratch.pointer.is_null() && scratch.size >= 384,
        "password verifier refused",
    )?;
    let start = scratch.pointer as usize;
    let offset = (result as usize).checked_sub(start);
    require(
        offset.is_some_and(|n| n <= scratch.size as usize - 384),
        "password verifier output bounds",
    )?;
    // SAFETY: `result` lies within the scratch buffer with at least 384 bytes after it, as checked
    // above.
    let output = unsafe { std::slice::from_raw_parts(result.cast::<u8>(), 384) };
    let end = output
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| enzimos_platform::Error("password verifier output termination".into()))?;
    require(
        end == parts[1].len() && openssl::memcmp::eq(&output[..end], parts[1]),
        "administrator password incorrect",
    )
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (prctl, setgroups and others)."
)]
pub fn constrain() -> Result<()> {
    let parent = enzimos_platform::process_identity::parent_pid();
    for (kind, value) in [
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_CPU, 10),
        (libc::RLIMIT_AS, 128 * 1024 * 1024),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        require(
            // SAFETY: `limit` is a valid rlimit that outlives the call.
            unsafe { libc::setrlimit(kind, &limit) } == 0,
            "password verifier limits unavailable",
        )?;
    }
    if enzimos_platform::process_identity::effective_uid() == 0 {
        require(
            // SAFETY: setgroups with a zero count accepts a null list.
            unsafe { libc::setgroups(0, std::ptr::null()) } == 0
                // SAFETY: setresgid takes no pointers.
                && unsafe { libc::setresgid(65534, 65534, 65534) } == 0
                // SAFETY: setresuid takes no pointers.
                && unsafe { libc::setresuid(65534, 65534, 65534) } == 0,
            "password verifier privilege drop unavailable",
        )?;
    }
    require(
        parent > 0
            // SAFETY: This prctl option takes no pointers.
            && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0
            && enzimos_platform::process_identity::parent_pid() == parent
            // SAFETY: This prctl option takes no pointers.
            && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0
            // SAFETY: This prctl option takes no pointers.
            && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "password verifier confinement unavailable",
    )
}
