// SPDX-License-Identifier: MIT
//! Native retirement filter, separate from the legacy coordinator ABI.
//! Actual original actors gate installation; filter evidence grants no deletion.
use crate::{
    coordinator_seal as legacy,
    root_retirement_dm_control::{Original as DmControl, REMOVE as DM_REMOVE, STATUS as DM_STATUS},
    root_retirement_image_receipt::Receipt,
    root_retirement_kernel_boot::Original as Kernel,
    root_retirement_offline_inventory::Inventory,
    root_retirement_offline_mount::OwnedTop,
    root_retirement_offline_scope::{Mounts, Scope},
};
use enzimos_platform::{Result, files, require};
use serde_json::{Value, json};
use std::os::fd::AsRawFd;
const READ: &[u32] = &[
    0x81f8943c, // GET_SUBVOL_INFO: root-item identity and flags.
    0x8400941f, // FS_INFO: original filesystem membership/UUID.
    0x80081280, // BLKGETDISKSEQ: original device generation.
    0x80081272, // BLKGETSIZE64.
    0x125e,     // BLKROGET.
    0xc0709411, // TREE_SEARCH_V2: complete original Root Tree.
    0xd0009412, // INO_LOOKUP: original root-reference directory path.
];
const DESTROY: u32 = 0x5000943f; // SNAP_DESTROY_V2, SPEC_BY_ID in consuming actor.
const SYNC: u32 = 0x9408;
fn row(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
fn program(top: u32, owner: u32, dm: u32) -> Vec<libc::sock_filter> {
    let mut out = vec![
        row(0x20, 0, 0, 4),
        row(0x15, 1, 0, legacy::ARCH),
        row(0x06, 0, 0, legacy::KILL),
        row(0x20, 0, 0, 0),
    ];
    for nr in legacy::BASE.iter().chain([82, 264, 316, 437].iter()) {
        out.extend([row(0x15, 0, 1, *nr), row(0x06, 0, 0, legacy::ALLOW)]);
    }
    let mut ioctl = vec![
        row(0x20, 0, 0, 28),
        row(0x15, 1, 0, 0),
        row(0x06, 0, 0, legacy::DENY),
        row(0x20, 0, 0, 24),
    ];
    for request in READ {
        ioctl.extend([row(0x15, 0, 1, *request), row(0x06, 0, 0, legacy::ALLOW)]);
    }
    for request in [DESTROY, SYNC, DM_STATUS, DM_REMOVE] {
        let mut check = vec![
            row(0x20, 0, 0, 20),
            row(0x15, 1, 0, 0),
            row(0x06, 0, 0, legacy::DENY),
            row(0x20, 0, 0, 16),
            row(
                0x15,
                0,
                1,
                if request == DM_STATUS || request == DM_REMOVE {
                    dm
                } else {
                    top
                },
            ),
            row(0x06, 0, 0, legacy::ALLOW),
        ];
        if request == SYNC {
            check.extend([row(0x15, 0, 1, owner), row(0x06, 0, 0, legacy::ALLOW)]);
        }
        check.push(row(0x06, 0, 0, legacy::DENY));
        ioctl.push(row(0x15, 0, check.len() as u8, request));
        ioctl.extend(check);
    }
    out.push(row(0x15, 0, ioctl.len() as u8, 16));
    out.extend(ioctl);
    out.push(row(0x06, 0, 0, legacy::DENY));
    out
}
/// The installed native retirement syscall filter.
pub struct Installed<'a, 's> {
    scope: &'s Scope,
    mounts: &'a Mounts<'s>,
    descriptor: i32,
    descriptor_flags: i32,
    owner: &'a OwnedTop<'a, 's>,
    owner_descriptor: i32,
    owner_flags: i32,
    control: &'a DmControl<'s>,
    control_descriptor: i32,
    inventory: &'a Inventory<'a, 's>,
    ledgers: &'a crate::root_retirement_offline_ledgers::Ledgers<'a, 's>,
    catalog: &'a crate::root_retirement_offline_catalog::Catalog<'a, 's>,
    loaders: &'a crate::root_retirement_offline_loaders::Loaders<'a, 's>,
    publications: &'a crate::root_retirement_offline_publications::Publications<'a, 's>,
    protection: &'a crate::root_retirement_offline_protection::Protection<'a, 's>,
    helpers: &'a crate::root_retirement_kernel_helpers::Disabled<'s>,
}
impl<'a, 's> Installed<'a, 's> {
    pub(crate) fn first_descriptions(
        &self,
    ) -> Result<crate::root_retirement_first_delete::Descriptions<'_>> {
        self.recheck()?;
        let originals = self.inventory.first_descriptions()?;
        require(
            originals.top.as_raw_fd() == self.descriptor,
            "actual first retirement selector differs from sealed original top descriptor",
        )?;
        Ok(originals)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, prctl).")]
    #[expect(
        clippy::too_many_arguments,
        reason = "Each argument is a distinct retained input of this step."
    )]
    pub(crate) fn install(
        scope: &'s Scope,
        mounts: &'a Mounts<'s>,
        owner: &'a OwnedTop<'a, 's>,
        verified: &crate::root_retirement_unlock_source::Verified<'_, '_, '_>,
        kernel: &Kernel<'_>,
        receipt: &Receipt<'_, '_, '_>,
        inventory: &'a Inventory<'a, 's>,
        control: &'a DmControl<'s>,
        ledgers: &'a crate::root_retirement_offline_ledgers::Ledgers<'a, 's>,
        catalog: &'a crate::root_retirement_offline_catalog::Catalog<'a, 's>,
        loaders: &'a crate::root_retirement_offline_loaders::Loaders<'a, 's>,
        publications: &'a crate::root_retirement_offline_publications::Publications<'a, 's>,
        protection: &'a crate::root_retirement_offline_protection::Protection<'a, 's>,
        helpers: &'a crate::root_retirement_kernel_helpers::Disabled<'s>,
    ) -> Result<Self> {
        scope.recheck()?;
        helpers.require_original_scope(scope)?;
        require(
            cfg!(target_arch = "x86_64") && std::mem::size_of::<usize>() == 8,
            "exact native x86-64 retirement filter required",
        )?;
        mounts.require_original_scope(scope)?;
        owner.require_original_mounts(mounts)?;
        verified.require_original_kernel(kernel)?;
        owner.require_original_unlock(verified)?;
        control.require_original_mapping(verified.mapping()?)?;
        kernel.require_original_scope(scope)?;
        inventory.require_original_boot(mounts, kernel, receipt)?;
        inventory.require_original_ledgers(ledgers)?;
        ledgers.require_idle()?;
        catalog.require_original_ledgers(ledgers)?;
        inventory.require_original_catalog(catalog)?;
        loaders.require_original_catalog(catalog)?;
        inventory.require_original_loaders(loaders)?;
        publications.require_original_actors(ledgers, loaders)?;
        inventory.require_original_publications(publications)?;
        protection.require_original_actors(catalog, mounts, loaders)?;
        inventory.require_original_protection(protection)?;
        let top = mounts.original_top()?;
        let descriptor = top.as_raw_fd();
        require(
            (0..1_048_576).contains(&descriptor),
            "bounded original native top descriptor",
        )?;
        // SAFETY: F_GETFL takes no pointers; it only reads the flags of a retained descriptor
        // number.
        let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        require(
            descriptor_flags >= 0 && descriptor_flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original native top read-only description",
        )?;
        let owner_descriptor = owner.original_descriptor()?.as_raw_fd();
        require(
            (0..1_048_576).contains(&owner_descriptor),
            "bounded original owned top descriptor",
        )?;
        // SAFETY: F_GETFL takes no pointers; it only reads the flags of a retained descriptor
        // number.
        let owner_flags = unsafe { libc::fcntl(owner_descriptor, libc::F_GETFL) };
        require(
            owner_flags >= 0 && owner_flags & libc::O_ACCMODE == libc::O_RDONLY,
            "original owned top read-only description",
        )?;
        let control_descriptor = control.descriptor()?;
        require(
            (0..1_048_576).contains(&control_descriptor),
            "bounded original DM control descriptor",
        )?;
        let mut rows = program(
            descriptor as u32,
            owner_descriptor as u32,
            control_descriptor as u32,
        );
        let filter = libc::sock_fprog {
            len: rows.len() as u16,
            filter: rows.as_mut_ptr(),
        };
        require(
            // SAFETY: This prctl option takes no pointers.
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0
                // SAFETY: `filter` is a sock_fprog pointing at instructions that outlive the call.
                && unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &filter) }
                    == 0,
            "native retirement filter unavailable; no deletion",
        )?;
        let result = Self {
            scope,
            mounts,
            descriptor,
            descriptor_flags,
            owner,
            owner_descriptor,
            owner_flags,
            control,
            control_descriptor,
            inventory,
            ledgers,
            catalog,
            loaders,
            publications,
            protection,
            helpers,
        };
        result.recheck()?;
        // All original joins must still work inside the installed profile.
        inventory.require_original_boot(mounts, kernel, receipt)?;
        result.recheck()?;
        Ok(result)
    }
    pub(crate) fn recheck(&self) -> Result<()> {
        self.recheck_retained_references()?;
        self.inventory.require_original_ledgers(self.ledgers)?;
        self.inventory
            .require_original_publications(self.publications)?;
        self.inventory
            .require_original_protection(self.protection)?;
        self.recheck_retained_references()
    }
    pub(crate) fn recheck_after_first(
        &self,
        proof: &crate::root_retirement_first_delete::After<'_, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_seal(self)?;
        self.recheck_retained_references()?;
        proof.recheck_kernel()?;
        self.recheck_retained_references()
    }
    pub(crate) fn recheck_advanced_first(
        &self,
        proof: &crate::root_retirement_first_delete::Advanced<'_, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_seal(self)?;
        self.recheck_retained_references()?;
        proof.recheck_kernel()?;
        self.recheck_retained_references()
    }
    pub(crate) fn recheck_next(
        &self,
        proof: &crate::root_retirement_first_delete::Next<'_, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_seal(self)?;
        self.recheck_retained_references()?;
        proof.recheck_kernel()?;
        self.recheck_retained_references()
    }
    pub(crate) fn recheck_cursor(
        &self,
        proof: &crate::root_retirement_cursor::State<'_, 'a, 's>,
    ) -> Result<()> {
        proof.require_original_seal(self)?;
        self.recheck_retained_references()?;
        proof.recheck_physical()?;
        self.recheck_retained_references()
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl).")]
    fn recheck_retained_references(&self) -> Result<()> {
        self.scope.recheck()?;
        self.helpers.require_original_scope(self.scope)?;
        self.ledgers.recheck()?;
        self.ledgers.require_idle()?;
        self.catalog.require_original_ledgers(self.ledgers)?;
        self.loaders.require_original_catalog(self.catalog)?;
        self.publications
            .require_original_actors(self.ledgers, self.loaders)?;
        self.protection
            .require_original_actors(self.catalog, self.mounts, self.loaders)?;
        self.mounts.require_original_scope(self.scope)?;
        self.owner.require_original_mounts(self.mounts)?;
        require(
            self.control.descriptor()? == self.control_descriptor,
            "original sealed DM control description changed",
        )?;
        require(
            self.mounts.original_top()?.as_raw_fd() == self.descriptor
                // SAFETY: F_GETFL takes no pointers; it only reads the flags of a retained
                // descriptor number.
                && unsafe { libc::fcntl(self.descriptor, libc::F_GETFL) } == self.descriptor_flags,
            "original sealed top description changed",
        )?;
        require(
            self.owner.original_descriptor()?.as_raw_fd() == self.owner_descriptor
                // SAFETY: F_GETFL takes no pointers; it only reads the flags of a retained
                // descriptor number.
                && unsafe { libc::fcntl(self.owner_descriptor, libc::F_GETFL) } == self.owner_flags,
            "original sealed mount owner description changed",
        )?;
        let status = files::read_kernel(std::path::Path::new("/proc/1/status"), 65536)?;
        let status = std::str::from_utf8(&status)
            .map_err(|_| enzimos_platform::Error("sealed PID1 state encoding".into()))?;
        require(
            status.lines().any(|line| line == "NoNewPrivs:\t1")
                && status.lines().any(|line| line == "Seccomp:\t2"),
            "native coordinator filter is not active",
        )?;
        self.scope.recheck()
    }
    pub(crate) fn require_original_journal(
        &self,
        journal: &crate::root_retirement_offline_journal::Journal<'a, 's>,
    ) -> Result<()> {
        self.recheck()?;
        self.inventory.require_original_journal(journal)?;
        self.recheck()
    }
    /// JSON evidence of this retained state; it grants no deletion.
    ///
    /// # Errors
    ///
    /// Fails when the retained state changed.
    pub fn evidence(&self) -> Result<Value> {
        self.recheck()?;
        Ok(
            json!({"native_filter_profile":2,"syscall_filter_active":true,"destructive_ioctl_bound_to_original_top":true,"kernel_inventory_without_child":true,"execution_authorized":false,"exclusive_block_device_verified":false}),
        )
    }
}
