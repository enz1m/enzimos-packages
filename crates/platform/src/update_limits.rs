// SPDX-License-Identifier: MIT
//! Bounds shared by the updater, native policy, and package worker.

/// Maximum number of package archives in one cohort.
pub const MAX_PACKAGES: usize = 2048;
/// One detached signature per archive, plus the repository database.
pub const MAX_COHORT_FILES: usize = 2 * MAX_PACKAGES + 1;
/// Maximum compressed bytes in one package archive.
pub const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum bytes across the cohort, including signatures and the database.
pub const MAX_COHORT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Descriptors for two retained cohorts plus the transaction's other inputs.
pub const COHORT_NOFILE: u64 = 16384;
