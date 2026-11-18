// SPDX-License-Identifier: MIT
//! Installer-media rescue entry, started directly as PID1 by `rdinit=`.
fn main() {
    enzimos_policy::media_rescue::main()
}
