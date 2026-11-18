# enzimOS Native Packages

System policy, the authenticated System1 backend and desktop OS integration for
the writable Arch-based enzimOS system: updates, snapshots, recovery, backups,
account policy and system settings. The service and policy executables are
written in Rust. Package hooks and boot integration also use shell scripts.

## Repository layout

- `crates/platform` — shared primitives: bounded JSON, descriptor-based
  filesystem guards, pinned process execution, publication and restic helpers.
- `crates/policy` — `enzimos-policy` (Root policy CLI) plus the
  recovery image, recovery run, media authentication and media rescue entry points.
- `crates/backend` — `enzimos-system-backend` (org.enzimos.System1),
  `enzimos-backup-worker`, `enzimos-secret-validator`, `enzimos-user-switch` and
  `enzimos-history`.
- `packaging/rust/` — the `enzimos-rust-packages` runtime package that carries
  the binaries listed in `packaging/rust/runtime.json`, the recovery initramfs
  hook and its configuration.
- [`native-policy/`](native-policy/README.md) — the `enzimos-native-policy` package: systemd units, timers,
  pacman hooks, sysctl/udev/network/firewall defaults. Units call
  `/usr/lib/enzimos-native/enzimos-policy`.
- [`system-backend/`](system-backend/README.md) — package recipe, D-Bus
  activation, system-bus policy and polkit rules for System1.
- [`desktop-integration/`](desktop-integration/README.md) — greeter, user switching, printing/mDNS, gaming and
  background-slice integration for the desktop image.
- [`keyring/`](keyring/README.md) — oo7 integration patch and login hooks, assembled by the image tooling.
- `recipes/enzimos-policy/` — metadata-only product policy recipe.

System applications should discover available operations through System1
`GetCapabilities`. The policy CLI also serves system units, package hooks and
boot scripts. It accepts a fixed set of actions and validates the selected
resources before changing them.

## Build and test

Requires Linux, Rust 1.95 or newer, a C toolchain, pkg-config and the native
development libraries for OpenSSL, Cairo, Pango, GLib and libxcrypt. Use the
workspace lockfile.

```sh
cargo build --release --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked
cargo fmt --all --check
```

Tests use temporary state, owned child processes and private buses. Install
D-Bus, GnuPG and util-linux for the corresponding integration tests. Socket fixtures require short,
user-owned paths with no group/world-writable ancestors. For a deeply nested
checkout, set `ENZIMOS_TEST_TMPDIR` to a short private directory outside the source
tree; tests create and remove their own temporary children there.

## Packaging

The enzimOS image builder assembles the runtime using
[`packaging/rust/runtime.json`](packaging/rust/runtime.json). Keep the policy,
backend and integration packages at compatible revisions. Building this workspace
does not activate system services. Use a disposable installed VM to check
system-bus activation, package upgrades, backup and restore, and recovery boot.
The test that requires privileged KCMP access is marked ignored for ordinary
development runs.

## License

MIT; see [LICENSE](LICENSE). Upstream dependencies keep their own licenses.
