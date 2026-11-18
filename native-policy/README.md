# enzimOS native policy

This package provides systemd units, timers, pacman hooks and OS defaults for
the Rust `enzimos-policy` binary. Applications request authenticated operations
through [System1](../system-backend/README.md).

## Storage and background work

Image assembly supplies verified filesystem/subvolume configuration, independent
security/control mounts and Snapper root/home configuration. User accounts and
backup credentials are never embedded in the package. The implementation uses
maintained Snapper, restic, NetworkManager, firewalld, chrony, polkit and AppArmor.

Home history and external backups have separate controls. Backup scheduling is
explicit opt-in with a verified destination/configuration binding. Disabled work
avoids source scans. Retention changes set future policy without immediately
running cleanup/pruning. Background maintenance uses bounded existing services;
there is no new process-scanning scheduler.

## Location

`/etc/geoclue/conf.d/90-enzimos.conf` keeps location off until the user turns
it on: GeoClue accepts only the enzUI session agent, which caps apps at
city level (internet address only) or allows nearby Wi-Fi networks, and the
lookups go to beaconDB without submitting anything.

## VPN shutdown

NetworkManager keeps VPN plugin daemons alive across its own restarts.
`enzimos-vpn-shutdown.service` ends leftover VPN daemons at system shutdown,
first with SIGTERM and then with SIGKILL after five seconds. A NetworkManager
restart leaves it running.

## Compressed swap at shutdown

udev watches zram devices, so closing `/dev/zram0` after swapoff makes udevd
probe it again while `systemd-zram-setup@zram0.service` resets it; the kernel
refuses whichever comes second with EBUSY. The `systemd-zram-setup@.service`
drop-in waits for udev (`udevadm settle`, 5 s) before each reset and tries the
reset at most three times. A reset that still fails fails the unit.

## Recovery and uncertain outcomes

Resource identities, journals and locks remain authoritative. Unknown or partial
state blocks automatic replay or deletion. A completed operation deduplicates;
cancellation does not claim rollback after entry. Restore delivery creates a new
private file without overwriting existing user data or restoring historical owner
metadata. Root generation retirement and independent recovery have separate
versioned review/coordinator contracts.

Boot generation retention is automatic: `enzimos-generation-retention.timer`
(20 minutes after boot, then daily) and any update plan or apply that would
exceed a resource bound run `enzimos-policy boot-retire auto`. It keeps the
newest update pair and offers older generations, oldest first, to the reviewed
boot-retirement plan, whose protections (current, this-boot or unfinished
generation, loader default, pins, last entry of a confirmed root, recovery
references) still refuse; it then removes `boot-stage/<id>` and
`module-views/<id>` of finished applies whose two generations are retired.
A busy operation lock exits 75 for a later retry.

Fallback roots are then retired online by `enzimos-policy root-retire auto`
(the same service, after boot retention). Each update keeps the previous root
as a fallback "birth"; the run keeps the newest two ready fallbacks, the running
root, any root a boot generation still names and any root that already has a
receipt, and offers the others, oldest root subvolume first and at most four
per run, to the reviewed root-retirement plan. Its protections (generation
catalog, pins, rebinds, recovery jobs and activations, backend rows, loader
entries, mounts in every namespace, the idle transition snapshot and the
complete kernel subvolume tree) decide. `prepare` writes a receipt; `delete`
then removes the history store and the root by exact subvolume ID, one durable
change per fully rechecked observation (prepared, executing, in-flight step,
next step, ..., deleted), so a crash is completed by the next run: an
in-flight target whose path, ID and UUID are all gone counts as deleted, an
identical one is deleted again, anything else stops for review; `finish` marks
the birth retired. Afterwards the read-only Snapper snapshot of the live root
that the birth was created from is removed by number and exact Btrfs identity
(only while the live root is still that birth's source and no unfinished
rebind or recovery job names it). Control retention later drops the completed
receipts and retired births.

A receipt refuses most other operations until it is complete or abandoned.
`root-retire abandon --id` ends an unstaged prepared or executing receipt
without deleting anything more (targets that remain stay in place); the
automatic run does this for an unstaged receipt from a previous boot that
never started deleting. Staged coordinator receipts (`root-retire stage`, the
offline path that asks for the LUKS passphrase in the recovery image) are
neither deleted online nor abandoned automatically: their boot entry is only
removed by the coordinator boot and `root-retire finish`. The offline path
keeps working for anyone who stages it.

`enzimos-policy backup ...` initializes an empty fixed repository or adopts an
authenticated existing one after explicit digest review. It requires a
preconfigured mounted independent Btrfs destination and Root-private credential;
prepared setup receipts prevent replay. It does not format drives, replace a pin
or enable scheduling on its own.

Internal block observations bind a held device descriptor to kernel disk sequence,
capacity and read-only state. The read-only sysfs topology guard follows partition
parents and mapped/RAID dependencies to whole-disk leaves. Backup admission rejects
source/control overlap even across different filesystem UUIDs, incomplete Btrfs
membership, unsupported virtual leaves and changing observations. These checks do
not freeze storage, authorize callers or establish offline key possession. Their
boot-local identities are not persistent destination pins.

Internal destination review can temporarily mount a retained Btrfs selection
read-only with log replay disabled. Kernel UUID/member count, complete membership,
source separation and mount protections must agree. Prepared receipts precede
mounting; identity-safe cleanup completes before a successful receipt. Unknown
outcomes require inspection. This read-only review is not a public mounting API
or filesystem health check.

The separate internal writable setup context requires that completed review and
one caller-owned operation lock. Fixed secure mount options, kernel filesystem
identity and source separation are checked before and after the body; completion
follows owned unmount and stub restoration. It supports a single lock across
credential storage and reviewed repository initialization/adoption.

## Development and qualification

Build with the sibling `enzimos-build` sandboxed builder, install signed candidates
only in disposable guests, and bind evidence to exact package bytes. Do not install
development policy on the host. Same-host reproducibility does not establish
cross-host, hardware, factory Secure Boot or release qualification.

Upstream dependency code and binaries retain their own licenses.
