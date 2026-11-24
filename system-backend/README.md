# Authenticated system backend

The `enzimos-system-backend` binary provides `org.enzimos.System1` on the system
bus. This directory supplies activation, polkit policy and an Arch package recipe.
The activation package and unit are named `enzimos-system-backend`.
Install it alongside the matching `enzimos-rust-packages` runtime. Package
replacement metadata lets pacman migrate installations of the previous backend
package. Reboot after the upgrade so D-Bus starts the backend in the new unit's
cgroup.
Rust sources are in [crates/backend](../crates/backend).

## Interface and ownership

`GetCapabilities` reports supported schemas, operations and read-only queries.
`Query` accepts bounded strict JSON; `Operation` provides durable
plan/submit/status/cancel workflows. Legacy `Execute` and `Job` methods retain
narrow compatibility contracts. Clients must discover capabilities rather than
assume every internal provider is publicly exposed.

The bus transport derives UID and PID from the unique system-bus sender. Polkit
and logind checks bind privileged work to an authorized local session. Caller
fields cannot substitute for this identity. Plans bind selected resources and
owner identity; completed work deduplicates, while uncertain outcomes block replay.
Cancellation cannot roll back a committed filesystem transaction. Public errors
exclude credentials and private command output.

Protected backup input uses retained sealed descriptors and a silent isolated
validator. It does not grant setup authority, enroll a repository, or expose a
public setup endpoint by itself. Setup still requires fresh session approval,
resource revalidation and durable completion acknowledgements.

## Backup runs and status

`Operation backup-create`, the daily schedule (`enzimos-backup.timer`, which
runs `--backup-automatic`) and `--backup-create` write to the primary
destination that `Query backups` reports as `primary`:

- `drive`: the configured backup drive. When a NAS share is also set up and
  its repository is ready, every successful backup then copies the new
  snapshot to the share and cleans the share up by the same retention policy.
  A failed copy never fails the backup.
- `share`: no backup drive is set up and the NAS share is ready
  (configuration, share and repository passwords, pinned repository). The
  backup worker captures system and home (not a drive's additional sources)
  straight into the share repository: its Restic child mounts the share with
  kernel CIFS (signed SMB 3, soft mount) in a private namespace, attaches the
  read-only sources beside it, leaves the network namespace and runs under
  the `enzimos-restic-native-remote-backup` AppArmor profile. The repository
  identity must match the share pin before and after. Retention then applies
  to the share repository. The schedule opt-in binds the share configuration
  and pin instead of a drive.
- `null`: neither is ready; planning refuses with
  `backup-destination-not-configured`.

A share that does not answer on the SMB port fails before anything is
captured, and a transfer that fails while the share stopped answering, with
`remote-share-unreachable`; other share refusals keep their `remote-share-*`
code. `GetCapabilities` lists both destinations under `backup_create`.

`Query backups` reports these run fields:

- `running`: `null` when idle, otherwise `{"since": <unix seconds>, "phase":
  "preparing"|"capturing"|"transferring"|"finishing"|"copying", "target":
  "drive"|"share"}`. A run that ended, died or belongs to an earlier boot reads
  as `null`.
- `run`: how the latest backup run ended (`ok`, `waiting-for-drive` or
  `failed` with `code`), for System1 jobs and scheduled runs alike.
- `remote_copy`: `null` before the first automatic copy, otherwise
  `{"state": "ok"|"failed", "at": <unix seconds>, "code": <error or null>}`.

`InspectBackgroundBroker` observes the current local user's fixed installed
broker without accepting a client-selected PID, unit or path. It starts no
application and grants no stop authority.

## Development and deployment

Build and test from the repository root. Private-bus tests exercise sender,
revocation and ownership boundaries. Installed system-bus activation, polkit,
storage and recovery behavior must be tested in disposable guests.

Build the activation package with `build_system_backend.py` from the image
builder. Pass the native-policy build report with `--native-policy` and the
Rust runtime summary with `--rust-runtime`. The builder checks the artifacts
and writes their exact versions into the recipe. See [LICENSE](../LICENSE).
