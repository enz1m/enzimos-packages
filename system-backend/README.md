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
