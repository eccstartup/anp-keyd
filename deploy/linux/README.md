# Linux boundary preview (M1 + M2 persistence)

This is a boundary implementation for integration testing. `protected_supported`
and `signing_available` are false. No grants or signing are exposed on its data
socket. The legacy `serve` command remains a separate development service.

Build on Linux, then install a **new** instance as root:

```sh
cargo build --locked --release
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --admin-user operator --agent-user agent-a --agent-user agent-b
sudo systemctl daemon-reload
sudo systemctl enable --now anp-keyd
anp-keyd admin status
anp-keyd probe --security
```

The installer refuses existing state, accounts, groups or deployment files. It
does not migrate keys. It creates a non-login service account, separate socket
groups/directories, root-owned config/binary and a systemd sandbox. Administrators
and Agents need fresh sessions after their groups change. Agents must have distinct
UIDs, no sudo, Docker/host-control socket or access to administrator processes.
The runtime does not infer this isolation from executable names or TTYs.

`admin status`, `admin lock-all` and `admin unlock --vault-id UUID --did DID --kid KID`
use the independent admin endpoint. Unlock is only usable for vaults explicitly
staged by an administrator and listed in the root-owned bootstrap config; managed
migration is pending M2/M5. Unlock prompts only after a service preflight, and
re-authenticates the next connection before sending the password. There is no
`--socket`, password argument or password environment override on this path.

`probe --security` prints observed ownership, modes, registry identities and the
kernel-authenticated service identity. It returns nonzero because full protected
release support remains unavailable. macOS refuses this mode explicitly.

Deployment configuration changes require restart. The installer explicitly initializes
`state.sqlite` once as the service UID; startup refuses a missing, corrupt, linked,
foreign-instance or newer-schema database. Bootstrap principals are imported only
at initialization. Editing bootstrap flags cannot restore disabled identities.

List live/history principal metadata and prepare an exact management operation:

```sh
anp-keyd admin list-principals
anp-keyd admin prepare-disable-principal --principal-id UUID
anp-keyd admin commit --operation-id UUID --digest SHA256
anp-keyd admin prepare-register-principal --uid UID
```

Inspect the returned effect and digest before committing. Commit accepts only the
stored operation, bound to the same admin UID, boot epoch, mutation epoch, wall
expiry and suspend-aware monotonic deadline. It is single use. Disable applies to
new connections immediately and revokes existing active grants in the same SQLite
transaction. Reassigning a disabled OS UID creates a new principal UUID/generation.

SQLite uses rollback journal DELETE, synchronous EXTRA, foreign keys and strict
schema checks. Audit/state changes commit together. Restart increments boot epoch,
revokes active grants, marks reserved requests outcome_unknown, invalidates pending
approvals and leaves all keys locked. Audit write failure latches emergency stop;
a restart is required after repair. These tables/recovery rules are implemented,
but issuing grants/signing requests remains unavailable until M3/M4.

M2 remains partial: key-role enrollment, concurrent KDF generation cancellation,
managed migration and cross-file lifecycle recovery are not yet implemented. New
management events use SQLite; existing JSONL files are retained without rewriting.
Runtime state is not silently imported from old M1 preview configurations.
For a NEW empty deployment only, explicit initialization is also available as
`anp-keyd init-protected-state` under the configured service UID. Never use deletion
and reinitialization as a migration or repair procedure.

The dependency is pinned to rusqlite 0.39.0 without default features, using bundled
SQLite (libsqlite3-sys 0.37.0, SQLite 3.51.3 in this lockfile). See the
[upstream source](https://github.com/rusqlite/rusqlite). This is not a full dependency
vulnerability audit.

To remove the service/binary, use `sudo python3 deploy/linux/install.py --uninstall`.
State, configuration and accounts are retained intentionally. Remove those only
through a separately reviewed backup/retirement procedure.

For isolated acceptance testing (never run the script on a daily-use host):

```sh
docker run --rm -v "$PWD:/src:ro" -w /src rust:1.90-bookworm \
  bash deploy/linux/test-container.sh
```

The harness requires a root Linux container and creates only disposable accounts
and files. It builds into `/tmp`, never into the read-only checkout. Tests include
cross-UID admin rejection through a PTY, v1/password rejection on the data socket,
service impersonation, unsafe path rejection, and lock/shutdown behavior. A running
container test does not verify the systemd sandbox; systemd host acceptance remains
an independent release gate.

## M1 baseline verification recorded on 2026-10-16

Linux Docker (Rust 1.90): 431 default tests passed, the explicit disposable fixture
passed, and all 33 multi-UID boundary checks passed. The installer was tested with
umask 0077. macOS: 444 tests passed with `mcp,hardware-software`. Clippy completed
with the existing unused import warning in `tests/hardware.rs`. New Rust modules
pass rustfmt; the repository-wide formatting baseline still has older differences.
No real user identities or host accounts were modified. The systemd unit has not
been accepted on a booted systemd host, and no production protected-mode support
is claimed.

## M2 persistence verification recorded on 2026-10-16

Rust 1.88 and 1.90 Linux Docker: each passed 438 default tests, one explicitly
requested disposable identity fixture, and all 49 boundary/persistence checks.
macOS (`mcp,hardware-software`): 451 tests passed. Seven persistence tests cover
restart invalidation, preserved quota consumption, unknown outcomes, audit failure
rollback, actor/digest/epoch binding, UID generation replacement, and deadline or
payload substitution rejection. The container also injects audit insertion failure
to verify emergency stop, and refuses missing/newer/corrupt/linked databases.

rusqlite 0.39.0 is pinned to preserve the tested Rust 1.88 baseline; future dependency
updates must pass both toolchain jobs. Clippy completed with the existing hardware
test import warning. No physical power-loss test, systemd host acceptance, or
cross-file lifecycle recovery acceptance is claimed.
