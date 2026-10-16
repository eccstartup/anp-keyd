# Linux v2 signing service and release gate

Linux v2 provides limited grants and durable signing. Protected release support
remains false pending actual systemd-host acceptance. The legacy `serve` command
is a separate development service. See the M5 section below for current migration,
client and update workflows; earlier command examples require `--sha256` too.

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
migration is available through the offline tool below. Unlock prompts only after a service preflight, and
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
and grants/signing now execute through the v2 transaction coordinator.

M2 adds `admin catalog` and typed `admin prepare --file CHANGE.json` operations.
The supported catalog actions are `EnrollVault`, `ConfirmRole`, `PublishPolicy`
and `InstallDocument`, wrapped as `{"kind":"Catalog","change":{...}}`.
Prepare returns the exact effect/digest; use the existing `admin commit` with that
operation ID and digest. Only authenticated administrators can access this API.

An administrator must first stage an existing vault under a configured UUID while
the service is stopped, preserving its encrypted envelopes/device secret and
protected ownership. `EnrollVault` validates the complete inventory against signed
DID documents and records every key as `unclassified`. `ConfirmRole` binds an
explicit role to exact kid, envelope and document digests. It checks the public key
and relationships; an identity binding key cannot be marked hot/recovery/challenge.
Re-enrollment revokes grants, preserves key handles and resets roles for confirmation.
The automated old-vault copy/backup/cutover workflow remains M5.

For example, prepare vault enrollment with this public JSON file:

```json
{"kind":"Catalog","change":{"action":"EnrollVault","vault_id":"VAULT_UUID"}}
```

Then inspect `admin catalog` and prepare role confirmation:

```json
{"kind":"Catalog","change":{"action":"ConfirmRole","key_id":"KEY_UUID","role":"root"}}
```

`PublishPolicy` accepts a UUID, consecutive positive version and fixed-schema
policy content (schema 1). Content is canonicalized and immutable; unknown fields,
ambiguous origins/paths/queries and unsupported profiles are rejected. This stores
policy versions used by the current request/grant evaluator.

`InstallDocument` accepts a vault UUID and an already signed public DID document.
It verifies the proof/path binding and existing key roles, binds the previous and
new document digests, and journals the exact approved bytes in SQLite. It provides
no caller-supplied signing-input operation. The commit first enters maintenance and
revokes grants, then atomically installs/fsyncs the document and records completion.
Restart rolls a durable intent forward only if the file matches the approved old
or new digest; an unknown file stops startup without overwriting it. Catalog-only
changes and audit records are atomic; interrupted file completion remains in
maintenance until recovery succeeds. Broader identity creation/rotation/backup
adapters remain subsequent lifecycle work.

KDF runs in a separate non-queueing single slot. Lock/metadata commit invalidates
older unlocks by generation; key installation rechecks catalog/disk state under
the management gate. Old local CLI commands (including `--root` symlinks, relative
paths and standalone probe) reject managed state directories. They remain available
for development vaults. No Agent gains access to protected vault files.

Schema 1 upgrades transactionally to schema 2 after integrity, instance and audit
validation; failed migration rolls back. Existing roles reset to unclassified.
Unknown newer versions are refused. New management events use SQLite; existing
JSONL files are retained without rewriting. Runtime state is not silently imported
from old M1 preview configurations.
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
test import warning at that baseline. No physical power-loss test or systemd host
acceptance was claimed for that baseline.

## Historical M2 completion verification on 2026-10-16

Rust 1.88 and 1.90 Linux containers each passed 452 default tests, one explicit
disposable identity fixture and 60 multi-UID boundary/management checks. macOS
`mcp,hardware-software` passed 465 tests. Eighteen persistence tests include actual
old/new signed-document replacement with injected completion-audit failure, durable
intent before the first file write, repeated restart recovery, journal substitution
rejection, migration rollback, unknown roles and policy immutability. Strict
all-targets Clippy passed; the prior hardware import warning's feature guard is
corrected. These are deterministic crash-boundary tests, not physical power-loss
experiments. At that checkpoint M3/M4 was still pending; the current executor is implemented, while systemd-host acceptance remains open.

## Historical M3 authorization preview verification on 2026-10-16

Rust 1.88 and 1.90 disposable Linux containers each passed 467 default tests and
one explicit temporary-identity fixture. Their independent-UID harnesses passed
85 and 89 checks respectively; the 1.90 run also builds MCP and verifies real
stdio initialization, v2 tool schemas, caller-scoped keys and no legacy fallback.
Set `ANP_KEYD_TEST_MCP=1` to include those MCP checks in the container harness.
macOS `mcp,hardware-software` passed 481 tests; strict all-targets Clippy passed.

At the M3 checkpoint, the implementation added exact-hot-key grants, revocation, immutable policy evaluation, dual-clock
deadlines, schema v3 and authenticated v2 CLI/MCP clients. Valid `SIGN_HTTP`
requests then returned `SIGNING_UNAVAILABLE`; M4 subsequently supplied transactional quota
reservation, idempotency, signing and durable result delivery.
At that historical checkpoint `protected_supported` remained false. The later M5 systemd-host acceptance below supersedes that release status.

## M5 current implementation

v2 now signs through durable reservation/result transactions and exact hot-key
grants. Restart revokes all old grants and locks keys. Actual Ubuntu 24.04.4/aarch64
systemd-host acceptance and a complete VM shutdown/boot have passed.

`build-info.protected_supported` describes Linux release build capability (no
software test double or seed export). Daemon replies and `probe --security` require
that capability AND root configuration `mode: "linux-protected-v1"`. Fresh release
installs select that explicit mode; development installs remain preview. Offline
updates preserve the existing mode: upgrading an old preview deployment requires
an explicit administrator config edit while stopped. The flag is a support
declaration, not continuous attestation of arbitrary host configuration.

Release binaries cannot enable `hardware-software`; the compiler rejects that
combination. `build-info` reports build mode and sensitive feature flags. Install
and update require a SHA-256 supplied from an independently verified build:

```sh
cargo build --locked --release
sha256sum target/release/anp-keyd
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --sha256 VERIFIED_SHA256 --admin-user operator --agent-user agent-a --agent-user agent-b
# Stop the service before update. The tool also requires the exclusive state lock.
sudo python3 deploy/linux/install.py --update --binary target/release/anp-keyd --sha256 VERIFIED_SHA256
```

`--allow-development-build` is an explicit testing opt-in; software test doubles
and seed-export builds are rejected even with this flag. Updates never overwrite
configuration/state or restart implicitly. Keep a compatible previous binary and
verified state backup; a schema downgrade must remain offline rather than enable v1.

### Offline migration and restore

Stop all legacy daemons and lifecycle writers, including versions that predate the
maintenance lock. Move the complete source into a root-owned directory with a
root-controlled parent chain, take ownership of all files, and restrict secrets
to 0600/directories to 0700. Do not leave another Agent-readable live source copy.
Then run the read-only inventory and the explicit cutover:

```sh
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault --apply --recovery-dir /root/keyd-recovery
```

The tool preserves encrypted envelopes, device.secret, public documents and audit
history, checks hashes, and opens every backup key through the operator's tty.
It copies only necessary recovery material, never runtime sockets/PIDs or plaintext
keys. Root remains responsible for stopping older processes and open FDs before
freezing the source. New legacy writers hold shared maintenance leases; cutover
requires the exclusive lease. Source gets a managed marker and remains root-owned.

`migration.json` records the exact inventory/vault/instance and durable cutover
phase. Re-run the same arguments after interruption. Partial backup/staging copies resume only from matching completed files; uncommitted
private temporary files are discarded. Unknown completed bytes are preserved and
refused for administrator inspection. Never discard the source or
recovery copy. Completed copies must match the original manifest; unknown bytes
stop the tool. Crashes between catalog/config changes cannot create grants:
only root config introduces the UUID, and startup registers it with audit in one
SQLite recovery transaction. Restart always invalidates grants.

After restart: prepare/commit Catalog.EnrollVault, confirm roles explicitly,
publish policy, unlock exact hot key, issue fresh grant, verify a real service,
then switch clients to v2. Every imported key starts locked and unclassified.
Restoring a recovery copy is the same migration process with its `vault/` as the
source and a fresh recovery directory/UUID. Do not restore old grants or overwrite
an active vault. Coordinate current remotely published documents before issuing
grants: local restore cannot roll back a remote publication.

The complete software snapshot plus its password can unlock keys; the recovery
copy is sensitive. Hardware envelopes require their actual backend/device and
fail closed when unavailable. Portable per-key archives remain readable through
the existing offline import flow; import into an administrator-owned staging
vault and then migrate. Historical plaintext exports/copies are not revoked.

### Client and service validation

`adapters/keyd-v2.mjs` provides a Node client and an existing anp-sdk connector.
The Rust CLI performs service authentication, callers persist request IDs, and
there is no automatic retry/downgrade. Production fetch uses the canonical signed
URL, original body, daemon headers and manual redirects.

Registration: prepare a `RegistrationChallenge` with exact root key, HTTPS origin
and the supported 32-character lowercase hex challenge. Confirm its digest, then
`admin complete-secret-operation --operation-id ID --digest DIGEST`; the root is
transient and never becomes a data key. Runtime uses hot grants. `RotateHotKey`
selects an already provisioned next hot key, removes the old method, signs the
new document, revokes grants and journals file recovery. Independently publish
and verify the returned document before making fresh grants. New hot material
can be provisioned in an offline administrator staging vault; online generation
is outside this first migration/rotation tool.

The disposable multi-UID harness exercises the actual migrator. Optionally set
`ANP_KEYD_ANP_TARGET` to a throwaway awiki-open-server physical origin configured
with `public_base_url=https://example.com`, `did_domain=example.com` and strict
signed-document verification. `anp-service-acceptance.py` verifies registration,
hot authentication, replay/body/expiry rejection and published hot rotation.
Only this test can send a logical HTTPS target over a separate physical local
HTTP route; production adapter does not offer that override.

The host harness is deliberately destructive and only accepts an isolated VM
whose PID 1 is systemd and whose root-owned mode-0600
`/var/lib/keyd-systemd-disposable` contains
`anp-keyd-disposable-systemd-v1`. With the temporary fixture generated by
`security_boundary::disposable_linux_fixture` copied under `/tmp`, run as root:

```sh
python3 deploy/linux/test-boundary.py --systemd --binary /path/to/release/anp-keyd
python3 deploy/linux/systemd-boot-check.py prepare
# Completely shut down and boot this disposable VM, then:
python3 deploy/linux/systemd-boot-check.py verify
```

The harness checks actual sandbox effects using a temporary ExecStartPost hook,
then removes that hook and restores the exact pre-fault test database before
checking boot with the original unit. It must never run on a production host.
