# Linux v2 deployment: current software release

Start with the [local-use guide](../LOCAL-USE.md) for the trust model and daily
administrator/Agent workflow. This page describes the Linux service. Ordinary
use does not require Apple membership, Xcode, SE or TPM.

The software boundary has been accepted on an Ubuntu 24.04.4/aarch64 systemd VM,
including complete VM shutdown/boot. A release build without seed export or
software hardware, explicitly deployed as `linux-protected-v1`, can report
`protected_supported=true`. This is a support declaration, not proof that every
new machine is configured safely. Physical TPM acceptance is still outstanding.

## New installation

Use a human-controlled checkout and a separate non-admin Agent account for each
security principal. The human must review code/build provenance and the digest;
computing a hash alone does not establish that the source is trustworthy.

```sh
cargo build --locked --release --features mcp
sha256sum target/release/anp-keyd
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --sha256 VERIFIED_SHA256 --admin-user operator --agent-user agent-a --agent-user agent-b
sudo systemctl daemon-reload
sudo systemctl enable --now anp-keyd
/usr/local/libexec/anp-keyd admin --config /etc/anp-keyd/service.json status
/usr/local/libexec/anp-keyd probe --security --config /etc/anp-keyd/service.json
```

Replace the account names and digest. `--features mcp` is optional for a CLI-only
installation. For a physical TPM root, build with `--features hardware-tpm` and
add `--tpm-device` to the installer, then run the separate acceptance in
[TPM.md](TPM.md); the installer grants only `/dev/tpmrm0` and pins the transport.
The fresh installer creates its own non-login service account,
socket groups, root-owned executable/configuration, SQLite state and systemd
unit. It refuses partial/existing installations rather than silently repairing
or replacing them. It does not migrate user keys. Use the separate offline
migration/update procedure below for existing installations. Establish fresh
sessions after group changes.

Agents must have no sudo/admin rights, Docker/host-control sockets, administrator
credentials, or access to administrator processes. The entire Agent must run under
its assigned UID, not just its signing subprocess. `cargo install` plus legacy
`serve` is a development workflow and does not establish this boundary.

## Acceptance on your own installation

First use a temporary identity and narrow grant, independently verify a real
signature, check that another Agent cannot use the grant/result or administer the
service, revoke the grant, and confirm that restart locks keys and invalidates old
authority. Run destructive fault and systemd sandbox tests only in an explicitly
marked disposable VM/container, never against daily state. The container harness
creates disposable accounts and is not a general host installation test:

```sh
docker run --rm -v "$PWD:/src:ro" -w /src rust:1.90-bookworm \
  bash deploy/linux/test-container.sh
```

This harness requires dependencies/network or a separately mounted Cargo cache.
It does not by itself accept the systemd sandbox, physical power loss or TPM.
Commands for marked disposable systemd VMs are below. Keep actual host acceptance
separate from unit tests, container results and build capability flags. Physical
TPM grants and acceptance are covered separately in [TPM.md](TPM.md); an
`swtpm` result there is emulator evidence, not physical acceptance.

## Management and current implementation


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
