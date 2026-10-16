# Linux boundary preview (M1)

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

Config changes require service restart. A newly assigned OS account must receive
a fresh principal UUID and generation; the preview has no reusable grants. Mutable
principal lifecycle and durable management state will move to SQLite in M2.

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

## Verification recorded on 2026-10-16

Linux Docker (Rust 1.90): 431 default tests passed, the explicit disposable fixture
passed, and all 33 multi-UID boundary checks passed. The installer was tested with
umask 0077. macOS: 444 tests passed with `mcp,hardware-software`. Clippy completed
with the existing unused import warning in `tests/hardware.rs`. New Rust modules
pass rustfmt; the repository-wide formatting baseline still has older differences.
No real user identities or host accounts were modified. The systemd unit has not
been accepted on a booted systemd host, and no production protected-mode support
is claimed.
