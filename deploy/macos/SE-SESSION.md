# Secure Enclave foreground login helper (U3 preview)

This bridge lets a trusted human login process perform the hardware portion of
unlocking one approved hot key while the existing separate-UID daemon continues
to own its vault, passphrase KDF, in-memory signing key, policy and grants.
It implements the operator's accepted login-dependent scope. It is not an
accepted formal SE distribution. `protected_supported=false` remains unchanged.

## Trust and protocol

The administrator UID, daemon, root-owned code/configuration and OS are trusted.
Agents must stay in separate non-admin UIDs. The helper runs as the configured
administrator in the active local graphical login session. A second service
account or a system LaunchDaemon cannot substitute for that login context.
Unrestricted code in the human UID remains part of the trusted management
principal; a native dialog is not an independent authorization boundary.

The helper opens no listener. It connects to the existing management socket,
authenticates its inode and kernel service UID and validates the daemon instance.
The daemon checks the helper's kernel UID against `admin_uids` before reading a
frame, then obtains the audit-session ID from `LOCAL_PEERTOKEN`. It requires a
local, graphical, non-root audit session and the matching primary console UID.
Root/system, remote and inactive-console sessions are refused. A signed binary
or claimed UID/session in a message cannot replace these checks.

The native prompt shows the exact vault/DID/kid and global session-end effects.
It has the existing Cancel/default and 120-second timeout, with no terminal
fallback. After consent, one authenticated persistent connection carries:

1. `START_SE_SESSION` with exact vault/DID/kid. The daemon accepts only an active
   catalog-confirmed hot key with an SE envelope; root/recovery/v1/software keys
   are refused. It returns its own validated encrypted envelope snapshot and a
   random session ID. No supplied path or caller-selected ECDH input is accepted.
2. The helper validates the envelope and calls SE locally. It sends the 32-byte
   HS in a fixed binary frame, followed by the existing bounded binary password
   frame. Neither is JSON, argv, environment, stdout, audit or persistent state.
   The helper holds no DEK, seed or `device.secret`. The daemon never returns HS.
3. The daemon performs the password/device/HS KDF and authenticated decryption,
   checks the resulting public key, and rechecks the exact envelope, mutation
   epoch, vault generation and live login context before installing the key.
   A concurrent lock or management mutation cancels installation.
4. The helper erases its HS/password containers and sends strictly sequenced,
   session-bound heartbeats once per second. It never reconnects automatically.

Hardware still performs P-256 ECDH wrapping/unwrapping. Business Ed25519 signing
runs in daemon software. HS necessarily crosses the authenticated local stream;
the trusted administrator and daemon can observe their own process memory.
This is not hardware-internal Ed25519 signing or protection against root/admin.

## Session lifetime and loss

Only one exact-key SE session is admitted at a time. The initial lease lasts at
most 900 seconds, using both an absolute wall deadline and continuous monotonic
time that includes macOS sleep. Heartbeats cannot move either deadline. A missing
heartbeat for 5 seconds, clock rollback relative to the last heartbeat, EOF,
invalid heartbeat, observed console-session change, unavailable console/audit
information or an unhealthy observer ends the lease.

The daemon observes console-user changes with SystemConfiguration notifications;
an observed logout/switch invalidates the old lease even if the same UID logs in
again. It also checks the current primary console UID and original audit session
directly. Observer failure/staleness refuses signing. OS notification dispatch is
asynchronous; this is detection-driven locking, not an instantaneous logout
barrier or a proof that no bytes could be in flight at the transition.

Session validity is checked before data execution, before a new signature and
before delivery of new or cached results. The signing coordinator remains held
through bounded data-frame delivery, so acknowledged teardown/revocation cannot
overtake a queued signature frame. Previously delivered signatures cannot be
recalled. The sweeper checks idle sessions once per second; heartbeat reads have
a 5-second deadline. On observed loss the daemon conservatively:

- Locks **all** loaded keys and cancels in-flight unlock installation.
- Transactionally revokes **all active and exhausted grants**, suppressing even
  the cached last-use result. Request IDs, quota use and tombstones remain.
- Advances the management mutation epoch, invalidating all prepared approvals.
- Persists `SE_SESSION_ENDED` audit evidence before continuing management/data.

Audit or cleanup failure latches emergency stop. There is no automatic software
fallback, quota refund, reconnect, grant issuance or restoration. A fresh session
requires a fresh unlock; a grant revoked by the old session requires a new
explicit approval. Existing per-key idle autolock remains in force and heartbeats
do not refresh it.

A long sleep expires the heartbeat on wake; the original 900-second deadlines
also continue across sleep. Screen lock alone is not promised to revoke all
already loaded keys: OS keychain restrictions may deny new unsealing, while an
existing live lease can continue signing until a loss condition or original
deadline. Fast user switching ends the old lease on observation. Full multi-user,
logout/relogin, lock, sleep and reboot behavior still needs host acceptance.

## Build and controlled use

Both helper and daemon must contain the bridge:

```sh
cargo build --locked --release --features mcp,hardware-se
```

`se-release.py` turns that executable into the helper bundle once the operator
has a real Apple-issued identity and provisioning profile. `plan` is the default
and changes nothing:

```sh
python3 deploy/macos/se-release.py plan --team-id TEAMID --application-id TEAMID.org.example.keyd
python3 deploy/macos/se-release.py build --team-id TEAMID \
  --application-id TEAMID.org.example.keyd --identity 'Developer ID Application: ...' \
  --profile /path/to/helper.provisionprofile
python3 deploy/macos/se-release.py verify --bundle target/se-release/ANPKeyd.app \
  --team-id TEAMID --application-id TEAMID.org.example.keyd --require-notarized
sudo python3 deploy/macos/se-release.py install --bundle target/se-release/ANPKeyd.app \
  --team-id TEAMID --application-id TEAMID.org.example.keyd --upgrade
```

`build` signs with hardened runtime and a timestamp, embeds the exact
provisioning profile and verifies the resulting bundle before reporting success.
`install` requires root, refuses an existing destination without `--upgrade`,
checks the Team/application identity and designated-requirement continuity, and
replaces the root-owned bundle atomically. No step claims hardware or
distribution acceptance.

Do not add `seed-export` or `hardware-software`. Run the signed helper from an
app-like bundle containing its authorized provisioning profile; use a narrow,
exact application/keychain group identity. Review the signed bytes with
`se-preflight.py --execution-context user-session`. Exit 0 of that tool is only
a signature prerequisite check, not profile/hardware/distribution acceptance.
The bundle and every installed executable/config ancestor must be root-owned,
non-writable by the Agent/human, with the existing no-symlink/no-extra-ACL policy.
The daemon remains a system service and never accesses the login keychain itself.

The current daily installation is not automatically updated. The existing update
tool refuses an occupied backup path; do not delete that backup just to proceed.
Review/archive it and approve the exact new binary digest as part of a controlled
update. Do not migrate real keys during initial acceptance.

After signed packaging, temporary SE hot-key provisioning and catalog approval,
run the installed helper from the human's local login session, using the approved
bundle executable path:

```sh
/ROOT_OWNED_BUNDLE/Contents/MacOS/anp-keyd admin \
  --config /Library/ANPKeyd/service.json se-session \
  --vault-id TEMPORARY_VAULT_UUID --did TEMPORARY_DID --kid EXACT_TEMPORARY_HOT_KID
```

The command opens the native prompt and stays in the foreground after unlock.
Closing its terminal/process ends the session. Approve a narrowly scoped grant
through the existing management workflow in a separate terminal. There is no
LaunchAgent auto-start or unattended passphrase storage in this initial version.

The cross-process persistence probe is a separate test example, not the helper
binary and not a release command:

```sh
cargo build --locked --release --features mcp,hardware-se,se-acceptance \
  --example se-persistence
python3 deploy/macos/se-persistence.py \
  --binary target/release/examples/se-persistence \
  --sha256 VERIFIED_SHA256 --team-id TEAMID \
  --application-id TEAMID.org.example.keyd \
  --other-uid 501 \
  --unsigned-binary /path/to/an-unsigned-se-persistence \
  --unsigned-sha256 VERIFIED_UNSIGNED_SHA256
```

It creates a persistent SE key in process A, reopens it in a new process B,
proves another UID is denied by the keychain, deletes the key and proves the old
envelope no longer opens. The `--unsigned-binary` phase proves that a build
without the entitlement cannot create a persistent key; an unsigned build is
expected to fail with `errSecMissingEntitlement` (`-34018`). Passing this tool
does not prove logout/relogin, sleep, reboot, upgrade or distribution.

## Verification boundaries

Ordinary regressions cover HS/password/device binding, envelope tampering,
concurrent lock cancellation, ordered non-renewable leases, socket disconnect,
observed login generation changes, cached exhausted-grant suppression and atomic
audit failure. They do not prove real SE persistence or OS lifecycle handling.

Two explicit tests require a real local graphical console and are ignored by
normal/headless CI. Run only against temporary fixtures:

```sh
cargo test --locked --features mcp,hardware-se --lib \
  security::se_session::tests::local_console_observer_and_kernel_audit_session_are_available \
  -- --ignored --exact --nocapture
cargo test --locked --features mcp,hardware-se --lib \
  persistence::tests::local_console_se_bridge_signs_and_disconnect_revokes_without_hardware_mock_claims \
  -- --ignored --exact --nocapture
```

The second uses synthetic HS, not a persistent SE key. It exercises real kernel
session/console checks, the management stream, KDF, upstream-verified hot-key
signing and changed-target rejection, then actual disconnect/lock/revocation and
cached-result suppression. Passing it is bridge evidence, not hardware evidence.

Remaining formal acceptance requires the actual signed helper and temporary SE
keys: persistent create/open in independent processes; Agent/other-UID keychain
denial; forged daemon rejection before prompt/secret; UI cancel/timeout; helper
crash/hang; logout/relogin of the same UID; user switch; lock/sleep; wall rollback;
actual whole-machine reboot; upgrade with the same authorized identity/profile;
and missing-key/device-failure recovery. Record exact hashes, feature flags,
profile/team/application identity and failures separately for each environment.
Certificate/profile setup and interactive logout/reboot require the operator.

References: [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains),
[primary console information](https://developer.apple.com/documentation/systemconfiguration/scdynamicstorecopyconsoleuser(_:_:_:)).
