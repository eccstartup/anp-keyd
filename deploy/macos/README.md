# macOS local UID boundary preview (U2)

This is a local-use implementation, not an accepted protected macOS release.
`macos-boundary-preview` always reports `protected_supported=false`, including
release builds. No paid Apple membership is needed to build and test this path.
Linux modes are rejected on macOS; no `macos-protected-v1` mode is accepted.

## Execution domains

The OS, root, installed daemon and human management account are trusted. Each
untrusted Agent must run under a distinct non-admin UID; all arbitrary code under
one UID is one principal. The provided installer configures one Agent account;
additional Agents require distinct accounts and explicit principal registration.
An Agent running in the human account has the human account's authority. Moving
only the signing client into another UID does not isolate an Agent that retains
access to the human account. No sudo, admin-group membership, stored human login
credentials, remote login to the management account, or inherited management
sessions may be handed to Agents. A UID boundary is not a VM or a general sandbox.

The service runs as `_anpkeyd`, with a disabled login shell. `_anpagent` has no
login password and is launched by a trusted operator. It can reach only the data
socket; its primary home `/var/empty` must not be used as a writable workspace.
Assign an Agent-owned working directory separately, without granting access to
the human's home. Do not install passwordless sudo or an Agent-controlled launchd
job with authority over the service or management account.

Root owns `/Library/ANPKeyd`, its executable/config and the launchd plist. The
service owns mode-0700 state and separate mode-0750 socket directories; sockets
are 0660. Socket groups allow transport access, while kernel UID authentication
and SQLite principal state decide authorization. Clients verify config ownership,
symlink-free paths, socket inode and daemon UID before sending secrets. macOS
extended ACL entries on trusted paths are rejected conservatively, even deny-only
entries. Do not remove system ACLs to get around a failure; choose/review a safe
installation location or resolve the policy explicitly. Local APFS is required.

The daemon disables core dumps and future debugger attachment using
`PT_DENY_ATTACH`. These are additional defenses, not claims of kernel/root
isolation. Unlike the Linux systemd unit, this launchd job does not claim a
filesystem/network syscall sandbox. Root/admin compromise, kernel escapes,
physical attacks, copied historical keys and same-UID arbitrary code are outside
this boundary. No Secure Enclave capability or hardware acceptance is introduced.

## Review and install

Build from the reviewed checkout, using the checked-in lockfile:

```sh
cargo build --locked --release --features mcp
shasum -a 256 target/release/anp-keyd
python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT
```

For the complete, explicitly approved local setup (account creation, installation,
launchd startup and limited read-only acceptance), the human may run:

```sh
sudo bash deploy/macos/setup-local.sh YOUR_HUMAN_ACCOUNT VERIFIED_SHA256
```

Enter the sudo password only in your own terminal. Run from a human-controlled
checkout after reviewing the scripts and exact binary digest. The script refuses
existing/partial installations; it is not an update or repair tool. The longer
commands below allow the same steps to be reviewed/run individually.

The account tool prints its complete command plan without modifying anything.
Review it before explicitly applying it as root:

```sh
sudo python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT --apply
```

This creates two hidden, password-disabled accounts and four groups, and adds
the human account to the management group. It refuses existing names, including
partially created installations; it never silently adopts or repairs accounts.
Interrupted provisioning needs administrator inspection. Log out/in for group
changes to take effect. Do not type a password into a chat or give it to an Agent.

Plan the installation first (replace the digest with the actual reviewed build):

```sh
python3 deploy/macos/install.py --binary target/release/anp-keyd \
  --sha256 VERIFIED_SHA256 --service-user _anpkeyd --agent-user _anpagent \
  --admin-user YOUR_HUMAN_ACCOUNT --sign-group _anpkeyd_sign --admin-group _anpkeyd_admin
# Repeat the same arguments with sudo and --apply only after reviewing the plan.
```

Installation requires a release build without seed-export or software hardware.
It copies exactly the SHA-256-checked bytes, initializes EMPTY state, and writes
the plist without starting it. Existing installations/state are never overwritten;
updates, migration and automatic recovery are not provided by this fresh installer.
It does not touch real identities or copy a daily-use vault. Failed installation
is retained for inspection, never automatically deleted/reinitialized.

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/org.anp-keyd.local.plist
/Library/ANPKeyd/bin/anp-keyd admin --config /Library/ANPKeyd/service.json status
sudo python3 deploy/macos/test-install.py
# Explicit stop; keys lock and old grants are invalidated on next startup:
sudo launchctl bootout system/org.anp-keyd.local
```

`RunAtLoad` starts the job after future boots once installed; crashes are not
silently retried (`KeepAlive=false`). SIGTERM/interrupt follow normal key-locking
shutdown. Startup refuses missing/corrupt state. Restart never restores grants.
Stopping/unloading is reversible; accounts, configuration, plist and state remain.
Retirement or updates require a separately reviewed offline procedure; do not
remove state to fix startup. New setup has no vaults; enrolling temporary keys
and approving roles/policies/grants use existing typed management operations.
Vault migration from Linux is not promised by this macOS installer.

## Native unlock window

From the trusted human account and installed root-owned binary:

```sh
/Library/ANPKeyd/bin/anp-keyd admin --config /Library/ANPKeyd/service.json unlock \
  --vault-id VAULT_UUID --did DID --kid KID --native-ui
```

The client authenticates the daemon before opening the native secure text field,
shows instance/service UID and exact vault/DID/key, then reconnects and re-verifies
identity before sending the password. Cancel is the default button; timeout,
close, empty input and unavailable UI fail closed, without terminal fallback.
No password passes through argv, environment, stdin, stdout or an AppleScript
helper. Application-owned secret copies are zeroized; CoreFoundation's internal
input storage cannot be guaranteed zeroized. Unlocking does not issue a grant.
The terminal management workflow remains authorized only for the separate human
UID. A PTY or a window's appearance does not confer administration. This initial
UI covers exact-key unlock; catalog/policy/grant/rotation remain typed admin CLI
operations. It is not a full graphical management application.

## Validation status and remaining acceptance

Automated local tests cover mode gates, extended ACL rejection, installer identity
policy, and existing persistence/protocol/signing regressions. Normal tests do
not create accounts, install launchd jobs, open password dialogs or use real keys.
`test-install.py` is a limited read-only live check: administrator service identity,
Agent PTY management rejection, unreadable state and inaccessible admin socket.
A successful run alone does not complete U2.

Before any supported macOS declaration, record a real multi-UID launchd run with
temporary identities, fake socket (including forged owner metadata), cross-principal
grant rejection, debugger/task-port denial, Agent access/escape attempts, UI
cancel/timeout/fake-daemon behavior, lock/revocation, service crash/reboot and a
real signed request. Native UI must also be visually checked in the human login
session. These host/interactive checks remain pending until the operator provides
and approves that environment. Software tests are not substitutes for them.

Apple references:
[launchd UserName/GroupName](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html),
[ACL entry semantics](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get_entry.3.html),
[code signing trust policies](https://developer.apple.com/library/archive/technotes/tn2206/).

Recorded 2026-10-16 before host installation: macOS default 494 tests, MCP 506
tests, six installer policy tests, strict Clippy and local release build passed.
Rust 1.90 Linux container regression passed 492 default tests, one explicit fixture
generator and 124 boundary checks. Live macOS installation/UI checks remain pending.
