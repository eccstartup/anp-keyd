//! Boundary preview: data cannot sign until the grant executor is available.
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UnixListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use super::protocol::{AdminRequest, DataRequest, Envelope, Reply, VERSION};
use super::{config::ServiceConfig, paths, protocol, DeadlineStream};
use crate::daemon::autolock::Autolock;
use crate::daemon::peer::{peer_identity, self_uid, PeerPolicy};
use crate::daemon::state::{DaemonState, Roots, SigningGates};
use crate::error::{KeydError, Result};
use crate::keystore::layout::KeydLayout;
use crate::persistence::clock::{Clock, SystemClock};
use crate::persistence::{Change, Database};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Boundary {
    config: ServiceConfig,
    vaults: BTreeMap<String, DaemonState>,
    // State changes serialize; KDF has a separate, non-queueing single slot.
    // Vault generation checks cancel unlocks that overlap LOCK_ALL.
    admin_gate: Mutex<()>,
    kdf_gate: Mutex<()>,
    database: Mutex<Database>,
    stopped: AtomicBool,
}

impl Boundary {
    pub fn new(config: ServiceConfig, database: Database) -> Result<Self> {
        config.validate()?;
        let vaults = config
            .vault_ids
            .iter()
            .map(|id| {
                let state = DaemonState::new(
                    Roots::Single(KeydLayout::at(
                        config.vault(id).expect("validated vault ID"),
                    )),
                    PeerPolicy::default(),
                    Autolock::idle(Duration::from_secs(900)),
                    SigningGates::new(false, false),
                );
                (id.clone(), state)
            })
            .collect();
        Ok(Self {
            config,
            vaults,
            admin_gate: Mutex::new(()),
            kdf_gate: Mutex::new(()),
            database: Mutex::new(database),
            stopped: AtomicBool::new(false),
        })
    }

    fn capabilities(&self, principal_id: Option<String>) -> Reply {
        let mut reply = Reply::code("OK");
        reply.instance_id = Some(self.config.instance_id.clone());
        reply.principal_id = principal_id;
        match self.database.lock() {
            Ok(db) => reply.boot_epoch = Some(db.boot_epoch),
            Err(_) => {
                self.emergency();
                return Reply::code("AUDIT_UNAVAILABLE");
            }
        }
        reply
    }

    fn lock_all(&self) {
        for state in self.vaults.values() {
            state.lock_everything();
        }
    }

    fn connection(&self, stream: UnixStream, admin: bool) -> Result<()> {
        let peer = peer_identity(&stream)?;
        let mut io = DeadlineStream::new(stream, Duration::from_secs(5));
        // Authorize before reading any payload, even on the management listener.
        let principal = if admin {
            if !self.config.admin_uids.contains(&peer.uid) {
                protocol::write(&mut io, &Reply::code("ADMIN_REQUIRED"))?;
                return Ok(());
            }
            None
        } else {
            if self.stopped.load(Ordering::SeqCst) {
                protocol::write(&mut io, &Reply::code("AUDIT_UNAVAILABLE"))?;
                return Ok(());
            }
            let principal = match self.database.lock() {
                Ok(db) => db.principal(peer.uid),
                Err(_) => Err(KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into())),
            };
            match principal {
                Ok(Some(principal)) => Some(principal.principal_id),
                Ok(None) => {
                    protocol::write(&mut io, &Reply::code("PRINCIPAL_DISABLED"))?;
                    return Ok(());
                }
                Err(_) => {
                    self.emergency();
                    protocol::write(&mut io, &Reply::code("AUDIT_UNAVAILABLE"))?;
                    return Ok(());
                }
            }
        };
        let mut reply = if admin {
            match protocol::read::<_, Envelope<AdminRequest>>(&mut io) {
                Ok(request) if request.version != VERSION => {
                    Reply::code("PROTOCOL_VERSION_UNSUPPORTED")
                }
                Ok(request) => {
                    let secret = if matches!(request.request, AdminRequest::Unlock { .. }) {
                        match protocol::read_secret(&mut io) {
                            Ok(secret) => Some(secret),
                            Err(_) => {
                                return protocol::write(&mut io, &Reply::code("PROTOCOL_INVALID"))
                            }
                        }
                    } else {
                        None
                    };
                    self.admin(peer.uid, request.request, secret)
                }
                Err(_) => Reply::code("PROTOCOL_INVALID"),
            }
        } else {
            match protocol::read::<_, Envelope<DataRequest>>(&mut io) {
                Ok(request) if request.version != VERSION => {
                    Reply::code("PROTOCOL_VERSION_UNSUPPORTED")
                }
                Ok(_) => self.capabilities(principal),
                Err(_) => Reply::code("PROTOCOL_INVALID"),
            }
        };
        if reply.code == "OK" {
            reply.instance_id = Some(self.config.instance_id.clone());
        }
        // New deadline for delivery; no secret payload is reflected in errors.
        io.reset(Duration::from_secs(5));
        protocol::write(&mut io, &reply)
        // Exactly one request; dropping the stream rejects inherited old sessions.
    }

    fn emergency(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.lock_all();
    }
    fn record(&self, event: serde_json::Value) -> bool {
        let result = self
            .database
            .lock()
            .map_err(|_| ())
            .and_then(|mut db| db.record(event).map_err(|_| ()));
        if result.is_err() {
            self.emergency();
            false
        } else {
            true
        }
    }

    fn admin(
        &self,
        actor: u32,
        request: AdminRequest,
        secret: Option<zeroize::Zeroizing<String>>,
    ) -> Reply {
        if self.stopped.load(Ordering::SeqCst) {
            self.lock_all();
            return Reply::code("AUDIT_UNAVAILABLE");
        }
        if matches!(request, AdminRequest::Capabilities {}) {
            return self.capabilities(None);
        }
        // Never queue a second KDF on the remaining admin connection slot.
        // This leaves capacity for a concurrent LOCK_ALL.
        let _guard = if matches!(request, AdminRequest::Unlock { .. }) {
            match self.kdf_gate.try_lock() {
                Ok(guard) => guard,
                Err(_) => return Reply::code("RESOURCE_BUSY"),
            }
        } else {
            match self.admin_gate.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    self.emergency();
                    return Reply::code("RESOURCE_BUSY");
                }
            }
        };
        match request {
            AdminRequest::Capabilities {} => unreachable!(),
            AdminRequest::ListPrincipals {} => {
                let result = self
                    .database
                    .lock()
                    .map_err(|_| ())
                    .and_then(|db| db.principals().map_err(|_| ()));
                match result {
                    Ok(principals) => {
                        let mut reply = Reply::code("OK");
                        reply.principals = Some(principals);
                        reply
                    }
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::Prepare { change } => {
                if let Change::RegisterPrincipal { uid } = &change {
                    if *uid == self.config.service_uid
                        || self.config.admin_uids.contains(uid)
                        || *uid == 0
                    {
                        return Reply::code("ADMIN_OPERATION_INVALID");
                    }
                }
                let Ok(now) = SystemClock.now() else {
                    self.emergency();
                    return Reply::code("AUDIT_UNAVAILABLE");
                };
                let result = self
                    .database
                    .lock()
                    .map_err(|_| KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()))
                    .and_then(|mut db| db.prepare(actor, change, now));
                match result {
                    Ok(prepared) => {
                        let mut reply = Reply::code("OK");
                        reply.prepared = Some(prepared);
                        reply
                    }
                    Err(KeydError::Misuse(_)) => Reply::code("ADMIN_OPERATION_INVALID"),
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::Commit {
                operation_id,
                digest,
            } => {
                let Ok(now) = SystemClock.now() else {
                    self.emergency();
                    return Reply::code("AUDIT_UNAVAILABLE");
                };
                let result = self
                    .database
                    .lock()
                    .map_err(|_| KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()))
                    .and_then(|mut db| db.commit(actor, &operation_id, &digest, now));
                match result {
                    Ok(()) => Reply::code("OK"),
                    Err(KeydError::Misuse(_)) => Reply::code("ADMIN_OPERATION_INVALID"),
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::LockAll {} => {
                let mut dropped = 0;
                for state in self.vaults.values() {
                    match state.lock(self.config.service_uid, None, None) {
                        Ok(count) => dropped += count,
                        Err(_) => {
                            self.emergency();
                            return Reply::code("RESOURCE_BUSY");
                        }
                    }
                }
                if !self.record(json!({"event":"LOCKED","actor":actor,"dropped":dropped})) {
                    return Reply::code("AUDIT_UNAVAILABLE");
                }
                Reply::code("OK")
            }
            AdminRequest::Unlock { vault_id, did, kid } => {
                let Some(passphrase) = secret else {
                    return Reply::code("PROTOCOL_INVALID");
                };
                let Some(state) = self.vaults.get(&vault_id) else {
                    return Reply::code("KEY_NOT_FOUND");
                };
                // No disk path or default binding key may be selected by callers.
                let prefix = format!("{did}#");
                let Some(fragment) = kid
                    .strip_prefix(&prefix)
                    .filter(|value| !value.is_empty() && !value.contains('#'))
                else {
                    return Reply::code("KEY_NOT_FOUND");
                };
                let outcome = state.unlock_guarded(
                    self.config.service_uid,
                    &did,
                    Some(fragment),
                    passphrase,
                    || {
                        if self.stopped.load(Ordering::SeqCst) {
                            Err(KeydError::Locked)
                        } else {
                            Ok(())
                        }
                    },
                );
                if !self.record(json!({"event":if outcome.is_ok() {"UNLOCKED"} else {"UNLOCK_REFUSED"},"actor":actor,"vault_id":vault_id,"kid":kid})) {
                    return Reply::code("AUDIT_UNAVAILABLE");
                }
                match outcome {
                    Ok(()) => Reply::code("OK"),
                    Err(_) => Reply::code("UNLOCK_REFUSED"),
                }
            }
        }
    }
}

/// Only unlink the socket inode created by this process.
struct SocketGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.dev() == self.dev && meta.ino() == self.ino {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

fn bind(path: &Path, uid: u32, gid: u32) -> Result<(StdListener, SocketGuard)> {
    paths::socket_parent(path, uid, gid)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let old = paths::socket(path, uid, gid)?;
            match UnixStream::connect(path) {
                Ok(_) => {
                    return Err(KeydError::Misuse(
                        "protected socket is already listening".into(),
                    ))
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(e) => return Err(e.into()),
            }
            let current = paths::socket(path, uid, gid)?;
            if old.dev() != current.dev() || old.ino() != current.ino() {
                return Err(KeydError::Permission(
                    "socket inode changed during cleanup".into(),
                ));
            }
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = StdListener::bind(path)?;
    let meta = fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.to_path_buf(),
        dev: meta.dev(),
        ino: meta.ino(),
    };
    nix::unistd::chown(path, None, Some(nix::unistd::Gid::from_raw(gid)))
        .map_err(|e| KeydError::Permission(format!("cannot set protected socket group: {e}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    paths::socket(path, uid, gid)?;
    listener.set_nonblocking(true)?;
    Ok((listener, guard))
}

async fn listen(
    boundary: Arc<Boundary>,
    listener: StdListener,
    admin: bool,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let listener = UnixListener::from_std(listener)?;
    let slots = Arc::new(Semaphore::new(if admin { 2 } else { 16 }));
    let mut tasks = JoinSet::new();
    let outcome = loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break Ok(()); }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(KeydError::Io(error)),
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                let stream = match stream.into_std() {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                if stream.set_nonblocking(false).is_err() { continue; }
                let boundary = boundary.clone();
                tasks.spawn_blocking(move || {
                    let _permit = permit;
                    if let Err(error) = boundary.connection(stream, admin) {
                        tracing::debug!("protected connection closed: {}", error.wire_message());
                    }
                });
            }
        }
    };
    // Drain on both shutdown and listener failure, before clearing keys.
    while tasks.join_next().await.is_some() {}
    outcome
}

#[cfg(target_os = "linux")]
fn harden_process() -> Result<()> {
    let limit = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Both libc calls receive valid pointers/constants; no borrowed memory escapes.
    let result = unsafe {
        nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &limit) == 0
            && nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
            && nix::libc::prctl(nix::libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    };
    if !result {
        return Err(KeydError::Misuse("cannot disable process dumps".into()));
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn harden_process() -> Result<()> {
    super::require_linux()
}

pub async fn serve(config: ServiceConfig, mut stop: watch::Receiver<bool>) -> Result<()> {
    super::require_linux()?;
    config.validate()?;
    if self_uid() != config.service_uid {
        return Err(KeydError::Permission(
            "daemon must run as configured service UID".into(),
        ));
    }
    if std::env::vars_os().any(|(key, _)| {
        key.to_string_lossy().starts_with("LD_") || key.to_string_lossy().starts_with("DYLD_")
    }) {
        return Err(KeydError::Misuse(
            "dynamic loader overrides forbidden".into(),
        ));
    }
    paths::validate_chain(&std::env::current_exe()?, &[0], false)?;
    harden_process()?;
    let _lock = paths::instance_lock(&config.state_dir, config.service_uid)?;
    for id in &config.vault_ids {
        paths::state_directory(&config.vault(id)?, config.service_uid)?;
    }
    let database = Database::recover(&config, SystemClock.now()?)?;
    let (sign, _sign_guard) = bind(&config.sign_socket, config.service_uid, config.agent_gid)?;
    let (admin, _admin_guard) = bind(&config.admin_socket, config.service_uid, config.admin_gid)?;
    let boundary = Arc::new(Boundary::new(config, database)?);
    tracing::info!("Linux boundary preview listening; signing and protected support unavailable");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let sweeper = {
        let boundary = boundary.clone();
        let mut sweep_stop = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    changed = sweep_stop.changed() => { if changed.is_err() || *sweep_stop.borrow() { break; } }
                    _ = timer.tick() => { for vault in boundary.vaults.values() { vault.sweep_all(Instant::now()); } }
                }
            }
        })
    };
    let sign_task = listen(boundary.clone(), sign, false, shutdown_rx.clone());
    let admin_task = listen(boundary.clone(), admin, true, shutdown_rx);
    tokio::pin!(sign_task, admin_task);
    let outcome = tokio::select! {
        result = &mut sign_task => {
            let _ = shutdown.send(true);
            let other = admin_task.await;
            result.and(other)
        }
        result = &mut admin_task => {
            let _ = shutdown.send(true);
            let other = sign_task.await;
            result.and(other)
        }
        _ = stop.changed() => {
            let _ = shutdown.send(true);
            let (sign_result, admin_result) = tokio::join!(sign_task, admin_task);
            sign_result.and(admin_result)
        }
    };
    let _ = sweeper.await;
    boundary.lock_all();
    outcome
}
