//! UID-separated signing boundary.
pub mod client;
pub mod config;
mod coordinator;
pub(crate) mod executor;
pub mod http;
pub mod json;
pub mod limits;
pub mod management_ui;
pub mod migration;
pub mod paths;
pub mod protocol;
pub mod server;
pub(crate) mod se_session;

use crate::error::{KeydError, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// Build capability; a running service additionally requires explicit protected mode.
pub const fn protected_build_supported() -> bool {
    cfg!(target_os = "linux")
        && !cfg!(debug_assertions)
        && !cfg!(feature = "hardware-software")
        && !cfg!(feature = "seed-export")
}

pub fn require_boundary_platform() -> Result<()> {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        Ok(())
    } else {
        Err(KeydError::Misuse(
            "UID boundary is unsupported on this platform; development mode remains available"
                .into(),
        ))
    }
}

/// A whole-frame deadline, rather than a timeout restarted by each arriving byte.
pub struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}
impl DeadlineStream {
    pub(crate) fn clone_socket(&self) -> Result<UnixStream> {
        Ok(self.stream.try_clone()?)
    }
    pub fn new(stream: UnixStream, budget: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + budget,
        }
    }
    pub fn reset(&mut self, budget: Duration) {
        self.deadline = Instant::now() + budget;
    }
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "frame deadline expired")
            })
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("set socket read timeout ({remaining:?}) failed: {error}"),
                )
            })?;
        self.stream.read(buffer).map_err(|error| {
            std::io::Error::new(error.kind(), format!("socket read failed: {error}"))
        })
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream
            .set_write_timeout(Some(remaining))
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("set socket write timeout ({remaining:?}) failed: {error}"),
                )
            })?;
        self.stream.write(buffer).map_err(|error| {
            std::io::Error::new(error.kind(), format!("socket write failed: {error}"))
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush().map_err(|error| {
            std::io::Error::new(error.kind(), format!("socket flush failed: {error}"))
        })
    }
}

pub fn probe(path: &Path) -> Result<()> {
    println!("anp-keyd security boundary probe");
    require_boundary_platform()?;
    let config = config::ServiceConfig::load(path)?;
    println!("config: root-owned, symlink-free, immutable to service and Agents");
    println!("service_uid: {}", config.service_uid);
    println!("admin_uids: {:?}", config.admin_uids);
    for principal in &config.principals {
        println!(
            "bootstrap principal (not live DB state): {} uid={} generation={} enabled={}",
            principal.principal_id, principal.uid, principal.generation, principal.enabled
        );
    }
    paths::state_directory(&config.state_dir, config.service_uid)?;
    println!("state: service-owned 0700");
    let admin = config.admin_uids.contains(&crate::daemon::self_uid());
    let (endpoint, group) = if admin {
        (&config.admin_socket, config.admin_gid)
    } else {
        (&config.sign_socket, config.agent_gid)
    };
    paths::socket(endpoint, config.service_uid, group)?;
    println!("caller socket: trusted group and 0750 directory, 0660 endpoint");
    let reply = client::Client::connect(path, admin)?.capabilities()?;
    println!(
        "server_identity: kernel UID verified; instance={}",
        reply.instance_id.unwrap_or_default()
    );
    println!("signing_available: {}", reply.signing_available);
    println!("protected_supported: {}", reply.protected_supported);
    if reply.protected_supported && config.protected_supported() {
        Ok(())
    } else {
        Err(KeydError::Misuse(
            "boundary checks passed; build or deployment is in preview/development mode".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trickling_bytes_cannot_extend_the_whole_frame_deadline() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for _ in 0..100 {
                if server.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let mut reader = DeadlineStream::new(client, Duration::from_millis(25));
        assert!(reader.read_exact(&mut [0; 100]).is_err());
        drop(reader);
        sender.join().unwrap();
    }
}
