//! Linux signing boundary. Protected release acceptance remains pending.
pub mod http;
pub mod client;
pub mod json;
pub mod config;
pub mod paths;
pub mod protocol;
pub mod server;
mod coordinator;
pub(crate) mod executor;
pub mod limits;
pub mod migration;

use crate::error::{KeydError, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub fn require_linux() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(KeydError::Misuse("Linux boundary preview is unsupported on this platform; development mode remains available".into()))
    }
}

/// A whole-frame deadline, rather than a timeout restarted by each arriving byte.
pub struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}
impl DeadlineStream {
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
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

pub fn probe(path: &Path) -> Result<()> {
    println!("anp-keyd security boundary probe");
    println!("protected_supported: false (Linux release acceptance pending)");
    require_linux()?;
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
    paths::socket(&config.sign_socket, config.service_uid, config.agent_gid)?;
    paths::socket(&config.admin_socket, config.service_uid, config.admin_gid)?;
    println!("sockets: separate groups and 0750 directories, 0660 endpoints");
    let admin = config.admin_uids.contains(&crate::daemon::self_uid());
    let reply = client::Client::connect(path, admin)?.capabilities()?;
    println!(
        "server_identity: kernel UID verified; instance={}",
        reply.instance_id.unwrap_or_default()
    );
    println!("signing_available: {}", reply.signing_available);
    Err(KeydError::Misuse(
        "boundary checks passed; Linux protected release acceptance is pending".into(),
    ))
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
