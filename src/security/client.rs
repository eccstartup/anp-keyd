//! Authenticate the service's kernel UID before any secret can be written.
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

use super::config::ServiceConfig;
use super::protocol::{self, AdminRequest, DataRequest, Envelope, Reply, VERSION};
use super::{paths, DeadlineStream};
use crate::daemon::peer::{peer_identity, self_uid};
use crate::error::{KeydError, Result};

pub struct Client {
    stream: DeadlineStream,
    config: ServiceConfig,
    admin: bool,
}

impl Client {
    pub fn connect(path: &Path, admin: bool) -> Result<Self> {
        super::require_boundary_platform()?;
        let config = ServiceConfig::load(path)?;
        if admin && !config.admin_uids.contains(&self_uid()) {
            return Err(KeydError::Permission("ADMIN_REQUIRED".into()));
        }
        let (socket, gid) = if admin {
            (&config.admin_socket, config.admin_gid)
        } else {
            (&config.sign_socket, config.agent_gid)
        };
        let before = paths::socket(socket, config.service_uid, gid)?;
        let stream = UnixStream::connect(socket)?;
        // Authenticate first, before tty prompting or serialization of a password.
        if peer_identity(&stream)?.uid != config.service_uid {
            return Err(KeydError::Permission("SERVER_IDENTITY_MISMATCH".into()));
        }
        let after = paths::socket(socket, config.service_uid, gid)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(KeydError::Permission("SERVER_IDENTITY_MISMATCH".into()));
        }
        Ok(Self {
            stream: DeadlineStream::new(stream, Duration::from_secs(5)),
            config,
            admin,
        })
    }

    pub fn capabilities(mut self) -> Result<Reply> {
        if self.admin {
            protocol::write(
                &mut self.stream,
                &Envelope {
                    version: VERSION,
                    request: AdminRequest::Capabilities {},
                },
            )?;
        } else {
            protocol::write(
                &mut self.stream,
                &Envelope {
                    version: VERSION,
                    request: DataRequest::Capabilities {},
                },
            )?;
        }
        self.reply()
    }

    /// Exactly one v2 request to the configured endpoint; never retries or downgrades.
    pub fn data(mut self, request: DataRequest) -> Result<Reply> {
        if self.admin {
            return Err(KeydError::Misuse("DATA_ENDPOINT_REQUIRED".into()));
        }
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request,
            },
        )?;
        self.reply()
    }

    pub fn principals(mut self) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::ListPrincipals {},
            },
        )?;
        self.reply()
    }
    pub fn catalog(mut self) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Catalog {},
            },
        )?;
        self.reply()
    }
    pub fn prepare(mut self, change: crate::persistence::Change) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Prepare { change },
            },
        )?;
        self.reply()
    }
    pub fn commit(mut self, operation_id: String, digest: String) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Commit {
                    operation_id,
                    digest,
                },
            },
        )?;
        self.reply()
    }

    pub fn lock_all(mut self) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::LockAll {},
            },
        )?;
        self.reply()
    }

    pub fn complete_secret_operation(
        mut self,
        operation_id: String,
        digest: String,
        secret: Zeroizing<String>,
    ) -> Result<Reply> {
        self.management()?;
        self.stream.reset(Duration::from_secs(5));
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::CompleteSecretOperation {
                    operation_id,
                    digest,
                },
            },
        )?;
        protocol::write_secret(&mut self.stream, &secret)?;
        self.stream.reset(Duration::from_secs(30));
        self.reply()
    }

    pub fn unlock(
        mut self,
        vault_id: String,
        did: String,
        kid: String,
        passphrase: Zeroizing<String>,
    ) -> Result<Reply> {
        self.management()?;
        // Prompting may have taken time; the read/write budget starts when sending.
        self.stream.reset(Duration::from_secs(5));
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Unlock { vault_id, did, kid },
            },
        )?;
        protocol::write_secret(&mut self.stream, &passphrase)?;
        self.stream.reset(Duration::from_secs(30));
        self.reply()
    }

    fn management(&self) -> Result<()> {
        if !self.admin {
            return Err(KeydError::Permission("ADMIN_REQUIRED".into()));
        }
        Ok(())
    }

    fn reply(&mut self) -> Result<Reply> {
        let reply: Reply = protocol::read(&mut self.stream)?;
        if reply.version != VERSION {
            return Err(KeydError::Protocol("PROTOCOL_VERSION_UNSUPPORTED".into()));
        }
        if reply.code == "OK"
            && reply.instance_id.as_deref() != Some(self.config.instance_id.as_str())
        {
            return Err(KeydError::Permission("SERVER_IDENTITY_MISMATCH".into()));
        }
        if reply.code != "OK" {
            return Err(KeydError::Permission(reply.code));
        }
        Ok(reply)
    }
}
