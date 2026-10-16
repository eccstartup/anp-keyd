//! Offline evidence only: the collector must authenticate and retain checkpoints
//! outside the service's trust domain. This does not gate signing or authenticate
//! a remote service. Unobserved suffixes and non-audit state are not anchored.
use super::*;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub instance_id: String,
    pub sequence: i64,
    pub digest: String,
}

fn rejected() -> KeydError {
    KeydError::Protocol("AUDIT_CHECKPOINT_REJECTED".into())
}

impl Checkpoint {
    fn validate(&self, instance: &str) -> Result<()> {
        if self.version != 1
            || self.instance_id != instance
            || !crate::principal::validate_uuid(instance)
            || self.sequence < 1
            || self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(rejected());
        }
        Ok(())
    }
}

/// Bounded, strict parsing; failure must never trigger automatic re-enrollment.
pub fn read(path: &Path) -> Result<Checkpoint> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(rejected());
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(rejected());
    }
    let checkpoint: Checkpoint = serde_json::from_slice(&bytes)?;
    checkpoint.validate(&checkpoint.instance_id)?;
    Ok(checkpoint)
}

/// Validate the entire chain and a retained prefix in one SQLite read snapshot.
/// The returned tip is a candidate: it becomes trusted only after the external
/// collector durably retains it. No database recovery, grants, or files change.
pub fn inspect(path: &Path, instance: &str, previous: Option<&Checkpoint>) -> Result<Checkpoint> {
    if !crate::principal::validate_uuid(instance) {
        return Err(rejected());
    }
    if let Some(p) = previous {
        p.validate(instance)?;
    }
    let metadata = std::fs::symlink_metadata(path)?;
    crate::security::paths::validate_file_metadata(&metadata, &[metadata.uid()], false)?;
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    connection
        .busy_timeout(Duration::from_millis(500))
        .map_err(db_error)?;
    connection
        .execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")
        .map_err(db_error)?;
    let tx = connection.transaction().map_err(db_error)?;
    let app: i64 = tx
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(db_error)?;
    let version: i64 = tx
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(db_error)?;
    let (stored, schema): (String, i64) = tx
        .query_row(
            "SELECT instance_id,schema_version FROM service_meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(db_error)?;
    if app != APPLICATION || version != SCHEMA || schema != SCHEMA || stored != instance {
        return Err(rejected());
    }
    verify_audit(&tx)?;
    if let Some(p) = previous {
        let retained: Option<String> = tx
            .query_row(
                "SELECT event_digest FROM audit_events WHERE seq=?1",
                [p.sequence],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        if retained.as_deref() != Some(p.digest.as_str()) {
            return Err(rejected());
        }
    }
    let (sequence, digest) = tx
        .query_row(
            "SELECT seq,event_digest FROM audit_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(db_error)?;
    let result = Checkpoint {
        version: 1,
        instance_id: stored,
        sequence,
        digest,
    };
    result.validate(instance)?;
    tx.commit().map_err(db_error)?;
    Ok(result)
}
