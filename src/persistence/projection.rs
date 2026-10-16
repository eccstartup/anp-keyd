//! Rebuildable JSONL projection. SQLite remains the only authorization truth.
use super::*;
use std::io::{BufWriter, Write};

/// Stream bounded batches through a separate read-only connection. No signing
/// coordinator or vault lock is held during file I/O, sync or replacement.
pub fn export(root: &Path) -> Result<i64> {
    let db_path = root.join("state.sqlite");
    let meta = std::fs::symlink_metadata(&db_path)?;
    crate::security::paths::validate_file_metadata(&meta, &[meta.uid()], false)?;
    let connection = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    connection
        .busy_timeout(Duration::from_millis(100))
        .map_err(db_error)?;
    let maximum: i64 = connection
        .query_row("SELECT COALESCE(MAX(seq),0) FROM audit_events", [], |r| {
            r.get(0)
        })
        .map_err(db_error)?;
    let directory = root.join("audit-export");
    match std::fs::symlink_metadata(&directory) {
        Ok(m) if m.is_dir() && m.uid() == meta.uid() && m.mode() & 0o777 == 0o700 => {}
        Ok(_) => return Err(unavailable()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        }
        Err(e) => return Err(e.into()),
    }
    let temporary = directory.join(format!(".projection-{}", uuid()));
    let outcome = (|| -> Result<i64> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)?;
        let mut output = BufWriter::new(file);
        let mut seq = 0;
        let mut tail = GENESIS.to_owned();
        while seq < maximum {
            let rows = {
                let mut s=connection.prepare("SELECT seq,prev,event_digest,event_data FROM audit_events WHERE seq>?1 AND seq<=?2 ORDER BY seq LIMIT 256").map_err(db_error)?;
                let rows = s
                    .query_map(params![seq, maximum], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Vec<u8>>(3)?,
                        ))
                    })
                    .map_err(db_error)?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(db_error)?;
                rows
            };
            if rows.is_empty() {
                return Err(unavailable());
            }
            for (next, prev, digest, data) in rows {
                if next != seq + 1 || prev != tail || audit_hash(next, &prev, &data) != digest {
                    return Err(unavailable());
                }
                let event: Value = serde_json::from_slice(&data)?;
                serde_json::to_writer(
                    &mut output,
                    &json!({"seq":next,"prev":prev,"event_digest":digest,"event_data":event}),
                )?;
                output.write_all(b"\n")?;
                seq = next;
                tail = digest;
            }
        }
        output.flush()?;
        output.get_ref().sync_all()?;
        drop(output);
        std::fs::rename(&temporary, directory.join("events.jsonl"))?;
        std::fs::File::open(&directory)?.sync_all()?;
        Ok(seq)
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    outcome
}
use std::os::unix::fs::DirBuilderExt;
