//! 审计：append-only 的 JSONL，每行带一条哈希链。
//!
//! ## 记什么，不记什么
//!
//! **记 `signature_base_digest`（签名基的 SHA-256），不记签名基本身。**
//! 签名基里逐行躺着请求头的原文 —— 包括 `authorization`、`cookie`、
//! `x-api-key` 这些东西。审计文件是给人看、给机器留、还会被备份走的，
//! 把请求原文抄进去等于把一份凭据副本从签名路径漏到了另一个文件里。
//! 摘要够用了：事后要核对"某次签名签的到底是不是那条请求"，把那条请求
//! 重新拼出签名基、算一次摘要、对上就行 —— 而这本来就需要请求原文在手，
//! 也就意味着能对上的那个人本来就有权看到它。
//!
//! ## 哈希链能保证什么，不能保证什么
//!
//! 每条记录写进去之前先算好它自己的 SHA-256，放进**下一条**记录的 `prev`
//! 字段。于是：
//!
//! - **改一行、删中间一行、把两行调个位置** → 链断，可检出。
//! - **砍掉尾巴** → 链本身仍然自洽，**光看这个文件检不出来**。
//!
//! 第二条是这类结构的固有边界，不是实现没做到：一份"自己证明自己完整"
//! 的文件在数学上不存在，总得有一个链外的锚。所以旁边多放了一个
//! `.anchor`，记着行数和末行哈希，每次追加后一起落盘。
//!
//! 于是**能检出**：文件被截断、被回滚到某个旧版本（只要锚没被一起改）。
//! **不能检出**：有人同时改了 `.jsonl` 和 `.anchor` —— 那需要把锚放到
//! 这台机器之外（另一台主机、或者一个只可追加的远端），v1 不做。
//! 所以这里给的是**篡改留痕**，不是**篡改免疫**。把话说清楚比给一个
//! 听起来更强、实际做不到的承诺要好。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::crypto::sha256;
use crate::error::{KeydError, Result};

/// 链的起点。第一条记录的 `prev` 是这个全零。
const GENESIS: [u8; 32] = [0u8; 32];

/// 一条审计记录。
///
/// 字段是**刻意具体**的：一个只写 `{"event":"sign"}` 的日志在事后什么也
/// 回答不了。记的是"谁、用哪把钥匙、覆盖了哪些分量、签名基的摘要"。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Event {
    /// 连接**被拒**。
    ///
    /// 这一条尤其重要：拒绝是安静发生的，没有它，一次跨 uid 的探测在
    /// 日志里和"什么都没发生"完全一样。
    Denied {
        uid: u32,
        pid: Option<i32>,
        reason: String,
    },
    Unlocked {
        uid: u32,
        did: String,
    },
    /// `did` 为空 = 全锁。
    Locked {
        uid: u32,
        did: Option<String>,
        /// 实际放掉了几把。
        dropped: usize,
    },
    Signed {
        uid: u32,
        did: String,
        kid: String,
        /// **实际**被覆盖的分量，从签名基里解析回来的那一份。
        covered: Vec<String>,
        /// 签名基的 SHA-256，hex。不是签名基本身 —— 见模块头。
        signature_base_digest: String,
    },
    /// 原始签名。这条路径默认关着，开了之后每次都要留痕。
    RawSigned {
        uid: u32,
        did: String,
        payload_len: usize,
        payload_digest: String,
    },
    /// 空闲超时收走了钥匙。
    Swept {
        dropped: usize,
    },
}

/// `.anchor` 的内容。
#[derive(Debug, Serialize, serde::Deserialize)]
struct Anchor {
    records: u64,
    tail: String,
}

/// 一个 append-only 的审计日志。
///
/// 不实现 `Sync` 的共享方式由调用方决定 —— 这里假定外部已经串好了
/// （守护进程只有一条写路径）。
#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    file: File,
    month: String,
    records: u64,
    tail: [u8; 32],
}

impl AuditLog {
    /// 打开（或新建）审计目录，并**先把整个链验一遍**。
    ///
    /// 校验放在打开时而不是某个定时任务里：一份被改过的审计日志必须在
    /// 守护进程开始往上追加之前就被发现，否则新的记录会接在一个断掉的
    /// 链后面，把断点掩盖成"看起来一直是这样"。
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

        let month = current_month();
        let path = dir.join(format!("{month}.jsonl"));

        let (records, tail) = match path.exists() {
            true => verify_chain(&path)?,
            false => (0, GENESIS),
        };

        // 锚文件对不上 = 上次之后这个文件被截断或被回滚过。
        check_anchor(dir, records, &tail)?;

        let file = open_append(&path)?;
        Ok(Self { dir: dir.to_path_buf(), file, month, records, tail })
    }

    /// 追加一条记录，落盘，并把锚一起更新。
    ///
    /// **先写记录、后写锚**，顺序不能反：反过来的话，记录写失败而锚推进了，
    /// 下次启动就会报一个并不存在的篡改。
    pub fn append(&mut self, event: &Event) -> Result<()> {
        self.rotate_if_needed()?;

        let record = Record {
            seq: self.records + 1,
            at: now_rfc3339(),
            prev: hex(&self.tail),
            event,
        };
        let mut line = serde_json::to_vec(&record)
            .map_err(|e| KeydError::Protocol(format!("audit record is not serializable: {e}")))?;
        // 这条记录的哈希算的是**写出去的那串字节**，所以校验时直接把
        // 文件里的原始行拿来做 SHA-256 就行，不需要重新序列化 —— 也不必
        // 担心哪天 serde 改了字段顺序就验不过。
        self.tail = sha256(&line);
        self.records += 1;

        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_all()?;

        self.write_anchor()?;
        Ok(())
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        let month = current_month();
        if month == self.month {
            return Ok(());
        }

        // 换月不重置链 —— 链跨文件延续，否则每个月的第一行都是一个
        // 谁都能伪造的新起点。
        self.month = month;
        self.file = open_append(&self.dir.join(format!("{}.jsonl", self.month)))?;
        Ok(())
    }

    fn write_anchor(&self) -> Result<()> {
        let anchor = Anchor { records: self.records, tail: hex(&self.tail) };
        let bytes = serde_json::to_vec(&anchor)
            .map_err(|e| KeydError::Protocol(format!("anchor is not serializable: {e}")))?;
        crate::keystore::layout::write_atomic(
            &self.dir.join(".anchor"),
            &bytes,
            crate::keystore::layout::SECRET_FILE_MODE,
        )
    }
}

#[derive(Serialize)]
struct Record<'a> {
    seq: u64,
    at: String,
    prev: String,
    #[serde(flatten)]
    event: &'a Event,
}

fn open_append(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(crate::keystore::layout::SECRET_FILE_MODE)
        .open(path)?;
    // 新文件先把权限盖死 —— `mode` 会被 umask 削，而审计文件不该受
    // 进程环境里的 umask 影响。
    fs::set_permissions(path, std::fs::Permissions::from_mode(crate::keystore::layout::SECRET_FILE_MODE))?;
    Ok(file)
}

/// 从头走一遍链。返回（行数，末行哈希）。
///
/// 任何一行对不上就报**第几行** —— "审计日志坏了"这种消息没法查。
fn verify_chain(path: &Path) -> Result<(u64, [u8; 32])> {
    let text = fs::read_to_string(path)?;
    let mut prev = GENESIS;
    let mut records = 0u64;

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim().is_empty() {
            return Err(KeydError::Protocol(format!(
                "audit line {number} is blank; a gap in an append-only log means it was rewritten"
            )));
        }

        let parsed: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            KeydError::Protocol(format!("audit line {number} is not readable JSON: {e}"))
        })?;
        let claimed = parsed
            .get("prev")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeydError::Protocol(format!("audit line {number} has no prev")))?;

        if claimed != hex(&prev) {
            return Err(KeydError::Protocol(format!(
                "the audit chain breaks at line {number}: it links to a record that is not \
                 the one before it, so a line was changed, removed, or moved"
            )));
        }

        prev = sha256(line.as_bytes());
        records = number as u64;
    }

    Ok((records, prev))
}

/// 锚和文件对不对得上。
///
/// 文件不存在而锚在 = 被删了；行数对不上 = 被截断或被追加过；
/// 末行哈希对不上 = 尾巴被换过。
fn check_anchor(dir: &Path, records: u64, tail: &[u8; 32]) -> Result<()> {
    let path = dir.join(".anchor");
    if !path.exists() {
        // 没有锚：要么是全新的目录，要么锚被人删了。空目录是正常起点；
        // 有记录却没有锚，就只能说不知道 —— 但不能当作没事。
        if records == 0 {
            return Ok(());
        }
        return Err(KeydError::Protocol(format!(
            "{} has {records} records but no .anchor; the anchor was removed, so \
             truncation can no longer be ruled out",
            dir.display()
        )));
    }

    let anchor: Anchor = serde_json::from_slice(&fs::read(&path)?)
        .map_err(|e| KeydError::Protocol(format!("{} is unreadable: {e}", path.display())))?;

    if anchor.records != records {
        return Err(KeydError::Protocol(format!(
            "the audit log holds {records} records but the anchor says {}; it was \
             truncated or rolled back",
            anchor.records
        )));
    }
    if anchor.tail != hex(tail) {
        return Err(KeydError::Protocol(
            "the last audit record does not match the anchor: the tail of the log was rewritten".into(),
        ));
    }
    Ok(())
}

fn current_month() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!("{:04}-{:02}", now.year(), u8::from(now.month()))
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 摘要的 hex 形式，给事件字段用。
pub fn digest_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(uid: u32) -> Event {
        Event::Unlocked { uid, did: "did:wba:example.com:user:alice:e1_abc".into() }
    }

    fn dir() -> super::tests::TempDir {
        TempDir::new()
    }

    #[test]
    fn a_signed_record_carries_the_base_digest_and_not_the_base() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&Event::Signed {
            uid: 501,
            did: "did:wba:example.com:u:a:e1_x".into(),
            kid: "did:wba:example.com:u:a:e1_x#key-1".into(),
            covered: vec!["@method".into(), "@target-uri".into()],
            signature_base_digest: digest_hex(b"@method: POST\n"),
        })
        .unwrap();
        drop(log);

        let text = fs::read_to_string(d.path().join(format!("{}.jsonl", current_month()))).unwrap();
        assert!(text.contains("SIGNED"));
        assert!(text.contains("signature_base_digest"));

        // 这条是模块头的那个承诺：签名基里可能有 authorization/cookie，
        // **不能**出现在审计文件里。
        assert!(!text.contains("@method: POST"), "the base itself leaked into the log: {text}");
        assert!(!text.contains("authorization"));
    }

    #[test]
    fn records_link_to_the_record_before_them() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        log.append(&sample(502)).unwrap();
        log.append(&sample(503)).unwrap();
        assert_eq!(log.records(), 3);
        drop(log);

        // 干净的文件，重开时校验通过。
        let reopened = AuditLog::open(d.path()).unwrap();
        assert_eq!(reopened.records(), 3);
    }

    /// 改一行 —— 中间那条被改过，链在第 3 行断掉（因为第 3 行记的是
    /// 改之前那条第 2 行的哈希）。
    #[test]
    fn editing_a_record_breaks_the_chain() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        log.append(&sample(502)).unwrap();
        log.append(&sample(503)).unwrap();
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let edited = text.replacen("\"uid\":502", "\"uid\":999", 1);
        assert_ne!(text, edited, "the fixture did not actually change anything");
        fs::write(&path, edited).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("breaks at line"), "{err}");
    }

    /// 删掉中间一行 —— 和改一行是同一类事故。
    #[test]
    fn removing_a_record_breaks_the_chain() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        for uid in [501, 502, 503] {
            log.append(&sample(uid)).unwrap();
        }
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("breaks at line"), "{err}");
    }

    /// **砍掉尾巴**：链自己仍然自洽 —— 光看 jsonl 是检不出来的。
    /// 能检出来是因为旁边那个锚。
    #[test]
    fn truncating_the_tail_is_caught_by_the_anchor_not_by_the_chain() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        for uid in [501, 502, 503] {
            log.append(&sample(uid)).unwrap();
        }
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        let truncated = format!("{}\n", kept.join("\n"));
        fs::write(&path, &truncated).unwrap();

        // 先确认这个前提：被砍过的文件，链本身是自洽的。
        fs::remove_file(d.path().join(".anchor")).unwrap();
        let (records, _) = verify_chain(&path).unwrap();
        assert_eq!(records, 2, "the truncated chain still validates on its own");

        // 锚一放回去，事故就露出来了。
        fs::write(
            d.path().join(".anchor"),
            serde_json::to_vec(&Anchor { records: 3, tail: hex(&GENESIS) }).unwrap(),
        )
        .unwrap();
        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("truncated or rolled back"), "{err}");
    }

    #[test]
    fn deleting_the_anchor_of_a_non_empty_log_is_refused() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        drop(log);

        fs::remove_file(d.path().join(".anchor")).unwrap();
        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("no .anchor"), "{err}");
    }

    /// 全新的空目录是正常起点，不是"锚不见了"。
    #[test]
    fn a_fresh_directory_opens_cleanly() {
        let d = dir();
        let log = AuditLog::open(d.path()).unwrap();
        assert_eq!(log.records(), 0);
    }

    #[test]
    fn rewriting_the_tail_in_place_is_caught_by_the_tail_hash() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        // 改最后一条，并把 prev 也改成自洽的 —— 链本身能过，锚过不了。
        let edited = text.replace("\"uid\":501", "\"uid\":777");
        fs::write(&path, edited).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(
            err.to_string().contains("does not match the anchor")
                || err.to_string().contains("breaks at line"),
            "{err}"
        );
    }

    #[test]
    fn digest_hex_is_sha256_in_hex() {
        // 空串的 SHA-256 是个到处都能对上的常数。
        assert_eq!(
            digest_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_audit_file_is_not_world_readable() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit file is mode {mode:o}");
        let mode = fs::metadata(d.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "audit dir is mode {mode:o}");
    }

    /// 事件是给人看的，字段名别飘。
    #[test]
    fn every_event_has_a_stable_tag_and_its_own_fields() {
        let events = [
            Event::Denied { uid: 1, pid: Some(2), reason: "cross-uid".into() },
            Event::Unlocked { uid: 1, did: "d".into() },
            Event::Locked { uid: 1, did: None, dropped: 2 },
            Event::Signed {
                uid: 1,
                did: "d".into(),
                kid: "k".into(),
                covered: vec!["@method".into()],
                signature_base_digest: "ab".into(),
            },
            Event::RawSigned { uid: 1, did: "d".into(), payload_len: 3, payload_digest: "cd".into() },
            Event::Swept { dropped: 1 },
        ];

        let tags: Vec<String> = events
            .iter()
            .map(|e| {
                serde_json::to_value(e).unwrap()["event"].as_str().unwrap().to_string()
            })
            .collect();
        assert_eq!(
            tags,
            ["DENIED", "UNLOCKED", "LOCKED", "SIGNED", "RAW_SIGNED", "SWEPT"]
        );
    }

    mod tempdir {
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir {
            path: PathBuf,
        }

        impl TempDir {
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "anp-keyd-audit-{}-{n}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { path }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    use tempdir::TempDir;
}
