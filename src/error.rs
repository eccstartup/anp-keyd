use thiserror::Error;

/// Every failure mode the daemon can produce.
///
/// Several variants are deliberately coarse: the wire protocol must not leak
/// *why* a credential failed, only *that* it failed.
#[derive(Debug, Error)]
pub enum KeydError {
    // —— 密钥库 ——
    #[error("bad passphrase")]
    BadPassphrase,
    #[error("device secret missing or wrong")]
    BadDeviceSecret,
    #[error("envelope aad mismatch: record does not belong to this identity")]
    AadMismatch,
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("key already exists: {0}")]
    KeyExists(String),
    #[error("key is locked")]
    Locked,

    // —— 身份 / peer ——
    ///
    /// 这一条**带**细节,和上面的口令类错误不一样:拿不到对端凭证是本地
    /// syscall 失败,errno 里没有秘密,丢掉它只会让"平台不支持"看起来
    /// 像"权限被拒"。
    #[error("peer credential could not be read: {0}")]
    PeerCredentialUnavailable(String),
    #[error("peer is not permitted to use key {0}")]
    Permission(String),

    // —— 签名 ——
    #[error("raw signing is disabled (start the daemon with --allow-raw-signing)")]
    RawDisabled,
    #[error("caller asked for a covered component the daemon will not sign: {0}")]
    CoveredSetRejected(String),

    // —— 其他 ——
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("invalid did: {0}")]
    Did(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("upstream: {0}")]
    Upstream(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, KeydError>;
