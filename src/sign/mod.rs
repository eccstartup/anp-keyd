//! 签名:后端接口 + RFC 9421 结构化请求。

pub mod backend;
pub mod ed25519;

pub use backend::Signer;
pub use ed25519::LockedSigningKey;
