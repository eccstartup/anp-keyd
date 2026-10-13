//! 签名:后端接口 + RFC 9421 结构化请求。

pub mod backend;
pub mod ed25519;
pub mod rfc9421;

pub use backend::Signer;
pub use ed25519::LockedSigningKey;
pub use rfc9421::{required_components, sign_request, SignRequest, Signed};
