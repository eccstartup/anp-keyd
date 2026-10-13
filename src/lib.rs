//! anp-keyd —— 持有 did:wba Ed25519 私钥、替 agent 签 RFC 9421 消息签名的本地守护进程。
//!
//! **agent 手里从来没有私钥字节。** 这个 crate 的全部结构都在服务这一句话。

pub mod crypto;
pub mod did;
pub mod error;
pub mod keystore;
pub mod sign;

pub use error::{KeydError, Result};
