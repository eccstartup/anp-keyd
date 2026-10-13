//! anp-keyd —— 持有 did:wba Ed25519 私钥、替 agent 签 RFC 9421 消息签名的本地守护进程。
//!
//! **agent 手里从来没有私钥字节。** 这个 crate 的全部结构都在服务这一句话。

pub mod audit;
pub mod cli;
pub mod client;
pub mod crypto;
pub mod daemon;
pub mod did;
pub mod error;
pub mod keystore;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod ops;
pub mod sign;
pub mod tty;

pub use error::{KeydError, Result};
