//! 守护进程:监听、认人、发签名。
//!
//! 这一层的每一件事都围绕一个前提:**连上来的进程是不可信的**。
//! 它可以是同一个用户下的另一个 agent —— 它拿得到 socket,但它不该拿得到钥匙。

pub mod peer;

pub use peer::{authorize, peer_identity, self_uid, PeerIdentity};
