//! 签名后端接口。
//!
//! v1 只有软件 Ed25519。这个 trait 存在的理由是计划 §2.4:密钥层级分成
//! 两层是为了给硬件留位置 —— 但**硬件是当包装密钥,不是当签名密钥**
//! (Apple SE 只支持 P-256,装不下 Ed25519)。所以将来插进 KEK 那一层的是
//! 硬件,这里这层接口是给 YubiKey 那类自带 Ed25519 元素的设备留的。

use crate::error::Result;
use crate::keystore::record::KeyAlgorithm;

/// 一个可以做签名的密钥。**不暴露私钥字节。**
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> KeyAlgorithm;

    /// `z6Mk...` multibase 公钥 —— 可公开,写进 DID 文档用的就是它。
    fn public_multibase(&self) -> &str;

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]>;
}
