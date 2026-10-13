//! 对称加密:XChaCha20-Poly1305。
//!
//! 选它而不是 AES-GCM 的理由(计划 §四):192 位随机 nonce,不需要维护计数器、
//! 也就不会 nonce 复用;软件实现本身就是常量时间,在没 AES-NI 的机器上
//! 没有缓存时序侧信道。写次数少的场景,这是白拿的好处。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{KeydError, Result};

/// XChaCha20-Poly1305 的 nonce 长度。
pub const NONCE_LEN: usize = 24;

/// 加密封装。`aad` 被认证但不加密 —— 它是把密文钉死在某个身份上的那根钉子。
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| KeydError::Crypto("aead seal failed".into()))
}

/// 解封。
///
/// 认证失败的**唯一**含义是"要么密钥错、要么密文被改"。AAD 不匹配在调用方
/// 那层就已经被 `aad_digest` 的比对抓走了,所以走到这里失败基本等于口令错。
pub fn open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| KeydError::BadPassphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9u8; 32];
    const NONCE: [u8; NONCE_LEN] = [3u8; NONCE_LEN];

    #[test]
    fn seal_open_roundtrip() {
        let ct = seal(&KEY, &NONCE, b"aad", b"secret seed").unwrap();
        assert_ne!(&ct[..9], b"secret seed");
        let pt = open(&KEY, &NONCE, b"aad", &ct).unwrap();
        assert_eq!(pt, b"secret seed");
    }

    #[test]
    fn wrong_aad_fails() {
        let ct = seal(&KEY, &NONCE, b"aad-a", b"payload").unwrap();
        assert!(open(&KEY, &NONCE, b"aad-b", &ct).is_err());
    }

    #[test]
    fn wrong_key_fails_as_bad_passphrase() {
        let ct = seal(&KEY, &NONCE, b"aad", b"payload").unwrap();
        let other = [4u8; 32];
        assert!(matches!(
            open(&other, &NONCE, b"aad", &ct),
            Err(KeydError::BadPassphrase)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut ct = seal(&KEY, &NONCE, b"aad", b"payload").unwrap();
        ct[0] ^= 1;
        assert!(open(&KEY, &NONCE, b"aad", &ct).is_err());
    }

    #[test]
    fn nonce_wrap_does_not_break_confidentiality() {
        // 同一个 nonce 配两把不同的密钥是安全的 —— nonce 复用只在同一把密钥下致命。
        let a = seal(&[1u8; 32], &NONCE, b"", b"one").unwrap();
        let b = seal(&[2u8; 32], &NONCE, b"", b"one");
        assert!(b.is_ok());
        assert_ne!(a, b.unwrap());
    }
}
