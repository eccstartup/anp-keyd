//! 软件 Ed25519 后端。
//!
//! `LockedSigningKey` 是解锁后的密钥在内存里唯一的存在形式:seed 躺在
//! `mlock` 住、不许换页、不许进 core dump 的页里,只用闭包借出。

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::crypto::hygiene::LockedBytes;
use crate::crypto::thumbprint::ed25519_multibase;
use crate::error::Result;
use crate::keystore::record::{KeyAlgorithm, KeyId};
use crate::sign::backend::Signer;

pub struct LockedSigningKey {
    id: KeyId,
    seed: LockedBytes,
    verifying: VerifyingKey,
    public_multibase: String,
}

impl LockedSigningKey {
    /// 从信封里解出来的 32 字节 seed 构造。
    pub fn from_seed(id: KeyId, seed: LockedBytes) -> Result<Self> {
        let verifying = seed.expose(|bytes| SigningKey::from_bytes(bytes).verifying_key());
        let public_multibase = ed25519_multibase(&verifying);
        Ok(Self {
            id,
            seed,
            verifying,
            public_multibase,
        })
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn did(&self) -> &str {
        &self.id.did
    }

    /// anp 的 `PublicKeyMaterial` 需要一把公钥;它**永远拿不到私钥**。
    pub fn anp_public_key(&self) -> anp::PublicKeyMaterial {
        anp::PublicKeyMaterial::Ed25519(self.verifying)
    }

    /// 自检用:验一个自己刚签出来的签名。
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
        self.verifying
            .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    }
}

impl Signer for LockedSigningKey {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Ed25519
    }

    fn public_multibase(&self) -> &str {
        &self.public_multibase
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        // `SigningKey` 在闭包里就地展开、就地丢弃;开了 `zeroize` 特性之后
        // 它带 `ZeroizeOnDrop`,展开出来的那份标量也不会留在栈上。
        Ok(self
            .seed
            .expose(|bytes| SigningKey::from_bytes(bytes).sign(msg).to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(seed_byte: u8) -> LockedSigningKey {
        let id = KeyId {
            did: "did:wba:example.com:user:alice:e1_x".into(),
            kid: "did:wba:example.com:user:alice:e1_x#key-1".into(),
            thumbprint: "e1_x".into(),
        };
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        LockedSigningKey::from_seed(id, seed).unwrap()
    }

    /// RFC 8032 §7.1 TEST 1:签名输出必须逐字节相等。
    #[test]
    fn signs_the_rfc8032_test1_vector() {
        let seed_bytes: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let expected: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let id = KeyId {
            did: "did:wba:example.com:user:alice:e1_x".into(),
            kid: "did:wba:example.com:user:alice:e1_x#key-1".into(),
            thumbprint: "e1_x".into(),
        };
        let mut seed_bytes = seed_bytes;
        let key = LockedSigningKey::from_seed(id, LockedBytes::new(&mut seed_bytes).unwrap()).unwrap();

        assert_eq!(key.sign(b"").unwrap(), expected);
    }

    #[test]
    fn signature_verifies_and_is_key_bound() {
        let key = key_from(1);
        let sig = key.sign(b"hello").unwrap();
        assert!(key.verify(b"hello", &sig));

        // 换一把钥匙验,必须失败。
        let other = key_from(2);
        assert!(!other.verify(b"hello", &sig));
        assert!(!key.verify(b"other message", &sig));
    }

    /// RFC 8032 §7.1 TEST 1 的公钥 → multikey 必须以 `z6Mk` 开头。
    #[test]
    fn public_multibase_comes_from_the_seed() {
        let key = key_from(42);
        assert!(key.public_multibase().starts_with("z6Mk"));
        assert_eq!(key.algorithm(), KeyAlgorithm::Ed25519);
    }
}
