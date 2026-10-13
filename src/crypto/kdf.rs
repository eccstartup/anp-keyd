//! 口令 → KEK 的推导。
//!
//! ```text
//! passphrase ──Argon2id(salt, params) ──┐
//!                                       ├─ HKDF-SHA256(salt) ──> KEK (32B)
//! device.secret ────────────────────────┘
//! ```
//!
//! **两个秘密都必须在场。** 只有口令、没有 `device.secret` → 推不出 KEK;
//! 只有 `device.secret`、没有口令 → 同样推不出。这是 1Password 的
//! 2SKD(账号密码 + Secret Key)在本地场景的对应物,它防的正是"谁能读备份,
//! 谁就能拿到私钥"。

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};

/// HKDF 的用途域分隔。换版本时必须改这个串,否则新旧 KEK 会撞。
const KEK_INFO: &[u8] = b"anp-keyd/v1/kek";

/// 生成信封时要求 Argon2id 用的参数。
///
/// 默认值按计划 §五:`m_cost = 65536` KiB(64 MiB)、`t_cost = 3`、`p_cost = 1`。
/// 这个成本就是它对离线爆破的抵抗 —— 调低它等于调低信封的强度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Config {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Argon2id(口令, salt, 参数) → 32 字节。
///
/// 这是整个流程里唯一**刻意慢**的一步:它的成本就是它对离线爆破的抵抗。
pub fn argon2id(
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| KeydError::Crypto(format!("bad argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| KeydError::Crypto(format!("argon2id failed: {e}")))?;
    Ok(out)
}

/// 把口令派生物与 `device.secret` 合成 KEK。
///
/// 接 `&LockedBytes` 而不是 `&[u8; 32]`:设备密钥从不以裸引用离开锁定区。
pub fn derive_kek(
    pass_key: &[u8; 32],
    device_secret: &LockedBytes,
    salt: &[u8],
) -> [u8; 32] {
    device_secret.expose(|dev| {
        // ikm = 口令派生物 ‖ device.secret。两个来源都必须贡献熵。
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(pass_key);
        ikm[32..].copy_from_slice(dev);

        let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut kek = [0u8; 32];
        // 32 字节对 HKDF-SHA256 永远是合法长度,这个 expect 不可能触发。
        hk.expand(KEK_INFO, &mut kek)
            .expect("32 is a valid HKDF-SHA256 output length");

        ikm.zeroize();
        kek
    })
}

/// 往锁定区里生成 32 字节随机数 —— 每把 key 的 DEK 与 seed 都走这里。
pub fn random_locked() -> Result<LockedBytes> {
    LockedBytes::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: u32 = 1024; // 测试里故意压低,否则每次跑测试都要等
    const T: u32 = 1;
    const P: u32 = 1;

    fn device(seed: u8) -> LockedBytes {
        LockedBytes::fill(|d| *d = [seed; 32]).unwrap()
    }

    #[test]
    fn argon2id_is_deterministic() {
        let a = argon2id(b"correct horse", b"0123456789abcdef", M, T, P).unwrap();
        let b = argon2id(b"correct horse", b"0123456789abcdef", M, T, P).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn argon2id_salt_changes_output() {
        let a = argon2id(b"same pass", b"salt-one-16bytes", M, T, P).unwrap();
        let b = argon2id(b"same pass", b"salt-two-16bytes", M, T, P).unwrap();
        assert_ne!(a, b, "same passphrase under a different salt must differ");
    }

    #[test]
    fn kek_needs_both_secrets() {
        let pass = argon2id(b"pw", b"salt-salt-salt-1", M, T, P).unwrap();

        let kek_a = derive_kek(&pass, &device(1), b"salt-salt-salt-1");
        let kek_b = derive_kek(&pass, &device(2), b"salt-salt-salt-1");
        assert_ne!(kek_a, kek_b, "a different device secret must change the KEK");

        let other_pass = argon2id(b"pw2", b"salt-salt-salt-1", M, T, P).unwrap();
        let kek_c = derive_kek(&other_pass, &device(1), b"salt-salt-salt-1");
        assert_ne!(kek_a, kek_c, "a different passphrase must change the KEK");
    }
}
