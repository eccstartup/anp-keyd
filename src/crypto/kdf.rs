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

/// 硬件绑定信封(v2)的用途域串。
///
/// 和 v1 不同串是**照上面那条注释办事**,不是碰巧:两版的 IKM 长度本来就不同
/// (64 vs 96 字节),撞不上,但一个能被指认出来的 KEK 域比"反正概率上不会撞"
/// 更值得依赖。
const KEK_INFO_BOUND: &[u8] = b"anp-keyd/v2/kek";

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
    // Envelope parameters are untrusted until AEAD verification, after the KDF.
    // Bound memory, iterations and lanes before allocating or deriving anything.
    if !(8..=262144).contains(&m_cost) || !(1..=10).contains(&t_cost) || !(1..=4).contains(&p_cost) {
        return Err(KeydError::Crypto("argon2 cost exceeds supported resource bounds".into()));
    }
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

/// 硬件绑定信封的 KEK —— **三路**熵。
///
/// ```text
/// passphrase ──Argon2id──┐
/// device.secret ─────────┼─ HKDF-SHA256(salt, "anp-keyd/v2/kek") ──> KEK (32B)
/// HS(硬件封装) ──────────┘
/// ```
///
/// 单独一个函数、单独一个 INFO 串,而不是给 [`derive_kek`] 加一个
/// `Option<HS>` 参数:后者的签名允许了"v2 的信封、走 v1 的派生"这种调用,
/// 而那正是这一整块要防的降级。两条路在类型上就是两条路。
///
/// 三路都必须在场。`HS` 由硬件封装、由信封携带 —— 少了这台机器上的硬件就打
/// 不开,这正是设计;`device.secret` 那一层没被替代,它管的是"备份拷走没用"。
pub fn derive_kek_bound(
    pass_key: &[u8; 32],
    device_secret: &LockedBytes,
    salt: &[u8],
    hs: &LockedBytes,
) -> [u8; 32] {
    hs.expose(|hs_bytes| {
        device_secret.expose(|dev| {
            // ikm = 口令派生物 ‖ device.secret ‖ HS
            let mut ikm = [0u8; 96];
            ikm[..32].copy_from_slice(pass_key);
            ikm[32..64].copy_from_slice(dev);
            ikm[64..].copy_from_slice(hs_bytes);

            let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
            let mut kek = [0u8; 32];
            hk.expand(KEK_INFO_BOUND, &mut kek)
                .expect("32 is a valid HKDF-SHA256 output length");

            ikm.zeroize();
            kek
        })
    })
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

    #[test]
    fn bound_kek_needs_all_three_paths() {
        let pass = argon2id(b"pw", b"salt-salt-salt-1", M, T, P).unwrap();
        let hs = |b: u8| LockedBytes::fill(|d| *d = [b; 32]).unwrap();
        let salt = b"salt-salt-salt-1";

        let base = derive_kek_bound(&pass, &device(1), salt, &hs(0x11));
        assert_ne!(base, derive_kek_bound(&pass, &device(2), salt, &hs(0x11)));
        assert_ne!(base, derive_kek_bound(&pass, &device(1), salt, &hs(0x12)));
        assert_ne!(
            base,
            derive_kek_bound(
                &argon2id(b"pw2", salt, M, T, P).unwrap(),
                &device(1),
                salt,
                &hs(0x11)
            )
        );
        // 定值性:同样的三路熵,KEK 必须逐字节相同。
        assert_eq!(base, derive_kek_bound(&pass, &device(1), salt, &hs(0x11)));
    }

    /// v1 和 v2 必须是两个域 —— 否则一个信封能被另一版的推导打开。
    #[test]
    fn the_two_versions_do_not_share_a_kek() {
        let pass = argon2id(b"pw", b"salt-salt-salt-1", M, T, P).unwrap();
        let salt = b"salt-salt-salt-1";
        let hs = LockedBytes::fill(|d| *d = [0u8; 32]).unwrap();

        // 故意让 HS 全零 —— 即便这样,两版也不能撞。
        assert_ne!(
            derive_kek(&pass, &device(1), salt),
            derive_kek_bound(&pass, &device(1), salt, &hs),
            "v1 and v2 must be separate HKDF domains"
        );
    }
}
