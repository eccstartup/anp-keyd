//! 信封解开:口令 + `device.secret` → 内存里的一把签名密钥。
//!
//! 顺序是刻意的:**AAD 自检 → 派生 KEK → 解 DEK → 解 seed**。任何一步不过
//! 就停在原地,不往下走。

use zeroize::Zeroize;

use crate::crypto::aead;
use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf;
use crate::error::{KeydError, Result};
use crate::keystore::record::{self, WrappedKey};
use crate::keystore::wrap::exact32;
use crate::sign::{LockedSigningKey, Signer};

/// 解开一个信封。
///
/// 失败时给什么错**是有讲究的**:
/// - `AadMismatch` —— 信封的头被人动过(改名/改标)。这不是口令问题。
/// - `BadPassphrase` —— 口令错,**或者** `device.secret` 存在但内容不对。
/// - `BadDeviceSecret` —— `device.secret` 根本不在了(由调用方判定)。
///
/// "`device.secret` 存在但内容错"和"口令错"在密码学上不可区分 —— 两者都让
/// KEK 变错,AEAD 只会说"认证失败"。所以这里报 `BadPassphrase`,而调用方
/// 负责在文件缺失时给出更准确的那个错。
pub fn unlock(
    wrapped: &WrappedKey,
    passphrase: &[u8],
    device_secret: &LockedBytes,
) -> Result<LockedSigningKey> {
    wrapped.validate()?;

    // ① 重算 AAD 摘要并比对。先于任何密码学。
    let aad = wrapped.verify_aad()?;

    // ② 口令 + device.secret → KEK。
    let salt = wrapped.kdf.salt_bytes()?;
    let mut pass_key = kdf::argon2id(
        passphrase,
        &salt,
        wrapped.kdf.m_cost,
        wrapped.kdf.t_cost,
        wrapped.kdf.p_cost,
    )?;
    let kek = kdf::derive_kek(&pass_key, device_secret, &salt);
    pass_key.zeroize();

    let nonce = wrapped.aead.nonce_bytes()?;

    // ③ KEK 解出 DEK。
    let dek_ciphertext = record::decode_b64(&wrapped.dek_ciphertext)?;
    let dek = exact32(aead::open(&kek, &nonce, &aad, &dek_ciphertext)?)?;

    // ④ DEK 解出 seed。
    let sk_ciphertext = record::decode_b64(&wrapped.sk_ciphertext)?;
    let seed = exact32(dek.expose(|d| aead::open(d, &nonce, &aad, &sk_ciphertext))?)?;

    let key = LockedSigningKey::from_seed(wrapped.id.clone(), seed)?;

    // ⑤ 信封上写的公钥必须就是这把 seed 的公钥。
    //
    // AAD 已经绑住了 `public_multibase`,所以正常路径上这一条不可能不过。
    // 留着是因为它**从私钥侧重新导出**了公钥:万一哪天信封格式变了、或者
    // 有人拿到口令重封了一个自相矛盾的信封,这里会在它走出去之前拦住。
    if key.public_multibase() != wrapped.public_multibase {
        return Err(KeydError::Protocol(
            "envelope advertises a public key that is not the one its sealed private key derives"
                .into(),
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Config;
    use crate::keystore::record::{KeyAlgorithm, KeyId};
    use crate::keystore::wrap::{seal, seed_to_public};
    use crate::sign::Signer;

    const PASS: &[u8] = b"correct horse battery staple";

    fn fast() -> Argon2Config {
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn device(byte: u8) -> LockedBytes {
        LockedBytes::fill(|d| *d = [byte; 32]).unwrap()
    }

    /// 造一个信封,同时把它的 seed 和公钥带出来供比对。
    fn fixture(did_suffix: &str) -> (WrappedKey, [u8; 32], LockedBytes) {
        let seed_bytes = [0x5Au8; 32];
        let seed = LockedBytes::fill(|d| *d = seed_bytes).unwrap();
        let (_, multibase) = seed_to_public(&seed);
        let did = format!("did:wba:example.com:user:alice:{did_suffix}");
        let wrapped = seal(
            KeyId {
                kid: format!("{did}#key-1"),
                did,
                thumbprint: did_suffix.to_string(),
            },
            KeyAlgorithm::Ed25519,
            multibase,
            "alice".into(),
            PASS,
            &device(7),
            &seed,
            fast(),
        )
        .unwrap();
        (wrapped, seed_bytes, seed)
    }

    /// 计划 M1 验收第 1 条:正确口令 + 正确 device.secret → 解出的私钥与
    /// 生成时**逐字节相同**。
    #[test]
    fn unlock_recovers_the_exact_seed() {
        let (wrapped, seed_bytes, _) = fixture("e1_x");
        let key = unlock(&wrapped, PASS, &device(7)).unwrap();

        let (expected_pub, expected_multibase) = seed_to_public(
            &LockedBytes::fill(|d| *d = seed_bytes).unwrap(),
        );

        // 最硬的一条:拿**生成时那把 seed** 的公钥去验解出来这把钥匙的签名。
        // 逐字节相同的话,这一条必然过;差一个 bit 就必然不过。
        assert_eq!(key.public_multibase(), expected_multibase);
        let sig = key.sign(b"probe").unwrap();
        expected_pub
            .verify_strict(b"probe", &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("the unlocked key must be byte-identical to the sealed one");

        assert!(key.verify(b"probe", &sig));
        assert!(!key.verify(b"probe!", &sig));
    }

    /// 负例 A:只给磁盘上的 `keys/*.json`、不给口令 → `BadPassphrase`。
    #[test]
    fn wrong_passphrase_yields_bad_passphrase() {
        let (wrapped, _, _) = fixture("e1_x");
        assert!(matches!(
            unlock(&wrapped, b"not the passphrase", &device(7)),
            Err(crate::error::KeydError::BadPassphrase)
        ));
        // 空口令(等价于"没给口令")同样如此。
        assert!(matches!(
            unlock(&wrapped, b"", &device(7)),
            Err(crate::error::KeydError::BadPassphrase)
        ));
    }

    /// 负例 B 的密码学一侧:口令对、但 `device.secret` 的内容不对 → 解不开。
    /// (文件整个缺失由 `keystore::device::load` 报 `BadDeviceSecret`。)
    #[test]
    fn wrong_device_secret_yields_bad_passphrase() {
        let (wrapped, _, _) = fixture("e1_x");
        assert!(matches!(
            unlock(&wrapped, PASS, &device(8)),
            Err(crate::error::KeydError::BadPassphrase)
        ));
    }

    /// 负例 C:把 A 的信封改标成 B 的 id → `AadMismatch`,且**先于解密**发生。
    #[test]
    fn relabelled_envelope_yields_aad_mismatch() {
        let (mut wrapped, _, _) = fixture("e1_x");
        wrapped.id.did = "did:wba:example.com:user:bob:e1_y".into();
        wrapped.id.kid = "did:wba:example.com:user:bob:e1_y#key-1".into();

        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));
    }

    #[test]
    fn swapping_in_another_keys_ciphertext_fails() {
        let (a, _, _) = fixture("e1_x");
        let (b, _, _) = fixture("e1_y");

        // 只换密文、不换头 —— AAD 会对上,但 AEAD 认证会失败。
        let mut patched = a.clone();
        patched.dek_ciphertext = b.dek_ciphertext.clone();
        patched.aead.nonce = b.aead.nonce.clone();
        assert!(unlock(&patched, PASS, &device(7)).is_err());

        let mut patched = a.clone();
        patched.sk_ciphertext = b.sk_ciphertext.clone();
        patched.aead.nonce = b.aead.nonce.clone();
        assert!(unlock(&patched, PASS, &device(7)).is_err());
    }

    #[test]
    fn tampering_with_kdf_params_is_caught_before_derivation() {
        let (mut wrapped, _, _) = fixture("e1_x");
        // 成本参数参与 AAD,所以在派生 KEK 之前就被拦下 —— 不会去申请
        // 那个被人改过的内存量。
        wrapped.kdf.m_cost = 8;
        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));

        let (mut wrapped, _, _) = fixture("e1_x");
        wrapped.kdf.salt = record::encode_b64(&[0x11; 32]);
        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));
    }

    /// 信封上写的公钥被换成别人的 → 在 AAD 那一步就被拦下。
    #[test]
    fn swapping_the_advertised_public_key_is_refused() {
        let (mut wrapped, _, _) = fixture("e1_x");
        wrapped.public_multibase = "z6Mkattackerattackerattackerattackerattacker".into();
        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));
    }
}
