//! RFC 7638 JWK 指纹 → did:wba 的 `e1_` 路径段。
//!
//! 指纹本身由上游 `anp` 算:它是**验签方**会用的同一份实现,自己重算一遍
//! 只会带来"两边算法微妙的差别"这种最难查的 bug。这一层只做拼装和校验。
//!
//! 上游有个容易踩的坑:`compute_multikey_fingerprint` 返回的是**裸的 43 字符
//! base64url 指纹**,`e1_` 前缀是 `anp` 内部自己拼的,不会给你。

use anp::PublicKeyMaterial;
use ed25519_dalek::VerifyingKey;

use crate::error::{KeydError, Result};

/// E1 路径段的字符数:`e1_` + 43。
const E1_FINGERPRINT_LEN: usize = 43;

/// 从 Ed25519 公钥算出 DID 路径最后一段,形如 `e1_<43 字符>`。
pub fn e1_segment(public: &VerifyingKey) -> Result<String> {
    let material = PublicKeyMaterial::Ed25519(*public);
    let fingerprint = anp::authentication::compute_multikey_fingerprint(&material)
        .map_err(|e| KeydError::Upstream(format!("multikey fingerprint failed: {e}")))?;
    debug_assert_eq!(fingerprint.len(), E1_FINGERPRINT_LEN);
    Ok(format!("e1_{fingerprint}"))
}

/// 从完整 DID 里取出最后那一段 `e1_...`。
pub fn e1_from_did(did: &str) -> Result<&str> {
    let last = did
        .rsplit(':')
        .next()
        .ok_or_else(|| KeydError::Did(format!("did has no segments: {did}")))?;
    let rest = last
        .strip_prefix("e1_")
        .ok_or_else(|| KeydError::Did(format!("did path does not end in an e1_ binding: {did}")))?;
    if rest.len() != E1_FINGERPRINT_LEN || !rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(KeydError::Did(format!(
            "malformed e1_ binding segment in did: {last}"
        )));
    }
    Ok(last)
}

/// Ed25519 公钥的 multikey 编码:`z` + base58btc(`0xed 0x01` ‖ 32 字节公钥)。
///
/// 上游有一个等价实现但它是私有的,所以这里重写一份。`0xed 0x01` 是 multicodec
/// 给 ed25519-pub 分配的 varint。
pub fn ed25519_multibase(public: &VerifyingKey) -> String {
    let mut buf = [0u8; 34];
    buf[0] = 0xed;
    buf[1] = 0x01;
    buf[2..].copy_from_slice(&public.to_bytes());
    format!("z{}", bs58::encode(buf).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 TEST 1 的公钥。
    const RFC8032_TEST1_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_TEST1_PK: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn test_key() -> VerifyingKey {
        VerifyingKey::from_bytes(&RFC8032_TEST1_PK).unwrap()
    }

    #[test]
    fn ed25519_derivation_matches_rfc8032_vector() {
        // 先把"RFC 8032 的公钥确实来自那个 seed"钉住,后面的指纹才立得住。
        let sk = ed25519_dalek::SigningKey::from_bytes(&RFC8032_TEST1_SK);
        assert_eq!(sk.verifying_key(), test_key());
    }

    #[test]
    fn multibase_has_the_z6mk_prefix() {
        let mb = ed25519_multibase(&test_key());
        assert!(mb.starts_with("z6Mk"), "ed25519 multikey must start z6Mk, got {mb}");
    }

    #[test]
    fn e1_segment_is_e1_plus_43_chars() {
        let seg = e1_segment(&test_key()).unwrap();
        assert!(seg.starts_with("e1_"));
        assert_eq!(seg.len(), 3 + 43);
        // 与 did_transition.rs 里那条正则同一个字母表。
        assert!(seg[3..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    /// 独立复算一遍指纹,确认上游给的确实是 RFC 7638 的定义。
    ///
    /// 这不是重复上游的实现,而是**验证**上游:JWK 的三个成员按字典序拼装、
    /// JCS 规范化、SHA-256、base64url 无填充 —— 只要上游哪一步走偏就会红。
    #[test]
    fn upstream_fingerprint_is_really_rfc7638() {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let key = test_key();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes());

        // 字典序:crv < kty < x
        let jwk = serde_json::json!({ "crv": "Ed25519", "kty": "OKP", "x": x });
        let canonical = serde_json_canonicalizer::to_vec(&jwk).unwrap();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(&canonical));

        assert_eq!(expected.len(), E1_FINGERPRINT_LEN);
        assert_eq!(e1_segment(&key).unwrap(), format!("e1_{expected}"));
    }

    #[test]
    fn e1_from_did_roundtrips() {
        let seg = e1_segment(&test_key()).unwrap();
        let did = format!("did:wba:example.com:user:alice:{seg}");
        assert_eq!(e1_from_did(&did).unwrap(), seg);
    }

    #[test]
    fn e1_from_did_rejects_non_binding_dids() {
        assert!(e1_from_did("did:wba:example.com:user:alice").is_err());
        assert!(e1_from_did("did:wba:example.com:user:alice:e1_short").is_err());
        assert!(e1_from_did("did:wba:example.com:user:alice:k1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
    }
}
