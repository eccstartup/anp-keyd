//! 磁盘记录 —— 信封的线格式。
//!
//! 磁盘上唯一存的是 `WrappedKey`。**没有任何字段携带明文密钥。**

use serde::{Deserialize, Serialize};

use crate::crypto::aead::NONCE_LEN;
use crate::error::{KeydError, Result};

/// 一个密钥在 did:wba 世界里的完整坐标。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyId {
    /// 形如 `did:wba:example.com:user:alice:e1_<指纹>`
    pub did: String,
    /// 形如 `did:wba:example.com:user:alice:e1_<指纹>#key-1`
    pub kid: String,
    /// `e1_` + 公钥 JWK 的 RFC 7638 指纹
    pub thumbprint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
    P256,
}

impl KeyAlgorithm {
    /// 磁盘上用 `serde` 的字符串,线上用单字节 —— 线上的编号一旦定下
    /// **就不能再改**,所以显式写出来,不跟着枚举顺序走。
    pub fn to_wire(self) -> u8 {
        match self {
            Self::Ed25519 => 0x01,
            Self::P256 => 0x02,
        }
    }

    /// 认不出来就是 `None`。**不许蒙一个默认值** —— 把 P-256 的密钥
    /// 当成 Ed25519 用,后果是签出来的东西验不过,或者更糟。
    pub fn from_wire(raw: u8) -> Option<Self> {
        match raw {
            0x01 => Some(Self::Ed25519),
            0x02 => Some(Self::P256),
            _ => None,
        }
    }
}

/// 口令派生的参数。**随信封一起存**,因为解开它必须重现这些参数。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// `"argon2id"`
    pub alg: String,
    /// base64, 32B
    pub salt: String,
    /// KiB
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub fn salt_bytes(&self) -> Result<Vec<u8>> {
        decode_b64(&self.salt)
    }
}

/// AEAD 的参数。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AeadParams {
    /// `"xchacha20poly1305"`
    pub alg: String,
    /// base64, 24B
    pub nonce: String,
    /// base64, SHA-256(信封头 JCS) —— 防移植/重放
    pub aad_digest: String,
}

impl AeadParams {
    pub fn nonce_bytes(&self) -> Result<[u8; NONCE_LEN]> {
        let raw = decode_b64(&self.nonce)?;
        raw.try_into()
            .map_err(|_| KeydError::Protocol(format!("nonce must be {NONCE_LEN} bytes")))
    }
}

/// 信封头里参与 AAD 的那部分字段。
///
/// 这一组字段就是"信封的身份"。改其中任何一个,解密都会失败 ——
/// 所以 A 的信封无法被改标成 B 的。
///
/// 比计划 §四列的字段多三个:`kdf_m_cost` / `kdf_t_cost` / `kdf_p_cost`。
/// 信封文件是**不可信输入**,而成本参数决定了解开它时守护进程要申请多少
/// 内存 —— 不绑进 AAD,能写这个文件的人就能替守护进程挑 Argon2 的内存开销
/// (抬到几 GB 就是一次 OOM),而且症状和"口令错"长得一模一样。
/// 绑进来之后,这类改动在**分配任何内存之前**就以 `AadMismatch` 暴露。
#[derive(Debug, Serialize)]
struct AadHeader<'a> {
    version: u8,
    did: &'a str,
    kid: &'a str,
    algorithm: KeyAlgorithm,
    public_multibase: &'a str,
    kdf_alg: &'a str,
    kdf_salt: &'a str,
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    label: &'a str,
}

/// 磁盘上唯一存的东西。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WrappedKey {
    pub version: u8,
    pub id: KeyId,
    pub algorithm: KeyAlgorithm,
    /// 公钥,可公开。`z6Mk...` multibase
    pub public_multibase: String,
    /// 人读的标签,仅供 `LIST_KEYS` 展示
    #[serde(default)]
    pub label: String,
    pub kdf: KdfParams,
    pub aead: AeadParams,
    /// base64(被 KEK 包住的 DEK)
    pub dek_ciphertext: String,
    /// base64(被 DEK 包住的 Ed25519 seed)
    pub sk_ciphertext: String,
    /// RFC3339
    pub created_at: String,
    /// v1 恒为 None;分层信封就是给硬件根留的这个位置(计划 §2.4)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware: Option<HardwareRoot>,
}

/// v1 不实现,但**结构留在这里** —— 密钥层级分两层正是为了让 SE/TPM
/// 能插进 KEK 那一层当包装密钥。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HardwareRoot {
    SecureEnclave { tag: String },
    Tpm { handle: u32 },
}

pub const RECORD_VERSION: u8 = 1;

impl WrappedKey {
    /// 安全等级:从磁盘读回来的记录先过这一关,再谈密码学。
    pub fn validate(&self) -> Result<()> {
        if self.version != RECORD_VERSION {
            return Err(KeydError::Protocol(format!(
                "unsupported envelope version {} (this build speaks {RECORD_VERSION})",
                self.version
            )));
        }
        if self.id.thumbprint.is_empty() || self.id.did.is_empty() || self.id.kid.is_empty() {
            return Err(KeydError::Protocol("envelope has an incomplete KeyId".into()));
        }
        Ok(())
    }

    /// 重算 AAD 摘要。
    ///
    /// **每一次解开之前都要重算**,再和存下来的 `aead.aad_digest` 比。
    /// 这个比对先于任何解密,所以"被改过标签的信封"在这里就露馅了。
    pub fn aad_digest(&self) -> Result<[u8; 32]> {
        let header = AadHeader {
            version: self.version,
            did: &self.id.did,
            kid: &self.id.kid,
            algorithm: self.algorithm,
            public_multibase: &self.public_multibase,
            kdf_alg: &self.kdf.alg,
            kdf_salt: &self.kdf.salt,
            kdf_m_cost: self.kdf.m_cost,
            kdf_t_cost: self.kdf.t_cost,
            kdf_p_cost: self.kdf.p_cost,
            label: &self.label,
        };
        let canonical = serde_json_canonicalizer::to_vec(&header)
            .map_err(|e| KeydError::Protocol(format!("jcs failed on envelope header: {e}")))?;
        Ok(crate::crypto::sha256(&canonical))
    }

    /// 信封上那把公钥,读回成一把可用的钥匙。
    ///
    /// 文档的**重建**用它:DID 文档里写什么,取决于这把钥匙;而重建发生在
    /// 签名之前、在解密之后 —— 手上当时只有信封和刚解出来的 seed。从 seed
    /// 再推一次公钥也行,但那是"再算一遍",而这里要的是"信封上声明的是哪
    /// 一把" —— 两者一旦不同,信封就已经坏了,那就该在这里炸掉。
    pub fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        if self.algorithm != KeyAlgorithm::Ed25519 {
            return Err(KeydError::Protocol(
                "this build only holds Ed25519 keys".into(),
            ));
        }
        crate::crypto::thumbprint::ed25519_from_multibase(&self.public_multibase)
    }

    /// AAD 自检:摘要是重新算出来的,不是信存下来的那个数。
    pub fn verify_aad(&self) -> Result<[u8; 32]> {
        let recomputed = self.aad_digest()?;
        let stored = decode_b64(&self.aead.aad_digest)?;
        // 定长比较,不因为"摘要不是秘密"就偷懒用 `==`。
        if !crate::crypto::ct_eq(&recomputed, &stored) {
            return Err(KeydError::AadMismatch);
        }
        Ok(recomputed)
    }
}

pub(crate) fn encode_b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn decode_b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| KeydError::Protocol(format!("bad base64 in envelope: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WrappedKey {
        WrappedKey {
            version: RECORD_VERSION,
            id: KeyId {
                did: "did:wba:example.com:user:alice:e1_abc".into(),
                kid: "did:wba:example.com:user:alice:e1_abc#key-1".into(),
                thumbprint: "e1_abc".into(),
            },
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: "z6Mkexample".into(),
            label: "alice".into(),
            kdf: KdfParams {
                alg: "argon2id".into(),
                salt: encode_b64(&[1u8; 32]),
                m_cost: 65536,
                t_cost: 3,
                p_cost: 1,
            },
            aead: AeadParams {
                alg: "xchacha20poly1305".into(),
                nonce: encode_b64(&[2u8; NONCE_LEN]),
                aad_digest: String::new(),
            },
            dek_ciphertext: encode_b64(&[3u8; 48]),
            sk_ciphertext: encode_b64(&[4u8; 48]),
            created_at: "2026-10-13T00:00:00Z".into(),
            hardware: None,
        }
    }

    #[test]
    fn aad_is_stable_across_serialization() {
        let k = sample();
        assert_eq!(k.aad_digest().unwrap(), k.aad_digest().unwrap());
    }

    #[test]
    fn relabelling_the_did_breaks_the_aad() {
        let mut k = sample();
        let sealed = k.aad_digest().unwrap();
        k.aead.aad_digest = encode_b64(&sealed);

        // 现在把信封改标成"别人的"。
        k.id.did = "did:wba:example.com:user:bob:e1_abc".into();
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    #[test]
    fn changing_the_label_breaks_the_aad() {
        let mut k = sample();
        let sealed = k.aad_digest().unwrap();
        k.aead.aad_digest = encode_b64(&sealed);

        k.label = "production".into();
        assert!(
            matches!(k.verify_aad(), Err(KeydError::AadMismatch)),
            "a label the user reads must not be silently editable"
        );
    }

    /// 成本参数必须绑进 AAD —— 否则能写这个文件的人就能替守护进程挑
    /// Argon2 的内存开销。
    #[test]
    fn downgrading_the_cost_params_breaks_the_aad() {
        for tamper in [
            (|k: &mut WrappedKey| k.kdf.m_cost = 8) as fn(&mut WrappedKey),
            |k: &mut WrappedKey| k.kdf.t_cost = 1,
            |k: &mut WrappedKey| k.kdf.p_cost = 4,
        ] {
            let mut k = sample();
            k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
            tamper(&mut k);
            assert!(
                matches!(k.verify_aad(), Err(KeydError::AadMismatch)),
                "cost parameters are part of the envelope's identity"
            );
        }
    }

    /// 公钥也是信封身份的一部分:换掉它等于让守护进程对外宣称一把
    /// 自己签不出来的钥匙。
    #[test]
    fn swapping_the_public_key_breaks_the_aad() {
        let mut k = sample();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());

        k.public_multibase = "z6Mkattacker".into();
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    #[test]
    fn changing_the_salt_breaks_the_aad() {
        let mut k = sample();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());

        k.kdf.salt = encode_b64(&[9u8; 32]);
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    #[test]
    fn verifying_a_matching_aad_succeeds() {
        let mut k = sample();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
        assert!(k.verify_aad().is_ok());
    }

    /// 信封上写的公钥要能读回成一把真钥匙 —— 重建文档时用的就是它。
    #[test]
    fn the_envelope_public_key_reads_back() {
        let seed = crate::crypto::hygiene::LockedBytes::fill(|d| *d = [5u8; 32]).unwrap();
        let (expected, multibase) = crate::keystore::wrap::seed_to_public(&seed);

        let mut k = sample();
        k.public_multibase = multibase;
        assert_eq!(k.verifying_key().unwrap(), expected);

        // 不是 Ed25519 的算法不在这里"试着解一下"。
        k.algorithm = KeyAlgorithm::P256;
        assert!(k.verifying_key().is_err());
    }
}
