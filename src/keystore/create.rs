//! 生成一把新的 did:wba 密钥,并把它的信封写下去。
//!
//! 这里的顺序是有讲究的:**先有 seed,再由 seed 推出公钥,再由公钥算出 DID**。
//! 反过来(先定 DID 再想办法凑公钥)是不可能做到的 —— 也就意味着 DID 的
//! `e1_` 段天然就是公钥的指纹,不需要额外信任任何东西。

use serde_json::Value;

use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf::Argon2Config;
use crate::crypto::thumbprint::e1_segment;
use crate::did::document::{build_unsigned, DidDocumentSpec};
use crate::error::Result;
use crate::keystore::layout::KeydLayout;
use crate::keystore::record::{KeyAlgorithm, KeyId, WrappedKey};
use crate::keystore::{device, store, wrap};

/// 一次生成的产物。
pub struct Created {
    /// 要落盘的那个信封。
    pub wrapped: WrappedKey,
    pub did: String,
    /// 根密钥验证方法的完整 id(`did#key-1`)。
    pub verification_method: String,
    /// **未签名**的文档。签名是 `publish` 的事,因为它需要私钥在场。
    pub document: Value,
}

/// 只生成,不碰磁盘。
pub fn generate(
    spec: &DidDocumentSpec,
    label: &str,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    argon: Argon2Config,
) -> Result<Created> {
    // seed 从生到封一直待在锁定区里,中途不出现裸副本。
    let seed = LockedBytes::generate()?;
    let (verifying, public_multibase) = wrap::seed_to_public(&seed);
    let thumbprint = e1_segment(&verifying)?;

    // DID 由上游按公钥算出来 —— 不是我们拼的,所以指纹必然自洽。
    let (did, document) = build_unsigned(spec, &verifying)?;
    let verification_method = format!("{did}#{}", spec.fragment);

    // 上游一定把 e1_ 段追加在最后,这一点我们刚在 build_unsigned 里依赖过;
    // 这里再核一次,免得哪天上游改了行为而 DID 悄悄和公钥脱钩。
    debug_assert!(did.ends_with(&thumbprint), "upstream DID {did} lost the e1_ binding");

    let wrapped = wrap::seal(wrap::SealRequest {
        id: KeyId {
            did: did.clone(),
            kid: verification_method.clone(),
            thumbprint,
        },
        algorithm: KeyAlgorithm::Ed25519,
        public_multibase,
        label: label.to_string(),
        passphrase,
        device_secret,
        seed: &seed,
        argon,
    })?;

    Ok(Created {
        wrapped,
        did,
        verification_method,
        document,
    })
}

/// 生成并落盘:信封进 `keys/`,设备密钥不在就顺手建一把。
///
/// DID 文档**不**在这里写 —— 没有签名的文档写到磁盘上只会让人误以为
/// 它已经发布了。`publish` 负责签完再写。
pub fn create(
    layout: &KeydLayout,
    spec: &DidDocumentSpec,
    label: &str,
    passphrase: &[u8],
    argon: Argon2Config,
) -> Result<Created> {
    layout.ensure()?;
    let device_secret = device::load_or_create(layout)?;

    let created = generate(spec, label, passphrase, &device_secret, argon)?;
    store::save_new(layout, &created.wrapped)?;
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::thumbprint::e1_from_did;
    use crate::sign::Signer;

    fn fast() -> Argon2Config {
        Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    fn spec() -> DidDocumentSpec {
        DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
    }

    fn device() -> LockedBytes {
        LockedBytes::fill(|d| *d = [0x33; 32]).unwrap()
    }

    #[test]
    fn the_key_id_is_consistent_with_the_documents_own_public_key() {
        let c = generate(&spec(), "alice", b"pw", &device(), fast()).unwrap();

        // DID 最后一段 == e1_ 段 == KeyId.thumbprint
        assert_eq!(e1_from_did(&c.did).unwrap(), c.wrapped.id.thumbprint);
        assert!(c.did.ends_with(&c.wrapped.id.thumbprint));
        assert_eq!(c.wrapped.id.did, c.did);
        assert_eq!(
            c.wrapped.id.kid,
            format!("{}#key-1", c.did),
            "the kid must be a real verification method id in the document"
        );
        assert_eq!(c.document["id"], Value::String(c.did.clone()));

        // 信封上写的公钥就是文档里写的公钥。
        let methods = c.document["verificationMethod"].as_array().unwrap();
        assert!(methods
            .iter()
            .any(|m| m["publicKeyMultibase"] == Value::String(c.wrapped.public_multibase.clone())));
    }

    #[test]
    fn two_generated_keys_never_collide() {
        let a = generate(&spec(), "alice", b"pw", &device(), fast()).unwrap();
        let b = generate(&spec(), "alice", b"pw", &device(), fast()).unwrap();
        assert_ne!(a.did, b.did, "each key must get its own DID");
        assert_ne!(a.wrapped.sk_ciphertext, b.wrapped.sk_ciphertext);
    }

    #[test]
    fn create_writes_an_envelope_that_loads_back() {
        let dir = std::env::temp_dir().join(format!("keyd-create-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = KeydLayout::at(dir.clone());
        let created = create(&layout, &spec(), "alice", b"pw", fast()).unwrap();

        // 信封在,设备密钥也在(create 顺手建的)。
        let loaded = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
        assert_eq!(loaded.id.did, created.did);
        assert!(device::exists(&layout));

        // 但没有签名的文档不该出现在 dids/ 里。
        assert!(
            !layout.did_path(&created.did).exists(),
            "create must not publish an unsigned document"
        );

        // 用刚建出来的 device.secret 能解开它。
        let device_secret = device::load(&layout).unwrap();
        let key = crate::keystore::unlock(&loaded, b"pw", &device_secret).unwrap();
        assert_eq!(key.public_multibase(), created.wrapped.public_multibase);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_documents_are_unsigned() {
        let c = generate(&spec(), "alice", b"pw", &device(), fast()).unwrap();
        assert!(
            c.document.get("proof").is_none(),
            "generate must hand back an unsigned document"
        );
    }
}
