//! DID 文档的构造、签名、以及**路径绑定校验**。
//!
//! 绑定校验是这里最要紧的一件事。一个 `did:wba` 的最后一段是
//! `e1_<公钥指纹>` —— 也就是说,DID 这个字符串本身就把公钥写进去了。
//! 于是"文档里的公钥"和"DID 里的指纹"必须互相对得上,否则就是
//! 「拿一个 DID 去兑现一把不属于它的钥匙」。这条检查必须在**发布前**
//! 和**使用前**都做。

use serde_json::Value;

use crate::crypto::thumbprint::e1_segment;
use crate::did::parse::parse_did_wba;
use crate::error::{KeydError, Result};
use crate::sign::{LockedSigningKey, Signer};

/// 根密钥在文档里的 fragment。上游的 `VM_KEY_AUTH` 也是这个值。
pub const ROOT_FRAGMENT: &str = "key-1";

/// 文档里**除根密钥之外**的一把验证方法。
///
/// 上游的 `SuppliedDidKey` 里有一个 `role` 字段,但**它不会写进文档** ——
/// 落到 JSON 里的只有 `id`/`type`/`controller`/`publicKeyMultibase`,加上
/// 它在哪几个关系数组里被列过。所以从文档读回来的时候,role 只能重新猜一个
/// 非根的;好在除此之外它是无损的,而 role 唯一被用到的地方就是"附加密钥
/// 不得是 RootControl"那一条检查。
#[derive(Debug, Clone)]
pub struct ExtraKey {
    pub fragment: String,
    pub public_key: ed25519_dalek::VerifyingKey,
    pub relationships: Vec<anp::authentication::DidVerificationRelationship>,
}

impl ExtraKey {
    pub fn new(
        fragment: impl Into<String>,
        public_key: ed25519_dalek::VerifyingKey,
        relationships: Vec<anp::authentication::DidVerificationRelationship>,
    ) -> Self {
        Self { fragment: fragment.into(), public_key, relationships }
    }
}

/// 一个 did:wba 的"坐标" —— 文档挂在哪、路径是什么。
#[derive(Debug, Clone)]
pub struct DidDocumentSpec {
    /// 域名,不含端口。IP 字面量会被上游拒绝。
    pub host: String,
    pub port: Option<u16>,
    /// `e1_` 段**之前**的路径段。`e1_` 段由上游按公钥算出来追加。
    pub path_segments: Vec<String>,
    pub fragment: String,
}

impl DidDocumentSpec {
    pub fn new(host: impl Into<String>, path_segments: Vec<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            path_segments,
            fragment: ROOT_FRAGMENT.to_string(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_fragment(mut self, fragment: impl Into<String>) -> Self {
        self.fragment = fragment.into();
        self
    }
}

/// 构造一份**未签名**的 did:wba 文档,同时把它的 DID 返回。
///
/// 把 DID 和文档一起返回是刻意的:DID 的最后一段是当前这把公钥算出来的,
/// 调用方没有机会自己拼一个和公钥对不上的 DID 出来。
pub fn build_unsigned(
    spec: &DidDocumentSpec,
    root: &ed25519_dalek::VerifyingKey,
) -> Result<(String, Value)> {
    build_unsigned_with(spec, root, Vec::new())
}

/// 同上,但允许在根密钥之外再挂几把。热密钥和恢复密钥走这里。
pub fn build_unsigned_with(
    spec: &DidDocumentSpec,
    root: &ed25519_dalek::VerifyingKey,
    extra: Vec<ExtraKey>,
) -> Result<(String, Value)> {
    let additional_keys = extra
        .into_iter()
        .map(|key| anp::authentication::SuppliedDidKey {
            fragment: key.fragment,
            // 上游拒收 role 为 `RootControl` 的附加密钥(index > 0 时直接
            // `InvalidDidDocument`)。这不是我们可以绕的:一个 DID 只能有
            // 一个根,其余的都得是别的角色。
            role: anp::authentication::DidKeyRole::RequestSigning,
            public_key: anp::PublicKeyMaterial::Ed25519(key.public_key),
            relationships: key.relationships,
        })
        .collect();

    let options = anp::authentication::SuppliedE1DidDocumentOptions {
        port: spec.port,
        path_segments: spec.path_segments.clone(),
        agent_description_url: None,
        services: Vec::new(),
        root_key: anp::authentication::SuppliedDidKey {
            fragment: spec.fragment.clone(),
            role: anp::authentication::DidKeyRole::RootControl,
            public_key: anp::PublicKeyMaterial::Ed25519(*root),
            relationships: vec![
                anp::authentication::DidVerificationRelationship::Authentication,
                anp::authentication::DidVerificationRelationship::AssertionMethod,
            ],
        },
        additional_keys,
    };

    let document = anp::authentication::build_unsigned_e1_did_document(&spec.host, options)
        .map_err(|e| KeydError::Upstream(format!("building the DID document failed: {e}")))?;

    let did = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| KeydError::Upstream("the built document has no id".into()))?
        .to_string();

    Ok((did, document))
}

/// 用守护进程里的私钥给文档盖上 `DataIntegrityProof`。
///
/// 私钥只在 `Signer::sign` 里露一次面,而且是借出去的;`complete_w3c_proof`
/// 会**自己拿公钥验一遍**我们刚签出来的签名,所以"签错钥匙"这种事在这里
/// 就会当场炸掉,不会流到磁盘上。
pub fn sign_document(
    document: &Value,
    key: &LockedSigningKey,
    verification_method: &str,
) -> Result<Value> {
    let prepared = anp::proof::prepare_w3c_proof(
        document,
        &key.anp_public_key(),
        verification_method,
        anp::proof::ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".into()),
            proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.into()),
            cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.into()),
            created: None,
            domain: None,
            challenge: None,
        },
    )
    .map_err(|e| KeydError::Upstream(format!("preparing the DID document proof failed: {e}")))?;

    let signature = key.sign(prepared.signing_input())?;

    anp::proof::complete_w3c_proof(prepared, &signature)
        .map_err(|e| KeydError::Upstream(format!("completing the DID document proof failed: {e}")))
}

/// 从 DID 字符串 + 公钥**重建**出那份文档。
///
/// 签名路径需要文档,但签名路径手里只有磁盘上的信封(它存了 DID 和公钥),
/// 没有当初构造文档时的那些参数。好在 DID 本身就是那些参数的编码 ——
/// 域名、端口、路径段全在里面。
///
/// 重建之后**必须**和原来的 DID 逐字节相等,否则拒。这一条保证了
/// 「我们手上的 DID」和「我们重建出的文档」说的是同一件事;不相等就说明
/// 这个 DID 不是规范形式(比如被额外百分号编码过),那就别猜,直接失败。
pub fn rebuild(did: &str, root: &ed25519_dalek::VerifyingKey) -> Result<Value> {
    rebuild_with(did, root, Vec::new())
}

/// 同上,但把附加密钥一起挂回去。
///
/// **给已经挂了热密钥/恢复密钥的 DID 重发文档时必须走这一条。** 走
/// [`rebuild`] 等于拿着一份只有根密钥的文档去盖掉线上那份 —— 而
/// `deactivated`/`successorDid` 也好、热密钥也好、恢复密钥也好,全在
/// 那次重发里消失。这正是"文档是以 DIDs 为键的、覆盖写"这件事最危险的地方:
/// 覆盖不会报错,只会静静地少掉东西。
pub fn rebuild_with(
    did: &str,
    root: &ed25519_dalek::VerifyingKey,
    extra: Vec<ExtraKey>,
) -> Result<Value> {
    let parts = parse_did_wba(did)?;
    let mut path_segments = parts.path_segments.clone();
    let last = path_segments
        .pop()
        .ok_or_else(|| KeydError::Did(format!("{did} has no e1_ binding segment")))?;
    if !last.starts_with("e1_") {
        return Err(KeydError::Did(format!("{did} has no e1_ binding segment")));
    }

    let spec = DidDocumentSpec {
        host: parts.host,
        port: parts.port,
        path_segments,
        fragment: ROOT_FRAGMENT.to_string(),
    };
    let (rebuilt, document) = build_unsigned_with(&spec, root, extra)?;
    if rebuilt != did {
        return Err(KeydError::Did(format!(
            "{did} is not in the canonical form this build produces (got {rebuilt})"
        )));
    }
    Ok(document)
}

/// 校验一份文档确实是它自称的那个 DID 的文档。
///
/// 三道,缺一不可:
/// 1. `document.id` 就是我们要找的 DID —— 上游的绑定检查是从文档里读 id
///    再自己和自己比,所以它查不出"这是别人的文档";
/// 2. **自己重算** `e1_` 指纹,和对得上才算过 —— 给的是能查原因的错误;
/// 3. 上游的规范性检查(含 proof 验签)。
pub fn verify_path_binding(did: &str, document: &Value) -> Result<()> {
    let parts = parse_did_wba(did)?;
    let expected = parts
        .e1_segment()
        .ok_or_else(|| KeydError::Did(format!("{did} has no e1_ binding segment")))?;

    let document_id = document.get("id").and_then(Value::as_str).unwrap_or_default();
    if document_id != did {
        return Err(KeydError::Did(format!(
            "this document is {document_id:?}, not {did:?}"
        )));
    }

    let method = authentication_method(document).ok_or_else(|| {
        KeydError::Did("no authentication-authorized verification method in the document".into())
    })?;
    let material = anp::authentication::extract_public_key(&method)
        .map_err(|e| KeydError::Did(format!("unreadable verification method: {e}")))?;
    let actual = match &material {
        anp::PublicKeyMaterial::Ed25519(pk) => e1_segment(pk)?,
        _ => {
            return Err(KeydError::Did(
                "the e1_ path binding requires an Ed25519 root key".into(),
            ))
        }
    };
    if actual != expected {
        return Err(KeydError::Did(format!(
            "{did} claims fingerprint {expected}, but its key hashes to {actual}"
        )));
    }

    if !anp::authentication::validate_did_document_binding(document, true) {
        return Err(KeydError::Did(format!(
            "the document for {did} failed the normative did:wba binding check"
        )));
    }
    Ok(())
}

/// 找回一份文档里被 `authentication` 授权的那把验证方法。
fn authentication_method(document: &Value) -> Option<Value> {
    let authorized = document.get("authentication")?.as_array()?;
    authorized.iter().find_map(|entry| {
        // `authentication` 里可能是内联对象,也可能是一个引用字符串。
        let id = entry
            .as_str()
            .or_else(|| entry.get("id").and_then(Value::as_str))?;
        if !anp::authentication::is_authentication_authorized(document, id) {
            return None;
        }
        anp::authentication::find_verification_method(document, id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::keystore::record::KeyId;

    fn key(seed_byte: u8) -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId {
                did: String::new(),
                kid: String::new(),
                thumbprint: String::new(),
            },
            seed,
        )
        .unwrap()
    }

    fn spec() -> DidDocumentSpec {
        DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
    }

    fn signed_document(seed_byte: u8) -> (String, Value) {
        let k = key(seed_byte);
        let (did, unsigned) = build_unsigned(&spec(), &k.verifying_key()).unwrap();
        let method = format!("{did}#{ROOT_FRAGMENT}");
        let signed = sign_document(&unsigned, &k, &method).unwrap();
        (did, signed)
    }

    #[test]
    fn the_did_ends_with_the_keys_own_fingerprint() {
        let k = key(3);
        let (did, doc) = build_unsigned(&spec(), &k.verifying_key()).unwrap();

        let expected = e1_segment(&k.verifying_key()).unwrap();
        assert!(did.starts_with("did:wba:example.com:user:alice:"), "{did}");
        assert!(did.ends_with(&expected), "{did} should end with {expected}");
        assert_eq!(doc["id"], did.as_str());
    }

    #[test]
    fn the_root_key_lands_in_authentication_and_assertion() {
        let k = key(4);
        let (did, doc) = build_unsigned(&spec(), &k.verifying_key()).unwrap();
        let method = format!("{did}#{ROOT_FRAGMENT}");

        for relationship in ["authentication", "assertionMethod"] {
            let list = doc[relationship].as_array().unwrap();
            assert!(
                list.iter().any(|v| v.as_str() == Some(method.as_str())),
                "{relationship} must list the root key"
            );
        }
    }

    #[test]
    fn signing_produces_a_verifiable_data_integrity_proof() {
        let (did, doc) = signed_document(5);
        let proof = &doc["proof"];

        assert_eq!(proof["type"], anp::proof::PROOF_TYPE_DATA_INTEGRITY);
        assert_eq!(proof["cryptosuite"], anp::proof::CRYPTOSUITE_EDDSA_JCS_2022);
        assert_eq!(proof["proofPurpose"], "assertionMethod");
        assert_eq!(proof["verificationMethod"], format!("{did}#{ROOT_FRAGMENT}"));

        // 上游的规范性检查会连 proof 一起验。
        assert!(anp::authentication::validate_did_document_binding(&doc, true));
        assert!(verify_path_binding(&did, &doc).is_ok());
    }

    /// 核心攻击面:拿一份**别的钥匙**签出来的文档,冒充成这个 DID 的文档。
    /// 第一步就得被 DID 里的指纹拦住。
    #[test]
    fn a_document_signed_by_another_key_cannot_claim_this_did() {
        let (did, _) = signed_document(6);
        let (_, other_doc) = signed_document(7);

        // 把别的文档的 id 改成我们问的这个 DID,假装它是。
        let mut imposter = other_doc.clone();
        imposter["id"] = Value::String(did.clone());

        assert!(
            verify_path_binding(&did, &imposter).is_err(),
            "a document whose key does not hash to the DID's fingerprint must be refused"
        );
    }

    /// 把文档里的公钥换成另一把 —— 指纹对不上,必须拒。
    #[test]
    fn swapping_the_public_key_breaks_the_binding() {
        let (did, doc) = signed_document(8);
        let other = key(9);

        let mut tampered = doc.clone();
        let method_id = format!("{did}#{ROOT_FRAGMENT}");
        let multibase = other.public_multibase().to_string();
        for m in tampered["verificationMethod"].as_array_mut().unwrap() {
            if m["id"].as_str() == Some(method_id.as_str()) {
                m["publicKeyMultibase"] = Value::String(multibase.clone());
            }
        }

        assert!(verify_path_binding(&did, &tampered).is_err());
    }

    #[test]
    fn an_unsigned_document_does_not_pass_the_binding_check() {
        let k = key(10);
        let (did, unsigned) = build_unsigned(&spec(), &k.verifying_key()).unwrap();

        // 指纹那一条过得去(公钥确实是对的),但没有 proof,规范性检查必须拒。
        assert!(verify_path_binding(&did, &unsigned).is_err());
    }

    #[test]
    fn a_did_without_an_e1_segment_is_refused() {
        let (_, doc) = signed_document(11);
        assert!(verify_path_binding("did:wba:example.com:user:alice", &doc).is_err());
    }

    #[test]
    fn port_and_extra_path_segments_survive_the_round_trip() {
        let k = key(12);
        let spec = DidDocumentSpec::new("example.com", vec!["user".into(), "bob".into()])
            .with_port(8443);
        let (did, unsigned) = build_unsigned(&spec, &k.verifying_key()).unwrap();

        assert!(did.starts_with("did:wba:example.com%3A8443:user:bob:"), "{did}");
        // 端口必须能从 DID 解回 URL —— 否则发布出去没人找得到。
        assert_eq!(
            crate::did::parse::did_url_path(&did).unwrap(),
            format!(
                "https://example.com:8443/user/bob/{}/did.json",
                e1_segment(&k.verifying_key()).unwrap()
            )
        );

        let method = format!("{did}#{ROOT_FRAGMENT}");
        let signed = sign_document(&unsigned, &k, &method).unwrap();
        assert!(verify_path_binding(&did, &signed).is_ok());
    }
}
