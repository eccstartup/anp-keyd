//! `proofValue` 的两种字母表 —— 上游发的和对端要的**不是同一种**。
//!
//! ANP-03 §2.5.5(照 W3C Data Integrity)要的是 multibase base58btc,也就是一个
//! `z` 前缀。awiki-open-server 只认这一种(`service_identity._decode_proof_value`
//! 看见别的前缀直接报 `did_document_proof_value_invalid`),anp-sdk 也只发这一种
//! (`crypto/dataIntegrity.encodeProofValue`)。
//!
//! 但上游 `anp` 1.0.6 的 `complete_w3c_proof` 交出来的是**裸的 base64url**
//! (`keys::base64url_encode`,没前缀)。而且它自己那一版验签在看见 `z` 时会换一条
//! **不一样**的签名输入(`proof::verify_w3c_proof` 里把 `@context` 并进 proof options,
//! 那句注释写着 "Keep legacy base64url signing/generation bytes unchanged")——
//! 所以它既发不出对端要的东西,也验不了对端要的东西。两条都在 2026-10-14 量过:
//! 拿它发的 base64url 去注册,服务端报 `did_document_proof_value_invalid`;
//! **同一个签名**换成 `z`+base58btc,注册当场成功。
//!
//! **换字母表不动签名。** 签名的输入是 `jcs(proof options) ‖ jcs(document minus proof)`,
//! 而 `proofValue` 本来就被剔在输入外面(上游的 `compute_signing_input` 只收 `proof`
//! 去掉 `proofValue` 之后的那一份)。这里重编的是**同一批字节**,不是"再签一次"——
//! 所以换完不需要私钥,也不可能因为换而签坏。
//!
//! 反方向的那个函数是给**上游的验签**用的:它只认得 base64url。把文档交给它之前
//! 先换回去,它算出来的签名输入和我们签的那一份逐字节相同(理由同上:`proofValue`
//! 不进输入),于是它验的就是我们真正签过的东西,而不是"同一种东西的另一种编码"。

use base64::Engine as _;
use serde_json::Value;

use crate::error::{KeydError, Result};

/// ANP-03 §2.5.5 / W3C Data Integrity 的 multibase 前缀:base58btc。
const MULTIBASE: char = 'z';

/// 一条 Ed25519 签名固定 64 字节。两边都按它判"这一串到底是不是签名"。
const SIGNATURE_LEN: usize = 64;

/// 上游交出来的 `proofValue`(裸 base64url)→ 对端要的 `z` + base58btc。
pub fn to_multibase(value: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| {
            KeydError::Upstream(format!(
                "the proofValue upstream handed back is not base64url: {error}"
            ))
        })?;
    if bytes.len() != SIGNATURE_LEN {
        return Err(wrong_length("the proofValue upstream handed back", bytes.len()));
    }
    Ok(format!("{MULTIBASE}{}", bs58::encode(&bytes).into_string()))
}

/// 一份文档里 `proofValue`(multibase base58btc)→ 上游验签能读的裸 base64url。
pub fn to_base64url(value: &str) -> Result<String> {
    let body = value.strip_prefix(MULTIBASE).ok_or_else(|| {
        KeydError::Did(format!(
            "the document's proofValue is not multibase base58btc (no `{MULTIBASE}` prefix): {value:?}"
        ))
    })?;
    let bytes = bs58::decode(body).into_vec().map_err(|error| {
        KeydError::Did(format!(
            "the document's proofValue has no valid base58btc in it: {error}"
        ))
    })?;
    if bytes.len() != SIGNATURE_LEN {
        return Err(KeydError::Did(format!(
            "the document's proofValue decodes to {} byte(s), not {SIGNATURE_LEN} — it is not an Ed25519 signature",
            bytes.len()
        )));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
}

/// 就地把一份文档的 `proof.proofValue` 从上游那种换成对端要的那种。
///
/// 没有 `proof`、或者 `proofValue` 不是字符串,都拒 —— 两个调用方都站在
/// "这一份一定有 proof"的位置上,悄悄返回等于把"签名没发生"咽下去。
pub fn into_multibase(document: &mut Value) -> Result<()> {
    rewrite(document, to_multibase)
}

/// 反方向,给上游的验签用。见模块头那段:换的是字母表,不是签名。
pub fn into_base64url(document: &mut Value) -> Result<()> {
    rewrite(document, to_base64url)
}

/// 这一串是不是已经在 multibase base58btc 里了。
///
/// 给"只在对的输入上动手"那种调用方用:一份**没有** `proofValue`、或者
/// `proofValue` 本来就是 base64url 的文档,不该在这里被拦下来 ——
/// "这份文档到底能不能用"由上游那条规范性检查说了算,不是由换字母表这一步。
pub fn is_multibase(value: &str) -> bool {
    value.starts_with(MULTIBASE)
}

/// 一份文档,**上游那版验签读得懂的形式**:只换 `proofValue` 的字母表,别的原样。
///
/// 上游 `anp` 1.0.6 的 `validate_did_document_binding` / `validate_did_document_method`
/// 只认得裸 base64url(理由见模块头),所以任何一个"把文档交给上游"的地方都得先过这一步。
///
/// **只换该换的那种。** 没有 `proof`、`proofValue` 不是字符串、或者本来就是
/// base64url 的,一律原样交回去:"这份文档能不能用"由上游那条规范性检查说了算,
/// 换字母表这一步不该抢在它前面报一句不一样的话。
pub fn as_upstream_reads_it(document: &Value) -> Result<Value> {
    let mut copy = document.clone();
    let multibase = document
        .get("proof")
        .and_then(|proof| proof.get("proofValue"))
        .and_then(Value::as_str)
        .is_some_and(is_multibase);
    if multibase {
        into_base64url(&mut copy)?;
    }
    Ok(copy)
}

fn rewrite(document: &mut Value, how: impl Fn(&str) -> Result<String>) -> Result<()> {
    let proof = proof_object_mut(document)?;
    let current = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| KeydError::Upstream("this document's proof has no proofValue".into()))?
        .to_string();
    proof.insert("proofValue".to_string(), Value::String(how(&current)?));
    Ok(())
}

fn proof_object_mut(document: &mut Value) -> Result<&mut serde_json::Map<String, Value>> {
    document
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| KeydError::Upstream("this document has no proof object".into()))
}

fn wrong_length(what: &str, got: usize) -> KeydError {
    KeydError::Upstream(format!(
        "{what} decodes to {got} byte(s), not {SIGNATURE_LEN} — it is not an Ed25519 signature"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 一条固定的签名(64 字节),用来把两种编码钉死。
    fn signature() -> Vec<u8> {
        (0u8..64).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect()
    }

    fn multibase_of(bytes: &[u8]) -> String {
        format!("{MULTIBASE}{}", bs58::encode(bytes).into_string())
    }

    #[test]
    fn base64url_and_multibase_are_the_same_bytes() {
        let bytes = signature();
        let base64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let multibase = to_multibase(&base64url).unwrap();
        assert_eq!(multibase, multibase_of(&bytes));
        assert_eq!(to_base64url(&multibase).unwrap(), base64url);
    }

    #[test]
    fn a_payload_that_is_not_64_bytes_is_refused_on_both_sides() {
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8, 2, 3]);
        assert!(to_multibase(&short).is_err());
        assert!(to_base64url(&multibase_of(&[1u8, 2, 3])).is_err());
    }

    #[test]
    fn a_multibase_that_is_not_base58btc_is_refused() {
        // base64url 里的 `+`/`/` 不在 base58btc 字母表里;`l` 也不在。
        assert!(to_base64url(&format!("z{}", "l".repeat(64))).is_err());
        // 前缀不对。
        assert!(to_base64url(&multibase_of(&signature())[1..]).is_err());
    }

    #[test]
    fn rewriting_a_document_touches_only_the_proof_value() {
        let mut document = json!({
            "id": "did:wba:example.com:user:e1_x",
            "proof": {
                "type": "DataIntegrityProof",
                "created": "2026-10-14T00:00:00Z",
                "verificationMethod": "did:wba:example.com:user:e1_x#key-1",
                "proofPurpose": "assertionMethod",
                "cryptosuite": "eddsa-jcs-2022",
                "proofValue": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature()),
            },
        });
        let before = document.clone();
        into_multibase(&mut document).unwrap();

        let mut expected = before.clone();
        expected["proof"]["proofValue"] = json!(multibase_of(&signature()));
        assert_eq!(document, expected);

        // 再换回去,逐字节回到原来的那份 —— 换的是字母表,没有别的副作用。
        into_base64url(&mut document).unwrap();
        assert_eq!(document, before);
    }

    #[test]
    fn a_document_without_a_usable_proof_is_refused() {
        assert!(into_multibase(&mut json!({"id": "did:wba:x:y:e1_z"})).is_err());
        assert!(into_multibase(&mut json!({"proof": {}})).is_err());
        assert!(into_multibase(&mut json!({"proof": {"proofValue": 7}})).is_err());
    }
}
