//! RFC 9421 HTTP 消息签名 —— **由守护进程决定签什么**。
//!
//! 这个模块是"agent 手里从来没有私钥字节"这句话最容易被架空的地方。
//! 光是不给私钥不够:如果 agent 能挑「这条签名覆盖哪些分量」,它就能让守护
//! 进程签一条只覆盖 `@method` 的签名,拿去配一个完全不同的 body 和 URL ——
//! 私钥没泄露,但签名被用在了别处。这就是盲目签名。
//!
//! 所以这里的规矩是:
//!
//! 1. **覆盖面由 [`required_components`] 决定,不接受调用方输入。**
//! 2. 请求里凡是会进入签名基的东西(方法、URL、头值)先过一遍边界校验 ——
//!    签名基是**按行**拼的,一个带 `\n` 的头值能凭空插进一行
//!    `"@authority": evil.com`,那就等于把覆盖面让给了调用方。
//! 3. 拼完之后**再从签名基里把覆盖面解析回来**,确认它真的是我们要的那一组。
//!    这一步不信任上游,也不信任我们自己的调用参数。

use std::collections::BTreeMap;

use serde_json::Value;

use crate::crypto::sha256;
use crate::error::{KeydError, Result};
use crate::sign::{LockedSigningKey, Signer};

/// 一条待签的 HTTP 请求。
#[derive(Debug, Clone)]
pub struct SignRequest {
    /// HTTP 方法,如 `POST`、`GET`。
    pub method: String,
    /// 完整的请求 URL(`@target-uri` 就是它)。
    pub url: String,
    pub headers: BTreeMap<String, String>,
    /// 请求体。给了就一定会覆盖 `content-digest`。
    pub body: Option<Vec<u8>>,
}

/// 签完之后的产物。
#[derive(Debug, Clone)]
pub struct Signed {
    /// 要加到请求上的头:`Signature-Input`、`Signature`,有 body 时还有 `Content-Digest`。
    pub headers: BTreeMap<String, String>,
    /// **实际**被覆盖的分量,从签名基里解析回来的。
    pub covered: Vec<String>,
    /// 签名基的 SHA-256 —— 审计日志记这个,不记签名基本身。
    pub signature_base_digest: [u8; 32],
}

/// 守护进程要求覆盖的最小集合。
///
/// 少了 `@method`,签名可以被换成另一个方法;少了 `@target-uri`,可以被换成
/// 另一个资源;少了 `@authority`,可以被换成另一个服务。有 body 时少了
/// `content-digest`,签名就和 body 脱钩了,body 可以随便换。
///
/// 这是一个**下限**,不随调用方的意愿变。
pub fn required_components(req: &SignRequest) -> Vec<String> {
    let mut components = vec![
        "@method".to_string(),
        "@target-uri".to_string(),
        "@authority".to_string(),
    ];
    if req.body.is_some() {
        components.push("content-digest".to_string());
    }
    components
}

impl SignRequest {
    /// 进入签名基之前必须过的那一关。
    pub fn validate(&self) -> Result<()> {
        validate_method(&self.method)?;
        validate_url(&self.url)?;
        for (name, value) in &self.headers {
            validate_header_name(name)?;
            validate_header_value(name, value)?;
        }
        self.validate_content_digest()
    }

    /// 请求体的摘要必须是**守护进程自己算的**。
    ///
    /// 上游的 `prepare_http_signature_headers` 往头表里填 `Content-Digest`
    /// 用的是 `or_insert_with` —— 调用方要是预先塞了一个,上游就会照着那个
    /// 值去签,而那个值和真实请求体可以毫无关系。上游的 verifier 会重算摘要
    /// 从而发现不一致,但不是每个验签方都会这么做;只信签名、不核对 body 的
    /// 验签方就会中招。
    fn validate_content_digest(&self) -> Result<()> {
        let Some((name, supplied)) = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-digest"))
        else {
            return Ok(());
        };

        let Some(body) = &self.body else {
            return Err(KeydError::Protocol(format!(
                "header {name:?} is present but there is no body; a digest the daemon did not \
                 compute itself must never reach the signature base"
            )));
        };

        let actual = anp::authentication::build_content_digest(body);
        if supplied.trim() != actual {
            return Err(KeydError::Protocol(format!(
                "the supplied Content-Digest does not match the request body, which hashes to {actual}"
            )));
        }
        Ok(())
    }
}

/// 签一条请求。
///
/// 顺序是刻意的:先校验输入 → 定覆盖面 → 让上游拼基 → **把覆盖面解析回来核对**
/// → 才把字节递给私钥。私钥一签,就再也没有回头路了。
pub fn sign_request(
    document: &Value,
    key: &LockedSigningKey,
    req: &SignRequest,
) -> Result<Signed> {
    req.validate()?;
    let required = required_components(req);

    // 把调用方的 `Content-Digest` 摘掉,让上游按**我们自己**看到的 body 重新算。
    // 上面已经校验过它和 body 一致,所以摘掉不会改变结果 —— 但它从此不再可能
    // 是一条由调用方选定的值。
    let mut headers = req.headers.clone();
    headers.retain(|name, _| !name.eq_ignore_ascii_case("content-digest"));

    let prepared = anp::authentication::prepare_http_signature_headers(
        document,
        &req.url,
        &req.method,
        Some(&headers),
        req.body.as_deref(),
        anp::authentication::HttpSignatureOptions {
            keyid: Some(key.id().kid.clone()),
            nonce: None,
            created: None,
            expires: None,
            // 这里就是"守护进程决定"落到实处的地方 —— 这个值不是调用方给的。
            covered_components: Some(required.clone()),
        },
    )
    .map_err(|e| KeydError::Upstream(format!("preparing the HTTP signature failed: {e}")))?;

    let signature_base = prepared.signing_input();
    let signature_base_text = std::str::from_utf8(signature_base)
        .map_err(|_| KeydError::Protocol("the signature base is not valid UTF-8".into()))?;

    // 在签名**之前**核对:签名基里真正被覆盖的,必须包含我们要的那一组。
    let covered = verify_covered_set(signature_base_text, &required)?;
    let signature_base_digest = sha256(signature_base);

    let signature = key.sign(signature_base)?;

    // `complete_http_signature_headers` 会拿文档里的公钥先验一遍我们刚签出来的
    // 签名。签错钥匙这种事在这一步当场炸掉,不会流出去。
    let headers = anp::authentication::complete_http_signature_headers(prepared, &signature)
        .map_err(|e| KeydError::Upstream(format!("completing the HTTP signature failed: {e}")))?;

    Ok(Signed {
        headers,
        covered,
        signature_base_digest,
    })
}

/// 从签名基里把**实际**被覆盖的分量解析回来,并确认 `required` 全在里面。
///
/// 解析的是 `@signature-params` 那一行括号里的列表 —— RFC 9421 规定它就是
/// 覆盖面的权威声明。另外核对每个列出来的分量在基里都真有对应的一行,免得
/// 出现「声称覆盖了、其实没写进去」。
pub fn verify_covered_set(signature_base: &str, required: &[String]) -> Result<Vec<String>> {
    let covered = covered_components(signature_base)?;

    for want in required {
        if !covered.iter().any(|c| c.eq_ignore_ascii_case(want)) {
            return Err(KeydError::CoveredSetRejected(format!(
                "{want} is missing from the covered set; \
                 a signature that does not cover it can be replayed against another request"
            )));
        }
    }

    // 已被覆盖的分量必须在基里有自己那一行 —— 否则基是残缺的。
    let present = base_line_components(signature_base);
    for component in &covered {
        if !present.iter().any(|p| p.eq_ignore_ascii_case(component)) {
            return Err(KeydError::CoveredSetRejected(format!(
                "{component} is listed as covered but has no line in the signature base"
            )));
        }
    }

    Ok(covered)
}

/// 解析签名基里 `@signature-params` 的括号列表。
fn covered_components(signature_base: &str) -> Result<Vec<String>> {
    let params_line = signature_base
        .lines()
        .find(|line| line.starts_with("\"@signature-params\":"))
        .ok_or_else(|| {
            KeydError::CoveredSetRejected("the signature base has no @signature-params line".into())
        })?;

    let list = params_line
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(inner, _)| inner)
        .ok_or_else(|| {
            KeydError::CoveredSetRejected("the @signature-params line has no component list".into())
        })?;

    let parsed = parse_component_list(list)?;
    if parsed.is_empty() {
        return Err(KeydError::CoveredSetRejected(
            "the signature covers nothing at all".into(),
        ));
    }
    Ok(parsed)
}

/// `"@method" "@authority" "content-digest";sf` → `["@method", "@authority", "content-digest"]`
///
/// 分量后面可以跟参数(如 `;sf`、`;key="x"`),但这里只关心分量本身。
fn parse_component_list(list: &str) -> Result<Vec<String>> {
    let bytes = list.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] != b'"' {
            return Err(KeydError::CoveredSetRejected(format!(
                "malformed component list at byte {i}: expected a quoted component id"
            )));
        }
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i >= bytes.len() {
            return Err(KeydError::CoveredSetRejected(
                "unterminated component id in the signature params".into(),
            ));
        }
        // 引号都是 ASCII,所以这里一定切在字符边界上。
        out.push(list[start..i].to_string());
        i += 1;
        // 跳过分量后面的参数,吃到下一个**不在引号里**的空白为止。
        // 参数值可以是带空格的引号串(`;key="a b"`),所以不能只找空白。
        while i < bytes.len() {
            match bytes[i] {
                b if b.is_ascii_whitespace() => break,
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                }
                _ => i += 1,
            }
        }
    }

    Ok(out)
}

/// 基里每一行的分量名(不含 `@signature-params` 那行)。
fn base_line_components(signature_base: &str) -> Vec<String> {
    signature_base
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix('"')?;
            let (name, _) = rest.split_once("\":")?;
            Some(name.to_string())
        })
        .collect()
}

/// RFC 7230 的 token 字符集。
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
                        | b'_' | b'`' | b'|' | b'~'
                )
        })
}

/// 有控制字符就会破坏"一行一个分量"的签名基结构。
fn has_control_characters(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || c == '\u{7f}')
}

fn validate_method(method: &str) -> Result<()> {
    if !method.bytes().all(|b| b.is_ascii_uppercase()) || !is_token(method) {
        return Err(KeydError::Protocol(format!(
            "{method:?} is not an uppercase HTTP method token"
        )));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<()> {
    if has_control_characters(url) {
        return Err(KeydError::Protocol(
            "the request URL contains control characters".into(),
        ));
    }
    if url.contains(' ') {
        return Err(KeydError::Protocol(
            "the request URL contains a space; it must be percent-encoded".into(),
        ));
    }
    if !url.starts_with("https://") {
        // did:wba 是绑在域名上的身份,明文 HTTP 上没有任何意义。
        return Err(KeydError::Protocol(format!(
            "refusing to sign a non-HTTPS request URL: {url:?}"
        )));
    }
    let rest = &url["https://".len()..];
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err(KeydError::Protocol(format!(
            "the request URL has no authority: {url:?}"
        )));
    }
    // 带 userinfo 的 URL 会让 `@authority` 的抽取结果和用户的直觉不一致。
    if authority.contains('@') {
        return Err(KeydError::Protocol(format!(
            "the request URL carries userinfo, which is not signed as part of @authority: {url:?}"
        )));
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<()> {
    if !is_token(name) {
        return Err(KeydError::Protocol(format!(
            "{name:?} is not a valid HTTP header name"
        )));
    }
    Ok(())
}

/// 头值里的换行会**伪造出一整行签名基**。
///
/// 签名基是按行拼的,一行形如 `"名字": 值`。一个值为
/// `x\r\n"@authority": evil.com` 的头能插进一行假的 `@authority`,
/// 于是"覆盖了 @authority"这句话就变成假的 —— 覆盖面被调用方拿到了。
fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(KeydError::Protocol(format!(
            "header {name:?} contains a line break; it would forge signature base lines"
        )));
    }
    if has_control_characters(value) {
        return Err(KeydError::Protocol(format!(
            "header {name:?} contains control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::did::document::{build_unsigned, sign_document, DidDocumentSpec};
    use crate::keystore::record::KeyId;

    fn key(seed_byte: u8) -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId { did: String::new(), kid: String::new(), thumbprint: String::new() },
            seed,
        )
        .unwrap()
    }

    /// 造一把钥匙 + 它自己的(已签名)文档 —— 上游要文档来查 keyid 的授权。
    fn fixture(seed_byte: u8) -> (LockedSigningKey, Value) {
        let k = key(seed_byte);
        let spec = DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()]);
        let (did, unsigned) = build_unsigned(&spec, &k.verifying_key()).unwrap();
        let signed = sign_document(&unsigned, &k, &format!("{did}#key-1")).unwrap();

        // 文档必须是自洽的,否则后面测的就不是签名逻辑了。
        crate::did::document::verify_path_binding(&did, &signed).unwrap();

        // 把 kid 补成文档里的那个 —— fixture 里先造了空 id。
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        let with_id = LockedSigningKey::from_seed(
            KeyId {
                did: did.clone(),
                kid: format!("{did}#key-1"),
                thumbprint: did.rsplit(':').next().unwrap().to_string(),
            },
            seed,
        )
        .unwrap();
        assert_eq!(with_id.public_multibase(), signed["verificationMethod"][0]["publicKeyMultibase"]
            .as_str()
            .unwrap());
        (with_id, signed)
    }

    fn request(body: Option<&[u8]>) -> SignRequest {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        SignRequest {
            method: "POST".into(),
            url: "https://example.com/api/agents/alice".into(),
            headers,
            body: body.map(|b| b.to_vec()),
        }
    }

    #[test]
    fn a_body_less_request_covers_the_three_derived_components() {
        let (key, doc) = fixture(21);
        let mut req = request(None);
        req.method = "GET".into();

        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(signed.covered, ["@method", "@target-uri", "@authority"]);
        assert!(signed.headers.contains_key("Signature"));
        assert!(signed.headers.contains_key("Signature-Input"));
        assert!(!signed.headers.contains_key("Content-Digest"));
    }

    #[test]
    fn a_request_with_a_body_always_covers_content_digest() {
        let (key, doc) = fixture(22);
        let signed = sign_request(&doc, &key, &request(Some(b"{\"hello\":1}"))).unwrap();

        assert!(signed.covered.iter().any(|c| c == "content-digest"));
        assert!(signed.headers.contains_key("Content-Digest"));
        // 摘要必须是**这个** body 的。
        assert_eq!(
            signed.headers["Content-Digest"],
            anp::authentication::build_content_digest(b"{\"hello\":1}")
        );
    }

    /// 上游的 verify 会重新拼一遍签名基并验签。我们自己签的东西必须过得去 ——
    /// 否则等于我们在自娱自乐。
    #[test]
    fn the_signature_verifies_against_the_upstream_verifier() {
        let (key, doc) = fixture(23);
        let req = request(Some(b"payload"));

        let signed = sign_request(&doc, &key, &req).unwrap();

        let mut headers = req.headers.clone();
        for (name, value) in &signed.headers {
            headers.insert(name.clone(), value.clone());
        }

        let metadata = anp::authentication::verify_http_message_signature(
            &doc,
            &req.method,
            &req.url,
            &headers,
            req.body.as_deref(),
        )
        .expect("our own signature must verify under the upstream verifier");

        assert_eq!(metadata.keyid, key.id().kid);
        assert_eq!(metadata.components, signed.covered);
    }

    // ---- 反盲目签名 ----

    /// 覆盖面是由我们决定的:**没有**任何输入能让它变成一组更弱的分量。
    #[test]
    fn the_covered_set_is_fixed_regardless_of_headers_url_and_query() {
        let (key, doc) = fixture(24);

        let mut req = request(None);
        req.method = "GET".into();
        req.url = "https://example.com/anything?a=1&b=2".into();
        req.headers.insert("x-custom".into(), "v".into());
        req.headers.insert("content-type".into(), "text/plain".into());

        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(signed.covered, ["@method", "@target-uri", "@authority"]);

        // 基里的 @authority 出自 URL,所以上游照真实 URL 重拼一定能验过。
        let mut headers = req.headers.clone();
        headers.extend(signed.headers.clone());
        anp::authentication::verify_http_message_signature(
            &doc, &req.method, &req.url, &headers, None,
        )
        .expect("the authority in the base must come from the URL, not from a header");
    }

    /// 派生分量的名字(`@method` 之类)根本不是合法的头名,所以调用方
    /// 连"用一个头去冒充它"这一步都走不到。
    #[test]
    fn a_header_cannot_impersonate_a_derived_component() {
        for name in ["@method", "@authority", "@target-uri", "@signature-params"] {
            let mut req = request(None);
            req.headers.insert(name.into(), "evil".into());
            assert!(
                matches!(req.validate(), Err(KeydError::Protocol(_))),
                "{name:?} must not be usable as a header name"
            );
        }
    }

    /// 调用方给的 `Content-Digest` 和 body 对不上 → 拒。对得上 → 用它,
    /// 但值仍然是我们自己算出来的那个。
    #[test]
    fn a_content_digest_the_daemon_did_not_compute_is_refused() {
        let (key, doc) = fixture(28);

        let mut req = request(Some(b"the real body"));
        req.headers
            .insert("content-digest".into(), "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into());
        assert!(matches!(req.validate(), Err(KeydError::Protocol(_))));
        assert!(sign_request(&doc, &key, &req).is_err());

        // 没有 body 却带着摘要 —— 同样拒。
        let mut req = request(None);
        req.headers
            .insert("content-digest".into(), anp::authentication::build_content_digest(b"x"));
        assert!(req.validate().is_err());

        // 对得上的那个值没问题,而且签出来的摘要一定等于 body 的摘要。
        let body = b"the real body";
        let mut req = request(Some(body));
        req.headers
            .insert("content-digest".into(), anp::authentication::build_content_digest(body));
        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(
            signed.headers["Content-Digest"],
            anp::authentication::build_content_digest(body)
        );
    }

    #[test]
    fn signing_the_same_request_twice_differs_because_of_the_nonce() {
        let (key, doc) = fixture(25);
        let a = sign_request(&doc, &key, &request(None)).unwrap();
        let b = sign_request(&doc, &key, &request(None)).unwrap();
        assert_ne!(a.headers["Signature"], b.headers["Signature"]);
        assert_ne!(a.signature_base_digest, b.signature_base_digest);
    }

    // ---- 签名基注入 ----

    /// 头值里的换行能凭空伪造一行签名基。必须在边界上挡掉。
    #[test]
    fn a_header_value_with_a_line_break_is_refused() {
        let (key, doc) = fixture(26);

        for evil in [
            "x\r\n\"@authority\": evil.com",
            "x\n\"@authority\": evil.com",
            "x\r\"@method\": GET",
        ] {
            let mut req = request(None);
            req.headers.insert("x-forwarded-host".into(), evil.to_string());
            assert!(
                matches!(req.validate(), Err(KeydError::Protocol(_))),
                "{evil:?} must not reach the signature base"
            );
            assert!(sign_request(&doc, &key, &req).is_err());
        }
    }

    /// URL 里的换行同理 —— `@target-uri` 是原样写进基里的。
    #[test]
    fn a_url_with_a_line_break_is_refused() {
        for evil in [
            "https://example.com/x\n\"@authority\": evil.com",
            "https://example.com/x\r\n\r\nGET /admin HTTP/1.1",
            "https://example.com/x y",
        ] {
            let mut req = request(None);
            req.url = evil.into();
            assert!(req.validate().is_err(), "{evil:?} must not be signed");
        }
    }

    #[test]
    fn only_https_urls_and_real_methods_are_signed() {
        let mut req = request(None);
        req.url = "http://example.com/x".into();
        assert!(req.validate().is_err(), "plaintext HTTP must be refused");

        for evil in ["get", "POST /x HTTP/1.1", "GE T", ""] {
            let mut req = request(None);
            req.method = evil.into();
            assert!(req.validate().is_err(), "{evil:?} is not a method token");
        }
    }

    #[test]
    fn a_url_with_userinfo_is_refused() {
        let mut req = request(None);
        req.url = "https://evil.com@example.com/x".into();
        assert!(req.validate().is_err(), "userinfo would not be covered by @authority");
    }

    #[test]
    fn bad_header_names_are_refused() {
        for evil in ["bad name", "bad:name", "", "bad\nname", "bad\"name"] {
            let mut req = request(None);
            req.headers.clear();
            req.headers.insert(evil.into(), "v".into());
            assert!(req.validate().is_err(), "{evil:?} is not a header name");
        }
    }

    // ---- 覆盖面核对本身 ----

    #[test]
    fn a_base_that_drops_a_required_component_is_rejected() {
        let base = "\"@method\": POST\n\
                    \"@signature-params\": (\"@method\");created=1;keyid=\"k\"";
        assert!(matches!(
            verify_covered_set(base, &["@method".into(), "@authority".into()]),
            Err(KeydError::CoveredSetRejected(_))
        ));
    }

    /// 声称覆盖了、基里却没有那一行 —— 也是残缺的基。
    #[test]
    fn a_base_that_claims_a_component_it_does_not_include_is_rejected() {
        let base = "\"@method\": POST\n\
                    \"@signature-params\": (\"@method\" \"@authority\");created=1;keyid=\"k\"";
        assert!(matches!(
            verify_covered_set(base, &["@method".into()]),
            Err(KeydError::CoveredSetRejected(_))
        ));
    }

    #[test]
    fn a_base_with_no_signature_params_line_is_rejected() {
        assert!(verify_covered_set("\"@method\": POST", &["@method".into()]).is_err());
    }

    #[test]
    fn a_base_covering_nothing_is_rejected() {
        let base = "\"@signature-params\": ();created=1;keyid=\"k\"";
        assert!(verify_covered_set(base, &[]).is_err());
    }

    #[test]
    fn component_ids_with_parameters_are_parsed() {
        let list = "\"@method\" \"content-digest\";sf \"x\";key=\"a b\"";
        assert_eq!(
            parse_component_list(list).unwrap(),
            ["@method", "content-digest", "x"]
        );
    }

    #[test]
    fn malformed_component_lists_are_rejected() {
        for bad in ["@method", "\"unterminated", "1", ""] {
            let r = parse_component_list(bad);
            assert!(
                r.is_err() || r.unwrap().is_empty(),
                "{bad:?} is not a valid component list"
            );
        }
    }

    #[test]
    fn the_real_signature_base_parses_back_to_what_we_asked_for() {
        let (key, doc) = fixture(27);
        let req = request(Some(b"body"));

        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(
            signed.covered,
            ["@method", "@target-uri", "@authority", "content-digest"]
        );
    }
}
