//! Conservative v2 HTTP grammar. Policy, digest and future signer share this object.
use crate::error::{KeydError, Result};
use crate::sign::rfc9421::SignRequest;
#[cfg(feature = "mcp")]
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Body {
    Absent {},
    Present { bytes: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Body,
    pub nonce: Option<String>,
}
#[derive(Debug, Clone)]
pub struct CanonicalHttpRequest {
    request: SignRequest,
    origin: String,
    path: String,
    query: Option<String>,
}
fn denied() -> KeydError {
    KeydError::Misuse("POLICY_DENIED".into())
}
/// A strict ASCII subset preserved by HTTP URL serializers, without percent decoding.
pub(crate) fn safe_target_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~/:@!$&'()*+,;=".contains(&b)
}
impl CanonicalHttpRequest {
    pub fn new(input: HttpRequest) -> Result<Self> {
        if input.url.len() > 4096 || input.headers.len() > 64 {
            return Err(denied());
        }
        let rest = input.url.strip_prefix("https://").ok_or_else(denied)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        let host = host.to_ascii_lowercase();
        if host.is_empty()
            || host.len() > 253
            || host.ends_with('.')
            || host.split('.').any(|s| {
                s.is_empty()
                    || s.len() > 63
                    || s.starts_with('-')
                    || s.ends_with('-')
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(denied());
        }
        // Numeric IPv4 spellings are deliberately excluded: URL parsers accept
        // octal/hex/short addresses with different wire destinations.
        if !host
            .rsplit('.')
            .next()
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_alphabetic()))
        {
            return Err(denied());
        }
        let port = match port {
            None | Some("443") => String::new(),
            Some(p)
                if p.parse::<u16>()
                    .ok()
                    .filter(|v| *v != 0)
                    .map(|v| v.to_string())
                    .as_deref()
                    == Some(p) =>
            {
                format!(":{p}")
            }
            _ => return Err(denied()),
        };
        let origin = format!("https://{host}{port}");
        let tail = &rest[end..];
        let (path, query) = tail
            .split_once('?')
            .map_or((tail, None), |(p, q)| (p, Some(q)));
        let path = if path.is_empty() { "/" } else { path };
        if path.len() > 2048
            || !path.starts_with('/')
            || path.contains("//")
            || path.split('/').any(|p| p == "." || p == "..")
            || path.bytes().any(|b| !safe_target_byte(b))
        {
            return Err(denied());
        }
        if let Some(q) = query {
            let mut keys = BTreeSet::new();
            if q.is_empty()
                || q.len() > 2048
                || q.bytes()
                    .any(|b| !safe_target_byte(b) || b == b'+' || b == b'\'')
                || q.split('&').any(|pair| {
                    let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
                    k.is_empty() || !keys.insert(k)
                })
            {
                return Err(denied());
            }
        }
        let mut headers = BTreeMap::new();
        for (name, value) in input.headers {
            let name = name.to_ascii_lowercase();
            if [
                "host",
                "authorization",
                "signature",
                "signature-input",
                "content-length",
                "transfer-encoding",
                "connection",
            ]
            .contains(&name.as_str())
                || headers.insert(name, value).is_some()
            {
                return Err(denied());
            }
        }
        let body = match input.body {
            Body::Absent {} => None,
            Body::Present { bytes } => Some(bytes),
        };
        // v2 frames are bounded; keep the independently callable API bounded too.
        if body.as_ref().is_some_and(|b| b.len() > 16384) {
            return Err(denied());
        }
        let covered = if headers.contains_key("content-type") {
            vec!["content-type".into()]
        } else {
            vec![]
        };
        let request = SignRequest {
            method: input.method,
            url: format!(
                "{origin}{path}{}",
                query.map_or(String::new(), |q| format!("?{q}"))
            ),
            headers,
            body,
            covered,
            nonce: input.nonce,
        };
        request.validate().map_err(|_| denied())?;
        Ok(Self {
            request,
            origin,
            path: path.into(),
            query: query.map(str::to_owned),
        })
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
    pub fn method(&self) -> &str {
        &self.request.method
    }
    pub fn body_len(&self) -> usize {
        self.request.body.as_ref().map_or(0, Vec::len)
    }
    pub fn has_body(&self) -> bool {
        self.request.body.is_some()
    }
    pub fn signing_request(&self) -> &SignRequest {
        &self.request
    }
    pub fn digest(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let bytes=serde_json_canonicalizer::to_vec(&serde_json::json!({"profile":"anp-http-v2","method":self.request.method,"url":self.request.url,"headers":self.request.headers,"body":self.request.body,"nonce":self.request.nonce})).map_err(|_|denied())?;
        Ok(Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(url: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            url: url.into(),
            headers: BTreeMap::new(),
            body: Body::Present { bytes: vec![] },
            nonce: None,
        }
    }
    #[test]
    fn ambiguous_targets_and_headers_are_rejected() {
        for url in [
            "http://example.com/x",
            "https://u@example.com/x",
            "https://example.com/#x",
            "https://example.com/a/../x",
            "https://example.com/a/./x",
            "https://example.com//x",
            "https://example.com/%2fx",
            "https://example.com/a\\b",
            "https://example.com/?a=1&a=2",
            "https://example.com/?a=%31",
            "https://example.com/?a=+",
            "https://127.1/x",
            "https://example.com:0443/x",
            "https://example.com:/x",
            "https://example.com./x",
            "https://example.com/?",
            "https://example.com/a b",
        ] {
            assert!(CanonicalHttpRequest::new(input(url)).is_err(), "{url}");
        }
        for pair in [("Content-Type", "content-type"), ("X-Test", "x-test")] {
            let mut r = input("https://example.com/x");
            r.headers.insert(pair.0.into(), "one".into());
            r.headers.insert(pair.1.into(), "two".into());
            assert!(CanonicalHttpRequest::new(r).is_err());
        }
        for name in [
            "authorization",
            "host",
            "signature",
            "content-length",
            "transfer-encoding",
        ] {
            let mut r = input("https://example.com/x");
            r.headers.insert(name.into(), "x".into());
            assert!(CanonicalHttpRequest::new(r).is_err());
        }
    }
    #[test]
    fn canonical_target_body_and_digest_have_one_representation() {
        let a = CanonicalHttpRequest::new(input("https://EXAMPLE.com:443")).unwrap();
        assert_eq!(a.signing_request().url, "https://example.com/");
        assert_eq!(
            a.digest().unwrap(),
            CanonicalHttpRequest::new(input("https://example.com/"))
                .unwrap()
                .digest()
                .unwrap()
        );
        let mut absent = input("https://example.com/");
        absent.body = Body::Absent {};
        assert_ne!(
            a.digest().unwrap(),
            CanonicalHttpRequest::new(absent).unwrap().digest().unwrap()
        );
        let mut r = input("https://example.com/x");
        r.headers
            .insert("Content-Digest".into(), "sha-256=:wrong:".into());
        assert!(CanonicalHttpRequest::new(r).is_err());
        let mut r = input("https://example.com/x");
        r.headers.insert("x".into(), "line\nvalue".into());
        assert!(CanonicalHttpRequest::new(r).is_err());
    }
    #[test]
    fn bounded_parser_sweep_never_accepts_encoded_or_control_paths() {
        for byte in 0..=255u8 {
            let target = format!("https://example.com/a{}b", char::from(byte));
            if byte <= 32 || byte >= 127 || [b'%', b'\\', b'#'].contains(&byte) {
                assert!(CanonicalHttpRequest::new(input(&target)).is_err(), "{byte}");
            }
        }
    }
}
