//! Fixed policy schema and evaluation against one canonical request.
use super::*;
use std::collections::BTreeSet;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
    schema_version: u32,
    name: String,
    purpose: String,
    origin: String,
    methods: Vec<String>,
    paths: Vec<String>,
    query: Query,
    body: Body,
    signature_profile: String,
    pub(super) grant_limits: Limits,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Query {
    None {},
    Exact { value: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    mode: String,
    max_bytes: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub(super) max_duration_seconds: u32,
    pub(super) max_uses: u32,
}

pub(super) fn normalize(content: Value) -> Result<Value> {
    let p: Policy = serde_json::from_value(content).map_err(|_| invalid())?;
    let authority = p.origin.strip_prefix("https://").ok_or_else(invalid)?;
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if p.schema_version != 1
        || p.purpose != "http-authentication"
        || p.signature_profile != "anp-http-v2"
        || p.name.is_empty()
        || p.name.len() > 128
        || p.name.chars().any(char::is_control)
        || host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || !host
            .rsplit('.')
            .next()
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_alphabetic()))
        || host.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || port.is_some_and(|v| {
            v.parse::<u16>()
                .ok()
                .filter(|p| *p != 0 && *p != 443)
                .map(|p| p.to_string())
                != Some(v.to_owned())
        })
        || p.methods.is_empty()
        || p.methods.len() > 16
        || p.methods.iter().any(|s| {
            !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(&s.as_str())
        })
        || p.methods.iter().collect::<BTreeSet<_>>().len() != p.methods.len()
        || p.paths.is_empty()
        || p.paths.len() > 64
        || p.paths.iter().collect::<BTreeSet<_>>().len() != p.paths.len()
        || p.paths.iter().any(|s| {
            !s.starts_with('/')
                || s.len() > 2048
                || s.contains("//")
                || s.split('/').any(|p| p == "." || p == "..")
                || s.bytes()
                    .any(|b| !crate::security::http::safe_target_byte(b))
        })
        || !["empty", "bounded"].contains(&p.body.mode.as_str())
        || (p.body.mode == "empty" && p.body.max_bytes != 0)
        || p.body.max_bytes > 16 * 1024 * 1024
        || p.grant_limits.max_duration_seconds == 0
        || p.grant_limits.max_uses == 0
    {
        return Err(invalid());
    }
    if let Query::Exact { value } = &p.query {
        let mut keys = BTreeSet::new();
        if value.is_empty()
            || value.len() > 2048
            || value
                .bytes()
                .any(|b| !crate::security::http::safe_target_byte(b) || b == b'+' || b == b'\'')
            || value.split('&').any(|pair| {
                let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
                k.is_empty() || !keys.insert(k)
            })
        {
            return Err(invalid());
        }
    }
    serde_json::to_value(p).map_err(|_| invalid())
}

pub(super) fn parse(content: Value) -> Result<Policy> {
    serde_json::from_value(normalize(content)?).map_err(|_| invalid())
}
pub(super) fn evaluate(
    content: Value,
    request: &crate::security::http::CanonicalHttpRequest,
) -> Result<()> {
    let p = parse(content)?;
    let query = match &p.query {
        Query::None {} => None,
        Query::Exact { value } => Some(value.as_str()),
    };
    if p.origin != request.origin()
        || !p.methods.contains(&request.method().to_owned())
        || !p.paths.contains(&request.path().to_owned())
        || query != request.query()
        || request.body_len() > p.body.max_bytes as usize
        || (p.body.mode == "empty" && request.body_len() != 0)
        || (p.body.mode == "bounded" && !request.has_body())
    {
        return Err(KeydError::Misuse("POLICY_DENIED".into()));
    }
    Ok(())
}
