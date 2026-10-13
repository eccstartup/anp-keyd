//! `did:wba` 的解析与 URL 映射。
//!
//! 一个绑定式 did:wba 长这样:
//!
//! ```text
//! did:wba:example.com:user:alice:e1_<43字符指纹>
//!          └─域名─┘ └──路径段──┘ └─ e1 绑定段 ─┘
//! ```
//!
//! 域名段里若带端口,`:` 会被百分号编码成 `%3A`(上游 `build_did_base` 就是
//! 这么写的),所以解析时**必须**解码,拼 URL 时用的是解出来的那个。
//!
//! 解析规则是照着上游 `resolve_did_wba_document_with_options` 对齐的 ——
//! 我们和解析器必须对同一个 DID 得出同一个 URL,不然发布出去没人找得到。

use crate::error::{KeydError, Result};

/// 一个 `did:wba` 拆开之后的样子。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWbaParts {
    /// 百分号解码之后的域名,不含端口。
    pub host: String,
    pub port: Option<u16>,
    /// `e1_` 段之前的所有段,顺序即原顺序。
    pub path_segments: Vec<String>,
}

impl DidWbaParts {
    /// 主机段,带端口时是 `host:port`。
    pub fn authority(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    /// 做 HTTPS 请求时用的 URL 前缀。
    pub fn origin(&self) -> String {
        format!("https://{}", self.authority())
    }

    /// 最后一段是不是 `e1_` 绑定段;是就返回它。
    pub fn e1_segment(&self) -> Option<&str> {
        self.path_segments
            .last()
            .filter(|s| s.starts_with("e1_"))
            .map(String::as_str)
    }

    /// 不含 `e1_` 段的部分 —— 也就是这个 DID 的"目录"。
    pub fn path_only(&self) -> Vec<&str> {
        match self.e1_segment() {
            Some(_) => self.path_segments[..self.path_segments.len() - 1]
                .iter()
                .map(String::as_str)
                .collect(),
            None => self.path_segments.iter().map(String::as_str).collect(),
        }
    }
}

/// 拆一个 `did:wba`。
pub fn parse_did_wba(did: &str) -> Result<DidWbaParts> {
    let rest = did
        .strip_prefix("did:wba:")
        .ok_or_else(|| KeydError::Did(format!("not a did:wba: {did}")))?;

    // 注意:**不能**先百分号解码再按 `:` 切 —— 编码后的 `%3A` 正是为了
    // 让端口里的那个冒号不参与分段。先切段,再解码域名段。
    let mut segments = rest.split(':');
    let encoded_host = segments.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        KeydError::Did(format!("did:wba has no domain segment: {did}"))
    })?;

    let decoded_host = percent_decode(encoded_host);
    let (host, port) = split_port(&decoded_host, did)?;
    check_host(&host)?;

    let path_segments: Vec<String> = segments.map(str::to_string).collect();
    for segment in &path_segments {
        check_path_segment(segment)?;
    }

    Ok(DidWbaParts { host, port, path_segments })
}

/// 域名这一段的规则,单独拿出来给**还没成为 DID 的**输入用。
///
/// 「规格文件里的 `host` 合不合法」和「DID 里的域名段合不合法」是同一个
/// 问题,答案也只能有一份 —— 否则两份规则迟早对不上,而对不上的那一侧
/// 会放行一个发布出去谁都找不到的 DID。所以规则住在这里,由解析器和
/// [`crate::did::spec`] 一起调。
pub(crate) fn check_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(KeydError::Did("did:wba has an empty domain".into()));
    }
    // 一个绑在裸 IP 上的 did:wba 不是"域名验证过的身份",而发布流程会照着
    // 这个域名去拼取回地址 —— 允许 IP 等于允许把文档推到任意地址。
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(KeydError::Did(format!(
            "did:wba must bind a domain, not an IP address: {host}"
        )));
    }
    if !is_plausible_domain(host) {
        return Err(KeydError::Did(format!("did:wba has a malformed domain: {host:?}")));
    }
    Ok(())
}

/// 一个路径段的规则,理由和 [`check_host`] 一样单独拿出来。
pub(crate) fn check_path_segment(segment: &str) -> Result<()> {
    if segment.is_empty() {
        return Err(KeydError::Did("did:wba has an empty path segment".into()));
    }
    if segment == "." || segment == ".." {
        return Err(KeydError::Did(format!(
            "did:wba path segment is a relative-path token: {segment:?}"
        )));
    }
    // 路径段只允许 RFC 3986 的 unreserved 字符。
    //
    // 上游拼 URL 时**不**对路径段做百分号解码,所以 `%2F` 不会当场变成
    // 斜杠 —— 但它会在服务端被解成斜杠,于是取回地址就能被拐到别的路径。
    // 与其依赖"对端不会解码",不如在这里只放行一定能安全拼进 URL 的字符。
    if !segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~'))
    {
        return Err(KeydError::Did(format!(
            "did:wba path segment has a character that is not URL-safe: {segment:?}"
        )));
    }
    Ok(())
}

/// DID → 取回的 URL。
///
/// ```text
/// did:wba:example.com:user:alice:e1_abc  →  https://example.com/user/alice/e1_abc/did.json
/// did:wba:example.com                    →  https://example.com/.well-known/did.json
/// ```
pub fn did_url_path(did: &str) -> Result<String> {
    let parts = parse_did_wba(did)?;
    Ok(format!("{}/did.json", resolution_directory(&parts)))
}

/// 取回 URL 的目录部分(不含 `did.json`)。发布文档时要用它做校验。
pub fn resolution_directory(parts: &DidWbaParts) -> String {
    if parts.path_segments.is_empty() {
        format!("{}/.well-known", parts.origin())
    } else {
        format!("{}/{}", parts.origin(), parts.path_segments.join("/"))
    }
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// 域名段里允许出现 `host:port`,端口是**最后一个**冒号之后的全数字。
fn split_port(host: &str, did: &str) -> Result<(String, Option<u16>)> {
    let Some((head, tail)) = host.rsplit_once(':') else {
        return Ok((host.to_string(), None));
    };
    if tail.is_empty() {
        return Err(KeydError::Did(format!("did:wba has a trailing colon: {did}")));
    }
    // 全数字才当端口。否则说明这个域名本身就不对(比如 IPv6 字面量)。
    if !tail.bytes().all(|b| b.is_ascii_digit()) {
        return Err(KeydError::Did(format!(
            "did:wba domain segment has a non-numeric port: {did}"
        )));
    }
    let port: u16 = tail
        .parse()
        .map_err(|_| KeydError::Did(format!("did:wba port is out of range: {did}")))?;
    if head.is_empty() {
        return Err(KeydError::Did(format!("did:wba has an empty domain before the port: {did}")));
    }
    Ok((head.to_string(), Some(port)))
}

/// 域名的最小合理性检查:有点、无空白、无控制字符。
///
/// 不做完整的 DNS 校验 —— 那是解析器的事;这里只挡住会破坏 URL 的东西。
fn is_plausible_domain(host: &str) -> bool {
    host.contains('.')
        && host.len() <= 253
        && host.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '%'
        })
        && !host.starts_with('.')
        && !host.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_path_bound_did() {
        let p = parse_did_wba("did:wba:example.com:user:alice:e1_abc123").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, None);
        assert_eq!(p.path_segments, ["user", "alice", "e1_abc123"]);
        assert_eq!(p.e1_segment(), Some("e1_abc123"));
        assert_eq!(p.path_only(), ["user", "alice"]);
        assert_eq!(p.authority(), "example.com");
    }

    /// 上游把端口写成 `%3A`,解析时必须还原 —— 否则我们和解析器会拼出
    /// 两个不同的 URL,发布出去的文档没人找得到。
    #[test]
    fn percent_encoded_port_is_decoded() {
        let p = parse_did_wba("did:wba:example.com%3A8443:user:alice:e1_abc").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, Some(8443));
        assert_eq!(p.authority(), "example.com:8443");
        assert_eq!(
            did_url_path("did:wba:example.com%3A8443:user:alice:e1_abc").unwrap(),
            "https://example.com:8443/user/alice/e1_abc/did.json"
        );
    }

    #[test]
    fn bare_did_goes_to_well_known() {
        assert_eq!(
            did_url_path("did:wba:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn path_bound_did_url_matches_the_resolver_rule() {
        assert_eq!(
            did_url_path("did:wba:example.com:user:alice:e1_abc123").unwrap(),
            "https://example.com/user/alice/e1_abc123/did.json"
        );
    }

    #[test]
    fn rejects_non_wba_and_malformed_dids() {
        for bad in [
            "did:web:example.com",
            "did:wba:",
            "did:wba:localhost:user",       // 没有点,不是域名
            "did:wba:127.0.0.1:user",       // IP 字面量
            "did:wba:example.com::user",    // 空段
            "did:wba:example.com%3A:user",  // 冒号后没端口
            "did:wba:example.com%3A99999",  // 端口越界
        ] {
            assert!(
                parse_did_wba(bad).is_err(),
                "{bad:?} should not parse as a did:wba"
            );
        }
    }

    /// 路径段里的分隔符逃逸必须被挡住:否则它能改写取回 URL 的目录。
    #[test]
    fn rejects_path_segments_that_escape_the_directory() {
        for bad in [
            "did:wba:example.com:user:..:e1_abc",
            "did:wba:example.com:user:.",
            "did:wba:example.com:user%2Fetc:e1_abc", // `%` 会在服务端被解码
            "did:wba:example.com:user/../etc:e1_abc",
            "did:wba:example.com:user alice:e1_abc",  // 空格
        ] {
            assert!(
                parse_did_wba(bad).is_err(),
                "{bad:?} must not be accepted as a did:wba path"
            );
        }
    }
}
