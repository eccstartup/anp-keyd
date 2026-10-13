//! 一份 DID 文档**该有什么** —— 和"怎么构造、怎么签"分开。
//!
//! 这里只回答两个问题:
//!
//! 1. **它挂在哪** —— `host` / `port` / 路径段 / fragment。这几样合起来
//!    决定 DID 字符串;把它们交给 [`compose_did_wba`] 就能算出 DID,不需要
//!    先造一份文档出来。
//! 2. **它还声明什么** —— agent description 的地址、写进 `service` 数组的
//!    条目(WNS handle 绑定就在这一档)。
//!
//! 它不碰私钥,也不产出最终文档。构造规范形式的文档是
//! [`crate::did::document`] 的事,签名是更后面的事。
//!
//! # 为什么规格能离开这份代码
//!
//! 文档的形状是**协议面**,变得比钥匙保管快(上游已经在加 `did:atp`;
//! WNS handle 是后来才有的)。所以"文档里放什么"必须能从外面说,而不是
//! 每次都在 `keygen` 的代码里加一行 —— 见 [`SpecFile`]。
//!
//! 但**构造**留在这里。这一条不能动:守护进程只签它自己从参数拼出来的
//! 文档,不签任何送给它的字节 —— 否则防盲签那道墙就从后门拆掉了
//! (见 `docs/DESIGN.md` 第七节)。

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::thumbprint::e1_segment;
use crate::did::parse::parse_did_wba;
use crate::error::{KeydError, Result};

/// 根密钥在文档里的 fragment。上游的 `VM_KEY_AUTH` 也是这个值。
pub const ROOT_FRAGMENT: &str = "key-1";

/// 构造一份文档所需的全部输入。
#[derive(Debug, Clone)]
pub struct DidDocumentSpec {
    /// 域名,不含端口。IP 字面量会被上游拒绝。
    pub host: String,
    pub port: Option<u16>,
    /// `e1_` 段**之前**的路径段。`e1_` 段由 [`compose_did_wba`] 按公钥追加。
    pub path_segments: Vec<String>,
    /// 根密钥在文档里的 fragment。这一份构建里**恒为** [`ROOT_FRAGMENT`],
    /// 而且不从那份规格文件来 —— 见 [`SpecFile`]。
    pub fragment: String,
    /// 文档要声明的 agent description 地址。
    pub agent_description_url: Option<String>,
    /// 写进文档 `service` 数组的条目,原样。
    ///
    /// **WNS handle 绑定走的就是这一档**:上游
    /// `wns::build_handle_service_entry(did, local_part, domain)` 产出一条
    /// `ANPHandleService` 条目,交给 `with_service` 放进来的,就是它。
    /// 本工具不解释这些条目,只负责让它们进文档并被签名覆盖。
    pub services: Vec<Value>,
}

impl DidDocumentSpec {
    pub fn new(host: impl Into<String>, path_segments: Vec<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            path_segments,
            fragment: ROOT_FRAGMENT.to_string(),
            agent_description_url: None,
            services: Vec::new(),
        }
    }

    /// 只从 DID 反推出的那一部分 —— 坐标。可选项都为空。
    ///
    /// 这就是 `publish` 的起点:手上只有一个 DID,文档该长什么样由 DID
    /// 自己说着,额外声明什么得另外给(见 [`SpecFile`])。
    pub fn coordinates_from_did(did: &str) -> Result<Self> {
        let parts = parse_did_wba(did)?;
        let mut path_segments = parts.path_segments.clone();
        let last = path_segments
            .pop()
            .ok_or_else(|| KeydError::Did(format!("{did} has no e1_ binding segment")))?;
        if !last.starts_with("e1_") {
            return Err(KeydError::Did(format!("{did} has no e1_ binding segment")));
        }
        if path_segments.is_empty() {
            return Err(KeydError::Did(format!(
                "{did} has no path segment before the e1_ binding, which did:wba requires"
            )));
        }
        Ok(Self {
            host: parts.host,
            port: parts.port,
            path_segments,
            fragment: ROOT_FRAGMENT.to_string(),
            agent_description_url: None,
            services: Vec::new(),
        })
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_fragment(mut self, fragment: impl Into<String>) -> Self {
        self.fragment = fragment.into();
        self
    }

    pub fn with_agent_description_url(mut self, url: impl Into<String>) -> Self {
        self.agent_description_url = Some(url.into());
        self
    }

    pub fn with_service(mut self, service: Value) -> Self {
        self.services.push(service);
        self
    }

    /// 套上规格文件里的可选项。坐标**不**从这里来 —— 那些由 DID 决定,
    /// 由 [`SpecFile::check_coordinates`] 核对。
    pub fn with_overlay_from(mut self, file: &SpecFile) -> Self {
        self.agent_description_url = file.agent_description_url.clone();
        self.services = file.services.clone();
        self
    }

    /// 一份**已经签出来的**文档现在所体现的规格:坐标从它的 `id` 来,
    /// 可选项从它自己的 `service` 数组里捡回来。
    ///
    /// 这是"把它重签一遍,别的内容一个字节不动"的起点 —— 换热密钥、摘钥匙、
    /// 重发,走的都是这条路。少了这一步,重签出来的文档会**静静地**丢掉
    /// `service`:它由规格说了算(在上游的构建器里),所以不在"上游不认识的
    /// 属性原样搬回去"那一档里,而覆盖写是不报错的。WNS handle 绑定就挂在
    /// 这里,丢了它等于换了一把钥匙之后这个名字不再属于你。
    pub fn from_document(document: &Value) -> Result<Self> {
        let did = document
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| KeydError::Did("the document has no id".into()))?;
        let spec = Self::coordinates_from_did(did)?;
        Ok(spec.with_overlay_from_document(document))
    }

    /// 同上,但套在一份已有的规格上(坐标由调用方给)。
    pub fn with_overlay_from_document(mut self, document: &Value) -> Self {
        let did = document.get("id").and_then(Value::as_str).unwrap_or_default();
        let entries = match document.get("service").and_then(Value::as_array) {
            Some(entries) => entries,
            None => return self,
        };
        let ad_id = format!("{did}#ad");
        let mut services = Vec::with_capacity(entries.len());
        for entry in entries {
            // `agentDescriptionUrl` 在文档里长成一条 `AgentDescription`
            // 服务条目(上游 `build_service_entries` 干的),所以它要从
            // 这一档里认出来,否则下次重建时它会被当成一条普通 service
            // 再拼一遍 —— 于是每重建一次,文档里就多一条 `#ad`。
            let is_ad = entry.get("id").and_then(Value::as_str) == Some(ad_id.as_str())
                && entry.get("type").and_then(Value::as_str) == Some("AgentDescription");
            if is_ad {
                self.agent_description_url = entry
                    .get("serviceEndpoint")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            } else {
                services.push(entry.clone());
            }
        }
        self.services = services;
        self
    }

    /// 这份规格应该产出的 DID。
    pub fn did(&self, root: &VerifyingKey) -> Result<String> {
        compose_did_wba(self, root)
    }

    /// DID 就是这个规格的坐标吗。
    ///
    /// 出版本格式变了(比如路径段被额外百分号编码过),这里对不上 ——
    /// 那种 DID 不是我们能产出、也不该拿去签的形状。
    pub fn check_canonical(&self, did: &str, root: &VerifyingKey) -> Result<()> {
        let composed = self.did(root)?;
        if composed != did {
            return Err(KeydError::Did(format!(
                "{did} is not in the canonical form this build produces (got {composed})"
            )));
        }
        Ok(())
    }
}

/// 坐标 + 公钥 → DID 字符串。
///
/// 走的是上游 `build_did_base` + `join_did` 的同一条路:端口里的冒号编码成
/// `%3A`,路径段用 `:` 连接,`e1_<指纹>` 追加在最后。这里重写一份是为了
/// **不为了拿一个字符串去造一整份文档** —— 那份文档 `keygen` 根本不用,
/// 造出来就扔了。
///
/// 与上游同形这件事由一条测试钉住:同一份规格,这里合成的 DID 必须等于
/// `build_unsigned` 产出文档里的 `id`。上游哪天改了拼法,那条测试会红。
pub fn compose_did_wba(spec: &DidDocumentSpec, root: &VerifyingKey) -> Result<String> {
    if spec.path_segments.is_empty() || spec.path_segments.iter().any(|s| s.trim().is_empty()) {
        return Err(KeydError::Did(
            "did:wba requires at least one non-empty path segment before the e1_ binding".into(),
        ));
    }

    let base = match spec.port {
        Some(port) => format!("did:wba:{}%3A{port}", spec.host),
        None => format!("did:wba:{}", spec.host),
    };
    let mut segments = spec.path_segments.clone();
    segments.push(e1_segment(root)?);
    let did = format!("{base}:{}", segments.join(":"));

    // 合成出来的字符串必须能被我们自己的解析器读回去。域名、端口编码、
    // 路径段的字符集都是上游约定,这一步是"我们和解析器说的是同一件事"
    // 的兜底 —— 发布出去没人找得到,比这里报错糟得多。
    let parts = parse_did_wba(&did)?;
    if parts.e1_segment() != segments.last().map(String::as_str) {
        return Err(KeydError::Did(format!(
            "composed {did} does not round-trip through the parser"
        )));
    }
    Ok(did)
}

/// 磁盘上的规格文件 —— 文档形状的**唯一来源**。
///
/// ```json
/// {
///   "host": "example.com",
///   "path": "agents/mybot",
///   "agentDescriptionUrl": "https://example.com/agents/mybot/ad.json",
///   "services": [
///     { "id": "did:wba:…#handle", "type": "ANPHandleService",
///       "serviceEndpoint": "https://wns.example.com/alice" }
///   ]
/// }
/// ```
///
/// `port` 可以不给(默认无端口)。
///
/// **根密钥的 fragment 不在这里**,而且不能给:这份文件决定的是"文档声明
/// 什么",而 `key-1` 不是一条声明 —— 它是本工具自己认根密钥用的那个名字
/// (生命周期里的热密钥编号、`authentication` 的指认、重签时的"别弄丢"那一
/// 档,都按它来找)。把它开放出去,等于允许造出一份**本工具自己看不懂**的
/// 文档:下一次重签会把根密钥当成一把附加密钥再挂一遍。
///
/// 认不出的字段**直接拒**,不做静默忽略 —— 一个拼错的 `service` 被吃掉,
/// 结果是文档里少一条声明,而签出来的东西看着完全正常。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpecFile {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `e1_` 段之前的路径,用 `/` 分隔(如 `agents/mybot`)。
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_description_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Value>,
}

impl SpecFile {
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|error| {
            KeydError::Protocol(format!("could not read {}: {error}", path.display()))
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            KeydError::Protocol(format!("{} is not a usable spec file: {error}", path.display()))
        })
    }

    /// 落一份模板 —— 给"我想从一份写好的规格开始"用。
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|error| KeydError::Protocol(format!("could not render the spec: {error}")))
    }

    /// 变成一份完整的规格。坐标在这里,可选项也在。
    ///
    /// 坐标的两条规则(域名、路径段)由 [`crate::did::parse`] 里那一份说了算
    /// —— 和解析一个 DID 时用的是同一个函数。这里先查一遍,是为了让
    /// "文件里写的坐标不合法"在**读文件的时候**就说出来,而不是等到人敲完
    /// 两遍口令、钥匙已经生成出来之后。
    pub fn to_spec(&self) -> Result<DidDocumentSpec> {
        let host = self.host.trim();
        crate::did::parse::check_host(host)?;
        let mut spec = DidDocumentSpec::new(host.to_string(), split_path(&self.path)?);
        spec.port = self.port;
        Ok(spec.with_overlay_from(self))
    }

    /// 规格文件里的坐标必须和 DID 说的是同一个地方。
    ///
    /// 这是防"文件是 A 的、DID 是 B 的"那类错:两处都写了一遍坐标,就有
    /// 对不上的可能,而对不上时**必须报错**,不能挑一个信 —— 挑错了就是拿
    /// 一个 DID 去签另一个地方的文档。
    pub fn check_coordinates(&self, did: &str) -> Result<()> {
        let parts = parse_did_wba(did)?;
        if !parts.host.eq_ignore_ascii_case(self.host.trim()) {
            return Err(KeydError::Did(format!(
                "the spec file is for {:?}, but {did} is on {:?}",
                self.host.trim(),
                parts.host
            )));
        }
        if parts.port != self.port {
            return Err(KeydError::Did(format!(
                "the spec file says port {:?}, but {did} says {:?}",
                self.port, parts.port
            )));
        }
        let expected = split_path(&self.path)?;
        let mut actual = parts.path_segments.clone();
        actual.pop(); // e1_ 绑定段不属于坐标
        if expected != actual {
            return Err(KeydError::Did(format!(
                "the spec file says path {}, but {did} says {}",
                expected.join("/"),
                actual.join("/")
            )));
        }
        Ok(())
    }
}

impl From<&DidDocumentSpec> for SpecFile {
    fn from(spec: &DidDocumentSpec) -> Self {
        Self {
            host: spec.host.clone(),
            port: spec.port,
            path: spec.path_segments.join("/"),
            agent_description_url: spec.agent_description_url.clone(),
            services: spec.services.clone(),
        }
    }
}

/// `agents/mybot` → `["agents", "mybot"]`。规格文件里 `path` 那一栏的规则。
///
/// 空段直接拒:`a//b` 会被上游拼成一条带空段的路径,而那个 DID 解析出来的
/// URL 和它看起来的样子不一样。字符集的规则不在这里另写一份,而是调解析器
/// 用的那个([`crate::did::parse::check_path_segment`])—— 两份规则迟早会
/// 对不上,而对不上的那一侧会放行一个当初解析不回来的 DID。
pub fn split_path(path: &str) -> Result<Vec<String>> {
    // 两头的空白和 `/` 都削掉 —— 粘贴一个 URL 的时候很容易带进来,而它们
    // 在路径段里本来就不可能合法(字符集那一关会拒),所以这里削掉不会
    // 产生歧义:没有"你到底要不要那个空格"的问题。
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(KeydError::Did(format!(
            "the path {path:?} has no segments; did:wba needs at least one before the e1_ one"
        )));
    }
    let segments: Vec<String> = trimmed.split('/').map(str::to_string).collect();
    for (index, segment) in segments.iter().enumerate() {
        crate::did::parse::check_path_segment(segment).map_err(|error| {
            KeydError::Did(format!("the path {path:?} has a bad segment at position {index}: {error}"))
        })?;
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::wrap::seed_to_public;
    use crate::crypto::hygiene::LockedBytes;

    fn key() -> VerifyingKey {
        let seed = LockedBytes::fill(|d| *d = [7u8; 32]).unwrap();
        seed_to_public(&seed).0
    }

    fn spec() -> DidDocumentSpec {
        DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
    }

    /// 合成的 DID 必须和上游产出的 `id` 逐字节一致。
    ///
    /// 这一条是 [`compose_did_wba`] 存在的全部理由 —— 它替掉了一次
    /// `build_unsigned`,所以它必须和那次调用产出同一个字符串。上游改了
    /// 拼法(端口编码、分段顺序)这条就会红。
    #[test]
    fn the_composed_did_matches_what_the_document_builder_puts_in_the_id() {
        use crate::did::document::build_unsigned;

        for spec in [
            spec(),
            spec().with_port(8443),
            DidDocumentSpec::new("a.b.example.co.uk", vec!["x".into()]),
        ] {
            let composed = compose_did_wba(&spec, &key()).unwrap();
            let (from_document, _) = build_unsigned(&spec, &key()).unwrap();
            assert_eq!(composed, from_document);
        }
    }

    #[test]
    fn a_port_is_percent_encoded_like_upstream() {
        let did = compose_did_wba(&spec().with_port(8443), &key()).unwrap();
        assert!(did.starts_with("did:wba:example.com%3A8443:user:alice:e1_"), "{did}");
    }

    #[test]
    fn the_composed_did_round_trips_through_the_parser() {
        let did = compose_did_wba(&spec().with_port(8443), &key()).unwrap();
        let parts = parse_did_wba(&did).unwrap();
        assert_eq!(parts.host, "example.com");
        assert_eq!(parts.port, Some(8443));
        assert_eq!(parts.path_only(), ["user", "alice"]);
    }

    #[test]
    fn a_spec_with_no_path_segment_is_refused() {
        let bare = DidDocumentSpec::new("example.com", Vec::new());
        assert!(compose_did_wba(&bare, &key()).is_err());
    }

    #[test]
    fn coordinates_come_back_out_of_a_did() {
        let did = compose_did_wba(&spec().with_port(8443), &key()).unwrap();
        let back = DidDocumentSpec::coordinates_from_did(&did).unwrap();
        assert_eq!(back.host, "example.com");
        assert_eq!(back.port, Some(8443));
        assert_eq!(back.path_segments, ["user", "alice"]);
        // 反推出来的坐标能合成回同一个 DID。
        assert_eq!(back.did(&key()).unwrap(), did);
    }

    #[test]
    fn a_non_canonical_did_is_caught() {
        let did = compose_did_wba(&spec(), &key()).unwrap();
        let spec = DidDocumentSpec::coordinates_from_did(&did).unwrap();
        assert!(spec.check_canonical(&did, &key()).is_ok());

        // 同一个身份、漏了一个路径段 —— 不是这个 spec 的 DID。
        let other = compose_did_wba(
            &DidDocumentSpec::new("example.com", vec!["alice".into()]),
            &key(),
        )
        .unwrap();
        assert!(spec.check_canonical(&other, &key()).is_err());
    }

    #[test]
    fn a_spec_file_round_trips() {
        let spec = spec()
            .with_agent_description_url("https://example.com/agents/mybot/ad.json")
            .with_service(serde_json::json!({
                "id": "did:wba:example.com:user:alice:e1_x#handle",
                "type": "ANPHandleService",
                "serviceEndpoint": "https://wns.example.com/alice",
            }));
        let file = SpecFile::from(&spec);
        let text = file.to_json().unwrap();
        let back: SpecFile = serde_json::from_str(&text).unwrap();
        let rebuilt = back.to_spec().unwrap();
        assert_eq!(rebuilt.host, spec.host);
        assert_eq!(rebuilt.path_segments, spec.path_segments);
        assert_eq!(rebuilt.agent_description_url, spec.agent_description_url);
        assert_eq!(rebuilt.services, spec.services);
    }

    #[test]
    fn an_unknown_field_in_the_spec_file_is_refused() {
        // 拼错的 `service`(单数)会被吃掉 —— 那等于文档里少一条声明,
        // 而签出来的东西看着完全正常。所以认不出的字段直接拒。
        let text = r#"{
            "host": "example.com",
            "path": "user/alice",
            "service": []
        }"#;
        assert!(serde_json::from_str::<SpecFile>(text).is_err());
    }

    /// 根密钥的 fragment **不是**这份文件能改的东西。
    ///
    /// 它一旦能改,就能造出一份**本工具自己看不懂**的文档:生命周期那边按
    /// 写死的 `key-1` 去找根密钥,找不到就把根密钥当成一把附加密钥 —— 于是
    /// 下一次重签会给同一把密钥再挂一条 `#hot` 的验证方法,而且一路不报错。
    /// 挡在文件这一层最省事:字段不存在,就没有"改错了"这回事。
    #[test]
    fn the_root_fragment_cannot_be_set_from_the_spec_file() {
        let text = r#"{
            "host": "example.com",
            "path": "user/alice",
            "fragment": "hot"
        }"#;
        assert!(
            serde_json::from_str::<SpecFile>(text).is_err(),
            "a spec file must not be able to move the root key off {ROOT_FRAGMENT}"
        );
        assert_eq!(SpecFile::from(&spec()).to_spec().unwrap().fragment, ROOT_FRAGMENT);
    }

    #[test]
    fn a_spec_file_pointing_at_another_host_is_refused() {
        let did = compose_did_wba(&spec(), &key()).unwrap();
        let mismatch = SpecFile {
            host: "evil.example".into(),
            port: None,
            path: "user/alice".into(),
            agent_description_url: None,
            services: Vec::new(),
        };
        assert!(mismatch.check_coordinates(&did).is_err());

        let right = SpecFile::from(&spec());
        assert!(right.check_coordinates(&did).is_ok());
    }

    #[test]
    fn a_spec_file_with_the_wrong_path_is_refused() {
        let did = compose_did_wba(&spec(), &key()).unwrap();
        let wrong = SpecFile {
            host: "example.com".into(),
            port: None,
            path: "user/bob".into(),
            agent_description_url: None,
            services: Vec::new(),
        };
        assert!(wrong.check_coordinates(&did).is_err());
    }

    /// 一份带 service 声明的文档,按它自己的规格重建一遍,`service` 必须
    /// 逐字节一样。
    ///
    /// 这一条钉的是一个**会静静咬人**的地方:`service` 由规格说了算,所以它
    /// 不在"上游不认识的属性原样搬回去"那一档里 —— 只按 DID 重建的话,
    /// WNS handle 绑定会从文档里消失,而覆盖写是不报错的。
    #[test]
    fn the_overlay_survives_a_rebuild() {
        use crate::did::document::build_unsigned;

        let spec = spec()
            .with_agent_description_url("https://example.com/agents/mybot/ad.json")
            .with_service(serde_json::json!({
                "id": "#handle",
                "type": "ANPHandleService",
                "serviceEndpoint": "https://wns.example.com/alice",
            }));
        let (did, document) = build_unsigned(&spec, &key()).unwrap();

        // 上游把 `#handle` 补成了完整 id,并且把 agent description 也做成
        // 一条服务条目 —— 所以文档里是两条。
        let entries = document["service"].as_array().unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");

        let back = DidDocumentSpec::from_document(&document).unwrap();
        assert_eq!(back.did(&key()).unwrap(), did);
        assert_eq!(back.agent_description_url, spec.agent_description_url);
        assert_eq!(back.services.len(), 1);

        let (_, again) = build_unsigned(&back, &key()).unwrap();
        assert_eq!(
            again["service"], document["service"],
            "rebuilding from a document must not drop or duplicate service entries"
        );
    }

    /// 坐标的规则只有一份,放在解析器那边。这里确认规格文件也走那一份 ——
    /// 否则"文件里写了个 IP"会一路走到发布,发出去一个谁都找不到的 DID。
    #[test]
    fn a_spec_file_with_a_host_that_is_not_a_domain_is_refused() {
        for host in ["", "   ", "127.0.0.1", "localhost", "[::1]"] {
            let file = SpecFile {
                host: host.into(),
                port: None,
                path: "user/alice".into(),
                agent_description_url: None,
                services: Vec::new(),
            };
            assert!(file.to_spec().is_err(), "{host:?} must not be usable as a did:wba host");
        }
    }

    /// 路径段的字符集同理:`%2F` 会在服务端被解成斜杠,于是取回地址就能
    /// 被拐到别的路径去。
    #[test]
    fn a_spec_file_with_a_path_that_escapes_is_refused() {
        for path in ["", "/", "user/../etc", "user%2Fetc", "user alice", "user/./alice"] {
            let file = SpecFile {
                host: "example.com".into(),
                port: None,
                path: path.into(),
                agent_description_url: None,
                services: Vec::new(),
            };
            assert!(file.to_spec().is_err(), "the path {path:?} must not be accepted");
        }
    }
}
