//! 同 DID 内改文档 —— 也就是"**换密钥但不换身份**"。
//!
//! 路径型 DID 的形状决定了这里只有一条路可走:
//!
//! ```text
//! did:wba:example.com:agents:mybot:e1_<binding key 的指纹>
//!        └── 你控制的域名 ──┘└─ 路径 ─┘└──── 身份就是这个 ────┘
//! ```
//!
//! **最后一段是绑定密钥的指纹。** 它一动,DID 就变 —— 那不是轮换,是迁移
//! (见 [`crate::did::migrate`])。所以"能换密钥而不换身份"的全部余地,都在
//! 绑定密钥**之外**的那些验证方法上:规范原文说得很清楚,只要路径里那把
//! 指纹不变,文档里加新验证密钥、废掉旧的、改 service 端点都是允许的。
//!
//! 于是这个模块只做三件事:读出文档里非绑定的那些密钥、算出下一个可用的
//! fragment、以及把注销标记写进去。密码学一步都没有 —— 改完还是要拿绑定
//! 密钥去重签,那一步在 [`crate::did::document::sign_document`]。

use serde_json::Value;

use crate::did::document::{ExtraKey, ROOT_FRAGMENT};
use crate::did::parse::parse_did_wba;
use crate::error::{KeydError, Result};

/// 热密钥的 fragment 前缀。`key-1` 被根密钥占了,所以从 `key-2` 开始。
pub const HOT_KEY_PREFIX: &str = "key-";
/// 恢复密钥的 fragment。
pub const RECOVERY_FRAGMENT: &str = "recovery-1";

/// 文档里被 `deactivated` 标记为已注销。
pub fn is_deactivated(document: &Value) -> bool {
    document.get("deactivated").and_then(Value::as_bool) == Some(true)
}

/// 文档指向的后继 DID。
pub fn successor_of(document: &Value) -> Option<&str> {
    document.get("successorDid").and_then(Value::as_str)
}

/// `did:wba:example.com:a:b:e1_xxx` → `example.com:a:b`。
///
/// 这就是规范说的 **stable subject path**:绑定指纹**之前**的那一段。
/// 是不是"同一个主体换了把钥匙",看的就是它 —— 域名、端口、路径段全都
/// 必须一样,唯独最后那把密钥可以不同。
pub fn subject_path(did: &str) -> Result<String> {
    let parts = parse_did_wba(did)?;
    if parts.path_segments.is_empty() {
        return Err(KeydError::Did(format!("{did} has no path segments")));
    }
    let mut segments = parts.path_segments.clone();
    // 最后一段必须是 e1_ 绑定段;不是的话这个 DID 根本不是路径型。
    let last = segments.pop().unwrap_or_default();
    if !last.starts_with("e1_") {
        return Err(KeydError::Did(format!("{did} has no e1_ binding segment")));
    }
    let mut out = parts.host.clone();
    if let Some(port) = parts.port {
        out.push_str(&format!(":{port}"));
    }
    for segment in segments {
        out.push(':');
        out.push_str(&segment);
    }
    Ok(out)
}

/// 文档里**除根密钥之外**的验证方法,按它们在 `verificationMethod` 里的顺序。
///
/// 读不出来的一律报错,不跳过:一份文档里有一条读不懂的验证方法,意味着
/// 我们接下来重签的时候会把它**弄丢** —— 而丢掉的可能是别人正靠着的热密钥
/// 或者恢复密钥。宁可现在失败。
pub fn extra_keys(document: &Value, did: &str) -> Result<Vec<ExtraKey>> {
    let root_id = format!("{did}#{ROOT_FRAGMENT}");
    let methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| KeydError::Did("the document has no verificationMethod array".into()))?;

    let mut out = Vec::with_capacity(methods.len().saturating_sub(1));
    for method in methods {
        let id = method
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| KeydError::Did("a verification method has no id".into()))?;
        if id == root_id {
            continue;
        }

        let fragment = id
            .strip_prefix(&format!("{did}#"))
            .ok_or_else(|| {
                KeydError::Did(format!(
                    "the verification method {id} does not belong to {did} — \
                     a document may not vouch for a key in someone else's namespace"
                ))
            })?
            .to_string();

        let material = anp::authentication::extract_public_key(method)
            .map_err(|e| KeydError::Did(format!("{id}: unreadable public key: {e}")))?;
        let public_key = match material {
            anp::PublicKeyMaterial::Ed25519(key) => key,
            _ => {
                return Err(KeydError::Did(format!(
                    "{id} is not an Ed25519 key, and this build cannot re-sign a document \
                     containing one — re-signing would silently drop it"
                )))
            }
        };

        let mut relationships = Vec::new();
        for (name, relationship) in [
            ("authentication", anp::authentication::DidVerificationRelationship::Authentication),
            ("assertionMethod", anp::authentication::DidVerificationRelationship::AssertionMethod),
            ("keyAgreement", anp::authentication::DidVerificationRelationship::KeyAgreement),
        ] {
            let listed = document
                .get(name)
                .and_then(Value::as_array)
                .is_some_and(|list| list.iter().any(|entry| entry.as_str() == Some(id)));
            if listed {
                relationships.push(relationship);
            }
        }

        out.push(ExtraKey { fragment, public_key, relationships });
    }
    Ok(out)
}

/// 当前那把热密钥 —— `authentication` 里那个**不是**绑定密钥的。
///
/// 冷热分离的意义就在这一条:绑定密钥是冷的(它的指纹就是 DID,动不了),
/// 日常签名用的那把挂在 `authentication` 下,可以随时换。
pub fn hot_key(document: &Value, did: &str) -> Result<Option<ExtraKey>> {
    Ok(extra_keys(document, did)?
        .into_iter()
        .find(|key| {
            key.relationships
                .contains(&anp::authentication::DidVerificationRelationship::Authentication)
        }))
}

/// 下一个可用的热密钥 fragment:`key-2`、`key-3`……
///
/// 用"当前用掉的最大编号 + 1",不是"数量 + 1":轮换过几轮之后编号会留下
/// 空洞,而重用一个已经退休过的编号会让两份**内容不同**的文档顶着同一个
/// `id` —— 任何缓存过旧文档的验证方都会把新签名判成坏签名。单调递增,
/// 不复用。
pub fn next_hot_fragment(document: &Value, did: &str) -> Result<String> {
    let mut highest = 1u32;
    for key in extra_keys(document, did)? {
        if let Some(number) = key.fragment.strip_prefix(HOT_KEY_PREFIX) {
            if let Ok(number) = number.parse::<u32>() {
                highest = highest.max(number);
            }
        }
    }
    Ok(format!("{HOT_KEY_PREFIX}{}", highest + 1))
}

/// 把文档标记成已注销,可选指向后继。
///
/// 规范的两条硬要求落在这里:
/// - **`successorDid` 只能指向直接下一代。** 已经注销过、且指向的是**另一个**
///   后继时,这里报错而不是改写 —— 回头改前一代的 successor 会让历史上
///   出现两条指向不同下一代的边,而"迁移路径"是靠这条边走出来的。
/// - 注销**不是删除**。老文档必须继续可解析,否则别人从旧 DID 出发就
///   找不到新家了;`deactivated` 只是告诉它"别再往这儿发了,往那边走"。
pub fn deactivate(document: &Value, successor: Option<&str>) -> Result<Value> {
    if let Some(existing) = successor_of(document) {
        if successor != Some(existing) {
            return Err(KeydError::Did(format!(
                "this document already points at {existing} as its successor, and a \
                 successor edge may only be written once — changing it would erase the \
                 path the previous migration was recorded on"
            )));
        }
    }

    let mut out = document.clone();
    let object = out
        .as_object_mut()
        .ok_or_else(|| KeydError::Did("the document is not a JSON object".into()))?;
    object.insert("deactivated".into(), Value::Bool(true));
    match successor {
        Some(successor) => {
            object.insert("successorDid".into(), Value::String(successor.to_string()));
        }
        // 永久注销:显式抹掉,不留一条指向空气的边。
        None => {
            object.remove("successorDid");
        }
    }
    Ok(out)
}

/// 重签之前把旧的 `proof` 摘掉。
///
/// proof 覆盖的是**整份文档**,包括它自己那一块吗?不 —— 摘掉是为了让
/// 签名输入里的文档和它将来的样子一致。留着一份旧 proof 去签一份新文档,
/// 签出来的东西覆盖的是旧 proof 的字节,而那正是要被替换掉的东西。
pub fn strip_proof(document: &Value) -> Result<Value> {
    let mut out = document.clone();
    let object = out
        .as_object_mut()
        .ok_or_else(|| KeydError::Did("the document is not a JSON object".into()))?;
    object.remove("proof");
    Ok(out)
}

/// 文档的一个能进审计日志的指纹 —— JCS 之后的 SHA-256。
///
/// 审计里记这个而不是记整份文档:整份文档太大,而指纹足够回答"当时发布的
/// 是这一份吗"。
pub fn document_digest(document: &Value) -> Result<String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let canonical = serde_json_canonicalizer::to_vec(document)
        .map_err(|e| KeydError::Protocol(format!("the document is not canonically encodable: {e}")))?;
    let digest = Sha256::digest(&canonical);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// 把一条 `verificationMethod` 从文档里彻底摘掉。
///
/// "彻底"是重点:只从 `verificationMethod` 里删、把 `id` 留在
/// `authentication` 里,得到的是一份**指向不存在的方法**的文档 —— 上游的
/// 规范性检查会拒,而拒绝的理由会指向一个跟真因毫无关系的地方。
pub fn remove_method(document: &Value, method_id: &str) -> Result<Value> {
    let mut out = document.clone();
    let object = out
        .as_object_mut()
        .ok_or_else(|| KeydError::Did("the document is not a JSON object".into()))?;

    let mut removed = false;
    if let Some(methods) = object.get_mut("verificationMethod").and_then(Value::as_array_mut) {
        let before = methods.len();
        methods.retain(|method| method.get("id").and_then(Value::as_str) != Some(method_id));
        removed = methods.len() != before;
    }

    for name in ["authentication", "assertionMethod", "keyAgreement"] {
        if let Some(list) = object.get_mut(name).and_then(Value::as_array_mut) {
            list.retain(|entry| entry.as_str() != Some(method_id));
            // 空的关系数组留在文档里是噪音,而且它和"这个关系没被用过"
            // 在 JSON 上长得一样 —— 摘掉。
            if list.is_empty() {
                object.remove(name);
            }
        }
    }

    if !removed {
        return Err(KeydError::Did(format!(
            "{method_id} is not a verification method in this document"
        )));
    }
    Ok(out)
}

/// 两份文档说的是不是同一个主体。
///
/// 判断依据是 stable subject path,不是 DID 本身 —— 换绑密钥会改 DID,
/// 但主体没变。迁移要挡的是相反的情况:两个 path 根本不同的 DID 之间的
/// "迁移",那不是换密钥,那是**冒名**。
pub fn same_subject(old: &str, new: &str) -> Result<bool> {
    Ok(subject_path(old)? == subject_path(new)?)
}
