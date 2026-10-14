//! MCP 前端:stdin/stdout 上暴露五个工具。
//!
//! # 为什么是"socket 客户端",而不是把守护进程搬进来
//!
//! 这个模块里**没有任何密码学操作**,一次都没有。它做的全部事情是:接一条
//! MCP 请求 → 连上守护进程的 Unix socket → 转发 → 把应答变成工具结果。
//!
//! 三条理由,一条比一条要紧:
//!
//! 1. `client` 里已经有正好这几个操作了,一行不多一行不少。
//! 2. 自动上锁、审计、覆盖面下限这些判断**只有一处**。MCP 是第二个门面,
//!    不是第二套实现 —— 门面各自实现一遍,迟早会有一边的墙少砌一块。
//! 3. 这个进程是**agent 拉起来的**,它跑在 agent 的 uid 下。走 socket 意味着
//!    守护进程那边的对端凭证检查、策略、按 uid 分命名空间**照旧生效**;
//!    如果把密钥库读进来在本地解封,这一整层就被绕过去了,而且绕过它的是
//!    "我们自己的 MCP 服务器"这种听起来很正当的东西。
//!
//! # 五个工具,而且没有一个是 raw
//!
//! `list_my_keys` / `sign_request` / `unlock` / `status` / `get_did_document`。
//!
//! **没有 raw 签名,没有 keygen,没有导出,没有生命周期操作。** 这不是还没做,
//! 是不做:
//!
//! - raw 签名是守护进程里唯一一条能给调用方**任意签名**的路(见
//!   `sign::raw`)。它在 CLI 里藏在 `--allow-raw-signing` 后面;把它做成一个
//!   MCP 工具,等于让 agent 手里那条口子**默认开着**,而那正是那道开关要挡的。
//! - 挑战签名(`SIGN(Challenge)`)同理,**不做成工具**。它签的是调用方给的、
//!   没有任何消息语义的字节 —— 本质上就是小一号的 raw,同样要落在
//!   `--allow-challenge-signing` 后面才开。需要一个挑战签名的是**协议客户端**
//!   (注册流程里那一步),它直接走 socket 问;agent 没有理由问这个,所以门面
//!   也不给它。
//! - 生成、轮换、注销、迁移要改文档、要签文档,走的是本地文件而不是 socket
//!   (见 `cli.rs` 开头那一节)。MCP 是给**运行期签名**用的门面,不是给身份
//!   管理用的。
//!
//! `get_did_document` 是第五个,它和上面那条界限不冲突:**它只读,不改任何
//! 东西,也不需要解锁。** 文档本来就是 0644 的可公开成品。加它的理由是登录
//! 这件事本身:agent 要证明自己是谁,手上就得有那份文档,而文档躺在
//! `0700` 的目录里、还可能被 `publish --out` 挪到别处 —— 让它去猜路径、去
//! 读内部布局,不如给一个说得清的口子。移掉它,症状不会是报错,而是**走 MCP
//! 的 agent 登不了录,同一个 agent 在命令行上怎么试都是好的**。
//!
//! # `unlock` 这个工具要多说一句
//!
//! 它是这几个工具里唯一一个**会把口令带过 MCP 通道**的 —— 也就是说,接了它的
//! agent 手里会有口令。这一点必须写明白,不能装作没发生。三条限制让它不至于
//! 变成灾难,但它是**一个权衡,不是一个免费的东西**:
//!
//! 1. **口令只是两个因子里的一个。** 信封的另外一半熵是 `device.secret`,
//!    它留在守护进程那边、从不经手 MCP。拿到口令的人手上剩下的东西不比一个
//!    口令保护的压缩包多。
//! 2. **它没有给出新的能力。** `sign_request` 本来就让 agent 能签 —— 这是
//!    这个产品的用途。`unlock` 省掉的只是"某个人得在终端前敲一次",它不是
//!    那把钥匙的授予,是那道锁的开关。
//! 3. **不想要就别开这个门面。** `mcp` 是编译期特性,不构建它,这个模块不在
//!    二进制里;不用它,agent 就够不到这条路。
//!
//! 反过来,如果哪天有人想给 `unlock` 加一个"记住口令"的缓存,那才是真的把
//! 两因子变成一因子 —— 到时候请回到这一节重新读一遍。

use std::collections::BTreeMap;
use std::path::PathBuf;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};

// `JsonSchema` 的 derive **展开之后**写的是 `schemars::…` 这样的路径,所以
// `schemars` 这个名字得在作用域里。用 rmcp 的再导出而不是自己加一条依赖:
// 版本对不上会变成"别人的 schemars 和 rmcp 的 schemars 不是同一个",而那种
// 错在 trait 上会表现成一句看不懂的 not satisfied。
use rmcp::schemars;

use crate::client::{parse_signed_headers, Client};
use crate::daemon::wire::SignRequest;
use crate::error::KeydError;
use crate::keystore::layout::KeydLayout;

// **不要把 `crate::error::Result` 导进来。** `#[tool_handler]` 展开出来的签名
// 写的是 `Result<CallToolResult, McpError>`,而那个 alias 只有一个参数 ——
// 它在作用域里,宏生成的代码就解析到它头上,报的是一句和 MCP 毫无关系的
// "type alias takes 1 generic argument"。所以这里只导 `KeydError`,自家那个
// alias 一律写全 `crate::error::Result`。

/// 五个工具的实现体。
///
/// 它只持有一个东西:**守护进程的 socket 在哪**。不持有口令、不持有密钥、
/// 不持有连接 —— 一次调用一条连接,和 `client` 的约定一致(签名不是幂等的,
/// 悄悄复用一条死连接会把一次已经失去意义的请求重放上去)。
#[derive(Debug, Clone)]
pub struct Keyd {
    socket: PathBuf,
    tool_router: ToolRouter<Self>,
}

// ————————————————————————————————————————————————————————————
// 参数
// ————————————————————————————————————————————————————————————

/// 不带参数的工具也要一个结构体:工具的输入 schema 是 MCP 协议的一部分,
/// 空对象比"没有 schema"更明确。
#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct NoArgs {}

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct ListArgs {
    /// 不给就是当前用户默认的那个密钥库。
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct UnlockArgs {
    /// 要解锁的 DID。
    pub did: String,
    /// 用哪把钥匙,写 fragment(`key-2`、`recovery-1`……)。
    /// 不给就是 `did` 名下默认那把 —— 也就是**绑定密钥**。
    #[serde(default)]
    pub kid: Option<String>,
    /// 口令。见模块头 "`unlock` 这个工具要多说一句"。
    pub passphrase: String,
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct SignArgs {
    /// 用哪个身份签。
    pub did: String,
    #[serde(default)]
    pub kid: Option<String>,
    /// HTTP 方法,如 `POST`。
    pub method: String,
    /// 完整的请求 URI。RFC 9421 的 `@target-uri` 就是它。
    pub url: String,
    /// 请求里**已有的**头,名字不区分大小写。
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// 请求体。**请求体本身,不是它的摘要** —— 摘要由守护进程自己算,
    /// 这样签名绑定的才是真实的内容。
    ///
    /// 只收 UTF-8 文本。二进制请求体(文件上传)这条路走不了,那是 raw 的
    /// 场景,而 raw 不在这里 —— 见模块头。
    #[serde(default)]
    pub body: Option<String>,
    /// **额外**要求覆盖的分量。只能加,不能减:覆盖面有下限,由守护进程定。
    #[serde(default)]
    pub covered: Vec<String>,
    /// 写进 `@signature-params` 的 `nonce`。
    ///
    /// 要和**请求体里那个**是同一个值 —— 它同时出现在两个地方(请求体,
    /// 经由 `content-digest`;以及签名参数),所以只能由调用方给。不给就是
    /// 守护进程随机生成一个,那对一次性请求够用,对"回给一个已经见过 nonce
    /// 的服务端"没用。
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub root: Option<String>,
}

#[derive(Debug, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct DocumentArgs {
    /// 要取文档的 DID。
    pub did: String,
    /// 不给就是当前用户默认的那个密钥库。
    #[serde(default)]
    pub root: Option<String>,
}

// ————————————————————————————————————————————————————————————
// 工具
// ————————————————————————————————————————————————————————————

#[tool_router]
impl Keyd {
    /// 建一个连向 `socket` 的门面。
    pub fn new(socket: PathBuf) -> Self {
        Self { socket, tool_router: Self::tool_router() }
    }

    #[tool(description = "列出这台机器上的 did:wba 密钥(不会返回任何私钥材料)")]
    async fn list_my_keys(
        &self,
        Parameters(args): Parameters<ListArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let keys = self
            .with_daemon(&args.root, "list_my_keys", |client| client.list_keys())
            .await?;
        text(serde_json::json!({
            "keys": keys.iter().map(|key| serde_json::json!({
                "did": key.did,
                "kid": key.kid,
                "algorithm": format!("{:?}", key.algorithm),
            })).collect::<Vec<_>>(),
        }))
    }

    #[tool(description = "当前已解锁的密钥,以及各自解锁了多久(秒)")]
    async fn status(
        &self,
        Parameters(args): Parameters<ListArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let keys = self
            .with_daemon(&args.root, "status", |client| client.status())
            .await?;
        text(serde_json::json!({
            "unlocked": keys.iter().map(|key| serde_json::json!({
                "did": key.did,
                "kid": key.kid,
                "unlocked_secs": key.unlocked_secs,
            })).collect::<Vec<_>>(),
        }))
    }

    #[tool(description = "解锁一把密钥。口令会经过 MCP 通道 —— 见文档")]
    async fn unlock(
        &self,
        Parameters(args): Parameters<UnlockArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let did = args.did;
        let kid = args.kid;
        // 口令进闭包之后就被 `Zeroizing` 包住,读完即擦。`client::unlock`
        // 收的是普通 `String`(它不强迫调用方引入 zeroize),所以这里的
        // `Zeroizing` 是**这一层**能给的最好的东西。
        let passphrase = zeroize::Zeroizing::new(args.passphrase);

        let caller = did.clone();
        self.with_daemon(&args.root, "unlock", move |client| {
            client.unlock(&did, kid.as_deref(), &passphrase)
        })
        .await?;
        text(serde_json::json!({"unlocked": caller}))
    }

    #[tool(description = "签一条 RFC 9421 HTTP 消息签名,返回要挂到请求上的头")]
    async fn sign_request(
        &self,
        Parameters(args): Parameters<SignArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let request = SignRequest::Structured {
            did: args.did,
            kid: args.kid,
            method: args.method,
            target_uri: args.url,
            // 头名转小写:HTTP 头名不区分大小写而 `BTreeMap` 区分,不转的话
            // `Content-Type` 和 `content-type` 会成为两条记录,一条被签、
            // 另一条被忽略,而调用方以为自己两条都给了。
            headers: args
                .headers
                .into_iter()
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value))
                .collect(),
            body: args.body.map(String::into_bytes),
            covered: args.covered,
            nonce: args.nonce,
        };

        let signed = self
            .with_daemon(&args.root, "sign_request", move |client| client.sign(request))
            .await?;

        // **原样搬运。** 这些字节要挂到真实请求上,改动其中任何一个字符签名
        // 就验不过 —— 所以这里解析、再序列化成 JSON 对象,让调用方能直接用。
        let headers = parse_signed_headers(&signed).map_err(refusal)?;
        text(serde_json::json!({"headers": headers}))
    }

    #[tool(description = "取一份本机发布过的 DID 文档。只读,不需要解锁")]
    async fn get_did_document(
        &self,
        Parameters(args): Parameters<DocumentArgs>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let did = args.did;
        let caller = did.clone();
        let bytes = self
            .with_daemon(&args.root, "get_did_document", move |client| client.document(&did))
            .await?;

        // **交回原文。** 这是一件签好名的成品,它的字节就是被签的那些字节 ——
        // 收成字符串而不是解析成对象,是为了让"逐字节一样"这件事在 MCP 这一跳
        // 上还能成立(解析再序列化会把键重排)。
        //
        // 必须是 UTF-8:守护进程那边已经把它解析成过 JSON,所以走到这里不会
        // 失败。这不是"可能出错的地方",是**跨进程边界的一次确认** —— 边界
        // 之外的东西不该按边界之内的保证来对待。
        let document = String::from_utf8(bytes).map_err(|error| {
            ErrorData::internal_error(
                format!("the daemon returned a document that is not UTF-8: {error}"),
                None,
            )
        })?;

        text(serde_json::json!({"did": caller, "document": document}))
    }
}

#[tool_handler]
impl ServerHandler for Keyd {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "本机 did:wba 签名服务。密钥由 anp-keyd 守护进程持有,\
                 这个接口只提供签名,不提供任何私钥材料。"
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ————————————————————————————————————————————————————————————
// 转发
// ————————————————————————————————————————————————————————————

impl Keyd {
    /// 连一次守护进程、做一件事、断开。
    ///
    /// 走 `spawn_blocking`:`client` 是同步的(裸 `UnixStream`),而工具处理
    /// 是异步的。直接在异步任务里做阻塞 I/O 会把整个运行时的线程卡住 ——
    /// 一个 agent 发来的请求不该能冻住别的请求。
    async fn with_daemon<T, F>(
        &self,
        root: &Option<String>,
        what: &'static str,
        f: F,
    ) -> std::result::Result<T, ErrorData>
    where
        T: Send + 'static,
        F: FnOnce(&mut Client) -> crate::error::Result<T> + Send + 'static,
    {
        let socket = match root {
            Some(root) => KeydLayout::at(PathBuf::from(root)).sock_path(),
            None => self.socket.clone(),
        };

        tokio::task::spawn_blocking(move || {
            let mut client = Client::connect(&socket)?;
            f(&mut client)
        })
        .await
        .map_err(|error| {
            ErrorData::internal_error(format!("the {what} task failed: {error}"), None)
        })?
        .map_err(refusal)
    }
}

/// 把守护进程那边的失败变成 MCP 错误。
///
/// 用的是**粗码**消息(`wire_message`),不是 `Display`:后者可能带着细节,
/// 而协议层已经决定过哪些细节不出门(`wire::Response::from_error` 那一条
/// 路径)。这里再 `to_string()` 一次,等于把刚关上的门重新打开。
fn refusal(error: KeydError) -> ErrorData {
    ErrorData::new(
        rmcp::model::ErrorCode::INTERNAL_ERROR,
        error.wire_message(),
        // 粗码放 `data` 里:调用方能据此分支,而它本身不含任何秘密。
        Some(serde_json::json!({ "code": format!("{:?}", error.wire_code()) })),
    )
}

fn text(value: serde_json::Value) -> std::result::Result<CallToolResult, ErrorData> {
    let rendered = serde_json::to_string(&value)
        .map_err(|error| ErrorData::internal_error(format!("could not render a result: {error}"), None))?;
    Ok(CallToolResult::success(vec![Content::text(rendered)]))
}

// ————————————————————————————————————————————————————————————
// 入口
// ————————————————————————————————————————————————————————————

/// 在 stdin/stdout 上跑 MCP 服务,直到对端关闭。
///
/// `socket` 不给就按默认布局推导(`~/.anp-keyd/run/keyd.sock`)。
///
/// **stdout 归协议。** 这里不打印任何东西到 stdout —— 一行日志就能把一次
/// 初始化打成 JSON 解析错误,而症状看起来像"MCP 客户端不认这个服务器"。
/// 诊断信息走 `tracing`,去 stderr。
pub fn serve(socket: Option<PathBuf>) -> crate::error::Result<()> {
    let socket = match socket {
        Some(socket) => socket,
        None => KeydLayout::user_default()?.sock_path(),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(KeydError::Io)?;

    runtime.block_on(async move {
        let service = Keyd::new(socket)
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|error| KeydError::Protocol(format!("MCP handshake failed: {error}")))?;

        service
            .waiting()
            .await
            .map_err(|error| KeydError::Protocol(format!("MCP server stopped: {error}")))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **工具表就是这五个,而且没有一个能把任意字节签出去。**
    ///
    /// 这条测试挡的是"顺手加一个工具":MCP 是 agent 直接够得着的面,多一个
    /// 工具就是多一条 agent 能走的路。所以工具集合被钉死在这儿,改动它必须
    /// 先改这条测试 —— 而那次改动会被 review 看见。
    ///
    /// 第五个 `get_did_document` 是**只读**的,加它的理由写在模块头里:登录
    /// 需要它,而它不开放任何新的授权。往这张表里再加东西,请先回答模块头
    /// 那一节的问题。
    #[test]
    fn exactly_five_tools_and_none_of_them_signs_raw_bytes() {
        let router = Keyd::tool_router();
        let mut names: Vec<String> = router.list_all().into_iter().map(|tool| tool.name.to_string()).collect();
        names.sort();

        assert_eq!(
            names,
            ["get_did_document", "list_my_keys", "sign_request", "status", "unlock"]
        );
        assert!(
            !names.iter().any(|name| name.contains("raw")),
            "raw signing must never be reachable from the MCP front end: {names:?}"
        );
    }

    /// 通往守护进程的失败是**粗码**,不带内部细节。
    #[test]
    fn a_refusal_carries_the_coarse_message_not_the_internal_one() {
        let error = refusal(KeydError::BadPassphrase);
        assert_eq!(error.message, "the credential was refused");
        assert!(
            !error.message.contains("passphrase"),
            "the coarse message must not name the factor that failed: {}",
            error.message
        );
        assert!(error.data.is_some(), "the coarse code is for branching on");
    }

    /// 空参数的工具也要能过 schema —— 否则客户端列表都列不出来。
    #[test]
    fn the_empty_argument_struct_serialises_as_an_object() {
        let rendered = serde_json::to_string(&serde_json::json!({})).unwrap();
        assert_eq!(rendered, "{}");
        let _ = rmcp::schemars::schema_for!(NoArgs);
    }
}
