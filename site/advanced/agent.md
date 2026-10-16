# Agent 接入与模式

Linux v2 请使用仓库 `skills/anp-keyd/SKILL.md`、`adapters/keyd-v2.mjs` 或 `mcp --config`。必须提供管理员配置、grant 和持久 request_id；收到签名后按规范化 URL 与原 body 发送，不跟随重定向。没有普通 Agent challenge/password/raw 操作，错误不触发 v1 回退。`protected_supported=false` 仍是发行状态。

以下保留旧开发模式接入说明，同 UID 不提供私钥隔离。

# 接到 agent 上

## 一、MCP

`mcp` 子命令在 stdin/stdout 上说 MCP,把几个工具转发给守护进程。**它自己不开密钥库,也不碰密码学。**

```bash
cargo install --path . --features mcp
```

MCP 客户端的配置里,那一行 `command` 就指向这个子命令,参数是 `["mcp"]`:

```json
{
  "mcpServers": {
    "anp-keyd": { "command": "/path/to/anp-keyd", "args": ["mcp"] }
  }
}
```

| 工具 | 干什么 |
|---|---|
| `list_my_keys` | 列出这台机器上的钥匙 |
| `status` | 列出当前已解锁的钥匙 |
| `sign_request` | 签一条请求 |
| `get_did_document` | 取回一份本机发布过的文档 |

MCP 不提供解锁工具或密码参数。用户通过本机 CLI 解锁；当前 v1 会经 socket
发送口令；Linux v2 管理客户端已有独立服务 UID 认证。

::: info 有一条明确的"没有"
那条比 `Raw` 窄的挑战签名路(见[不显然的默认值](/reference/defaults#关于能签任意字节的那两条路))**不进 MCP**。

agent 手里不该有"签这串字节"的工具。
:::

## 二、写给 agent 看的说明

仓库里 [`skills/anp-keyd/`](https://github.com/eccstartup/anp-keyd/tree/master/skills/anp-keyd) 是一份 Claude Code skill:告诉 agent 怎么查状态、怎么签、怎么把两个头逐字节挂上去、被拒的那些码各自什么意思。

它还写了**三件绝不做的事**:

- 不要口令
- 不替人跑生命周期命令
- 24 个词不许进聊天

装上它:

```bash
cp -r skills/anp-keyd ~/.claude/skills/          # 只给自己用
cp -r skills/anp-keyd .claude/skills/            # 给这个项目里的会话用
```

## 三、自己写客户端

线上格式是长度前缀:

```
u32_be(len) || payload
```

消息类型只有六种:

| 消息 | 对应命令 |
|---|---|
| `LIST_KEYS` | `list` |
| `SIGN` | `sign` |
| `UNLOCK` | `unlock` |
| `LOCK` | `lock` |
| `STATUS` | `status` |
| `GET_DOCUMENT` | `document` |

[`src/client/mod.rs`](https://github.com/eccstartup/anp-keyd/blob/master/src/client/mod.rs) 就是一份可以直接抄的最小实现。

## 那几件"agent 不该做的事"

守护进程这边是靠**两条默认关着的路**挡的:

- `sign --raw` —— 任意签名的能力,要 `serve --allow-raw-signing`
- `sign --challenge` —— 同样签你给的原字节,但输入**有上界**(256 字节)

两条都默认关,理由在[不显然的默认值](/reference/defaults)里。**它们是"给调用方签东西"这件事的全部出口**,不开就等于没有。
