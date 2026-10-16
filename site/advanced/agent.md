# Agent 接入

本页介绍 Linux v2。服务须先由管理员部署，Agent 使用独立 UID，获得受保护配置路径、grant_id 和 exact key_id。正式 Linux release 且配置为 `linux-protected-v1` 才声明保护支持。macOS 和同 UID 运行保留开发能力。

完整协议、管理变更和恢复说明见仓库 [ADAPTER.md](https://github.com/eccstartup/anp-keyd/blob/master/docs/ADAPTER.md)。

## CLI

把公开请求保存为 request.json，以 Agent UID 运行：

```sh
anp-keyd data --config /etc/anp-keyd/service.json --file request.json
```

```json
{
  "operation": "SIGN_HTTP",
  "grant_id": "ADMIN_SUPPLIED_GRANT_ID",
  "request_id": "6b79d06e-33cf-44e2-8209-81938b6a8ed3",
  "http": {
    "method": "GET",
    "url": "https://service.example.com/v1/status",
    "headers": {},
    "body": {"state": "absent"},
    "nonce": null
  }
}
```

grant 和目标须与管理员配置一致。每个新操作生成并保存自己的 UUID，重试使用原 ID，不能重复使用此示例 UUID。CLI 自动封装 v2 版本；成功回复的业务数据在 data 字段。

数据操作还有 GET_CAPABILITIES、LIST_AUTHORIZED_KEYS、GET_GRANT_STATUS、GET_DOCUMENT 和 GET_REQUEST_STATUS。数据面没有密码、解锁、根签名、raw、challenge 或生命周期入口。

## 发送与恢复

发送必须使用 daemon 返回的规范化 URL、原始 body 字节和签名头，禁用自动重定向。body 显式区分 absent 与 present；present 空数组也签摘要。当前 body 上限 16384 字节，整帧 65536 字节，URL 仅支持保守 HTTPS DNS 子集。

应用在签名前持久保存 request_id 和精确输入。超时后先查询原 ID，不换 ID 自动重签。completed 表示签名结果持久化，不代表远端业务执行；outcome_unknown 需要结合审计和业务状态处理。撤销、过期或重启后不再交付失效缓存。

## Node 和现有 SDK

仓库 [adapters/keyd-v2.mjs](https://github.com/eccstartup/anp-keyd/blob/master/adapters/keyd-v2.mjs) 提供 KeydV2Client、keydV2Signer 和 keydV2Connector；Node 18+，通过 Rust CLI 认证 daemon。client.fetch 禁用重定向，不自动重试；它不会替应用持久化操作状态。

SDK createConfig/signRequest 接缝已有验收，但已验版本的高层 resolveVerificationKey 错将 hot 指纹与 DID 根指纹比较，尚未兼容。SDK 的 ANP-02 body 与 awiki JSON-RPC envelope 不同；先构造正确 body 再签，不能签后重写。不能自动回退 root grant。

## MCP

启用 mcp feature 后，由 Agent 所属执行域启动：

```json
{
  "mcpServers": {
    "anp-keyd": {
      "command": "/usr/local/libexec/anp-keyd",
      "args": ["mcp", "--config", "/etc/anp-keyd/service.json"]
    }
  }
}
```

| 工具 | 输入 |
|---|---|
| list_my_keys | 空对象 |
| grant_status | grant_id |
| get_did_document | key_id |
| sign_request | grant_id、request_id、http |
| request_status | request_id |

配置在启动时固定，工具参数不能覆盖 socket、root、config、DID 或 kid。口令不经 MCP。stdout 属于协议，诊断走 stderr。不带 --config 的 MCP 是旧开发路径，不是失败后的降级方案。

当前 MCP 源码部分描述仍含“M4 未启用”的旧文案，服务端事务执行器已经启用；能力判断以 capabilities 和实际结果为准。这处源码文案仍需单独修正。

## 管理动作

管理员通过独立 admin 通道 prepare/commit 建权、撤销和角色确认；注册 proof 与轮换用 complete-secret-operation 短期解封根密钥。挑战来源由可信管理适配器校验，普通 Agent 不代办。

daemon 重启使旧 grant 失效并锁定密钥。恢复运行需要管理员重新解锁和建权。文档本地生成不代表远端发布或撤销已生效。

写给 Agent 的操作约束见仓库 [skill](https://github.com/eccstartup/anp-keyd/tree/master/skills/anp-keyd)。skill 不授予管理权限，也不能替代 daemon 策略检查。
