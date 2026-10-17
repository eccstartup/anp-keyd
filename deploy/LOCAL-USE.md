# 本机使用：先建立边界，再交给 Agent

正式使用时，服务、管理员和 Agent 用三个系统账号：

| 账号 | 运行什么 | 能做什么 |
|---|---|---|
| 管理员（你本人） | 管理命令 | 批准变更、解锁、撤销、轮换 |
| 服务账号 | anp-keyd daemon | 保存私钥、状态和审计，执行签名 |
| Agent 账号 | 整个 AI 框架 | 只能请求签名和查询自己的授权 |

**整个 Agent 框架及其工具进程**都要在 Agent 账号下运行。只把签名子进程换账号，而模型的 shell 仍有管理员权限，边界不成立。

不要给 Agent sudo、Docker 管理权限、管理员凭据、真实身份口令，也不要让它能改服务程序或配置。

## 1. 安装

Linux 按[仓库安装说明](linux/README.md)部署 systemd 服务：

```bash
cargo build --locked --release --features mcp
sha256sum target/release/anp-keyd
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --sha256 你核对过的SHA256 --admin-user operator --agent-user agent-a
sudo systemctl daemon-reload
sudo systemctl enable --now anp-keyd
```

macOS 按[macOS 说明](macos/README.md)安装本机预览。安装后用一次性身份和公开口令做验收，不要用真实密钥试错。

## 2. 准备身份

新安装没有身份。两种来源：

- **新身份**：按 [README](../README.md) 里的五分钟试用生成，然后由管理员迁入托管目录。
- **旧身份**：停止旧 daemon 和所有写者，用离线迁移工具迁入：

```bash
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault \
  --apply --recovery-dir /root/keyd-recovery
```

迁移会核对摘要、逐钥验证恢复副本，并把新 vault 里的钥匙标成未分类、锁定状态。

## 3. 登记、确认角色、发布策略、创建 grant

下面所有管理变更都分两步：`prepare` 生成计划和摘要，你核对后 `commit`。示例里的 UUID 和网址都要换成真实值。

先看当前有什么：

```bash
anp-keyd admin --config /etc/anp-keyd/service.json list-principals
anp-keyd admin --config /etc/anp-keyd/service.json catalog
```

### 3.1 确认热钥匙

从 `catalog` 找到日常签名用的那把钥匙的 `key_id`：

```json
{"kind":"Catalog","change":{"action":"ConfirmRole","key_id":"HOT_KEY_UUID","role":"hot"}}
```

```bash
anp-keyd admin --config /etc/anp-keyd/service.json prepare --file role.json
anp-keyd admin --config /etc/anp-keyd/service.json commit \
  --operation-id PREPARED_OPERATION_UUID --digest PREPARED_DIGEST
```

只有确认成 hot 的钥匙才能进入普通 Agent 的 grant。root 和 recovery 钥匙不用于日常签名。

### 3.2 发布策略

策略规定 Agent 能访问哪里。下面的例子只允许 `GET https://service.example.com/v1/status`：

```json
{
  "kind": "Catalog",
  "change": {
    "action": "PublishPolicy",
    "policy_id": "POLICY_UUID",
    "version": 1,
    "content": {
      "schema_version": 1,
      "name": "read-agent-status",
      "purpose": "http-authentication",
      "origin": "https://service.example.com",
      "methods": ["GET"],
      "paths": ["/v1/status"],
      "query": {"mode": "none"},
      "body": {"mode": "empty", "max_bytes": 0},
      "signature_profile": "anp-http-v2",
      "grant_limits": {"max_duration_seconds": 900, "max_uses": 100}
    }
  }
}
```

同样 `prepare` 后 `commit`。

### 3.3 创建 grant

```json
{
  "kind": "Grant",
  "change": {
    "action": "Create",
    "principal_id": "AGENT_PRINCIPAL_UUID",
    "key_id": "HOT_KEY_UUID",
    "policy_id": "POLICY_UUID",
    "policy_version": 1,
    "expiry": 1792125000,
    "max_uses": 10
  }
}
```

`expiry` 是 Unix 秒，必须是未来时间，不能写 0。`max_uses` 是这张 grant 最多能签几次。提交后从返回的 effect 里取 `grant_id`，把它交给 Agent。

### 3.4 解锁

```bash
anp-keyd admin --config /etc/anp-keyd/service.json unlock \
  --vault-id VAULT_UUID --did DID --kid FULL_KID
```

口令由管理 CLI 从终端读取，不经过 Agent、MCP 或聊天。解锁只让钥匙可用，不会自己产生授权；授权来自上面的 grant。

## 4. 启动 Agent

确认 Agent 账号：

```bash
sudo -u agent-a -- id
```

输出应该是 Agent 的 UID，不是你自己的 UID。然后让整个 AI 框架在 `agent-a` 账号和专用工作目录下启动。不要把人类 HOME、令牌和管理员环境整体传给它。

Agent 可以用 CLI：

```bash
anp-keyd data --config /etc/anp-keyd/service.json --file request.json
```

也可以用 MCP：

```bash
anp-keyd mcp --config /etc/anp-keyd/service.json
```

MCP 需要构建时启用 `mcp` feature。工具参数不能覆盖配置文件、socket、DID 或 kid。

## 5. 日常：失败、重试、撤销

- 每个新操作自己生成并保存 `request_id`。重试时复用原 ID；不要因为超时换一个新 ID 重签。
- `outcome_unknown` 不表示没签名。停止自动重试，先查询状态并核对远端结果。
- 发送时用 daemon 返回的规范化 URL、原始 body 和签名头，关闭自动重定向。
- 撤销 grant 后不再产生新签名，但已经发出去的签名收不回来。

撤销：

```json
{"kind":"Grant","change":{"action":"Revoke","grant_id":"GRANT_ID"}}
```

同样 `prepare` 后 `commit`。

服务重启后所有 grant 失效、钥匙锁定、未完成批准作废。需要你重新解锁和建权，不会自动恢复。

## 6. macOS 预览和 SE

macOS 提供独立账号的本机预览，始终 `protected_supported=false`。Secure Enclave 登录助手、真实注销/休眠/整机重启、正式签名和持久 SE 仍需要单独验收，见[SE 说明](macos/SE-SESSION.md)。

预览测试通过不等于 macOS 正式发行完成，也不能把结果套到 Linux 受保护部署上。
