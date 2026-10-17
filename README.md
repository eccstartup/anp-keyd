# anp-keyd

anp-keyd 是一个跑在本机的服务，替你的 AI Agent 保管 did:wba 的 Ed25519 私钥，并只在允许的范围内替它签名 HTTP 请求。

Agent 通过本地 socket 提交请求，拿回签名头。私钥不出服务进程，Agent 也拿不到。

## 它解决什么问题

Agent 要代表你访问网站，网站用 did:wba 验证签名。如果直接把私钥给 Agent，一次提示注入或一个坏依赖就可能把私钥带走。

用 anp-keyd 后：

- 私钥存在本机服务里，Agent 读不到，也不能通过接口取出。
- 你给 Agent 一张许可条（grant）：哪把钥匙、哪个网站和路径、有效期、最多几次。
- 超出范围、过期、次数用光、被你撤销、机器重启，都会拒绝签名。

## 五分钟试用

这一步只让你看效果，所有东西都在你的账号下运行，**不建立安全边界**。需要 Rust 1.88+。

```bash
cargo install --path .
mkdir -p /tmp/keyd-lab
anp-keyd --root /tmp/keyd-lab spec \
  --host example.com --path agents/mybot --out /tmp/keyd-lab/mybot.spec.json
anp-keyd --root /tmp/keyd-lab keygen --spec /tmp/keyd-lab/mybot.spec.json
```

`keygen` 会让你输入两遍口令，然后打印一个 DID，记下来。

```bash
anp-keyd --root /tmp/keyd-lab serve
```

换一个终端，解锁钥匙：

```bash
anp-keyd --root /tmp/keyd-lab unlock --did 你的DID
```

签名：

```bash
anp-keyd --root /tmp/keyd-lab sign --did 你的DID \
  --method GET --url https://service.example.net/orders/42
```

输出是两行签名头：

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=...;expires=...;keyid="did:wba:..."
Signature: sig1=:...:
```

把这两行原样放进 HTTP 请求头，不能改任何一个字符。试完关掉：

```bash
anp-keyd --root /tmp/keyd-lab stop
```

## 正式部署（Linux）

正式使用时，服务、管理员、Agent 分别是三个系统账号。Agent 账号读不到私钥、配置和状态。

安装由人类管理员执行：

```bash
cargo build --locked --release --features mcp
sha256sum target/release/anp-keyd
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --sha256 你核对过的SHA256 --admin-user operator --agent-user agent-a
sudo systemctl daemon-reload
sudo systemctl enable --now anp-keyd
```

装好后还没有身份。接下来：

1. 准备一个 did:wba 身份（新生成，或从旧机器迁入）。
2. 管理员登记身份，确认哪把钥匙是热钥匙。
3. 发布策略：允许访问哪个网站、哪个路径、哪些 HTTP 方法。
4. 创建 grant：给哪个 Agent、用哪把钥匙、用到什么时候、最多几次。
5. 管理员输入口令解锁热钥匙。
6. Agent 开始请求签名。

完整命令和 JSON 见[本机使用指南](deploy/LOCAL-USE.md)和 [Agent 接入说明](docs/ADAPTER.md)。

## Agent 怎么用

Agent 在自己的系统账号下提交一个请求文件：

```json
{
  "operation": "SIGN_HTTP",
  "grant_id": "管理员给的GRANT_ID",
  "request_id": "每次新操作自己生成的UUID",
  "http": {
    "method": "GET",
    "url": "https://service.example.com/v1/status",
    "headers": {},
    "body": {"state": "absent"},
    "nonce": null
  }
}
```

```bash
anp-keyd data --config /etc/anp-keyd/service.json --file request.json
```

`grant_id` 决定这次签名能用哪把钥匙、访问哪里、最多几次；`request_id` 是这次操作的唯一编号。

返回签名结果后，用返回的 URL、原始 body 和签名头发送请求，并关闭自动重定向。

超时或结果不确定时，用同一个 `request_id` 查询 `GET_REQUEST_STATUS`，不要换一个新 ID 重签。

## 注意事项

- 重启后所有 grant 作废、钥匙重新锁定，需要管理员重新解锁和建权。
- 撤销只阻止新签名，已经发出去的签名收不回来。
- 同一个系统账号里的程序属于同一个主体；只隔离签名子进程不够，整个 Agent 都要在 Agent 账号下运行。
- 管理员、root、内核和 daemon 本身是信任前提。
- macOS 目前只有本机预览，`protected_supported=false`；受保护部署在 Linux。

## 文档

- [本机使用：先建立边界，再交给 Agent](deploy/LOCAL-USE.md)
- [Linux 部署](deploy/linux/README.md)、[TPM](deploy/linux/TPM.md)
- [Agent 接入与 SDK](docs/ADAPTER.md)
- [安全设计与威胁模型](docs/DESIGN.md)
- [macOS 预览](deploy/macos/README.md)、[Secure Enclave](deploy/macos/SE-SESSION.md)
- [独立审计采集器](deploy/checkpoints/README.md)
- [Node 客户端与 SDK connector](adapters/README.md)
- [给 Agent 的 skill](skills/anp-keyd/SKILL.md)
- 文档站：[anp-keyd.vercel.app](https://anp-keyd.vercel.app)

## 许可

Apache-2.0。见 [LICENSE](LICENSE)。
