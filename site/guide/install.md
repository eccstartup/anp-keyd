# 安装

需要 Rust 1.88 或更新。受保护部署目前只支持 Linux；macOS 提供独立账号的本机预览。

## Linux 受保护部署

服务、管理员和 Agent 会用三个系统账号。先构建，再核对二进制摘要，然后安装：

```bash
cargo build --locked --release --features mcp
sha256sum target/release/anp-keyd
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --sha256 你核对过的SHA256 \
  --admin-user operator --agent-user agent-a --agent-user agent-b
sudo systemctl daemon-reload
sudo systemctl enable --now anp-keyd
```

不需要 MCP 时去掉 `--features mcp`。`--agent-user` 可以写多个，每个 Agent 一个账号。

安装器会建立服务账号、socket 组、root 所有的程序与配置、SQLite 状态和 systemd 服务。它拒绝覆盖已有安装，不会自动迁入身份。

装完检查：

```bash
/usr/local/libexec/anp-keyd admin --config /etc/anp-keyd/service.json status
/usr/local/libexec/anp-keyd probe --security --config /etc/anp-keyd/service.json
```

安装成功只说明服务和权限检查通过。此时还没有身份，也还不能签名。接下来要准备身份、发布策略、创建 grant 并解锁，见[本机使用](/guide/local-use)和[接到 Agent 上](/advanced/agent)。

更新用 `--update`，先停服务：

```bash
cargo build --locked --release
sha256sum target/release/anp-keyd
sudo systemctl stop anp-keyd
sudo python3 deploy/linux/install.py --update \
  --binary target/release/anp-keyd --sha256 你核对过的SHA256
sudo systemctl start anp-keyd
```

更新不会覆盖配置和状态，也不会自动重启。旧 grant 在重启后失效。

### 什么时候报告 `protected_supported=true`

同时满足三个条件：

- 正式 Linux release；
- 没启用 `hardware-software` 或 `seed-export`；
- 配置显式为 `linux-protected-v1`。

preview、调试构建和 macOS 都是 false。这个标志是支持范围声明，不是对任意宿主配置的持续证明。新安装默认选择保护模式；旧 preview 配置升级时保留原模式，需要管理员停机后明确切换。

### TPM

需要 TPM 后端时：

```bash
cargo build --locked --release --features hardware-tpm
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --sha256 你核对过的SHA256 --admin-user operator --agent-user agent-a \
  --tpm-device /dev/tpmrm0
```

安装器只授予 `/dev/tpmrm0` 并把传输固定到该设备。验收步骤见[TPM 说明](/advanced/hardware-root)和仓库 `deploy/linux/TPM.md`。

## macOS 本机预览

macOS 预览不要求完整 Xcode、付费开发者会员或 Secure Enclave。从源码编译需要 Rust 和 Command Line Tools。

```bash
cargo build --locked --release --features mcp
shasum -a 256 target/release/anp-keyd
python3 deploy/macos/provision-accounts.py --admin-user 你的账号
sudo bash deploy/macos/setup-local.sh 你的账号 你核对过的SHA256
```

安装器建立独立账号和 launchd 服务，拒绝覆盖已有安装。它始终报告 `protected_supported=false`。

整个 Agent 必须在独立的非管理员账号下运行。只切换签名子进程的账号不构成隔离。

已有的安装不要重复执行 setup；更新按 `deploy/macos/update-local.py` 的步骤先看计划、核对后再执行。

## 本地开发

```bash
cargo install --path .
anp-keyd probe
```

这不会建立服务/管理员/Agent 隔离，只适合临时身份和可信进程。用法见[五分钟跑通](/guide/quickstart)。

## 可选 feature

| feature | 作用 |
|---|---|
| `mcp` | 启用 MCP；v2 用 `mcp --config` |
| `seed-export` | 离线维护用的明文导出；默认不编入，启用后不声明保护支持 |
| `hardware-se` | macOS Secure Enclave 后端；正式发行和持久化未验收 |
| `hardware-tpm` | Linux TPM 后端；部署范围已验收，实体芯片保护声明未做 |
| `hardware-software` | 测试替身，不是硬件；release 构建拒绝 |

指定硬件不可用时会报错，不会退回纯软件封装。

## 本地检查

```bash
RUST_LOG=info cargo test --locked --offline
RUST_LOG=info cargo test --locked --offline --features mcp,hardware-software
cargo clippy --locked --offline --all-targets --features mcp,hardware-software -- -D warnings
```

这些是软件回归测试，不能代替多账号、systemd 或实体硬件验收。离线运行要求依赖已经缓存。
