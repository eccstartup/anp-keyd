# 安装与模式选择

需要 Rust 1.88 或更新。开发模式支持 macOS 和 Linux；受保护部署当前只支持 Linux。

## Linux 受保护部署

在 Linux 构建正式 release。需要 MCP 时另加 --features mcp：

```sh
cargo build --locked --release
```

由管理员独立核对构建来源与 SHA-256，然后为新的服务实例安装：

```sh
sudo python3 deploy/linux/install.py --binary target/release/anp-keyd \
  --sha256 VERIFIED_BINARY_SHA256 \
  --admin-user operator --agent-user agent-a --agent-user agent-b
sudo systemctl daemon-reload
sudo systemctl enable --now anp-keyd
anp-keyd admin status
anp-keyd probe --security
```

替换示例用户名和摘要。安装器拒绝已有部署，更新使用单独的 --update 流程；它不自动迁移身份。组权限变更后需新登录会话。管理员和 Agent UID 不得重叠，Agent 无 sudo 或宿主管理 socket。

合格 release 的新安装选择 linux-protected-v1；旧 preview 配置升级保留原模式，需管理员停机后明确切换。正式 Linux release 且显式保护模式才报告 protected_supported=true；这是支持范围声明，probe 也不能代替完整宿主检查。

安装后还需迁入身份、确认 hot 角色、发布策略、解锁并建立 grant，才有可用签名。见[Agent 接入](/advanced/agent)及仓库 [ADAPTER](https://github.com/eccstartup/anp-keyd/blob/master/docs/ADAPTER.md)。

## macOS 本机独立 UID 预览

普通预览不要求完整 Xcode、付费开发者会员或 SE。从源码编译需要 Rust 与 Command Line Tools。可信人类管理员、服务和整个 Agent 各用独立 UID；root 持有安装与配置，始终报告 `protected_supported=false`。

```sh
cargo build --locked --release --features mcp
shasum -a 256 target/release/anp-keyd
python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT
sudo bash deploy/macos/setup-local.sh YOUR_HUMAN_ACCOUNT VERIFIED_SHA256
```

先审核源码、账号计划和摘要，再由人类终端执行 sudo。安装器建立账号和 launchd 服务，拒绝已有安装；新状态没有真实密钥。整个 Agent 必须在独立非管理员 UID 中启动，仅切换签名子进程不足以隔离。

已有安装不要重复 setup。先验收候选，再查看保留状态的更新计划：

```sh
python3 deploy/macos/update-local.py --binary target/release/anp-keyd --sha256 VERIFIED_SHA256
# 若已有 previous，审核后加 --archive-previous；它先完整归档，不覆盖归档。
# 核对计划后，由人类以 sudo 执行同一命令并加 --apply。
```

重启锁钥并撤销旧 grant，配置/状态保留。不要删除备份来绕过检查。macOS 通用真实身份迁移尚未验收，临时 fixture 不用于真实身份导入。

按[本机使用指南](/guide/local-use)完成临时签名、跨 UID、撤销与重启验收。详细安装/验收命令见[仓库 macOS 说明](https://github.com/eccstartup/anp-keyd/blob/master/deploy/macos/README.md)。SE 登录助手及正式发行是独立未完成项，见[硬件根](/advanced/hardware-root)。

## 本地开发

```sh
cargo install --path .
anp-keyd probe
```

这不会建立 Linux v2 的服务/管理员/Agent 隔离。仅用临时身份和可信进程运行[开发快速体验](/guide/quickstart)。v1 解锁口令经过旧 socket，不能作为受保护管理通道。

## 可选 feature

| feature | 范围 |
|---|---|
| mcp | 启用 MCP；v2 使用 mcp --config |
| seed-export | 离线维护导出；默认不编入，启用后不声明保护支持 |
| hardware-se | macOS SE 后端，发行及持久化仍待专项验收 |
| hardware-tpm | Linux TPM 后端，实体权限和故障仍待验收 |
| hardware-software | 测试替身，不是硬件；release 拒绝 |

指定硬件不可用时拒绝，不静默降级。默认不启用硬件后端。

口令由可信管理 CLI 从控制终端读取，发送前认证 daemon；不会写入 argv、环境变量或 MCP 参数。Agent 能创建 PTY，所以终端不证明人类在场，授权依赖管理员 UID 和管理通道。

## 本地检查

```sh
RUST_LOG=info cargo test --locked --offline
RUST_LOG=info cargo test --locked --offline --features mcp,hardware-software
cargo clippy --locked --offline --all-targets --features mcp,hardware-software -- -D warnings
```

这些是本地软件回归，不能替代 Linux 多 UID/systemd 或实体硬件验收。离线命令要求已有依赖缓存；硬件 feature 按平台单独测试。详见[测试与向量](/advanced/testing)。
