# 本机使用：先建立边界，再交给 Agent

Linux 正式 release 的 `linux-protected-v1` 提供受保护部署；macOS 提供独立 UID 本机预览，始终报告 `protected_supported=false`。Secure Enclave 是另外一项尚未完成发行验收的增强。普通 macOS 预览不要求购买 Apple 开发者会员、安装完整 Xcode 或配置 SE；源码编译需要 Rust 和 Command Line Tools。

## 1. 谁可以运行什么

可信人类管理员管理配置、身份、策略、grant 和解锁；独立服务账号保存状态并签名；每个不可信 Agent 使用不同的非管理员 UID。必须让**整个 Agent 框架及其工具进程**运行在该 UID 下。只把签名子进程切换账号，而模型的 shell 仍有管理员权限，不能建立这个边界。

不要给 Agent sudo、Docker 管理权限、管理员凭据、真实身份密码或可修改的服务程序/配置。独立 UID 也不是整机安全证明：还要检查 Agent 能读到的共享目录、凭据和框架插件。管理员、root、内核及可信 daemon 是信任前提；同 UID 的任意代码属于同一个主体。

## 2. 安装和验收

人类从可信、审核过的 checkout 安装，核对构建来源及 SHA-256，不要 sudo 执行 Agent 可篡改的脚本。

- macOS：按 [安装说明](macos/README.md) 建立服务账号、Agent 账号、root-owned 安装与 launchd 作业，再运行临时密钥验收。
- Linux：按 [安装说明](linux/README.md) 部署 systemd 服务，完成对应主机验收；容器通过不代表自己的主机通过。

验收使用公开口令和可丢弃身份，不能使用真实密钥。安装检查通过只说明有限的权限/健康检查通过；实际签名、跨 UID、撤销、正常重启和异常退出应分别通过。任何 FAIL 都应保留完整输出并停止宣称验收完成。测试不会自动更新日常安装。

2026-10-17 本机复测发现旧 macOS 安装版本在异常退出后的管理请求出现 `set socket read timeout ... EINVAL`。旧版本的整套复测因此中止。修复提交 `7392419` 的候选（SHA-256 `5747c5d18c8bcffcc6a0f93bdc59dd6642461565867b63749cc98c50eca4693d`）随后由操作员完成 macOS 临时实例全套非交互验收，包括实际签名、跨 UID 拒绝、撤销、正常重启、异常退出后锁钥/撤权及假 socket 拒绝。随后操作员使用固定摘要完成验收机器的日常安装更新，独立只读复核摘要一致、实例身份不变、boot_epoch=3、服务健康；原版本和更早备份均保留。其他机器仍需各自验收并执行更新，不能从本次结果推断已经更新；本次未重跑原生 UI、整机重启或持久 SE 验收。不要靠重复授权请求掩盖失败。

## 3. 准备真实身份和有限授权

新安装初始没有真实身份。管理员先确认身份来源、备份和恢复要求，再使用受支持的管理流程注册主体、安装文档、划分 hot/root/recovery 角色、配置策略并审批有限 grant。使用 `admin --help` 查看当前命令和 schema，不要直接向托管目录复制文件或用开发 CLI 绕过管理接口。

Linux 提供经检查的离线迁移流程，见平台说明；macOS 提供显式离线迁入工具和[完整 Agent 演练流程](macos/AGENT.md)，须先完成当前主机的临时身份与 UI 验收，再由管理员操作真实迁入；不能把容器回归当作 macOS 实机验收。临时 fixture 不是生产身份。因此“空服务健康”不等于已经可以替现有身份签名。

grant 应固定主体和 exact hot key，限制目标、HTTP 方法、路径、query、body、期限和次数。普通 Agent 不使用 root/recovery key。人类确认准确目标后通过可信解锁 UI 输入口令；口令不经过模型、聊天或 MCP。解锁与授权是两个操作，解锁本身不会生成 grant。

macOS 示例（由可信人类账号执行，替换所有占位符）：

```sh
/Library/ANPKeyd/bin/anp-keyd admin --config /Library/ANPKeyd/service.json status
/Library/ANPKeyd/bin/anp-keyd admin --config /Library/ANPKeyd/service.json catalog
/Library/ANPKeyd/bin/anp-keyd admin --config /Library/ANPKeyd/service.json unlock \
  --vault-id VAULT_UUID --did DID --kid EXACT_KID --native-ui
```

## 4. 启动整个 Agent

macOS 操作员可先确认账号：

```sh
sudo -u _anpagent -- /usr/bin/id
sudo install -d -o _anpagent -g _anpagent -m 0700 /Users/Shared/anp-agent
```

输出应是 Agent UID，而非人类管理员 UID。然后按所用框架的账号部署方法，让整个框架在该账号和专用工作目录启动；运行时、依赖和配置也需可读且可信。不要把人类 HOME、令牌或管理员环境整体传给 Agent。以上命令只准备工作目录，不会自动安装或配置 AI 框架。

框架内部可调用数据 CLI 或 MCP，例如：

```sh
/Library/ANPKeyd/bin/anp-keyd data --config /Library/ANPKeyd/service.json --file request.json
/Library/ANPKeyd/bin/anp-keyd mcp --config /Library/ANPKeyd/service.json
```

这些进程应继承 Agent UID。MCP 构建需要 `mcp` feature；请求仍需符合当前协议、已注册主体和有效 grant。不要在管理员账号启动不可信框架后认为 MCP 会自动隔离它。

## 5. 日常失败、重试和撤销

适配器应发送 daemon 返回的规范化 URL、原始 body 与签名头，并关闭自动重定向。使用持久 request_id；相同操作重试复用原 ID。`outcome_unknown` 不能自动换 ID 重签；先查询状态并核查远端结果。本地幂等不保证远端业务只执行一次。

接收方必须验证 exact hot key 在活动 DID 文档中的授权，以及 body、nonce、期限和重放。旧 SDK 可能错误地要求 hot key 匹配根指纹；使用包含该兼容修复的版本。仓库的本地 SDK 验证不代表任意公开发布版本已经兼容。

撤销会阻止新签名和缓存结果重新交付，无法追回已交付的签名。服务重启后密钥锁定、旧 grant 失效，需要人类重新确认；不会自动恢复授权。备份和口令同样敏感，软件信封及口令泄露可能允许离线解密。

macOS 的 SE 登录助手、真实注销/休眠/整机重启、正式签名及持久 SE 仍有独立验收门槛，见 [SE 说明](macos/SE-SESSION.md)。不要把普通预览测试通过写成 U3 已完成。
