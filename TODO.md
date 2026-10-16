# TODO

当前受保护改造的进度以本地 `docs/plan-security-v2.md` 为准；此处列未完成的发行工作。

- [ ] Linux systemd 真实主机验收：验证安装路径、服务沙箱、升级、独立 UID 与故障恢复。完成前保持 `protected_supported=false`。
- [ ] macOS 受保护运行环境、可信管理 UI、SE 正式签名分发和持久化。
- [ ] 实体 TPM 的权限、故障与恢复专项验收；软件替身不等于硬件结果。
- [ ] 远端审计检查点、回滚检测、受限无人值守恢复。
- [ ] 按实际需求扩展注册 challenge 格式；当前仅支持管理端精确批准的 awiki 32 位小写 hex 格式。
- [ ] 外部 awiki-cli-rs2 专用适配仍需解决其固定 path 依赖；本仓库交付 Node v2 客户端及 anp-sdk connector。

已实现：独立管理通道与服务 UID 认证、主体/角色/策略、exact-key grant、期限与撤销、事务签名、去重、结果恢复、资源限制、旧审计关联、离线迁移与恢复校验、管理注册 proof、预配置热密钥轮换、发行特性检查。

签名核心不联网；发布 DID 文档由独立适配器执行并核验。历史明文导出无法撤回，不提供远程多租户 KMS 或普通 Agent raw 签名。
