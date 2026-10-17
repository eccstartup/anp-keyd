# TODO

当前受保护改造的进度以本地 `docs/plan-security-v4.md` 为准；此处列未完成的发行工作。

- [x] Linux systemd 真实主机验收已完成；仅正式 Linux release 且显式受保护模式声明支持。
- [ ] macOS 受保护运行环境、可信管理 UI、SE 正式签名分发和持久化。发布包与跨进程持久化工具已备（`se-release.py`、`se-persistence.py`，验收特性默认关）；仍缺 Apple 签发身份/配置文件、真机登录会话与生命周期验收、分发审核。
- [x] TPM 部署范围验收（Docker + 内核 `tpm_vtpm_proxy`）：安装、设备权限、systemd 沙箱、服务 UID、跨进程封存/打开、跨 UID 拒绝、删除后拒绝全部通过；`acceptance_scope_complete=true`，报告仍记录 `virtualization=docker`、`physical_tpm_acceptance_complete=false`。
- [ ] 实体 TPM 硬件保护声明（可选）：用真芯片复跑并覆盖句柄/设备丢失、权限变化、设备故障、升级与恢复、换机复制；不作该声明前保持 physical=false，`swtpm` 结果不得当作物理验收。
- [x] U4 独立审计采集器、SSH 固定端点、原子保管、回滚/分叉/崩溃/断网验收；交付部署模板与两容器验收。保持本地审计签名继续策略，不承诺在线强制锚定或非审计状态保护。
- [ ] 受限无人值守恢复（须先指定 workload 与可信解封机制）。
- [ ] 按实际需求扩展注册 challenge 格式；当前仅支持管理端精确批准的 awiki 32 位小写 hex 格式。
- [x] 外部 awiki-cli-rs2：依赖改造已完成并推送——只删掉 `../anp/...` path 依赖，保留 `anp =1.0.3`、`anp-identity =0.2.3` 原版本钉（二者 crates.io 上均有），`Cargo.lock` 只补 `source`/`checksum`；`cargo check --locked --workspace` 通过、`cargo test -p awiki-im-core --lib` 1522 项全过。提交 `a8c5663c` 已推到 fork `eccstartup/awiki-cli-rs2` 的 `eccstartup` 分支，未推上游、未开 PR。升级 `anp-identity` 0.2.5 需先做 awiki 自己的 DID 文档迁移（0.2.5 拒绝 P6 legacy bundle，185/1522 测试失败），单列。本仓库侧交付已完成：Node v2 客户端及 anp-sdk connector，SDK 侧最低兼容版本 `@connectx-sdk/core@0.4.2`。

已实现：独立管理通道与服务 UID 认证、主体/角色/策略、exact-key grant、期限与撤销、事务签名、去重、结果恢复、资源限制、旧审计关联、离线迁移与恢复校验、管理注册 proof、预配置热密钥轮换、发行特性检查。

签名核心不联网；发布 DID 文档由独立适配器执行并核验。历史明文导出无法撤回，不提供远程多租户 KMS 或普通 Agent raw 签名。
