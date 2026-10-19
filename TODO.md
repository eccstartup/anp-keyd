# TODO

当前受保护改造的进度以本地 `docs/plan-security-v5.md` 为准；此处列未完成的发行工作。

- [x] Linux systemd 真实主机验收已完成；仅正式 Linux release 且显式受保护模式声明支持。
- [x] macOS 持久 SE 与主机生命周期验收：真实 SE＋开发签名助手＋独立 UID 服务通过；用户切换、注销/重新登录、短/长休眠、整机重启、升级、密钥丢失、签名身份与钥匙串权限变化均已验收，临时密钥均按精确标签删除并复查。保护声明仍为 `macos-boundary-preview`、`protected_supported=false`。
- [ ] macOS 原始钥匙串跨 UID 隔离：同签名、同访问组的探针仍能在 Agent UID 重算 HS（含新 SessionCreate 会话），反例保留；需解决该 OS 层隔离问题或重述产品边界。软件登录身份拒绝不能替代 OS 隔离。
- [ ] macOS 物理 Secure Enclave/设备故障路径：本机无法诱发，仅验证了软件可见拒绝（探测报告 NOT USABLE、删除密钥后报“no key with that label”）。
- [ ] macOS SE 正式分发：当前只有本机 Apple Development 身份与短期 profile；需 Developer ID 证书、公证、长期安装身份、正式发行产物与分发审核。
- [ ] macOS 本机预览的一条命令初始化（`install.sh --bootstrap`）：在预览模式下生成身份、登记主体、创建 grant 并解锁；当前该参数只支持 Linux 受保护部署，macOS 按 `deploy/macos/AGENT.md` 手动完成。
- [x] TPM 部署范围验收（Docker + 内核 `tpm_vtpm_proxy`）：安装、设备权限、systemd 沙箱、服务 UID、跨进程封存/打开、跨 UID 拒绝、删除后拒绝全部通过；`acceptance_scope_complete=true`，报告仍记录 `virtualization=docker`、`physical_tpm_acceptance_complete=false`。
- [ ] 实体 TPM 硬件保护声明（可选）：用真芯片复跑并覆盖句柄/设备丢失、权限变化、设备故障、升级与恢复、换机复制；不作该声明前保持 physical=false，`swtpm` 结果不得当作物理验收。
- [x] U4 独立审计采集器、SSH 固定端点、原子保管、回滚/分叉/崩溃/断网验收；交付部署模板与两容器验收。保持本地审计签名继续策略，不承诺在线强制锚定或非审计状态保护。
- [ ] 受限无人值守恢复（须先指定 workload 与可信解封机制）。
- [ ] 按实际需求扩展注册 challenge 格式；当前仅支持管理端精确批准的 awiki 32 位小写 hex 格式。
- [x] 外部 awiki-cli-rs2：依赖改造已完成并推送——只删掉 `../anp/...` path 依赖，保留 `anp =1.0.3`、`anp-identity =0.2.3` 原版本钉（二者 crates.io 上均有），`Cargo.lock` 只补 `source`/`checksum`；`cargo check --locked --workspace` 通过、`cargo test -p awiki-im-core --lib` 1522 项全过。提交 `a8c5663c` 已推到 fork `eccstartup/awiki-cli-rs2` 的 `eccstartup` 分支，未推上游、未开 PR。升级 `anp-identity` 0.2.5 需先做 awiki 自己的 DID 文档迁移（0.2.5 拒绝 P6 legacy bundle，185/1522 测试失败），单列。本仓库侧交付已完成：Node v2 客户端及 anp-sdk connector，SDK 侧最低兼容版本 `@connectx-sdk/core@0.4.2`。

已实现：独立管理通道与服务 UID 认证、主体/角色/策略、exact-key grant、期限与撤销、事务签名、去重、结果恢复、资源限制、旧审计关联、离线迁移与恢复校验、管理注册 proof、预配置热密钥轮换、发行特性检查。

签名核心不联网；发布 DID 文档由独立适配器执行并核验。历史明文导出无法撤回，不提供远程多租户 KMS 或普通 Agent raw 签名。
