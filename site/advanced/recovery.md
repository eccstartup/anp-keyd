# 迁移与恢复

## Linux v2：先验证恢复点

停止旧 daemon 和所有生命周期写者，将源材料放到管理员保护的路径。离线工具先只读检查，再执行迁移：

```sh
python3 deploy/linux/migrate-vault.py --source /root/frozen-vault
python3 deploy/linux/migrate-vault.py --source /root/frozen-vault \
  --apply --recovery-dir /root/keyd-recovery
```

工具执行维护锁、摘要核对、恢复副本逐钥验证和旧路径禁用。恢复副本包含 device.secret 和加密信封，必须保持管理员保护；不能留在 Agent 工作目录。硬件绑定不能靠复制绕过硬件依赖。

新 vault 登记后，密钥锁定、角色未分类。管理员确认角色，发布策略、解锁并创建新 grant，完成真实服务认证再切换客户端。旧 grant 不因重启或恢复重新有效。

数据库丢失或损坏时停止服务，恢复经验证的成套状态；不要生成空库、重算审计链尾或使用未知文件修补。文档已发布到网络的状态也需独立核对，本地回滚不会撤回线上变更。

## 开发身份的便携恢复

助记词和 anp-keyd-archive v1 属于另行控制的离线维护流程。export-seed 只在启用 seed-export 的构建中存在，该构建不声明受保护支持；不要为恢复方便把导出能力加进 Agent 数据面。

24 个 BIP-39 词直接编码 32 字节 Ed25519 seed，不使用标准 BIP-39 PBKDF2 seed 派生。用其他钱包的 to_seed 可能得到不同钥匙而不报错。

恢复可使用 import-mnemonic 或 import-archive，将 seed 用目标环境的口令和 device.secret 重新封装；托管目录不能经本地生命周期 CLI 直接修改，需经过批准的迁入流程。

旧归档仍能用旧归档口令打开，不会因为导入后换了本地口令而失效。同一 seed 的所有副本都能继续签名，清理当前文件不能撤销历史泄露；需要轮换、身份迁移及验证方状态刷新。

## 丢失材料意味着什么

| 丢失内容 | 影响 |
|---|---|
| 只有信封，没有 device.secret | 不能按原软件封装解密；新生成 secret 不能补回 |
| 完整软件目录，仍有正确口令 | 可解封；应把完整副本视为敏感备份 |
| 硬件根不可用 | 原硬件绑定信封无法靠磁盘复制解封；需要事先验证的独立恢复材料 |
| 没有任何可用 seed 或恢复材料 | 不能凭 DID、公钥或文档恢复私钥 |

备份准备好之后必须演练真实认证，不能只检查 JSON 可读或归档解密成功。

## 排查入口

受保护模式使用 admin status、admin catalog 和 probe --security；开发模式使用 probe。公开文档可用 verify-doc --did DID --file FILE 检查；检查本地文档不等于证明远端已刷新。

签名超时先查询原 request_id，outcome_unknown 不自动重签。签名结果与业务服务结果分开处理，详见[Agent 接入](/advanced/agent)。
