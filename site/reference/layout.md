# 磁盘与审计布局

## Linux v2 受保护服务

```text
/etc/anp-keyd/service.json          root 控制的信任配置
/usr/local/libexec/anp-keyd         root 控制的程序
/var/lib/anp-keyd/                  服务 UID 拥有，0700
  state.sqlite                     状态与事务审计，0600
  vaults/<vault_uuid>/
    device.secret
    keys/<thumbprint>.json          加密信封
    dids/<safe_did>.json            公开文档
  audit-export/events.jsonl         数据库审计投影
/run/anp-keyd/                      分离的签名/管理 socket 子目录
```

具体 socket 路径从受保护配置读取。连接组让请求到达端点，内核 UID 和持久主体决定授权。Agent 无权写程序、配置、状态或 socket 父目录；daemon 也无权修改部署信任配置。

## 状态与恢复

SQLite 是主体、角色、策略、grant、请求及审计真源。启动只打开已有实例，拒绝缺失、损坏、链接、外来实例及更新 schema；不能用自动建空库恢复服务。

重启先递增 boot epoch、废止旧 grant 和批准、将未决签名置为 outcome_unknown，并保持所有密钥锁定。数据库和公开文档不能通过一次普通文件 rename 同时提交；文档替换按已批准操作意图及旧/新摘要恢复，未知内容拒绝服务。

## 审计证据

授权、配额、撤销和签名事件与状态同事务写入 SQLite。events.jsonl 是按序导出的投影；重复导出不重复事件，失败保留上一份完整文件并报告健康状态。它不是第二个授权真源。

不记录密码、seed、原始敏感 body 或任意调用方凭据头。请求状态区分签名持久化与交付，不能把 completed 当成远端业务成功。

本地链和 OS 权限可以检查一致性、阻止 Agent 修改，但不能检测管理员整体回滚或重写。独立审计检查点尚未交付。

## 旧开发目录

旧 serve 默认使用 ~/.anp-keyd，包括 device.secret、keys/、dids/、按月 audit/、运行 log/ 和 run/。--root 可覆盖；旧 --system 的按 UID 布局不是 Linux v2 保护服务。

旧日志按月跨分片成链、配有本地锚，追加使用跨进程锁。迁入 v2 时校验并关联旧审计历史，不把新事件继续写回旧链。

## 副本与迁移

只复制信封而缺少 device.secret 不能解封；完整软件目录加正确口令可以解封，device.secret 不是不可复制的机器身份。硬件依赖必须另行验收。

迁移冻结旧写者、核对摘要、逐钥验证恢复副本，副本保存在管理员保护位置。丢失 device.secret 不能靠新生成文件补回。恢复和迁移也不能撤回过去泄露的 seed。
