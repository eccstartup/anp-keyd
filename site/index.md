---
layout: home

hero:
  name: anp-keyd
  text: 本地身份签名与有限授权
  tagline: 跑在你自己机器上的守护进程,替 agent 保管 did:wba 的 Ed25519 私钥,并按 RFC 9421 签 HTTP 消息签名。
  actions:
    - theme: brand
      text: 五分钟跑通
      link: /guide/quickstart
    - theme: alt
      text: 它挡什么,不挡什么
      link: /concepts/trust-model
    - theme: alt
      text: GitHub
      link: https://github.com/eccstartup/anp-keyd

features:
  - title: 私钥不出进程
    details: agent 通过 Unix socket 说话,请求里可以带方法、URL、头、请求体 —— 唯独没有一个字段能装私钥。守护进程自己重建签名基、自己决定覆盖面,签完把签名头递回来。
  - title: 独立主体与有限授权
    details: Linux v2 在独立 UID 下执行主体、密钥角色、目标策略、次数、期限和撤销。同 UID 开发模式不提供任意代码隔离；正式 Linux release 加显式 linux-protected-v1 已通过 systemd 主机验收。
  - title: 信封与恢复
    details: 口令派生材料与 device.secret 共同保护信封。整套软件目录加口令可以解封，缺少 device.secret 或所需硬件根时拒绝。
  - title: 硬件根可以再插一路
    details: 硬件根参与解封，Ed25519 签名仍在软件中执行。指定硬件不可用时拒绝，正式 SE 发行及实体 TPM 验收仍待完成。
  - title: 导出是缺席的,不是被拒绝的
    details: export-seed 在默认构建里不存在 —— 不是"被拒绝",是没有这段代码:没有分支、没有环境变量、没有可翻的开关。
  - title: 签名核心不联网
    details: Linux v2 使用 root 管理配置与本地 SQLite 记录授权、请求和审计。客户端负责网络发送；macOS 提供独立 UID 本机预览，protected_supported=false，见[本机使用](/guide/local-use)。
---

## 它长什么样

签名结果包括 Signature-Input、Signature，有 body 时还包括 Content-Digest。客户端保留原 body、使用规范化 URL，并禁用自动重定向。

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=1791913177;expires=1791913477;nonce="xUrKXp6Jcvy5Ha-CywsJKA";keyid="did:wba:example.com:agents:mybot:e1_abc…#key-1"
Signature: sig1=:VwRcADsdxfIJ5rQAXCXX3ygFsAP3l1ho+gdpNxcHzlZCdx/mef9yKzHgy9P1QzVVHQuxoAyffja4G6CbAaUDCA==:
```

多一个字符、少一个字符,签名就验不过 —— 所以这一路上没有任何一环替你"顺手整理"。

## 状态

早期阶段,`0.1.0`。命令行界面还会变;**落盘的两份格式不会** —— 助记词推导方案和归档格式已经冻结,因为它们决定了别人手里那份备份打得开还是打不开。动这两样东西之前请先读[设计说明](/design/)第三节。

硬件根(信封的第三路熵)已经写好,但默认构建里没有。

## 从哪儿开始

- 第一次接触 —— 先看[它是什么](/guide/what-is),再看[五分钟跑通](/guide/quickstart)
- 想知道它挡得住什么 —— [它挡什么,不挡什么](/concepts/trust-model)
- 想知道某个默认值为什么长这样 —— [不显然的默认值](/reference/defaults)
- 想知道为什么这么做 —— [设计说明](/design/)

Linux v2 事务签名、离线迁移、管理注册 proof 与热密钥轮换已有代码；systemd 主机验收已通过；正式 Linux 构建与显式保护模式报告 `protected_supported=true`，其他模式保持 false。
