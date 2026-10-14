# 出事的时候

## 换机器 / 重装系统

先在**旧机器**上把身份导出(需要一个**一次性的、和日常口令不同的**导出密码):

```bash
cargo install --path . --features seed-export
anp-keyd export-seed --did did:wba:…
```

会得到 24 个词和/或一个 `.anpkeyd.json` 归档。

::: danger 把词抄在纸上,不要放在这台机器上
导出之所以默认不在二进制里,就是因为这条路能一键把整把身份抽干 —— 见[它挡什么,不挡什么](/concepts/trust-model)。
:::

然后在**新机器**上:

```bash
anp-keyd import-mnemonic --did did:wba:…    # 24 个词
anp-keyd import-archive --file x.anpkeyd.json
```

导入之后两件事必须知道:

1. **这是一把克隆,不是副本。** 导入出来的钥匙和旧机器上的是**同一把**,两边都能签,而且**验证方分不出来**。旧机器上的那一份要处理掉。
2. **重新封装用的是这台机器的新 `device.secret` 和新口令。** 归档里的那个导出密码从此没用了。

## 装了钥匙的机器坏了,又没有备份

钥匙没了。

信封打不开,而且报的错和"口令敲错了"**一模一样** —— 这是**刻意的**:两者可区分,等于告诉拿到磁盘的人"你缺的是哪个因子"。

::: danger 所以:趁机器活着,把 24 个词抄下来
绑了硬件根的话,这一条从"该做"变成"**只能这么做**"。

导出要先解信封,解信封要硬件,所以那台机器一旦不在,**就没有第二条路** —— 也不能把磁盘搬到别的机器上再导出。

那正是硬件根要的性质,代价也就在这儿。
:::

## 怀疑哪里不对劲

```bash
anp-keyd probe
anp-keyd probe --did did:wba:…
```

它报告这台机器能不能兑现这个工具给出的承诺:

| 它查什么 | 查不出来会是什么症状 |
|---|---|
| 内存锁定建不建得起来 | 容器里 `ulimit -l` 太小、systemd 的 `LimitMEMLOCK` 没调,症状是**启动就失败** —— 这里能当场说清是哪一条不满足 |
| 一次崩溃会不会把种子写到磁盘上 | —— |
| `device.secret` 在不在、模式对不对 | —— |
| 这台机器有没有可用的硬件根、是哪一种、**能不能真的用** | SE 那一侧最容易被看出来:芯片在、框架也编进去了,但没有 Apple 签发的证书就建不出持久的 SE 私钥,于是"绑了硬件"根本兑现不了 |

::: tip 它一个字节的密钥材料都不打印
走 stdout 就是为了让你能放心把输出贴到 issue 里。
:::

## 还有一条路:文档

如果出问题的是**已发布的文档**而不是本机钥匙,有两个命令直接查它:

```bash
# 别处取来的那一份
anp-keyd verify-doc --did did:wba:… --file did.json

# 不带 --file:验本机那一份
anp-keyd verify-doc --did did:wba:…

# 也能直接从管道里验
curl -sS https://example.com/agents/mybot/e1_abc…/did.json \
  | anp-keyd verify-doc --did did:wba:… --file /dev/stdin

anp-keyd document --did did:wba:…          # 本机那一份的原文,逐字节
```

`document` 不用解锁 —— 那份文档本来就是给外面看的。

## 接着看

- [信封与归档](/concepts/envelope) —— 为什么导出必须先在本机解信封
- [磁盘布局](/reference/layout) —— 审计日志里能查出什么
