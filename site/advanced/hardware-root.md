# 硬件根

## 它解决什么

今天信封里那两个秘密**都是软件的**:口令(在人脑子里)+ `device.secret`(磁盘上 32 字节)。

把 `~/.anp-keyd/` 整个拷到另一台机器、又知道口令,就能拿到私钥;一份离线备份也能慢慢爆破。

硬件根补的正是这一路:**再插一个不可导出、拷不走的熵源进去。**

```
HS  = 32 随机字节,由硬件封装后存进信封(hs_ciphertext)
KEK = HKDF-SHA256( argon2id(口令) ‖ device.secret ‖ HS, salt )
```

三路少任何一路都开不了。

::: info 硬件是第三层,不替代 device.secret
后者管"**备份被拷走没用**",前者管"**拷到别的机器没用**"。两件事,两层。
:::

## 怎么开

```bash
cargo install --path . --features hardware-se    # 或 --features hardware-tpm
anp-keyd keygen --spec mybot.spec.json --hardware secure-enclave
```

认这个开关的还有 `add-recovery-key`、`rotate-hot-key`、`import-mnemonic`、`import-archive`。

**默认是 `none`** —— 硬件是**要的人开口要**的东西,不是悄悄加上去的东西。v1 的信封一个字节都没改,旧信封照旧能开。

::: danger 没有可用硬件根,就是拒绝生成,不降级
要硬件绑定而没有硬件,是一条**错误**,不是悄悄退回纯软件信封。

一个看起来在保护、其实没有的信封,比一个老实说自己是明文的口令加 `device.secret` **更糟**。
:::

## 两条纪律,是有意的代价

### 一、导出现在必须在本机做

导出要先解信封,而解信封要硬件。所以"把磁盘拷到别的机器上再导出"这条路**被硬件根关掉了** —— 这正是它的目的。

但代价是:**趁机器活着把那 24 个词抄下来。** 芯片坏了、机器丢了,**没有第二条路**。

### 二、`--hardware` 绑的是这台机器

把绑定过的信封整个目录拷到另一台机器,**打不开**,而且报的错会**指明是少了这台机器** —— 不是"口令错"。

两者可区分是刻意的。

::: warning 助记词和归档这两侧永远不碰硬件
不然芯片坏了就等于钥匙没了,等于没备份。

导出/导入是唯一允许的搬家路径,而且那条路径的产物是一把**硬件无关**的钥匙。
:::

## macOS 那半边的发行前置

**SE 私钥唯一的持久化机制就是钥匙串**,而写钥匙串需要 `application-identifier` 这个 entitlement —— **它只有 Apple 签发的证书能给**。

所以:

| 做法 | 结果 |
|---|---|
| 未签名的二进制建**永久** SE key | `errSecMissingEntitlement`(芯片在,是钥匙串拒绝) |
| ad-hoc 签名 + 手写 `keychain-access-groups` | 进程**被内核 SIGKILL** |
| ad-hoc 签名**不带**那个 entitlement | 正常运行,但 SE key 一退出就没了 |

::: danger 不要试中间那条
"ad-hoc 签名 + 手写 entitlement"已经量过,不是理论推演 —— **进程会被内核 SIGKILL**。
:::

也就是说 **SE 版本必须以签名身份分发**,`cargo build` 的产物做不到。这是**发行决策,不是代码里能补的一环**。

`probe` 会替你把这件事说出来,而不是报一个假的"通过"。

## Linux/TPM 没有这道门槛

走 `/dev/tpmrm0`,不要 entitlement,可选绑 PCR(**默认不绑** —— 绑了的话内核或固件一升级就把用户锁在门外)。

`swtpm` 能在本机把它模拟出来,所以那条代码路径是**可以真测的**,而且 2026-10-14 已经真的测过:`cargo test --features hardware-tpm` 全绿,`tests/tpm.rs` 的端到端也走通了。

::: details 那次真跑出来的三条,值得看一眼
"逐个对着 `tss-esapi` 源码核对"确实漏掉了三样,**三样都是运行时的,编译器一条也拦不住**:

- 带会话调 `tr_from_tpm_public` 会**段错误**(`tpm2-tss` 的一处空指针解引用 × 密码会话恰好是 `NULL`)
- `seal_probe` 报告里写着 "read back",却从来没调过 `TPM2_Unseal`
- 芯片上同时装载的对象很少,而 `create_primary` 每次都占一格,峰值超了会报一句和真正原因毫不相干的话

留着不删,是因为它正是"**核对过**"和"**验过**"之间那道差距的实证。
:::

## 还差什么

- **SE 的持久化没验过。** "SE key 留在钥匙串里、进程重启之后还开得了"需要签名身份,而这台机器上 `security find-identity -v -p codesigning` 是 **0 个**。没有身份就只能停在这里,不谎报做完。
- **硬件绑定的端到端验收仍然跑在软件替身上。** `tests/hardware.rs` 验的是那条路的**形状**;"HS 真的出不了这台机器"只有真后端能验 —— 文件头把这条缺口写明了,没拿绿勾去盖。

两条都不是代码问题,各自卡在发行身份和硬件上。

## 接着看

- [测试与向量](/advanced/testing) —— 假后端 `hardware-software` 为什么存在
- [不显然的默认值](/reference/defaults) —— `--hardware` 为什么默认 `none`
