# TODO

还没做完的事。**为什么**这么做(威胁模型、取舍)在 [docs/DESIGN.md](docs/DESIGN.md)
里,尤其是 §九 —— 这里只列**要动手的东西**。

M0–M5 的代码已经写完并提交,不在这个文件里。剩下来的是三件**不能在这里做完**
的事(只有一台机器、没有签名身份)、一件**做不了**的事、和一份对照表。

原来排在第一条的"TPM 后端从来没有被编译过"**已经做完了**(2026-10-14)——
记录留在下面,因为它是"核对源码"和"验过"之间那道差距的实证。

---

## 一、TPM 后端:✅ 已在 Linux 上编译并端到端验过(2026-10-14)

`cargo test --features hardware-tpm` 全绿(含新增的 `tests/tpm.rs` 三条),
`swtpm` 的端到端也走通了:`keygen --hardware tpm` → `probe` USABLE →
`publish` → `serve` → `unlock` → `sign` 出真的 RFC 9421 头;`swtpm` 重启
之后信封照旧打得开;`tpm2_evictcontrol` 删掉密封对象之后解锁**响亮地失败**
(`HardwareMissing`),信封一个字节没动 —— **没有静默降级**。

**"逐个对着源码核对"漏掉了三样,而三样都只在真信封上才露头**(都不是类型错,
编译器一条也拦不住):

1. `tpm2-tss 3.2.1` 的 `Esys_TR_FromTPMPublic_Finish` 有一处没查空指针的
   解引用,而密码会话恰好就是 `NULL` —— 带会话调 `tr_from_tpm_public` **段
   错误**,守护进程直接 SIGSEGV(139)。修法是那次调用刻意不带会话。
2. `seal_probe` 只做到 `EvictControl` 就返回,报告里却写着 "read back" ——
   `TPM2_Unseal`(也就是 `open` 唯一真正依赖的命令)从来没被任何一次体检
   碰过。
3. 芯片上**同时**装载的对象很少(swtpm 尤其少),`create_primary` 每调一次
   占一格。峰值超了报 `0x902 out of memory for object contexts`,而那句话
   指向"这颗 TPM 不能持久化"。

细节在 `src/keystore/hardware/tpm.rs` 的模块头(逐条带注释);重跑验证的命令
在 `tests/tpm.rs` 的文件头。

**还剩一处平台陷阱**(写代码时就避开了,记在这儿免得后人踩):持久化句柄
`0x81000000`–`0x81FFFFFF` 里,`>= 0x81800000` 那一段属于
`TPM2_PLATFORM_PERSISTENT`,要的是 **platformAuth** 而不是 owner auth。所以
`handle_for` 把句柄掩进 `0x81000000..=0x817FFFFF`。

---

## 二、SE 后端:ECDH 验过了,**持久化没验**

- ✅ ECDH 那条路在**真芯片**上跑过(`cargo test --all-features --lib hardware::se`,
  4 条,没有"skipped"字样)。
- ❌ **"SE key 留在钥匙串里、进程重启之后还开得了"没验过。** 它需要签名身份,
  而这台机器上 `security find-identity -v -p codesigning` 是 **0 个**。

没有身份就只能停在这里,**不谎报做完**。有身份之后的验收:

1. `keygen --hardware secure-enclave`,记下钥匙串标签。
2. 确认 `security find-key` 能找到它、并且重启进程之后还在。
3. 删掉它 → 信封打不开,而且报的错说得清是"少了这台机器"。

`src/keystore/hardware/se.rs` 的模块头写着同一条缺口。

---

## 三、硬件绑定的端到端验收用的是**软件替身**

`tests/hardware.rs` 跑的是 `--features hardware-software` 那个假后端,所以它验
的是那条路的**形状**:

- ✅ 版本分派(v1 照旧开、v2 要硬件)
- ✅ `hardware` / `hs_ciphertext` 进 AAD:换 tag、换种类、整个拆掉都被拦
- ✅ 硬件不在 → 打不开,报的错说得出少了什么
- ✅ 硬件在但口令错 → 打不开(两路熵是**都**要,不是任一)
- ✅ 没有后端时**拒绝生成**,不静默降级
- ✅ 同一把 seed,绑与不绑导出的 24 个词逐字相同
- ❌ **"HS 真的出不了这台机器"** —— 替身的 HS 就是一个文件。这条只有真后端
  能验,而且不可能在这里被验。

最后一条是有意的缺口,文件头写明了,没拿绿勾去盖。

---

## 四、硬件根的发行前置:macOS 必须签名分发

不是代码问题,是发行决策。SE 私钥唯一的持久化机制是钥匙串,写钥匙串要
`application-identifier`,而这个 entitlement **只有 Apple 签发的证书能给**。

实测(26.7.1 / arm64):

| 情形 | 结果 |
|---|---|
| 未签名二进制建**永久** SE key | `-34018 errSecMissingEntitlement`(芯片在,是钥匙串拒绝) |
| ad-hoc 签名 + 手写 `keychain-access-groups` | 进程**被内核 SIGKILL** |
| ad-hoc 签名**不带**该 entitlement | 正常运行(所以那个 kill 确实是 entitlement 引起的) |
| 未签名二进制建**非永久** SE key | 成功、ECDH 可用,进程一退就没了 |

**不要**去试"ad-hoc 签名 + 手写 entitlement"那条路 —— 它是表里第二行,已经
量过了。

`probe` 会把这件事说出来(那一节会报 NOT USABLE 并给出 remedy),而不是报一个
假的"通过"。

---

## 五、第三层:`--allow-binary` 能不能只给一个路径(做不了)

今天是 `--allow-binary cdhash:<hex>` / `sha256:<hex>`,那个十六进制串得人自己
先算出来(macOS 上要会用 `codesign -d`,Linux 上 `shasum` 一个正在跑的
`/proc/<pid>/exe`)。想要的是"给个路径就行",摘要由工具自己算。

**没做的理由不是麻烦,是它在 macOS 上不成立。** 对端身份那一侧
([src/daemon/peer.rs:167](src/daemon/peer.rs:167))只能给出两样:

- macOS:内核在 `connect(2)` 时冻结的 cdhash —— **它要求对端有代码签名**。
  未签名的二进制拿回来的是 `Ok(None)`("问到了,但没有身份"),
  而最该被 pin 住的那类目标(脚本、自己编译的 agent 二进制)恰好都在这一栏。
- Linux:`/proc/<pid>/exe` 的 realpath + 文件内容的 SHA-256。对端**给得出**。

所以"给个路径就行"会是一个**只在 Linux 上、且只对未被替换过的文件**成立、
在 macOS 上对最常见目标压根不成立的开关。那比现在这个更糟:它看起来像通用
做法。真要做,先得回答"未签名的对端怎么被指认"——那是另一件事(路径会被
替换、会被重编,Linux 上得配 Landlock/AppArmor 才收得住,同一条限制
`BinaryIdentity::ExecutableDigest` 的注释里已经写了)。

眼下的替代就是现在这条:**被拒的连接会把对端的 pin 写进 `log/serve.log`,
照抄进命令行即可**([src/daemon/server.rs](src/daemon/server.rs) 的
`refuse()`)。

---

## 六、跨月那一环的覆盖面窄于相邻几环

上一版 TODO 里那条"审计日志的多写者"已经做完了(语义在
[docs/DESIGN.md](docs/DESIGN.md) §五,测试在 `src/audit/log.rs`),**连同顺带
发现的一个更糟的** —— 换月之后 `AuditLog::open` 会把一次正常的换月报成
"第 1 行断链":链是跨月延续的,而它从 `GENESIS` 开始验。两个都修了,也都有
测试。

留下来的这条更窄:链跨月延续、`open()` 现在从上个月末行起验,**但只验当前
这个月那个文件**。历史上的月份文件在它们自己的那个月里被验过,之后不再验 ——
也就是说改掉一个**已经过去的**月份文件(连同它的末行)不会被发现;`.anchor`
只钉住最新那条尾巴。真要收住,得让锚记的是整条链而不是最后一环,那是一次
格式变更,得单开一件事。

---

## 七、和计划写得不一样的地方(已做,列在这儿免得对不上)

拿计划 §九 的验收单逐条核对时,这三条**做法换了**,不是漏了:

| 计划写的 | 实际做法 | 为什么 |
|---|---|---|
| M2 验收 #1:跨 uid → `ERR_PERMISSION` | 返回 `KeyNotFound`(`tests/negative.rs` 第 1 条) | `Permission` 等于承认"有这么一把钥匙,只是不给你" —— 那本身就是泄露 |
| M2 验收 #3:解锁后 dump 锁定区看密钥,`lock` 后应全为 0x00 | 换成 `probe`:**一个字节的密钥材料都不打印** | 计划里的做法要么跨进程做不到,要么会把私钥打到 stdout,而 probe 是 agent 同 uid 就能跑的命令 —— 那等于把 `seed-export` 那道门拆了。理由写在 `src/ops/probe.rs` 的模块头 |
| M4 验收 #3 的另一半:`strings /proc/<pid>/mem` 翻不到私钥 | **手工做**,没进自动化测试 | 读别的进程内存要 root(macOS)或 ptrace 许可(Linux);写一条只有特定平台特定权限下才跑得起来的测试,等于留一段没人跑过的代码,还会让"这条覆盖了"显得成立。守的是它的**前提**(能力、限制、失败即拒绝),那一步留给人拿真机做一次 |
| M5 验收 #6:`probe` 在**没有**硬件根的机器上不通过 | 照做了,判据是 `src/ops/probe.rs` 的 `hardware_hygiene()` | 这不是"多报一条警告"而是**改了这一节的通过条件**:从今往后一台普通机器跑 `probe` 会是失败的。理由是那四个字("体检过了")会被读成"M5 那个缺口补上了",而它没补。想翻回"没有硬件根只算提示",改的就是 `hardware_hygiene()` 那个返回值 —— 那是**一处**,不是散开的 |

**这一条是有代价的,先说清楚:** `probe` 现在是**开箱即失败**的(任何没有硬件
根的机器)。绑不绑硬件仍然完全合法,`keygen` 不带 `--hardware` 照样生成 v1
信封照样能用 —— 这一节说的是"这台机器还不够好",不是"你不能这么用"。如果这个
默认被证明是用起来太烦(比如装机脚本被它卡住),翻回"提示"是一处改动。

---

## 明确不做

原始计划 §十一 划的 v1 范围线,不在这儿重列也不打算做:凭据中介、远程多租户
解锁仪式、委托链 / biscuit 能力令牌。边界为什么划在这儿,见
[docs/DESIGN.md](docs/DESIGN.md) §一 和 §六。

