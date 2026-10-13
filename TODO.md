# TODO

还没做完的事。**为什么**这么做(威胁模型、取舍)在 [docs/DESIGN.md](docs/DESIGN.md)
里,尤其是 §九 —— 这里只列**要动手的东西**。

M0–M4 已经做完并验证过,不在这个文件里。全项目还剩三件没动工的事:一是里程碑
级的大件,二和三是小件(三还得先把语义想清楚)。

---

## 一、M5 硬件根(唯一一个没开始做的里程碑)

### 要解决什么

把 `~/.anp-keyd/` 整个目录拷到另一台机器、又知道口令,**今天就能拿到私钥**。
离线爆破一份备份也一样。

信封里那两个秘密都是软件的:口令(在人脑子里)+ `device.secret`(磁盘上 32 字节)。
要做的是再插一路**不可导出**的熵进去,让"拷贝无效"这件事成立。

### 位置已经留好了

计划 §2.4 定死的:**硬件只当包装密钥,不当签名密钥。**
macOS Secure Enclave 和 TPM 2.0 都不支持 Ed25519,所以让硬件里的 P-256 密钥
去封一把对称秘密,Ed25519 那把 seed 仍然躺在被包装的密文里。
两层 KEK/DEK 的层级就是为这个留的插口;`src/keystore/record.rs:140` 那个
`HardwareRoot` 枚举已经在那儿,只是从没被生产过。

### 设计要点

不是"硬件直接包 KEK" —— KEK 今天根本不落盘(它是派生出来的),要包它就得
先把存下来,多一步而且更弱。改成**三路一起进 HKDF**:

```
HS = 32 随机字节,由硬件封装后存进信封(hs_ciphertext)
KEK = HKDF-SHA256( argon2id(口令) ‖ device.secret ‖ HS, salt )
DEK = open(KEK, dek_ciphertext)
seed = open(DEK, sk_ciphertext)
```

信封的两层结构、`exact32`、"同一个 nonce 两个 key"这些全不动,只是 KEK 的熵
多了一路。少任何一路都开不了。

两个平台的封装原语不一样,用一个 trait 抹平:

- **macOS SE** 只支持 ECDH。HS 用 SE 公钥 + 临时密钥对封;开的时候调 SE 做 ECDH。
  **封的时候不需要硬件,开的时候必须在这台机器上** —— 这正是要的性质。
- **Linux TPM** 用 `TPM2_Create` + `TPM2_Unseal` 直接把 HS 封给 TPM,更简单也更强。
  可选绑 PCR,**默认不绑**(绑了的话内核或固件一升级就把用户锁在门外)。

### 记录格式

- **version 1 一个字节都不改**,旧信封照旧能开。
- 硬件绑定的写 **version 2**:`hardware` 和 `hs_ciphertext` 进 AAD 头
  (`src/keystore/record.rs:98` 那个 `AadHeader`),所以"绑了哪种硬件、哪个 tag"
  本身是被认证的。
- `unwrap` 按 version 分派;`validate()` 收 1 和 2。
- **归档(`anp-keyd-archive`)格式一个字节都不改** —— 它冻结,而且必须可搬。

### 两条实测出来的硬约束

1. **macOS SE 那半必须以 Apple 签发的证书签名后分发。** 在本机(26.7.1 / arm64)实测:
   - 未签名二进制建**永久** SE key → `-34018 errSecMissingEntitlement`
     (enclave 本身在,是钥匙串拒绝)
   - ad-hoc 签名 + 手写 `keychain-access-groups` → 进程**被内核 SIGKILL**
   - 同一机器、ad-hoc 签名**不带**该 entitlement → 正常运行(所以那个 kill
     确实是 entitlement 引起的)
   - 未签名二进制建**非永久** SE key → 成功、ECDH 可用,但进程一退就没了

   原因链条:SE 私钥**唯一的持久化机制就是钥匙串** → 写钥匙串要
   `application-identifier` → 这个 entitlement **只有 Apple 签发的证书能给**。
   `cargo build` 的产物做不到。这是发行决策,不只是代码。

2. **Linux/TPM 没有这道门槛**,走 `/dev/tpmrm0`,不要 entitlement,
   而且 `swtpm` 能在本机模拟,代码路径可以真测。

### 写死的四条不变量

1. **助记词和归档这两侧永远不碰硬件。** `mnemonic::to_words(&LockedBytes)`
   (`src/crypto/mnemonic.rs:47`)签名不变。否则芯片坏了 = 钥匙没了 = 等于没备份。
   导出/导入是唯一允许的搬家路径。
2. **没有可用硬件根就拒绝生成钥匙**,不做静默降级。不给"看起来在保护、其实没有"
   的中间态。
3. 硬件根是**第三层**,不替代 `device.secret`。后者管"备份拷走没用",前者管
   "拷到别的机器没用"。
4. 导出现在必须在本机做(它要先解信封)。这是有意的代价,**要写进 README 的纪律**:
   趁机器活着把那 24 个词抄下来。

### 动手顺序

1. **抽象层 + 纯软件的假后端。** 没有它,v2 格式在任何没有硬件的机器上都测不了,
   而这一块的正确性(版本分派、AAD、降级)恰恰是最该被测的。
2. **v2 记录格式**:AAD 分版、`unwrap` 分派、`hardware` 进 AAD;补"换 tag /
   拆硬件字段必失败"的测试。参照 `src/keystore/record.rs` 里现有的
   "每个被绑字段被改都会 `AadMismatch`"那组测试。
3. **Linux/TPM 真后端**`hardware-tpm`(`tss-esapi = "7.7"`),用 `swtpm` 验代码路径。
4. **macOS SE 真后端**`hardware-se`,ECDH 封装 + 钥匙串持久化。
   **需要签名身份才能端到端验** —— 先 `security find-identity -v -p codesigning`
   看有没有,没有就只写代码,不要谎报做完。
5. **`probe` 加一节**:这台机器有没有硬件根、是哪种、SE 能不能持久化。
   照现有立场:不成立就**体检不通过**,并把该装什么、该改什么说清楚
   (现有实现在 `src/ops/probe.rs`)。
6. **README**:硬件的威胁模型、必须签名分发这条前置、"趁机器活着抄助记词"的纪律。

feature 门控照 `seed-export` 和 `mcp` 的先例(模块声明、命令变体、Args
结构体、match 分支四处的 `#[cfg]`),默认都不开,保持默认构建的依赖轻。

### 怎么算做完

- 删掉硬件密钥(SE key / TPM 密封对象)→ 信封打不开
- 硬件在、但口令错 → 打不开
- 把硬件绑定过的信封**整个目录拷到另一台机器** → 打不开,而且报的错说得清
  是"少了这台机器"
- 同一把 seed,硬件绑定的信封和纯软件的信封,**导出的 24 个词逐字相同**
- `cargo test` 两种构建都绿;`cargo clippy --all-targets --all-features -- -D warnings` 干净
- `probe` 在**没有**硬件根的机器上不通过,并指名要装什么

---

## 二、审计日志的多写者(小,但会咬人)

`AuditLog` 的文档明说了它的假设:**"不实现 `Sync`,这里假定外部已经串好了
—— 守护进程只有一条写路径"**([src/audit/log.rs:159](src/audit/log.rs:159))。

但往它里面追加的不只守护进程:生命周期命令也各自开一份
(`src/ops/mod.rs:39`)。而 `append()` 是**读尾哈希 → 写记录 → 写锚文件**三步
([src/audit/log.rs:199](src/audit/log.rs:199)),三步之间没有跨进程的锁。

后果不是"日志乱了"这么轻:哈希链加锚文件是**防篡改**用的,一条因为并发而
断掉的链,在下次打开时会被报成篡改 —— 把一次合法的并发用成一次假的告警。

已经有的东西:文档 CAS 那一段有 `flock`(`src/did/migrate.rs:165`),
审计这一段没有。也没有任何测试覆盖两个写者。

要做:定清楚语义(要么跨进程加锁,要么把写收敛到守护进程一条路),然后
按语义补测试。

---

## 三、第三层:`--allow-binary` 能不能只给一个路径

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

## 四、和计划写得不一样的地方(已做,列在这儿免得对不上)

拿计划 §九 的验收单逐条核对时,这三条**做法换了**,不是漏了:

| 计划写的 | 实际做法 | 为什么 |
|---|---|---|
| M2 验收 #1:跨 uid → `ERR_PERMISSION` | 返回 `KeyNotFound`(`tests/negative.rs` 第 1 条) | `Permission` 等于承认"有这么一把钥匙,只是不给你" —— 那本身就是泄露 |
| M2 验收 #3:解锁后 dump 锁定区看密钥,`lock` 后应全为 0x00 | 换成 `probe`:**一个字节的密钥材料都不打印** | 计划里的做法要么跨进程做不到,要么会把私钥打到 stdout,而 probe 是 agent 同 uid 就能跑的命令 —— 那等于把 `seed-export` 那道门拆了。理由写在 `src/ops/probe.rs` 的模块头 |
| M4 验收 #3 的另一半:`strings /proc/<pid>/mem` 翻不到私钥 | **手工做**,没进自动化测试 | 读别的进程内存要 root(macOS)或 ptrace 许可(Linux);写一条只有特定平台特定权限下才跑得起来的测试,等于留一段没人跑过的代码,还会让"这条覆盖了"显得成立。守的是它的**前提**(能力、限制、失败即拒绝),那一步留给人拿真机做一次 |

---

## 明确不做

见 `docs/DESIGN.md` 和计划 §十一(v1 的范围线):凭据中介、远程多租户解锁仪式、
委托链 / biscuit 能力令牌。
