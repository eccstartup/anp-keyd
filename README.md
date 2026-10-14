# anp-keyd

一个跑在你自己机器上的守护进程,替 agent 保管 did:wba 的 Ed25519 私钥,
并按 [RFC 9421] 签 HTTP 消息签名。

**agent 手里从来没有私钥字节。** agent 通过 Unix socket 说话,请求里可以带
方法、URL、头、请求体 —— 唯独没有一个字段能装私钥。守护进程自己重建签名基、
自己决定覆盖面,签完把签名头递回来。

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=1791913177;expires=1791913477;nonce="xUrKXp6Jcvy5Ha-CywsJKA";keyid="did:wba:example.com:agents:mybot:e1_abc…#key-1"
Signature: sig1=:VwRcADsdxfIJ5rQAXCXX3ygFsAP3l1ho+gdpNxcHzlZCdx/mef9yKzHgy9P1QzVVHQuxoAyffja4G6CbAaUDCA==:
```

**什么时候会想要这个:** 你想让一个 agent 替你去访问别人的服务,但你不愿意
把身份交给它。你给它的是一条"请求签名"的通道,而不是那把钥匙。

[RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421

---

## 状态

早期阶段,`0.1.0`。命令行界面还会变;**落盘的两份格式不会** —— 助记词推导
方案和归档格式已经冻结,因为它们决定了别人手里那份备份打得开还是打不开。
动这两样东西之前请先读 [docs/DESIGN.md](docs/DESIGN.md) 第三节。

**硬件根(信封的第三路熵)已经写好了,但默认构建里没有。** macOS 那一半在真
芯片上验过 ECDH;Linux/TPM 那一半**已经在 Linux 上编译过、也跑过 `swtpm` 的
端到端**(2026-10-14)。细节在下面的
[硬件根](#硬件根)一节、[docs/DESIGN.md](docs/DESIGN.md) 第九节,以及还没做完
的部分(第十节)。

## 安装

需要 Rust 1.88 或更新,目前只能从源码构建:

```bash
cargo install --path .
```

(或者 `cargo build --release`,用 `target/release/anp-keyd`。)

没有别的依赖:不需要数据库、不需要网络、不需要配置文件。平台是 macOS 和
Linux。

**一条纪律先说一下:** 凡是需要口令的命令,都要求一个**真的控制终端**。
cron、CI、systemd 的 `ExecStartPre`、被 agent 拉起来的子进程都在这一条外面
—— 这是设计,不是遗漏。

## 五分钟跑通

**文档该有什么,由一份文件说了算 —— 不是由命令行的几个开关。** did.json
里除了密钥之外的东西(挂哪个域名、service 条目、agent description 地址)
通常来自别处:注册 WNS handle 的脚本、你们自己的配置。所以这里分开:
**你写规格,工具照它构造文档并签名。**

先起一份模板,它就是你手上那个文件:

```bash
anp-keyd spec --host example.com --path agents/mybot --out mybot.spec.json
```

```json
{
  "host": "example.com",
  "path": "agents/mybot"
}
```

之后随你改:`services` 里放 `{"id": "#handle", "type": "ANPHandleService",
"serviceEndpoint": "…"}` 这类条目,`id` 以 `#` 开头会被展开成 `{did}#…`;
`agentDescriptionUrl` 是个简写,等价于一条 `{did}#ad` 的 `AgentDescription`
条目;`port` 要写就写非默认端口。**这份文件里没有密钥,也不能有** ——
公钥是 keygen 那一刻才有的。

认不出的字段会被拒,而不是被悄悄忽略:"我以为我声明了"和"它真的声明了"是
两件事,而一个拼错的键正是这两件事开始分岔的地方。根密钥的 fragment 也不
在文件里(写了同样被拒):它不是一条声明,是本工具自己认根密钥用的名字。

```bash
anp-keyd keygen --spec mybot.spec.json
```

它会让你**敲两遍口令**(口令从终端读,不走命令行参数、不走环境变量),
打印出 DID,并告诉你怎么发布。`--spec` 没有默认值:坐标必须是**你写在
文件里的**那几个,由工具替你挑一个等于替你决定身份挂在哪儿。坐标的几条
规则(域名要是 FQDN 不是 IP、路径段必须 URL 安全、至少要有一段路径)在
`spec` 那一刻就报出来,而不是等到钥匙都生成好了才在别处报错。

```bash
anp-keyd publish --did did:wba:example.com:agents:mybot:e1_abc…
```

再敲一遍口令。它把文档盖上自签 proof,写进 `dids/`,并告诉你这个文件必须被
放在哪儿:

```
https://example.com/agents/mybot/e1_abc…/did.json
```

**这个工具不托管任何东西。** 谁来放这个文件是你的事 —— 那是别人验签时会去
请求的地址。

```bash
anp-keyd serve
```

敲完**就回到提示符**,守护进程在后台听着 `~/.anp-keyd/run/keyd.sock`。
中途那几行话会告诉你它听着哪儿、pid 是多少:

```
listening on /Users/you/.anp-keyd/run/keyd.sock (pid 12345)
to stop it: anp-keyd stop
```

不想要后台就在后面加 `--foreground`,那样它会占着这个终端 —— 服务管理器
(launchd、systemd)拉起来的时候**要**加这个:它们管的是一个进程,不想要
一个从它们手里跑掉的东西。

换个终端,解锁:

```bash
anp-keyd unlock --did did:wba:example.com:agents:mybot:e1_abc…
```

口令只在内存里,默认空闲 15 分钟自动上锁(`serve --idle SECS` 可调)。
然后就能签名了 —— 这一步谁都能做,包括 agent:

```bash
anp-keyd sign --did did:wba:example.com:agents:mybot:e1_abc… \
  --method GET \
  --url https://service.example.net/orders/42
```

签名头打到 stdout,**原样搬运** —— 不解析、不重排、不补引号。挂到真实请求
上去就行:多一个字符、少一个字符,签名就验不过。

带请求体的 POST:

```bash
anp-keyd sign --did … --method POST --url https://… \
  --header 'content-type: application/json' \
  --body request.json
```

给了 `--body`,`content-digest` 一定进覆盖面,而且**由守护进程自己算** ——
请求里带的同名头会被忽略。

有的服务要求请求认证里的 `nonce` 和请求体里那个**是同一个值**(防重放),
那就由调用方给:

```bash
anp-keyd sign --did … --method POST --url https://… \
  --header 'content-type: application/json' \
  --body request.json \
  --nonce "$(jq -r .nonce request.json)"
```

它同时出现在两处,所以守护进程没法替你挑:它只会把你给的这个值原样放进
`@signature-params`。不给就一个都不放,不会自己编一个。

agent 要证明自己是谁,手上得有 `publish` 出来的那份文档。它也从 socket 上
取,而且**不用解锁** —— 那份文档本来就是给外面看的:

```bash
anp-keyd document --did did:wba:example.com:agents:mybot:e1_abc…
```

打出来的是磁盘上那一份的**原文**,逐字节。这份文档是签过名的,内联进别处
靠的就是这一点,所以中间不会有人替你重排键或补空白。答得出来的是**本机
发布过的**那几个 DID,别人的答不出来 —— 守护进程不联网,那是客户端自己的事。

试的时候建议加 `--root DIR`,免得真钥匙和实验钥匙混在一起。

## 命令

分成两组,因为它们的信任关系不一样。

### 走 socket 的(给 agent 用)

连上守护进程要它做事,**从始至终不碰私钥字节**。

| 命令 | 干什么 |
|---|---|
| `sign` | 签一条 RFC 9421 请求,把签名头打到 stdout |
| `list` | 列出这台机器上的钥匙 |
| `status` | 列出当前已解锁的钥匙,以及各自解锁了多久 |
| `document` | 打出一份本机发布过的 DID 文档,**原样**——不用解锁 |
| `unlock` | 解锁一把钥匙(这一步是人做的,要敲口令) |
| `lock` | 上锁 |

### 不走 socket 的(给人用)

在终端上当场打开信封。它们留在你自己的进程里,agent 够不着。

| 命令 | 干什么 |
|---|---|
| `serve` | 常驻(默认进后台):在 Unix socket 上服务签名请求 |
| `stop` | 把后台那个守护进程停下来(没在跑也不报错) |
| `spec` | 写一份文档规格文件(模板),`keygen` / `publish` 读的就是它 |
| `keygen` | 生成一把新的 did:wba 密钥,把信封写进 `keys/` |
| `publish` | 按规格构造文档、盖上自签 proof,写出 did.json |
| `verify-doc` | 校验一份文档确实是它自称的那个 DID 的文档 |
| `probe` | 体检:这台机器能不能兑现这个工具给出的承诺 |
| `add-recovery-key` | 给一个 DID 加一把恢复密钥(预授权签一次迁移) |
| `rotate-hot-key` | 轮换日常签名用的热密钥 |
| `remove-key` | 从文档里摘掉一把非绑定密钥 |
| `migrate` | 迁移到一个新 DID:旧文档标记为已注销并指向它 |
| `deactivate` | 永久注销一个 DID,可以顺手指向一个后继 |
| `import-mnemonic` | 从 24 个词恢复一把绑定密钥,并重新封进信封 |
| `import-archive` | 从一个加密归档恢复 |

`--help` 是完整的参数参考。

### 只在特定构建里存在的几个

```bash
cargo install --path . --features seed-export    # 多出 export-seed
cargo install --path . --features mcp            # 多出 mcp
cargo install --path . --features hardware-se    # macOS:钥匙可以绑到 Secure Enclave
cargo install --path . --features hardware-tpm   # Linux:钥匙可以绑到 TPM 2.0
```

`export-seed` 把一把钥匙的种子导出来。默认构建里它**不存在** —— 不是"被
拒绝",是**没有这段代码**:没有分支、没有环境变量、没有可翻的开关。理由见
[docs/DESIGN.md](docs/DESIGN.md) 第六节。导入则相反,默认构建里就有。

`--hardware` 那个开关也只在对应构建里认那几种取值 —— 一个在这个平台上压根
不成立的取值**不会被列出来**。这正是[硬件根](#硬件根)那一节的原则:
不给"看起来在保护、其实没有"的中间态。

### 几个不显然的默认值

- **`keygen --spec` 没有默认值。** DID 是"坐标 + 公钥"算出来的,而坐标必须是
  **你写在文件里的**那几个 —— 由工具替你挑一个,等于替你决定身份挂在哪儿。
- **规格文件拒收未知字段。** "我以为我声明了"和"它真的声明了"是两件事,
  悄悄忽略一个拼错的键正是这两件事开始分岔的地方。
- **`spec --host` 拒收 IP 字面量。** did:wba 要求 FQDN。这一条在读规格文件时
  就报,不等到人坐下来敲口令。
- **根密钥的 fragment 写不进规格文件。** 它不是声明,是本工具自己认根密钥
  用的名字;开放出去能造出一份本工具自己看不懂的文档。
- **`publish` 不给 `--spec` 就沿用本地那份文档的声明。** 重发一次文档不该顺手
  把 service 条目清掉 —— 那是不报错的丢东西。
- **`publish --spec` 的坐标必须和 `--did` 说的一致。** 对不上直接拒,而不是
  挑一个信:拿一个 DID 去签另一个地方的文档,是这里最贵的一种错。
- **`serve --idle 0` 是"立刻上锁",不是"永不"。** 想要永不,别用 0。
- **`serve` 默认进后台,`stop` 靠 pid 文件找到它。** pid 文件会被核对:
  里面那个号码现在跑的**不是这个二进制**就拒绝动手(pid 会被回收,而
  `stop` 发的是 SIGTERM)。对不上时它不杀、也不删那个文件。
- **`sign --raw` 默认关着。** 那是守护进程里唯一一条能给调用方任意签名的路,
  要用得先 `serve --allow-raw-signing`。
- **`sign --url` 里的 URL 会按 URL 解析器的写法规范化。** host 归一成小写,默认
  端口去掉(`https://example.com:443/x` 按 `https://example.com/x` 签)。验签方
  是**自己解析 URL 再算一遍** `@authority` 的,两边必须是同一串 —— 照字面签
  `:443` 会得到一个"签名无效",把人指向钥匙而不是指向 URL。path、query、
  fragment 一个字节不动,非默认端口照旧。
- **`migrate --allow-different-subject` 默认关。** 默认放行等于让一次打错字
  的 `--to` 变成一次无人察觉的冒名。
- **`serve --system` 不给 `--allow-binary` 就拒绝启动。** 一个守护进程服务
  多个 uid 时,uid 已经不是承诺的粒度了 —— 只配了 uid 的"多用户"是假的
  多用户,那就不过。**不知道值该填什么?** 先拿一个匹配不上的 pin 起一次,
  守护进程会把每一条被拒的连接连同**可以直接抄进命令行**的那个 pin 写进
  `log/serve.log`。
- **`--hardware` 默认 `none`。** 硬件根是要的人开口要的东西。要了而没有,
  是错误,不是降级 —— 见[硬件根](#硬件根)。

## 它挡什么,不挡什么

**挡的:** agent 被注入之后拿不到私钥字节;同一个 uid 下的另一个进程读不到
口令;磁盘被偷(信封的熵一半在口令、一半在 `device.secret`);审计日志被
事后编辑;**绑了硬件根的话,连"把整个目录拷到另一台机器 + 知道口令"也不成**
(见[硬件根](#硬件根))。

**不挡的:** 同一个 uid 下的另一个 agent 冒充你(uid 是授权模型的地基,粒度
就是 uid,要再细一层得靠可执行文件身份);你亲手把 `export-seed` 敲了一遍;
归档文件本身的离线爆破;**没绑硬件根的信封,今天仍然是一个拷贝就走得掉的
东西**。

每一条是怎么成立的、为什么某些做法被**故意**排除,见
[docs/DESIGN.md](docs/DESIGN.md)。

## 硬件根

**它解决什么。** 今天信封里那两个秘密都是软件的:口令(在人脑子里)+
`device.secret`(磁盘上 32 字节)。把 `~/.anp-keyd/` 整个拷到另一台机器、又
知道口令,就能拿到私钥;一份离线备份也能慢慢爆破。硬件根补的是这一路:
**再插一个不可导出、拷不走的熵源进去。**

```
HS  = 32 随机字节,由硬件封装后存进信封(hs_ciphertext)
KEK = HKDF-SHA256( argon2id(口令) ‖ device.secret ‖ HS, salt )
```

三路少任何一路都开不了。硬件是**第三层**,不替代 `device.secret`:后者管
"备份被拷走没用",前者管"拷到别的机器没用"。

**怎么开:**

```bash
cargo install --path . --features hardware-se    # 或 --features hardware-tpm
anp-keyd keygen --spec mybot.spec.json --hardware secure-enclave
```

认这个开关的还有 `add-recovery-key`、`rotate-hot-key`、`import-mnemonic`、
`import-archive`。**默认是 `none`** —— 硬件是**要的人开口要**的东西,不是
悄悄加上去的东西。v1 的信封一个字节都没改,旧信封照旧能开。

**没有可用硬件根,就是拒绝生成,不降级。** 要硬件绑定而没有硬件,是一条
错误,不是悄悄退回纯软件信封:一个看起来在保护、其实没有的信封,比一个
老实说自己是明文的口令加 `device.secret` 更糟。

**两条纪律,是有意的代价:**

1. **导出现在必须在本机做。** 导出要先解信封,而解信封要硬件。所以
   "把磁盘拷到别的机器上再导出"这条路**被硬件根关掉了** —— 这正是它的目的,
   但代价是:**趁机器活着把那 24 个词抄下来。** 芯片坏了、机器丢了,没有第二
   条路。
2. **`--hardware` 绑的是这台机器。** 把绑定过的信封整个目录拷到另一台机器,
   打不开,而且报的错会指明是少了这台机器 —— 不是"口令错"。两者可区分是
   刻意的。

**助记词和归档这两侧永远不碰硬件。** 不然芯片坏了就等于钥匙没了,等于没
备份。导出/导入是唯一允许的搬家路径,而且那条路径的产物是一把**硬件无关**的
钥匙。

**macOS 有一条发行前置。** SE 私钥唯一的持久化机制就是钥匙串,而写钥匙串
需要 `application-identifier` 这个 entitlement —— **它只有 Apple 签发的证书
能给**。所以:

- 未签名的二进制建**永久** SE key → `errSecMissingEntitlement`(芯片在,
  是钥匙串拒绝)
- ad-hoc 签名 + 手写 `keychain-access-groups` → 进程**被内核 SIGKILL**
- ad-hoc 签名**不带**那个 entitlement → 正常运行,但 SE key 一退出就没了

也就是说 SE 版本**必须以签名身份分发**,`cargo build` 的产物做不到。这是
发行决策,不是代码里能补的一环 —— `probe` 会替你把这件事说出来,而不是
报一个假的"通过"。

**Linux/TPM 没有这道门槛。** 走 `/dev/tpmrm0`,不要 entitlement,可选绑 PCR
(**默认不绑** —— 绑了的话内核或固件一升级就把用户锁在门外)。`swtpm` 能在
本机把它模拟出来,所以那条代码路径是可以真测的 —— 但**它到目前为止还没有在
任何 Linux 机器上编译过**,见 [docs/DESIGN.md](docs/DESIGN.md) 第十节。

## 磁盘布局

根目录默认 `~/.anp-keyd`(`--root` 可覆盖;`--system` 下是
`/var/lib/anp-keyd/users/<uid>`)。

```
~/.anp-keyd/
├── device.secret              0600  这台机器的第二个因子。丢了 = 信封全废
├── keys/<thumbprint>.json     0600  信封,一把一个(v1 或绑了硬件的 v2)
├── dids/<did>.json            0644  已发布的文档(含自签 proof),给外面看
├── audit/YYYY-MM.jsonl        0600  审计日志。按月分片,链 + 锚
├── audit/.lock                0600  串行化追加的那把跨进程锁
├── log/serve.log              0600  守护进程的日志,给人排查用
└── run/
    ├── keyd.sock                    守护进程的 Unix socket
    └── keyd.pid               0600  它的 pid(`stop` 读这个)
```

目录 `0700`,秘密文件 `0600`,公开文件 `0644`。

`log/` 和 `audit/` 是两件事,别混:审计是哈希链加锚,是对外的证据;serve
日志是给人看的运行记录,随时可以删。

`audit/.lock` 是一把 `flock`,只包住**一次**追加(读尾哈希 → 写记录 → 写锚
那三步)。审计日志的写者不止守护进程一个 —— 每一条 CLI 命令各自开一份
`AuditLog`,而它们完全跑得起来的时间正是守护进程正忙的时候。两个写者各写各
的行会让链断掉,而链断正是我们用来发现篡改的信号:让一次合法的并发造出一个
假警报,比日志乱一点糟得多。锁是 `.lock` 那个文件而不是某一份 `.jsonl`,
因为后者换月会换成另一个。

**整份 `~/.anp-keyd/` 拷到另一台机器上是打不开的**,这是设计不是缺陷 ——
一半的熵是这台机器的 `device.secret`,绑了硬件根的话还多一路。要在别的机器
上用同一把身份,走下面那条路。

## 出事的时候

### 换机器 / 重装系统

先在**旧机器**上把身份导出成归档(需要一个**一次性的、和日常口令不同的**
导出密码):

```bash
cargo install --path . --features seed-export
anp-keyd export-seed --did did:wba:…
```

会得到 24 个词和/或一个 `.anpkeyd.json` 归档。**把词抄在纸上,不要放在这
台机器上。** 然后在**新机器**上:

```bash
anp-keyd import-mnemonic --did did:wba:…    # 24 个词
anp-keyd import-archive --file x.anpkeyd.json
```

导入之后两件事必须知道:

1. **这是一把克隆,不是副本。** 导入出来的钥匙和旧机器上的是**同一把**,
   两边都能签,而且验证方分不出来。旧机器上的那一份要处理掉。
2. **重新封装用的是这台机器的新 `device.secret` 和新口令。** 归档里的那个
   导出密码从此没用了。

### 装了钥匙的机器坏了,又没有备份

钥匙没了。信封打不开,而且报的错和"口令敲错了"**一模一样** —— 这是刻意的,
两者可区分等于告诉拿到磁盘的人"你缺的是哪个因子"。

所以:**趁机器活着,把 24 个词抄下来。**

绑了硬件根的话,这一条从"该做"变成"只能这么做":导出要先解信封,解信封要
硬件,所以那台机器一旦不在,**就没有第二条路** —— 也不能把磁盘搬到别的机器
上再导出。那正是硬件根要的性质,代价也就在这儿。

### 怀疑哪里不对劲

```bash
anp-keyd probe
anp-keyd probe --did did:wba:…
```

它报告这台机器能不能兑现这个工具给出的承诺:内存锁定建不建得起来(容器里
`ulimit -l` 太小、systemd 的 `LimitMEMLOCK` 没调,症状是**启动就失败**,而
这里能当场说清是哪一条不满足)、一次崩溃会不会把种子写到磁盘上、
`device.secret` 在不在、模式对不对,以及**这台机器有没有可用的硬件根、是哪
一种、能不能真的用**(SE 那一侧最容易被看出来:芯片在、框架也编进去了,但
没有 Apple 签发的证书就建不出持久的 SE 私钥,于是"绑了硬件"根本兑现不了)。

**它一个字节的密钥材料都不打印。** 走 stdout 就是为了让你能放心把输出贴到
issue 里。

## 接到 agent 上

`mcp` 子命令在 stdin/stdout 上说 MCP,把几个工具(`list_my_keys` /
`status` / `sign_request` / `unlock` / `get_did_document`)转发给守护进程。
它自己不开密钥库,也不碰密码学。

```bash
cargo install --path . --features mcp
```

MCP 客户端的配置里,那一行 `command` 就指向这个子命令,参数是 `["mcp"]`:

```json
{
  "mcpServers": {
    "anp-keyd": { "command": "/path/to/anp-keyd", "args": ["mcp"] }
  }
}
```

五个工具里只有 `unlock` 会把口令带过那条通道,而它是个**权衡不是免费的
东西**:口令只是两个因子之一(`device.secret` 从不经手 MCP),而且它给的
不是新能力 —— `sign_request` 本来就能签。不想要就别构建这个特性。

### 写给 agent 看的说明

[`skills/anp-keyd/`](skills/anp-keyd/SKILL.md) 是一份 Claude Code skill:
告诉 agent 怎么查状态、怎么签、怎么把两个头逐字节挂上去、被拒的那些码各自
什么意思,以及**三件绝不做的事**(不要口令、不替人跑生命周期命令、24 个词
不许进聊天)。

装上它:

```bash
cp -r skills/anp-keyd ~/.claude/skills/          # 只给自己用
cp -r skills/anp-keyd .claude/skills/            # 给这个项目里的会话用
```

自己写客户端也可以 —— 线上是 `u32_be(len) || payload`,消息类型只有六种
(`LIST_KEYS` `SIGN` `UNLOCK` `LOCK` `STATUS` `GET_DOCUMENT`)。
[`src/client/mod.rs`](src/client/mod.rs) 就是一份可以直接抄的最小实现。

## 测试

```bash
cargo test                    # 单元 + 集成 + 负例 + 外部向量
cargo test --all-features     # 连导出、MCP 和软件硬件后端一起
cargo clippy --all-targets --all-features
```

`--all-features` 里的 `hardware-software` 是一个**假后端**:它把"封起来的
熵"存在一个文件里,而不是芯片里。它存在的唯一理由是让 v2 记录格式在没有硬件
的机器上真的能被测(版本分派、AAD、拒绝降级那一整块)。它自己承认自己不是
硬件,所以 `probe` 不会拿它当"这台机器有硬件根"的证据。

`hardware-se` / `hardware-tpm` 那两条路不在 `--all-features` 里,因为
`#[cfg(target_os)]` 挡着:一台机器只能编出其中一条。SE 的 ECDH 在真芯片上
验过,**持久化还差签名身份**;TPM 那条在 Linux 上编过、也跑过 `swtpm` 的
端到端(`tests/tpm.rs`,三条都标了 `#[ignore]`,要 `-- --ignored` 才跑,
见那个文件头)。两边各自的缺口见 [docs/DESIGN.md](docs/DESIGN.md) 第十节。

六类测试,失败的含义不一样:

| 文件 | 回答的问题 | 红了意味着 |
|---|---|---|
| `src/**` 的单元测试 | 这个函数在它的假设下对不对 | 代码写错了 |
| `tests/cli.rs` | 真起一个二进制、真在一个终端上敲命令 | 给人看的那一层坏了 |
| `tests/signature_end_to_end.rs` | 整条路走通没有 | 接口对不上了 |
| `tests/negative.rs` | **产品承诺的那十件事今天还成立吗** | **有人把一道墙拆了** |
| `tests/tpm.rs` | **真芯片上:封得住、开得回、根没了就拒绝** | 第三路熵那一层坏了 |
| `tests/vectors/` + `tests/vectors.rs` | 外部标准和兄弟实现还认不认我们的实现 | **看它是哪一类出处**:RFC 抄本红了先怀疑实现;兄弟实现的值红了是两边分家了 |

另有四个单一命题,每个一个文件:`tests/probe.rs`(体检说的都是真的)、
`tests/mcp.rs`(MCP 那五个工具就是全部)、`tests/hardware.rs`(硬件绑定那
条路的**形状**:版本分派、AAD、硬件不在、口令错、拒绝降级)、
`tests/no_key_material_on_disk.rs`(走完一遍之后,磁盘上扫不出任何密钥材料)。

`tests/hardware.rs` 用软件替身跑,所以它验的是形状而不是"HS 真的出不了这台
机器" —— 最后那一条只有真后端能验,文件头把这条缺口写明了。它在默认构建里
只跑三条(拒绝降级那几条),开了 `hardware-software` 才是七条。

`tests/vectors/` 里的 JSON 每一条都带 `_source` 写明出处。出处有两类:**权威文本的
抄本**(RFC 8032、7638、8037、9421、8785,抄自哪一节都写着),和一个**兄弟实现自己
算出来的值**(`anp_sdk_*`,出处在它自己的测试里)。失败时该怀疑谁取决于它是哪一类:
抄本红了**先怀疑实现** —— 改一个向量让测试变绿,等于把这个文件存在的理由删掉;兄弟
实现的值红了是**两个实现分家了**,得先去两边的仓库里各读一遍,因为期望值那一串在别人
家也是断言,它有可能才是对的一方。这条规则写在 `tests/vectors.rs` 的文件头。

## 设计

这份 README 到这儿为止讲的是"怎么用"。[docs/DESIGN.md](docs/DESIGN.md) 讲
的是"为什么这么做":威胁模型、信封和归档为什么是两种东西、两份冻结的格式
各自的字节布局、导出为什么是**缺席**而不是被拒绝、以及还没有做的部分。

## 许可

Apache-2.0。见 [LICENSE](LICENSE)。
