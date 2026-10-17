> Linux v2 已实现有限授权、事务签名、迁移和管理轮换。真实 systemd 主机验收已通过。
> 正式 Linux 构建与显式 `linux-protected-v1` 部署报告 `protected_supported=true`；其他模式为 false。同 UID 开发模式不提供 Agent 隔离；v1 解锁口令经过 socket。
> 软件整套目录加口令可解封；硬件保护的是解封材料。

# anp-keyd

一个跑在你自己机器上的守护进程,替 agent 保管 did:wba 的 Ed25519 私钥,
并按 [RFC 9421] 签 HTTP 消息签名。

**socket 不返回私钥字节。** agent 通过 Unix socket 说话,请求里可以带
方法、URL、头、请求体 —— 唯独没有一个字段能装私钥。守护进程自己重建签名基、
自己决定覆盖面,签完把签名头递回来。

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=1791913177;expires=1791913477;nonce="xUrKXp6Jcvy5Ha-CywsJKA";keyid="did:wba:example.com:agents:mybot:e1_abc…#key-1"
Signature: sig1=:VwRcADsdxfIJ5rQAXCXX3ygFsAP3l1ho+gdpNxcHzlZCdx/mef9yKzHgy9P1QzVVHQuxoAyffja4G6CbAaUDCA==:
```

**什么时候会想要这个:** 你想让一个 agent 替你去访问别人的服务,但你不愿意
把身份交给它。你给它的是一条"请求签名"的通道,而不是那把钥匙。

想从头读一遍,有文档站:[anp-keyd.vercel.app](https://anp-keyd.vercel.app)。
那儿的正文是为网站重写的,和这一份不是同一套 —— 这里要的是"拿起来就干",
那儿要的是"先看明白";设计说明则是构建时从 [docs/DESIGN.md](docs/DESIGN.md)
原样引进去的,不重写。

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

## Linux v2 授权与事务签名

管理员通过 `admin prepare --file change.json` / `admin commit` 创建或撤销 grant；
创建对象为 `{"kind":"Grant","change":{"action":"Create","principal_id":"…","key_id":"…","policy_id":"…","policy_version":1,"expiry":1792125000,"max_uses":2}}`。
`expiry` 是实际部署时选择的未来 Unix 秒数，期限和次数不能超过不可变策略的上限。
管理员从 catalog 选择已确认的热密钥；根、恢复、challenge 和未分类密钥均不能进入普通 grant。
撤销对象为 `{"kind":"Grant","change":{"action":"Revoke","grant_id":"…"}}`。

Agent 使用 `anp-keyd data --file request.json`，默认读取 `/etc/anp-keyd/service.json`，
认证 daemon 后只发送一条 v2 请求，不自动重试或降级。例如：

```json
{"operation":"SIGN_HTTP","grant_id":"管理员交付的引用","request_id":"客户端生成并保留的 UUID","http":{"method":"GET","url":"https://example.com/test","headers":{},"body":{"state":"absent"},"nonce":null}}
```

有请求体时必须使用 `{"state":"present","bytes":[…]}`，空数组表示明确的空请求体。
当前上限为 16384 字节，且整帧不能超过 65536 字节。HTTPS DNS origin、方法、路径和 query
按精确策略检查；百分号编码、点路径、重复斜线、重复 query 键及重复大小写头均拒绝。
规范化统一 host 大小写和默认端口，调用端最终必须使用规范化 URL，禁用自动重定向。
数据请求还包括 `LIST_AUTHORIZED_KEYS`、`GET_GRANT_STATUS`（grant_id）、
`GET_DOCUMENT`（key_id）与 `GET_REQUEST_STATUS`（request_id）。

启用 MCP feature 后使用 `anp-keyd mcp --config /etc/anp-keyd/service.json`，
只提供 v2 授权工具，工具参数不能覆盖 socket、配置、DID 或 kid；未指定 `--config` 的旧 MCP
仍是显式开发模式。v2 已接入事务预留、次数消费、持久请求去重、结果缓存与撤销。
相同 request_id 与相同输入复用已提交结果；变更输入拒绝；不确定结果保留次数且不自动重签。
正式 Linux 构建在 `linux-protected-v1` 模式下报告 `protected_supported=true`；旧 preview、调试及 macOS 模式仍为 false。重启撤销所有旧 grant 并锁定密钥。

Node 适配器见 [adapters/keyd-v2.mjs](adapters/keyd-v2.mjs)，包含 v2 客户端和现有 anp-sdk
`AnpConnector` 接口。最终发送使用 daemon 返回的规范化 URL、原 body 和签名头，禁用自动重定向。
注册由可信管理端准备 `RegistrationChallenge`（exact root key、HTTPS origin、服务的 32 位小写 hex
challenge），再 `admin complete-secret-operation` 输入口令完成。root 仅瞬时解封，不进入 Agent 会话。
`RotateHotKey` 从预先配置的热密钥切换到下一把，重建并签署文档、撤销旧 grant、退休旧方法；
返回的公开文档仍需独立发布和验证，新授权由管理员创建。不会自动宣称远端已切换。

离线迁移先停止全部旧写者，把源放在 root 控制的路径并保护所有材料，然后：

```bash
python3 deploy/linux/migrate-vault.py --source /root/frozen-vault
python3 deploy/linux/migrate-vault.py --source /root/frozen-vault --apply --recovery-dir /root/keyd-recovery
```

工具核对摘要并通过 tty 打开恢复副本的每把钥匙；保留恢复日志和副本，旧路径标记禁用。
迁入后密钥锁定且角色未分类。启动服务，管理端 EnrollVault、确认角色并建立新 policy/grant，
完成真实认证后切换客户端。恢复副本含 device.secret 和加密信封，必须保持管理员保护；
硬件绑定材料不能靠复制绕过硬件，历史私钥副本也不会因此撤回。细节见 [Linux 部署说明](deploy/linux/README.md)。

## 安装

需要 Rust 1.88 或更新,目前只能从源码构建:

```bash
cargo install --path .
```

(或者 `cargo build --release`,用 `target/release/anp-keyd`。)

开发模式无需网络或配置文件。Linux 边界预览使用 bundled SQLite 和管理员保护的服务配置；macOS 另有独立 UID 本机预览，仍不声明正式受保护支持。

**一条纪律先说一下:** 凡是需要口令的命令,都要求一个**真的控制终端**。
cron、CI、systemd 的 `ExecStartPre`、被 agent 拉起来的子进程都在这一条外面
—— 这是设计,不是遗漏。

## 本机交给 Agent 使用

先读 [本机使用指南](deploy/LOCAL-USE.md) 和对应的 [macOS](deploy/macos/README.md) / [Linux](deploy/linux/README.md) 部署说明。整个不可信 Agent 必须运行在独立非管理员 UID；同管理员 UID 的进程仍是可信管理主体。新安装没有真实身份，临时密钥测试不能代替真实身份导入和授权。

## 五分钟跑通

以下是开发体验路径，不建立独立 UID 的 Agent 安全边界。

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

它同时出现在两处,所以守护进程没法替你挑:你给了,它就把这个值原样放进
`@signature-params`;不给,签名库里会随机挑一个 —— 但那个值只活在签名头上,
不会进你的请求体,两边自然对不上。所以**要两处同值,就必须由调用方给**。

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
- **`sign --raw` / `sign --challenge` 默认关闭。** 启用必须同时指定
  `serve --development --allow-raw-signing` 或
  `serve --development --allow-challenge-signing`，不能与 `--system` 同用。
  challenge 的 256 字节只是资源上限：文档 proof 输入只有 64 字节，仍能跨用途签名。
  启用任一路径均属于开发兼容能力，不构成用途隔离。
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

开发模式的 socket 不返回私钥；信封提供静态加密，但同 UID 任意代码执行
可接触文件与进程，不能承诺 Agent 拿不到私钥。`/dev/tty` 不能认证人类。

只复制不含 device.secret 的信封不足以解封；整套软件目录加口令可以解封。
硬件绑定增加本机解封依赖，签名仍在 daemon 普通内存执行。本地审计链与锚
可检测部分修改，不能抵御整套回滚。Linux v2 已实现独立 UID、有限 grant、事务签名、迁移与撤销；正式 Linux release 加显式 `linux-protected-v1` 已通过 systemd 主机验收。

## Linux 边界预览

新增 `serve-protected`、`admin status/lock-all/unlock` 和 `probe --security`。
M2 首批已接入 SQLite、启动恢复、事务审计，以及两阶段主体注册/禁用；
数据库须显式初始化，丢失或损坏时不会自动重建。
服务账号、管理员与 Agent 使用独立 UID，管理面和数据面分别监听；客户端先验证
服务内核 UID 再发送密码。配置和安装程序由 root 持有。

数据面签名、grant 和离线迁移已有实现；真实 systemd 主机验收已完成，保护声明仍要求正式 Linux 构建和显式保护模式。
安装器与一次性 Linux 容器验收见 [deploy/linux](deploy/linux/README.md)。
旧 `serve`、CLI 和 MCP 开发流程继续保留，两种服务不会自动降级互通。

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

**普通 macOS 本机预览不要求 SE、付费开发者会员或完整 Xcode。** 从源码编译需要 Rust 和 Command Line Tools。它使用独立服务/管理/Agent UID，仍报告 `protected_supported=false`，详见 [本机指南](deploy/LOCAL-USE.md)。

**SE 是另一项尚未完成的增强。** 已验证芯片 ECDH，现有后端依赖用户的数据保护钥匙串，系统 LaunchDaemon 不能靠增加证书直接取得登录上下文。`admin se-session` 登录助手已实现：限 exact hot key、最长 900 秒，失联/会话失效后锁钥撤权，不恢复旧 grant。正式签名/profile、持久 SE、真实注销/休眠/整机重启和升级仍待验收。CSR 本身不授予 entitlement；免费账号能否取得所需授权尚未确认，不要求用户先购买会员或安装完整 Xcode。见 [SE 会话说明](deploy/macos/SE-SESSION.md)。

**Linux/TPM 没有这道门槛。** 走 `/dev/tpmrm0`,不要 entitlement,可选绑 PCR
(**默认不绑** —— 绑了的话内核或固件一升级就把用户锁在门外)。`swtpm` 能在
本机把它模拟出来,所以那条代码路径是可以真测的 —— 2026-10-14 已经在 Linux 上
编过、也跑通了 `swtpm` 的端到端(见 [docs/DESIGN.md](docs/DESIGN.md) 第十节,
那里记着三个只有运行时才露头的 bug)。

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

**整份软件 `~/.anp-keyd/` 加口令可以解封**；只有缺少 device.secret 或所需硬件根时才不能解封。
一半的熵是这台机器的 `device.secret`,绑了硬件根的话还多一路。要在别的机器
上用同一把身份,走下面那条路。

## 独立审计检查点

U4 提供 `audit-checkpoint` 离线检查、固定 `audit-source` 源端，以及独立的 Python keeper。keeper 通过固定 SSH 主机密钥认证源端，在自己的 SQLite 中串行、原子保存检查点和不可变历史，拒绝旧结果覆盖、错误实例、已观测历史回滚及分叉。崩溃后按实际提交结果恢复，不自动重建或重新登记。

部署模板、SSH/sudo 边界、配置及故障策略见 [独立采集器说明](deploy/checkpoints/README.md)。将 keeper 放在服务 UID/Agent 无法修改的独立主机或执行及存储域，初次明确登记后再启用采集 timer。两容器真实 SSH 验收脚本和 CI 位于同目录。

采集器对连接、输出和观测期限设限；断网或持久化失败保留原证据并返回失败。观测超期会报警式报告，签名核心继续原有本地持久审计策略，不联网、不因检查点失联自动停签。未观测尾部仍明确为未知。检查点只锚定审计历史，不验证其他状态表，也不能抵御源端与独立 keeper 一起回滚或可信管理员失陷。

原离线检查仍可独立使用：

```bash
anp-keyd audit-checkpoint --database /trusted-snapshot/state.sqlite \
  --instance-id 12345678-1234-4234-8234-123456789abc \
  --previous /independent-evidence/previous.json
```

该命令只输出候选 JSON；首次人工登记用 `--enroll`。不要将 stdout 重定向覆盖 `--previous` 文件。需要自动保管时使用 keeper，而非自行覆盖检查点。

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
`status` / `sign_request` / `get_did_document`)转发给守护进程。
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

MCP 仅有四个工具，没有密码参数或解锁工具。需要解锁时，用户在自己的终端
执行 CLI。当前 v1 CLI 会向 daemon 发送口令，尚无受保护的服务端互认；
不要将这个开发流程视为独立管理员认证。

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
`tests/mcp.rs`(MCP 的四个工具就是全部)、`tests/hardware.rs`(硬件绑定那
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


### macOS 本机独立 UID 预览（U2）

新增 `macos-boundary-preview`：沿用 v2 双 socket、内核 UID 认证、持久授权和事务签名，
支持独立服务/Agent 账号、launchd 及管理端 `admin unlock --native-ui` 原生口令窗口。
本机编译和测试无需付费开发者会员；`protected_supported` 仍为 `false`。
账号与安装工具默认只打印计划，显式 `--apply` 才修改系统；空状态安装不迁移真实密钥。
现有同 UID Agent 不会因安装而自动获得隔离。
见 [本机部署、信任边界和待验收项目](deploy/macos/README.md)。

### macOS 连接期限修复与更新

修复 `7392419` 解决对端关闭后设置 socket 超时的间歇性 EINVAL，保持整帧截止时间且不自动重发请求。修复候选已通过 macOS 实机临时密钥签名、跨 UID、撤销、正常重启及 SIGKILL 验收；软件回归 523 项及 Linux 126 项边界检查通过。验收候选不等于已更新每台机器的日常安装。

已有安装使用 [更新工具](deploy/macos/README.md#daily-workflow-updates-and-restart)，核对实际二进制摘要后执行；已有 previous 备份可用 `--archive-previous` 完整归档，工具不会覆盖归档。更新重启会锁钥并撤销旧 grant，保留配置及状态。
