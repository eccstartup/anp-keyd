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

```bash
anp-keyd keygen --host example.com --path agents/mybot
```

它会让你**敲两遍口令**(口令从终端读,不走命令行参数、不走环境变量)。
然后打印出 DID,和一句提示:信封落在哪个文件里。

`--host` 是你控制的域名,`--path` 是 `e1_` 段之前的那一段路径。两个都没有
默认值 —— did:wba **要求**至少有一段路径,而且要求域名是 FQDN 不是 IP。

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

前台跑着,监听 `~/.anp-keyd/run/keyd.sock`。换个终端,解锁:

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

试的时候建议加 `--root DIR`,免得真钥匙和实验钥匙混在一起。

## 命令

分成两组,因为它们的信任关系不一样。

### 走 socket 的(给 agent 用)

连上守护进程,拿签名,**从始至终不碰私钥字节**。

| 命令 | 干什么 |
|---|---|
| `sign` | 签一条 RFC 9421 请求,把签名头打到 stdout |
| `list` | 列出这台机器上的钥匙 |
| `status` | 列出当前已解锁的钥匙,以及各自解锁了多久 |
| `unlock` | 解锁一把钥匙(这一步是人做的,要敲口令) |
| `lock` | 上锁 |

### 不走 socket 的(给人用)

在终端上当场打开信封。它们留在你自己的进程里,agent 够不着。

| 命令 | 干什么 |
|---|---|
| `serve` | 常驻:在 Unix socket 上服务签名请求 |
| `keygen` | 生成一把新的 did:wba 密钥,把信封写进 `keys/` |
| `publish` | 给文档盖上自签 proof,写出 did.json |
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

### 只在特定构建里存在的两个

```bash
cargo install --path . --features seed-export   # 多出 export-seed
cargo install --path . --features mcp           # 多出 mcp
```

`export-seed` 把一把钥匙的种子导出来。默认构建里它**不存在** —— 不是"被
拒绝",是**没有这段代码**:没有分支、没有环境变量、没有可翻的开关。理由见
[docs/DESIGN.md](docs/DESIGN.md) 第六节。导入则相反,默认构建里就有。

### 几个不显然的默认值

- **`keygen --path` 没有默认值。** 与其给一个注定会失败的默认值(光秃秃的
  `did:wba:example.com:e1_...` 不是合法 did:wba DID),不如让命令在解析参数
  时就把这条规则说出来。
- **`--host` 拒收 IP 字面量。** did:wba 要求 FQDN。
- **`serve --idle 0` 是"立刻上锁",不是"永不"。** 想要永不,别用 0。
- **`sign --raw` 默认关着。** 那是守护进程里唯一一条能给调用方任意签名的路,
  要用得先 `serve --allow-raw-signing`。
- **`migrate --allow-different-subject` 默认关。** 默认放行等于让一次打错字
  的 `--to` 变成一次无人察觉的冒名。
- **`serve` 不给 `--allow-binary` 时会打一条警告。** 只配了 uid 的"多用户"
  是假的多用户。

## 它挡什么,不挡什么

**挡的:** agent 被注入之后拿不到私钥字节;同一个 uid 下的另一个进程读不到
口令;磁盘被偷(信封的熵一半在口令、一半在 `device.secret`);审计日志被
事后编辑。

**不挡的:** 同一个 uid 下的另一个 agent 冒充你(uid 是授权模型的地基,粒度
就是 uid,要再细一层得靠可执行文件身份);你亲手把 `export-seed` 敲了一遍;
归档文件本身的离线爆破。

每一条是怎么成立的、为什么某些做法被**故意**排除,见
[docs/DESIGN.md](docs/DESIGN.md)。

## 磁盘布局

根目录默认 `~/.anp-keyd`(`--root` 可覆盖;`--system` 下是
`/var/lib/anp-keyd/users/<uid>`)。

```
~/.anp-keyd/
├── device.secret              0600  这台机器的第二个因子。丢了 = 信封全废
├── keys/<thumbprint>.json     0600  信封,一把一个
├── dids/<did>.json            0644  已发布的文档(含自签 proof),给外面看
├── audit/YYYY-MM.jsonl        0600  审计日志。按月分片,链 + 锚
└── run/keyd.sock                    守护进程的 Unix socket
```

目录 `0700`,秘密文件 `0600`,公开文件 `0644`。

**整份 `~/.anp-keyd/` 拷到另一台机器上是打不开的**,这是设计不是缺陷 ——
一半的熵是这台机器的 `device.secret`。要在别的机器上用同一把身份,走下面
那条路。

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

### 怀疑哪里不对劲

```bash
anp-keyd probe
anp-keyd probe --did did:wba:…
```

它报告这台机器能不能兑现这个工具给出的承诺:内存锁定建不建得起来(容器里
`ulimit -l` 太小、systemd 的 `LimitMEMLOCK` 没调,症状是**启动就失败**,而
这里能当场说清是哪一条不满足)、一次崩溃会不会把种子写到磁盘上、
`device.secret` 在不在、模式对不对。

**它一个字节的密钥材料都不打印。** 走 stdout 就是为了让你能放心把输出贴到
issue 里。

## 接到 agent 上

`mcp` 子命令在 stdin/stdout 上说 MCP,把四个工具(`list_my_keys` /
`status` / `sign_request` / `unlock`)转发给守护进程。它自己不开密钥库,
也不碰密码学。

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

四个工具里只有 `unlock` 会把口令带过那条通道,而它是个**权衡不是免费的
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

自己写客户端也可以 —— 线上是 `u32_be(len) || payload`,消息类型只有五种
(`LIST_KEYS` `SIGN` `UNLOCK` `LOCK` `STATUS`)。[`src/client/mod.rs`](src/client/mod.rs)
就是一份可以直接抄的最小实现。

## 测试

```bash
cargo test                    # 单元 + 集成 + 负例 + 外部向量
cargo test --all-features     # 连导出和 MCP 一起
cargo clippy --all-targets --all-features
```

五类测试,失败的含义不一样:

| 文件 | 回答的问题 | 红了意味着 |
|---|---|---|
| `src/**` 的单元测试 | 这个函数在它的假设下对不对 | 代码写错了 |
| `tests/cli.rs` | 真起一个二进制、真在一个终端上敲命令 | 给人看的那一层坏了 |
| `tests/signature_end_to_end.rs` | 整条路走通没有 | 接口对不上了 |
| `tests/negative.rs` | **产品承诺的那十件事今天还成立吗** | **有人把一道墙拆了** |
| `tests/vectors/` + `tests/vectors.rs` | 外部标准还认不认我们的实现 | 先怀疑实现,别改向量 |

另有三个单一命题,每个一个文件:`tests/probe.rs`(体检说的都是真的)、
`tests/mcp.rs`(MCP 那四个工具就是全部)、`tests/no_key_material_on_disk.rs`
(走完一遍之后,磁盘上扫不出任何密钥材料)。

`tests/vectors/` 里的 JSON 是**权威文本的抄本**,取自 RFC 8032、7638、8037、
9421、8785,每个文件都带 `_source` 写明抄自哪一节。**如果向量测试红了,先
怀疑实现** —— 改一个向量让测试变绿,等于把这个文件存在的理由删掉。

## 设计

这份 README 到这儿为止讲的是"怎么用"。[docs/DESIGN.md](docs/DESIGN.md) 讲
的是"为什么这么做":威胁模型、信封和归档为什么是两种东西、两份冻结的格式
各自的字节布局、导出为什么是**缺席**而不是被拒绝、以及还没有做的部分。

## 许可

Apache-2.0。见 [LICENSE](LICENSE)。
