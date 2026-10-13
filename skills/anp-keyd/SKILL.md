---
name: anp-keyd
description: 用本机 anp-keyd 守护进程给 HTTP 请求签 did:wba / RFC 9421 消息签名,或查看本机有哪些 DID 密钥、是否已解锁。当任务要"以某个 DID 的身份"发请求、要往请求上加 Signature / Signature-Input 头、或要弄清签名为什么被拒时用它。
---

# anp-keyd

本机的常驻守护进程,替你保管 did:wba 的 Ed25519 私钥,并按 RFC 9421 签
HTTP 消息签名。

**你(agent)任何时候都拿不到私钥字节,这是产品本身,不是权限限制。** 你能做
的是让守护进程替你签某一条具体的请求,拿回两个头。别去找绕过它的办法 ——
那些办法要么不存在,要么就是在把用户的身份交出去。

## 先看状态

```bash
anp-keyd list                 # 这台机器上有哪些钥匙(DID + kid)
anp-keyd status               # 当前已解锁的钥匙,以及解锁了多久
```

`list` 里有、`status` 里没有,就是**没解锁** —— 下一步签名会被拒。

## 签名

```bash
anp-keyd sign \
  --did did:wba:example.com:agents:mybot:e1_abc… \
  --method GET \
  --url https://service.example.net/orders/42
```

往 stdout 打两行:

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=…;expires=…;nonce="…";keyid="…#key-1"
Signature: sig1=:VwRcADsdxfIJ5rQAXCXX3ygFsAP3l1ho+gdpNxcHzlZCdx/mef9yKzHgy9P1QzVVHQuxoAyffja4G6CbAaUDCA==:
```

**原样挂到你要发的那条请求上。** 头名和头的值一个字节都不要改、不要重新
排序、不要重新格式化 —— 签名是算在这些字节上的,改一个字符服务端就验不过。
两个头的先后无所谓(HTTP 头有序无关),但值本身是逐字节绑定的。

带请求体时:

```bash
anp-keyd sign --did … --method POST --url … --header 'content-type: application/json' --body request.json
```

- `--body` 会让 `content-digest` 进覆盖面,而且摘要**由守护进程自己算**
  —— 你在 `--header` 里塞的同名头会被忽略,所以别塞。
- `--header '名字: 值'` 可以重复,把请求上已有的头告诉守护进程。
- `--cover NAME` 可以要求**多**签几个分量(比如 `content-type`),但**不能
  要求少签** —— 覆盖面由守护进程定下限,你只能加。想要减会被拒
  (`covered set rejected`)。
- 不要用 `--raw`:那是另一条路,需要守护进程显式开着 `--allow-raw-signing`,
  而且它签的是文件里的原始字节,不是你这条请求。

## 签名被拒了,对照着看

| 你看到的 | 意思 | 你该做什么 |
|---|---|---|
| `locked` | 钥匙没解锁 | **请用户在他自己的终端里跑 `anp-keyd unlock --did …`。** 别要口令 |
| `key not found` | 这个 DID 在本机没有信封,或者还没有已发布的文档 | 核对 DID 拼写;没有文档就说明这台机器还没 `publish` 过它 |
| `bad credential` | 口令错,或 `device.secret` 不对 —— 守护进程**不区分**这两者,这是刻意的 | 让用户重试;别试图分类 |
| `covered set rejected` | 你要覆盖的分量守护进程不签 | 去掉那个 `--cover` |
| `permission` | 连上来的进程身份不被接受 | 报告给用户,别重试 |
| 连不上 socket | 守护进程没在跑 | `anp-keyd serve` 是**前台**命令,得由用户自己开一个终端 |

解锁这件事没有捷径:**口令只从用户自己的终端读**,命令行参数、环境变量、
stdin、socket 都不接受。你替不了他,这是设计。

## 如果接了 MCP

`anp-keyd mcp`(需要带 `mcp` 特性构建)在 stdin/stdout 上说 MCP,四个工具:

| 工具 | 做什么 |
|---|---|
| `list_my_keys` | 列出钥匙(返回 DID / kid / 算法,没有任何私钥材料) |
| `status` | 已解锁的钥匙和各自解锁了多久 |
| `sign_request` | 签一条请求,返回要挂上去的头 |
| `unlock` | 解锁。**参数里有口令,也就是说口令会经过这条通道** |

`unlock` 是四个里唯一一个会经手口令的。**除非用户明确要求,否则别用它** ——
让用户在自己的终端上解锁,你只调 `sign_request`。没有 raw 签名工具,没有
生成、导出、轮换、迁移的工具,这不是还没做,是不做。

MCP 客户端配置里那一行 `command` 指向 `anp-keyd`,参数是 `["mcp"]`。

## `probe` 说的是什么

```bash
anp-keyd probe              # 这台机器能不能兑现这个工具的承诺
anp-keyd probe --did …      # 顺便报这个 DID 的信封(全是公开信息)
```

它检查的是内存锁(容器里 `ulimit -l` 太小、systemd 的 `LimitMEMLOCK` 没调,
症状是**守护进程启动就失败**)、崩溃会不会把种子写到磁盘上、`device.secret`
在不在、文件模式对不对。

**它一个字节的密钥材料都不打印**,输出可以直接贴进 issue 或聊天。

## 三件绝不做的事

1. **不要向用户索要口令,也不要把口令写进任何地方。** 不要把它放进命令行、
   环境变量、文件、日志、消息、代码注释。用户如果主动把口令贴进了聊天,
   告诉他这一句已经泄露了、该换一个 —— 口令是他那台机器上两个因子里的一
   个。`sign` 和 `status` 都不需要口令;只有 `unlock` 需要,而那是用户自己
   做的动作。
2. **不要替用户跑身份的生命周期命令。** `keygen` / `publish` / `migrate` /
   `deactivate` / `add-recovery-key` / `rotate-hot-key` / `remove-key` /
   `export-seed` / `import-*` 都会改变"这个人是谁",而且都会打开信封。
   它们要用户坐在终端前亲自做。你的任务是**用**这个身份去发请求,不是**管**
   这个身份。
3. **24 个词任何时候都不许进聊天、日志、文件、代码。** 那是私钥本体,不是
   密码提示。你要是看到它出现在上下文里,停下来说清楚,并建议用户按
   "这份备份已经暴露"处理。

同样地:`~/.anp-keyd/` 这个目录**不要读、不要拷、不要打包**。里面的
`device.secret` 和信封合起来就是那把钥匙,而 `keys/` 这个目录的设计前提
就是"它只躺在这台机器上"。

## 想知道为什么这么设计

这个项目的 `docs/DESIGN.md` 讲了威胁模型、信封和归档的区别、以及哪些做法是
被**故意**排除的。要改动这套东西的任何一部分之前,先读它。
