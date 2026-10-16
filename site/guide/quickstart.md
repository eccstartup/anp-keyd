# 五分钟跑通

本页演示旧开发模式，只适合临时身份与可信进程，不提供同 UID Agent 隔离。Linux v2 请使用管理员配置与有限 grant，接入说明见 [Agent 接入](/advanced/agent)。正式 Linux 构建与显式保护部署已通过 systemd 主机验收。

这一页从零走到第一行签名头。试的时候建议全程加 `--root DIR`,免得真钥匙和实验钥匙混在一起:

```bash
export KEYD="anp-keyd --root /tmp/keyd-lab"
```

## 一、先写规格,不是先写命令

**文档该有什么,由一份文件说了算 —— 不是由命令行的几个开关。**

did.json 里除了密钥之外的东西(挂哪个域名、service 条目、agent description 地址)通常来自别处:注册 WNS handle 的脚本、你们自己的配置。所以这里分开:**你写规格,工具照它构造文档并签名。**

先起一份模板:

```bash
$KEYD spec --host example.com --path agents/mybot --out mybot.spec.json
```

```json
{
  "host": "example.com",
  "path": "agents/mybot"
}
```

之后随你改:

- `services` 里放 `{"id": "#handle", "type": "ANPHandleService", "serviceEndpoint": "…"}` 这类条目,`id` 以 `#` 开头会被展开成 `{did}#…`
- `agentDescriptionUrl` 是个简写,等价于一条 `{did}#ad` 的 `AgentDescription` 条目
- `port` 要写就写非默认端口

::: info 这份文件里没有密钥,也不能有
公钥是 `keygen` 那一刻才有的。
:::

**认不出的字段会被拒,而不是被悄悄忽略。** "我以为我声明了"和"它真的声明了"是两件事,而一个拼错的键正是这两件事开始分岔的地方。

坐标的几条规则(域名要是 FQDN 不是 IP、路径段必须 URL 安全、至少要有一段路径)在 `spec` 那一刻就报出来,而不是等到钥匙都生成好了才在别处报错。根密钥的 fragment 也不在文件里 —— 它不是一条声明,是本工具自己认根密钥用的名字。

## 二、生成钥匙

```bash
$KEYD keygen --spec mybot.spec.json
```

它会让你**敲两遍口令**,打印出 DID,并告诉你怎么发布。

口令从终端读,不走命令行参数、不走环境变量。`--spec` **没有默认值**:坐标必须是**你写在文件里的**那几个,由工具替你挑一个等于替你决定身份挂在哪儿。

## 三、发布文档

```bash
$KEYD publish --did did:wba:example.com:agents:mybot:e1_abc…
```

再敲一遍口令。它把文档盖上自签 proof,写进 `dids/`,并告诉你这个文件必须被放在哪儿:

```
https://example.com/agents/mybot/e1_abc…/did.json
```

::: danger 这个工具不托管任何东西
谁来放这个文件是你的事 —— 那是别人验签时会去请求的地址。
:::

## 四、起守护进程

```bash
$KEYD serve
```

敲完**就回到提示符**,守护进程在后台听着 `~/.anp-keyd/run/keyd.sock`。中途那几行话会告诉你它听着哪儿、pid 是多少:

```
listening on /Users/you/.anp-keyd/run/keyd.sock (pid 12345)
to stop it: anp-keyd stop
```

不想要后台就在后面加 `--foreground`,那样它会占着这个终端 —— 服务管理器(launchd、systemd)拉起来的时候**要**加这个:它们管的是一个进程,不想要一个从它们手里跑掉的东西。

## 五、解锁

换个终端:

```bash
$KEYD unlock --did did:wba:example.com:agents:mybot:e1_abc…
```

这一步由可信操作者完成，要敲口令；控制终端不能证明人类在场。口令只在内存里,默认空闲 **15 分钟**自动上锁(`serve --idle SECS` 可调)。上锁是常态,不是故障。

## 六、签名

这一步谁都能做,包括 agent:

```bash
$KEYD sign --did did:wba:example.com:agents:mybot:e1_abc… \
  --method GET \
  --url https://service.example.net/orders/42
```

签名头打到 stdout,**原样搬运** —— 不解析、不重排、不补引号。挂到真实请求上去就行:多一个字符、少一个字符,签名就验不过。

### 带请求体

```bash
$KEYD sign --did … --method POST --url https://… \
  --header 'content-type: application/json' \
  --body request.json
```

给了 `--body`,`content-digest` **一定**进覆盖面,而且**由守护进程自己算** —— 请求里带的同名头会被忽略。

### 服务端要求 nonce 和请求体里那个是同一个值

有的服务防重放,要求请求认证里的 `nonce` 和 body 里那个是同一个值。那就由调用方给:

```bash
$KEYD sign --did … --method POST --url https://… \
  --header 'content-type: application/json' \
  --body request.json \
  --nonce "$(jq -r .nonce request.json)"
```

它同时出现在两处,所以守护进程**没法替你挑**:它只会把你给的这个值**原样**放进 `@signature-params`。

nonce 最多 256 字节，只接受可打印 ASCII，拒绝双引号、反斜线和控制字符。验证方仍须检查预期值及重放，随机 nonce 本身不提供重放记录。

::: warning 不给 `--nonce`,这条流程就不成立
守护进程会把"没有"交给上游,**上游自己随机一个** —— 签名里照样有一行 `nonce=`,只是那个值和你的请求体没有任何关系。

所以要"两处同值"这种防重放流程,`--nonce` 必须由调用方给。
:::

## 七、把文档取回来给对端

agent 要证明自己是谁,手上得有 `publish` 出来的那份文档。它也从 socket 上取,而且**不用解锁** —— 那份文档本来就是给外面看的:

```bash
$KEYD document --did did:wba:example.com:agents:mybot:e1_abc…
```

打出来的是磁盘上那一份的**原文,逐字节**。这份文档是签过名的,内联进别处靠的就是这一点,所以中间不会有人替你重排键或补空白。

答得出来的是**本机发布过的**那几个 DID,别人的答不出来 —— 守护进程不联网,那是客户端自己的事。

## 收工

```bash
$KEYD lock --did did:wba:example.com:agents:mybot:e1_abc…
$KEYD stop
```

## 接下去

- [命令行](/reference/commands) —— 完整的命令分组
- [不显然的默认值](/reference/defaults) —— 上面每一步背后都有一个"为什么不那样"
- [接到 agent 上](/advanced/agent) —— 让 agent 真的用起来
