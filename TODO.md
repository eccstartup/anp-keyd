# TODO

还没做完的事。**为什么**这么做在 [docs/DESIGN.md](docs/DESIGN.md)(威胁模型、取舍)
和 [docs/ADAPTER.md](docs/ADAPTER.md)(适配层的方案)里 —— 这里只列**要动手的东西**。

**一件就是一件事。** 上一版把每件事拆成字段、拆成步骤,读起来像进度条,做起来还要
自己把它们重新拼回一件事 —— 这一版不那样写。一件做到什么算完,写在条目里;怎么
做到,在对应的文档里。

上一版整份归档在 [docs/TODO-archive.md](docs/TODO-archive.md):M0–M5 已完成的记录、
TPM 的三处实测结论、"和计划写得不一样的地方"那张对照表,都在那儿,不往这里搬。

眼下的主线是**适配层** —— 在不让守护进程认识任何一个具体协议的前提下,让它满足
connectx / awiki-cli-rs2 这类工具的签名需求([docs/ADAPTER.md](docs/ADAPTER.md))。
硬件根和审计链是上一阶段的收尾,两件都堵着,理由在条目里。

---

## 一、适配层:把两个新原语做到 socket 上

`nonce` 透传,和只读的 `GET_DOCUMENT`。方案、理由、以及"为什么它不动授权模型"在
[docs/ADAPTER.md](docs/ADAPTER.md) §三。

**落点是共用层,不是某个前端的参数表。** `wire` 的类型加一处,`cli` 和 `mcp` 各接
一处 —— 漏掉第二处的症状**不是编译错误**,是走 MCP 的 agent 登不了录,而同一个
agent 在命令行上怎么试都是好的(§9.1)。`nonce` 只要一条约束:进签名基所以有长度
上限,**内容是透明的**,守护进程管长度、不管含义。

**算完的样子:** 两条路都签得出带调用方指定 nonce 的签名;`GET_DOCUMENT` 答得出
本机发布过的 DID 和它的文档,答不出别人的。

## 二、适配层:注册那个挑战签名 —— 先写下来,不必现在拍

awiki-open-server 的注册,除了 DID 文档自签,还要一次一次性挑战的证明:对服务端
下发的随机串做一次 Ed25519 签名(`challenge_signature`)。**那不是 RFC 9421**,而
[docs/ADAPTER.md](docs/ADAPTER.md) §十 那条线("不为适配打开 `Raw`")正挡在它前面。
三条路(不签 / 开一条比 `Raw` 窄的路 / 承认注册不在范围内)写在
[ADAPTER §3.3](docs/ADAPTER.md) —— 那是这份方案里**唯一一处要人拍的岔口**。

**但两个客户端都不发它** —— connectx 走文档自签 + 401 重签,awiki-cli-rs2 的注册 RPC
里没这个字段(**两个都核过了**)。所以"不签"这条路**今天零成本**:它挡不住任何人,
只是一条**将来**对端把"可选"翻成"必需"时才会咬人的线。先记在这儿,不急着拍;真要拍,
要么进第七节「明确不做」,要么变成第一节那条共用层上的一件东西。

**算完的样子:** 三条路里选定的那一条写进 ADAPTER 正文,§十二 里那条"未决"落定。

## 三、适配层:客户端侧,和验收

- **connectx:接的是 connector,不是 provider。** `AnpConnector.signRequest` 收
  method / url / nonce / handle,形状正好对上 keyd 的结构化路径;EIP-1193 那层只到
  `signMessage`,用它就得开 `Raw`。实现纪律照抄 `providers/README.md`:适配器里
  只做转发和错误翻译,出现 "ANP" 这个词就是边界划错了地方(§八)。`Locked` 原样
  交回给人,**不重试、不翻译成"签名失败"**(§六)。
- **awiki-cli-rs2:接缝已经在了,而且形状就是 keyd 的。** 它那层 `IdentitySigner` 的
  `http_signature_headers(kid, url, method, headers, body, options)` 正是结构化
  `SIGN`,而且 `options` **本来就带 `nonce`**;`did_document()` 正是 `GET_DOCUMENT`。
  `AnpIdentitySigner` 已经把同一批方法转手给 `anp-identity` 这个"custody 在别处"的
  实现 —— keyd 照它再写一份即可(§八)。**一处错位**:`sign_document_proof` 收的是
  调用方构造的文档,和 keyd 的不变量 3 对不上,注册那一段的改法要单独想。
- **验收是 §十一 那五条反证。** 核心是第一条:**停掉守护进程,connectx 必须失败**
  —— 不然只是多了一条可选路径,不叫抽出来了。

## 四、适配层:动手前要核实的(这次已经核掉四条)

1. **DID 推导 —— 已核对,两边一致。** connectx 的 `ed25519Fingerprint`(RFC 7638
   JWK 指纹 → SHA-256 → base64url 无填充 → `e1_`)和守护进程走的 `anp` 上游
   `compute_multikey_fingerprint`(同一个 JWK,过 RFC 8785 JCS,`URL_SAFE_NO_PAD`)
   是同一串字节。**实测过**:拿 connectx 自己的测试向量独立算了一遍,得到
   `e1_UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4`,和它断言的一致。剩下的是
   **在仓库里加一条向量测试把它钉住**,免得哪一边以后悄悄改了编码。
2. **签名基的跨语言一致性 —— 已核到序列化这一层。** 覆盖面
   (`@method @target-uri @authority content-digest`)、参数顺序
   (`created;expires;nonce;keyid`,两边都不带 `alg`)、`@signature-params` 那一行的
   拼法、行分隔用 `\n` 而不是 `\r\n`,`expires` 两边都固定 300 秒 —— **逐字节相同**。
   **还剩一处会对不上:** `@authority`。connectx 用 WHATWG `URL.host`,显式写出默认
   端口时会把 `:443` 吃掉;守护进程无网络构建下是从 URL 文本里切出来的,会**保留**
   `:443`。平时没人那么写,但"差一个字符就是另一条签名"正是这类地方的代价。
3. **上游版本错位 —— 已核掉,签名基逐字节一致。** 整条 awiki 都在 `anp 1.0.3`
   (Rust CLI 的 path 依赖 `=1.0.3` + Python 服务端的 wheel `anp-1.0.3`),只有 anp-keyd
   钉 `=1.0.6`。拿 1.0.3 那个 pin 的 commit(`096ca3e`)和 crates.io 上的 1.0.6 对拉了
   keyd **真正产字节**的三个入口:`http_signatures.rs`(签名基 + `content-digest`)
   **两份文件逐字节相同**;`compute_multikey_fingerprint` 所在的 `did_wba.rs` 不在差异
   清单里;唯一有差异且参与拼基的 `proof/mod.rs`,改动落在**验证那一支**,上游自己
   写着 *"Keep legacy base64url signing/generation bytes unchanged"*。**所以那一个补丁
   版的差不动签名基** —— 结论和比对过程记在 ADAPTER §十二 第 3 条。**这条关掉之后,
   这一节里剩下的字节级问题就只剩第 2 条那处 `@authority`**,而它靠"拿真对端跑一次"
   来收(§三 那两件客户端的验收,ADAPTER §十一)。
4. **`LIST_KEYS` 要不要报出密钥角色。** 判断仍是"不加",而且新证据是往这个方向弱的:
   `IdentitySigner` 里确实有一套角色词表(`DeviceAssertion` / `Authentication` /
   `KeyAgreement` / `RootControl`),但它**从文档里推**(读 `proof.verificationMethod`
   和 `keyAgreement`),不从密钥列表里要。客户端要的是那份文档,不是 `LIST_KEYS` 多几
   个字段(§3.4)。

## 五、硬件根(M5):剩下三件,两件堵在签名身份上

代码都写完、能验的也验过了(结论在归档里),剩下的**都不是代码问题**:

- **SE 的持久化没验过。** "SE key 留在钥匙串里、进程重启之后还开得了"需要签名身份,
  而本机 `security find-identity -v -p codesigning` 是 0 个。有身份之后的三步验收
  在归档里。
- **macOS 的 SE 版本必须签名分发。** 写钥匙串要 Apple 签发的
  `application-identifier`,这是发行决策。**不要去试"ad-hoc 签名 + 手写
  entitlement"** —— 已经量过,进程会被内核 SIGKILL。
- **硬件绑定的端到端验收仍然跑在软件替身上。** `tests/hardware.rs` 验的是那条路的
  **形状**;"HS 真的出不了这台机器"只有真后端能验。TPM 那半在 Linux 上真跑过了,
  SE 那半等身份。

## 六、审计链:跨月那一环的覆盖面窄于相邻几环

链跨月延续,`open()` 从上个月末行起验,**但只验当前这个月那个文件** —— 历史上的
月份文件在它们自己的那个月里被验过,之后不再验;`.anchor` 只钉住最新那条尾巴。
也就是说改掉一个**已经过去的**月份文件(连同它的末行)不会被发现。真要收住,得让
锚记的是整条链而不是最后一环 —— **那是一次格式变更**,单开一件事。

## 七、明确不做

适配这条路上不碰的(理由都在 [docs/ADAPTER.md](docs/ADAPTER.md) §十):打开 `Raw`、
让守护进程认识 ANP-02 的语义、让守护进程联网、`export` 上 socket、多用户细粒度
授权。加上原始计划 §十一 划掉的 v1 范围线(凭据中介、远程多租户解锁仪式、委托链 /
biscuit 能力令牌),边界见 [docs/DESIGN.md](docs/DESIGN.md) §一 和 §六。

**第二节那三条路不是"明确不做"** —— 它是一个还没定的岔口,定了之后要么进这一节,
要么变成上面某一条。
