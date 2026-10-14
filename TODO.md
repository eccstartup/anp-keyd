# TODO

还没做完的事。**为什么**这么做在 [docs/DESIGN.md](docs/DESIGN.md)(威胁模型、取舍)
和 [docs/ADAPTER.md](docs/ADAPTER.md)(适配层的方案)里 —— 这里只列**要动手的东西**。

**一件就是一件事。** 一件做到什么算完,写在条目里;怎么做到,在对应的文档里。

**这一份又收了一次工,所以旧的说法要去归档里对。** 上一版整份快照是归档里的
[docs/TODO-archive.md](docs/TODO-archive.md) 「整份归档三」—— 它做完的那几件
(§一 / §二 / §五)记录在归档的「追加五」和「追加六」里,**没收的只有一件**,搬过来时
成了下面第一节:

| 上一版 | 现在 | 是什么 |
|---|---|---|
| §二(awiki-cli-rs2 那一条) | 一 | awiki-cli-rs2 的接缝,堵在两处 path 依赖的版本钉上 |
| §三 | 二 | 硬件根剩下三件 |
| §四 | 三 | 明确不做 |

**这一版内部的规矩和上一版一样:做完的就在原地划掉,不搬走、不重编号** —— 等到这一版
也收工,再整份快照进归档。所以这个文件里,**没被划掉的才是还没做的**。

**适配层这条主线走完了**(2026-10-14):注册和登录已经对真的 `awiki-open-server`
跑通,而且是跨语言、跨进程跑通的(记录在归档「追加六」)。剩下的一件**不是代码没写**,
是在这台机器上开不了工;硬件根那三件也不是代码问题。理由都在条目里。

---

## 一、适配层:awiki-cli-rs2 的接缝 —— 形状对了,但开不了工

接缝已经在了,而且形状就是 keyd 的(源码在 `~/code/claude/awiki-cli-rs2`,结论写在
[docs/ADAPTER.md](docs/ADAPTER.md) §八):它那层 `IdentitySigner` 的
`http_signature_headers(kid, url, method, headers, body, options)` 正是结构化 `SIGN`,
而且 `options` **本来就带 `nonce`**;`did_document()` 正是 `GET_DOCUMENT`。
`AnpIdentitySigner` 已经把同一批方法转手给 `anp-identity` 这个"custody 在别处"的实现 ——
keyd 照它再写一份即可。两条要点:不能接在底层那个 `sign(kid, message)` 上(那是 `Raw`);
`sign_document_proof` 收的是调用方构造的文档,和 keyd 的不变量 3 错位,所以**注册那一段
的改法要单独想**,不是照抄。

**在这台机器上开不了工,而且不是环境没配好:** `Cargo.toml:43-44` 那两条 path 钉的是
`../anp/anp/rust`(`=1.0.3`)和 `../anp/anp-identity/crates/anp-identity`(`=0.2.3`),
两个目录本机都不存在,registry 上只有 `1.0.5`/`1.0.6` 和 `0.2.5`,`=` 钉死了换不上去。

**算完的样子:** 先在两件事里挑一件 —— **把上游那两个版本弄回来**,或者**松开那两条
钉** —— 然后 awiki-cli-rs2 的注册和登录对真的 `awiki-open-server` 各走完一遍,全程私钥
一个字节都没离开守护进程。**尺子和 connectx 那条一样**(归档「追加六」里的
`keyd-server-acceptance.mjs`),所以那条脚本可以照着改。**拍之前没有可写的代码。**

## 二、硬件根(M5):剩下三件,两件堵在签名身份上

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

## 三、明确不做

适配这条路上不碰的(理由都在 [docs/ADAPTER.md](docs/ADAPTER.md) §十):打开 `Raw`、
让守护进程认识 ANP-02 的语义、让守护进程联网、`export` 上 socket、多用户细粒度
授权。加上原始计划 §十一 划掉的 v1 范围线(凭据中介、远程多租户解锁仪式、委托链 /
biscuit 能力令牌),边界见 [docs/DESIGN.md](docs/DESIGN.md) §一 和 §六。

**上一版那个岔口(注册的挑战签名)已经拍定、也做完了**(2026-10-14,记录在归档
「追加五」):拍的是"开一条比 `Raw` 窄的路",所以它**没有**落进这一节。这一节里留给
它的只有两条照着那条路划出来的线:那条窄路**不进 `mcp`**(agent 手里不该有"签这串
字节"的工具,§9.3),以及"窄"不等于"有形状"—— 它只有一个 256 字节的上界。
