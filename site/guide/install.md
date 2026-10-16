# 安装

需要 **Rust 1.88 或更新**。目前只能从源码构建:

```bash
cargo install --path .
```

或者 `cargo build --release`,用 `target/release/anp-keyd`。

开发模式支持 macOS 和 Linux。Linux v2 使用 SQLite 和 root 管理的配置；protected supported 仍待真实主机验收。发行构建排除 hardware-software，安装/更新校验管理员给定的 SHA-256。

::: warning 一条纪律
交互式口令从控制终端读取。Agent 可以创建 PTY，所以终端本身不能证明人类在场；Linux v2 管理准入由独立管理员 UID 和经过认证的管理通道决定。

口令从 `/dev/tty` 读,不走命令行参数、不走环境变量、不走 stdin；CLI 解锁时会经过 v1 socket。TTY 不是人类身份认证。
:::

## 只在特定构建里存在的几个

默认构建里没有下面这些。要哪个就带哪个 feature:

```bash
cargo install --path . --features seed-export    # 多出 export-seed
cargo install --path . --features mcp            # 多出 mcp
cargo install --path . --features hardware-se    # macOS:钥匙可以绑到 Secure Enclave
cargo install --path . --features hardware-tpm   # Linux:钥匙可以绑到 TPM 2.0
```

| 特性 | 多出什么 | 为什么默认不在 |
|---|---|---|
| `seed-export` | `export-seed` | 一个能一键把整把身份抽干的接口,是 agent 被注入之后最想找的东西 —— 它干脆不在二进制里。见[导出为什么是缺席的](/design/) |
| `mcp` | `mcp` 子命令 | 在 stdin/stdout 上说 MCP,把几个工具转给守护进程。不想要这条门面就别构建它 |
| `hardware-se` | `--hardware secure-enclave` | 只认这个平台上成立的取值 |
| `hardware-tpm` | `--hardware tpm` | 同上 |

`--hardware` 那个开关也只在对应构建里认那几种取值 —— **一个在这个平台上压根不成立的取值不会被列出来**。这是[硬件根](/advanced/hardware-root)那一节的原则:不给"看起来在保护、其实没有"的中间态。

导入和导出是**不对称**的,而且是故意的:`import-mnemonic` / `import-archive` 在默认构建里就有,恢复自己的身份不该需要一次特殊编译;而**交出**身份应该。

## 装完先做一件事

```bash
anp-keyd probe
```

它报告这台机器能不能兑现这个工具给出的承诺:内存锁定建不建得起来、一次崩溃会不会把种子写到磁盘上、`device.secret` 在不在、模式对不对,以及这台机器有没有可用的硬件根。

**它一个字节的密钥材料都不打印** —— 走 stdout 就是为了让你能放心把输出贴到 issue 里。

## 测试(如果你想从源码验一遍)

```bash
cargo test                    # 单元 + 集成 + 负例 + 外部向量
cargo test --all-features     # 连导出、MCP 和软件硬件后端一起
cargo clippy --all-targets --all-features
```

六类测试各自失败的含义不一样,那件事在[测试与向量](/advanced/testing)里单独说 —— 尤其是 `tests/vectors/` 那一类:**改一个向量让测试变绿,等于把这个文件存在的理由删掉。**

## 接着看

- [五分钟跑通](/guide/quickstart) —— 从一份规格文件到第一行签名头
- [不显然的默认值](/reference/defaults) —— 装好了也别急着用,先看这页
