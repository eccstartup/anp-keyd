# 命令行

命令分成两组,**因为它们的信任关系不一样**。

## 走 socket 的(给 agent 用)

连上守护进程要它做事,**从始至终不碰私钥字节**。

| 命令 | 干什么 |
|---|---|
| `sign` | 签一条 RFC 9421 请求,把签名头打到 stdout |
| `list` | 列出这台机器上的钥匙 |
| `status` | 列出当前已解锁的钥匙,以及各自解锁了多久 |
| `document` | 打出一份本机发布过的 DID 文档,**原样** —— 不用解锁 |
| `unlock` | 解锁一把钥匙(这一步是人做的,要敲口令) |
| `lock` | 上锁 |

::: info 覆盖面只开放"加",不开放"减"
`sign --cover NAME` 可以要求**多覆盖**几个组件(可重复)。

但调用方**减不掉**任何东西 —— 哪些必须被覆盖是守护进程定的,不是请求里说不用就不用。
:::

## 不走 socket 的(给人用)

在终端上当场打开信封。它们留在你自己的进程里,**agent 够不着**。

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

::: tip `--help` 是完整的参数参考
这一页讲的是**分组和理由**,不是全部开关。
:::

## 只在特定构建里存在的几个

```bash
cargo install --path . --features seed-export    # 多出 export-seed
cargo install --path . --features mcp            # 多出 mcp
cargo install --path . --features hardware-se    # macOS:钥匙可以绑到 Secure Enclave
cargo install --path . --features hardware-tpm   # Linux:钥匙可以绑到 TPM 2.0
```

`export-seed` 把一把钥匙的种子导出来。默认构建里它**不存在** —— 不是"被拒绝",是**没有这段代码**:没有分支、没有环境变量、没有可翻的开关。理由见[导出为什么是缺席的](/design/)。

导入则相反,**默认构建里就有**。
