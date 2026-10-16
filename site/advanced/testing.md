# 测试与向量

这一页是给**想验一遍**的人看的。一个安全工具说"它挡得住 X",那句话本身不是证据;证据在测试里,而不同测试失败的含义完全不同。

```bash
RUST_LOG=info cargo test --locked --offline
RUST_LOG=info cargo test --locked --offline --features mcp,hardware-software
cargo clippy --locked --offline --all-targets --features mcp,hardware-software -- -D warnings
```

## 六类测试,失败的含义不一样

| 文件 | 回答的问题 | 红了意味着 |
|---|---|---|
| `src/**` 的单元测试 | 这个函数在它的假设下对不对 | 代码写错了 |
| `tests/cli.rs` | 真起一个二进制、真在一个终端上敲命令 | 给人看的那一层坏了 |
| `tests/signature_end_to_end.rs` | 整条路走通没有 | 接口对不上了 |
| `tests/negative.rs` | **产品承诺的那十件事今天还成立吗** | **有人把一道墙拆了** |
| `tests/tpm.rs` | 显式 TPM 环境：封装、解封和根丢失拒绝；可能使用 swtpm | 第三路熵那一层坏了 |
| `tests/vectors/` + `tests/vectors.rs` | 外部标准和兄弟实现还认不认我们的实现 | 看它是哪一类出处,见下 |

`tests/negative.rs` 那一行是这份表里最要紧的:**它红了不是"有个功能坏了",是"有一道承诺被拆了"。**

## 另有四个单一命题

每个一个文件,一个文件说一句话:

| 文件 | 命题 |
|---|---|
| `tests/probe.rs` | 体检说的都是真的 |
| `tests/mcp.rs` | 开发 MCP 四个、保护 MCP 五个工具及各自参数边界 |
| `tests/hardware.rs` | 硬件绑定那条路的**形状**:版本分派、AAD、硬件不在、口令错、拒绝降级 |
| `tests/no_key_material_on_disk.rs` | 走完一遍之后,磁盘上扫不出任何密钥材料 |

## `tests/vectors/`:红了该怀疑谁

这个目录里的 JSON 每一条都带 `_source` 写明出处。**出处有两类,失败时该怀疑谁取决于它是哪一类:**

::: danger 权威文本的抄本
RFC 8032、7638、8037、9421、8785 —— 抄自哪一节都写着。

**红了先怀疑实现。** 改一个向量让测试变绿,等于把这个文件存在的理由删掉。
:::

::: warning 兄弟实现自己算出来的值
`anp_sdk_*`,出处在它自己的测试里。

**红了是两个实现分家了**,得先去两边的仓库里各读一遍 —— 因为期望值那一串在别人家也是断言,**它有可能才是对的一方**。
:::

这条规则写在 `tests/vectors.rs` 的文件头。

## 关于测试替身 `hardware-software`

它是一个**假后端**:把"封起来的熵"存在一个文件里,而不是芯片里。

它存在的唯一理由是让 v2 记录格式在没有硬件的机器上真的能被测(版本分派、AAD、拒绝降级那一整块)。**它自己承认自己不是硬件**,所以 `probe` 不会拿它当"这台机器有硬件根"的证据。

`tests/hardware.rs` 用软件替身跑,所以它验的是**形状**而不是"HS 真的出不了这台机器" —— 最后那一条只有真后端能验,文件头把这条缺口写明了。它在默认构建里只跑三条(拒绝降级那几条),开了 `hardware-software` 才是七条。

## 实体硬件按平台单独验收

all-features 会请求启用所有 feature，但平台 cfg 只编译适用的后端；它不会自动运行 ignored 的硬件测试，也不适合作为发行构建命令。

- **SE 的 ECDH 在真芯片上验过**,持久化还差一个 Apple 签发的签名身份。这一步不是代码问题,见[硬件根](/advanced/hardware-root)。
- **TPM 那条在 Linux 上编过、也跑过 `swtpm` 的端到端**(`tests/tpm.rs`)。三条都标了 `#[ignore]`,要 `-- --ignored` 才跑,原因写在那个文件头。

两边各自的缺口都记在设计说明第十节里,没有藏起来。

## Linux v2 部署与故障验收

本地 Rust 回归不能代替多 UID、安装权限、systemd 沙箱、真实整机重启及服务兼容。deploy/linux 下的 test-boundary、systemd-checks、systemd-boot-check 和 anp-service-acceptance 使用显式隔离环境验收；故障注入不在日常主机执行。

已有 systemd 主机验收已通过，实体硬件和 macOS 保护域仍未交付。测试使用临时身份，注明代码基线、特性、部署模式和未验项；历史测试数字不作为当前运行结果。
