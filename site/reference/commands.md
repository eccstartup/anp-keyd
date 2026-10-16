# 命令行

先选择部署模式，再选择命令。Linux v2 的管理和数据请求分别使用独立 socket；同 UID 开发命令不具有这个权限边界。完整参数以当前二进制 --help 为准。

## Linux v2

| 命令 | 执行者及用途 |
|---|---|
| build-info | 查询构建能力，不表示任意宿主已安全 |
| serve-protected --config FILE | 专用服务 UID 运行，由安装器生成的 systemd unit 启动 |
| data --config FILE --file REQUEST.json | Agent 发起单条 v2 数据请求 |
| admin --config FILE status / catalog / list-principals | 管理员查看服务、钥匙/策略及主体 |
| admin --config FILE prepare --file CHANGE.json | 管理员准备精确变更，返回摘要和影响 |
| admin --config FILE commit --operation-id UUID --digest HASH | 提交同一次有效批准 |
| admin --config FILE unlock --vault-id UUID --did DID --kid KID | 管理员认证 daemon 后读取口令并解锁 |
| admin --config FILE lock-all | 管理员移除驻留密钥 |
| admin --config FILE complete-secret-operation --operation-id UUID --digest HASH | 管理员完成注册 proof 或预配置热密钥轮换 |
| probe --security --config FILE | 检查调用者所属端点、信任配置及支持声明 |

数据请求包含 GET_CAPABILITIES、LIST_AUTHORIZED_KEYS、GET_GRANT_STATUS、GET_DOCUMENT、SIGN_HTTP、GET_REQUEST_STATUS。不存在 Agent 解锁、任意字节签名或根签名操作。

具体管理 JSON、body 格式和 request_id 恢复流程见[Agent 接入](/advanced/agent)及仓库 [ADAPTER](https://github.com/eccstartup/anp-keyd/blob/master/docs/ADAPTER.md)。

## 开发与离线维护命令

| 命令组 | 范围 |
|---|---|
| serve / stop | 旧开发 daemon；不是 v2 systemd 服务管理 |
| sign / list / status / document / unlock / lock | 旧 socket 客户端，同 UID 不承诺隔离，v1 unlock 发送口令 |
| spec / keygen / publish / verify-doc | 本地身份与公开文档处理 |
| add-recovery-key / rotate-hot-key / remove-key / migrate / deactivate | 本地生命周期；托管目录拒绝这类直接写入旁路 |
| import-mnemonic / import-archive | 恢复身份并重新封装，默认构建可用 |
| probe | 本地开发环境体检；与 probe --security 区分 |

控制终端不是人类认证；程序可以创建 PTY。生命周期权限依赖 OS 和受信管理边界，不能因命令“给人用”就推断 Agent 调不到。

## 可选构建

| feature | 增加能力及限制 |
|---|---|
| mcp | MCP 前端；保护模式必须显式传 --config |
| seed-export | export-seed；默认没有，启用后不声明受保护支持 |
| hardware-se | macOS Secure Enclave 解封后端；发行和持久化仍待专项验收 |
| hardware-tpm | Linux TPM 后端；实体权限和故障仍待专项验收 |
| hardware-software | 测试替身；release 拒绝，不提供硬件保护 |
