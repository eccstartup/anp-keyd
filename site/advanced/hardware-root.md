# 硬件根

硬件根为信封解封增加 HS 材料，防止仅复制文件并知道口令就能在另一设备解封。当前 Ed25519 seed 解封后仍在软件中签名，不能描述为“身份私钥始终不离开硬件”。

```text
pass_key = Argon2id(passphrase, salt, parameters)
KEK = HKDF-SHA256(salt, pass_key || device.secret || HS, "anp-keyd/v2/kek")
```

device.secret 仍然需要。完整软件目录加口令可解封，只有受支持硬件参与且其访问控制成立时才具有相应设备依赖。

## 后端与证据范围

| 后端 | 机制 | 当前限制 |
|---|---|---|
| macOS Secure Enclave | P-256 ECDH，钥匙串 tag 定位 | 已有芯片 ECDH 记录；正式签名发行、持久化和重启恢复仍待验收 |
| Linux TPM 2.0 | TPM 创建/解封，持久句柄定位 | 已有 Linux 编译及 swtpm 端到端记录；实体访问权限及故障仍待验收 |
| hardware-software | 文件形式的测试替身 | 不提供硬件性质，release 拒绝构建 |

软件替身、模拟器和实体芯片证明的事情不同。不能将 swtpm 通过表述为实体 TPM 通过，也不能从硬件解封推出已具有启动状态/PCR 证明。

## 使用与发行

后端按平台选择 hardware-se 或 hardware-tpm feature；开发/离线建钥入口可指定 --hardware secure-enclave 或 --hardware tpm。默认 none。受保护目录内的管理操作仍须走可信管理流程，不能用本地命令旁路。

指定后端不可用必须拒绝，不能退回软件封装。v2 信封中的 hardware 和 hs_ciphertext 成对存在，后者空字符串不代表没有硬件绑定；具体格式见[设计说明](/design/)第九节及第三节。

SE 持久化和分发需要匹配签名及 entitlement。临时芯片 ECDH 成功不能证明持久化可发行；当前 macOS 也未开放受保护部署声明。TPM 设备访问与 systemd 沙箱配置需要实体环境单独验收。

## macOS 登录会话助手与未完成项

现有 SE 后端依赖用户数据保护钥匙串，系统 LaunchDaemon 不能仅增加证书来解决登录上下文。`admin se-session` 前台助手已实现并完成软件/合成 HS 桥接验证；这不代替持久 SE 验收。它只面向可信本地管理员、指定 exact hot key，不开放 Agent 解密接口；最多 900 秒，1 秒心跳、5 秒失联期限，会话失效后全局锁钥、撤权及抑制旧缓存，不自动恢复 grant。

正式签名身份/profile、持久 SE、真实注销/重新登录、休眠、整机重启、升级和实体 TPM 仍未完成。CSR 本身不授予 entitlement；免费账号能否获得所需授权尚未确认。普通 macOS 独立 UID 预览不需要付费会员、完整 Xcode 或硬件，见[本机使用](/guide/local-use)。

协议和操作限制见[SE 会话说明](https://github.com/eccstartup/anp-keyd/blob/master/deploy/macos/SE-SESSION.md)。

## 恢复代价

硬件失效或丢失后，不能靠复制绑定信封恢复 HS。应在设备可用时准备并验证独立恢复材料。助记词和便携归档不依赖原设备，但它们是可复制的完整身份材料，必须另行保护。

硬件封装、硬件内签名、备份可迁移性分别验收。详见[迁移与恢复](/advanced/recovery)和[测试与向量](/advanced/testing)。
