//! Linux 的 TPM 2.0 后端 —— `--features hardware-tpm`。第三路熵封在芯片里。
//!
//! ```text
//! seal:  生成 32 字节 → TPM2_Create(密封数据) → TPM2_Load → TPM2_EvictControl(0x81xxxxxx)
//! open:  TPM2_TRFromTPM(持久句柄) → TPM2_Unseal → 那 32 字节
//! ```
//!
//! # ⚠️ 这个文件**从来没有被编译过**
//!
//! 写它的机器是 macOS,`tss-esapi-sys` 的构建脚本在非 Linux 上直接 panic ——
//! 这里连 `cargo check` 都跑不了(交叉编译也试过,缺 `x86_64-linux-gnu-gcc`
//! 和 `pkg-config`)。所以这个文件里的每一个函数名、类型名、参数顺序都是
//! **照着 `~/.cargo/registry/src/` 里 vendored 的 `tss-esapi 7.7.0` 源码
//! 逐个核对出来的**,而不是照着记忆写的 —— 但"核对过"和"编译过"仍然是两件事。
//!
//! 第一次在 Linux 上编译它的人请把这句当回事:**先跑
//! `cargo test --features hardware-tpm`,再跑 `swtpm` 的端到端**。
//! `TODO.md` 里记着这一条,别把它当成已经验过的。
//!
//! # TPM 和 SE 的两处结构差别(不是抄漏了)
//!
//! 1. **这 32 字节是我们生成的,芯片只负责封住它。** SE 那一侧 HS 是从 ECDH
//!    里**推导**出来的,没有"递一个随机数进去"的余地;TPM 这一侧相反:
//!    `TPM2_Create` 的 `inSensitive` 就是要密封的明文,TPM 不生成它。但封完
//!    之后那份 private blob 只有**这颗** TPM 解得开(它由这颗芯片的种子派生
//!    出来的密钥加密),所以"拷到别的机器没用"这个性质一模一样。
//! 2. **封装这一侧不需要芯片。** SE 的 `seal` 只用到 SE 公钥(签名身份只在
//!    持久化时需要);TPM 的 `seal` 必须真的连上 TPM。所以 TPM 这一根**生成
//!    钥匙就必须在本机**,而 SE 那一根不一定。
//!
//! # PCR 绑定:刻意不做
//!
//! 计划里写的是"PCR 绑定可选,默认不绑定",理由是绑了之后**内核或固件一升级
//! 就把人锁在外面** —— 而人往往是在升级之后才发现自己再也开不了信封。
//!
//! 这里把"可选"落成了**不做**,不是漏了:一份默认关闭、又从没被跑过的
//! `PolicyPCR` 授权策略,比没有更危险 —— 它看起来是个选项,实际上是一段
//! 谁都没验过的代码。要加的话,加在 [`sealed_template`] 的 `with_auth_policy`
//! 上,连同一条 `PolicySession` 的 `policy_pcr` 调用和一套端到端测试。
//!
//! # 持久句柄落在哪一段是有讲究的
//!
//! `TPM2_PERSISTENT_FIRST..=TPM2_PERSISTENT_LAST` 是 `0x81000000..=0x81FFFFFF`,
//! 但其中 `0x81800000` 往上是**平台**段(`TPM2_PLATFORM_PERSISTENT`),往那儿
//! 写要 `platformAuth`,而我们只有 owner auth。所以 [`handle_for`] 只取低 23 位,
//! 把句柄钉在 owner 段里。

use std::str::FromStr;

use sha2::{Digest as Sha2Digest, Sha256};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::{ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::key_bits::{AesKeyBits, RsaKeyBits};
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Digest as TssDigest, KeyedHashScheme, Public, PublicBuilder, PublicKeyedHashParameters,
    RsaExponent, SensitiveData, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::utils::create_restricted_decryption_rsa_public;
use tss_esapi::Context;

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};
use crate::keystore::record::HardwareRoot;

use super::{HardwareBackend, RootProbe, SealedHardware};

pub static TPM: Tpm = Tpm;

pub struct Tpm;

const KIND: &str = "Linux TPM 2.0";
const HS_LEN: usize = 32;

/// 没有 `TPM2TOOLS_TCTI` / `TCTI` / `TEST_TCTI` 时用哪个传输。
///
/// `tpmrm0` 是**内核资源管理器**那个设备(`/dev/tpm0` 是裸设备,一次只容得下
/// 一个打开者,两个进程同时用就有一个报错)。
const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// owner 持久段的起点。
const PERSISTENT_FIRST: u32 = 0x8100_0000;

/// owner 段只到 `0x817FFFFF` —— 再往上是平台段,见模块头。
const OWNER_MASK: u32 = 0x007F_FFFF;

/// `probe` 拿来自我测试的那个句柄,钉在 owner 段的最上面,好和真实信封
/// (由 [`handle_for`] 散列出来的)离得远。
const PROBE_HANDLE: u32 = PERSISTENT_FIRST | OWNER_MASK;

// ————————————————————————————————————————————————————————————————————————
// 传输 / 上下文
// ————————————————————————————————————————————————————————————————————————

/// `TPM2TOOLS_TCTI`,`TCTI`,`TEST_TCTI` 里的第一个非空值;都没有就用默认。
///
/// 自己读这三个变量而不是用 `TctiNameConf::from_environment_variable()`,
/// 是因为那个函数**分不清**"一个都没设"和"设了但写错了" —— 两种情况都返回
/// `ParamsMissing`。分不清的后果是:一个人 `export TPM2TOOLS_TCTI=swtpm:port=abc`
/// 打错一个字段,我们却悄悄退回到 `/dev/tpmrm0`,而他永远不知道自己的设置
/// 从没生效过。
fn tcti_string() -> String {
    ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| DEFAULT_TCTI.to_string())
}

/// 开一个和 TPM 说话的上下文。
///
/// **这一步失败的含义是"这台机器上没有能用的 TPM"**,不是"信封不对" ——
/// 所以它是 [`KeydError::HardwareUnavailable`]。分清楚这一点,人才知道该去
/// 看 `dmesg` / 装 `swtpm`,而不是去翻信封。
fn context() -> Result<Context> {
    let raw = tcti_string();
    let conf = TctiNameConf::from_str(&raw).map_err(|error| {
        KeydError::HardwareUnavailable(format!(
            "{raw:?} is not a TCTI string this build understands ({error}); expected something \
             like `device:/dev/tpmrm0` or `swtpm:host=localhost,port=2321`"
        ))
    })?;
    Context::new(conf).map_err(|error| {
        KeydError::HardwareUnavailable(format!(
            "could not open a TPM session over {raw:?}: {error}. On a machine with a TPM 2.0 this \
             usually means /dev/tpmrm0 is missing or not readable by this user; without one, \
             `swtpm` can emulate it and `TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321` points \
             this build at the emulator"
        ))
    })
}

fn tpm_failed(what: &str, error: tss_esapi::Error) -> KeydError {
    KeydError::HardwareUnavailable(format!("the TPM refused to {what}: {error}"))
}

// ————————————————————————————————————————————————————————————————————————
// 模板
// ————————————————————————————————————————————————————————————————————————

/// 父键:Kernel 里常见的 "restricted decryption RSA" 主键。
///
/// 它不存任何东西,只是给子对象当种子用 —— 而且它**每个进程重建一次**,
/// 不需要持久化:TSS 的主键在同一层级、同一模板下是确定性的。
fn primary_template() -> Result<Public> {
    create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::Aes { key_bits: AesKeyBits::Aes256, mode: SymmetricMode::Cfb },
        RsaKeyBits::Rsa2048,
        RsaExponent::ZERO_EXPONENT,
    )
    .map_err(|error| tpm_failed("build the primary key template", error))
}

/// 密封数据对象的模板。
///
/// `KeyedHash` + `KeyedHashScheme::Null` 就是 TPM 里"密封数据"的标准写法
/// (TPM 规范里 sealed data 就是一个 keyed-hash 对象,方案为 NULL)。
///
/// 属性逐个说:
/// - `fixed_tpm` / `fixed_parent`:这个对象不能被复制出这颗芯片、父母也不能换。
///   **这两条才是"拷到别的机器打不开"的来源**,不是可选项。
/// - `no_da`:不进字典攻击计数器。这里的授权值是空的,重复失败**不会**锁死;
///   更重要的是别让一个 bug 把整颗 TPM 锁进 lockout。
/// - `user_with_auth`:允许用 password 会话解开(我们唯一的开法)。
/// - `admin_with_policy`:空策略下的默认位,和 `tpm2-tools` 造出来的密封对象一致。
fn sealed_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_admin_with_policy(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .build()
        .map_err(|error| tpm_failed("build the sealed object's attributes", error))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(TssDigest::default())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(TssDigest::default())
        .build()
        .map_err(|error| tpm_failed("build the sealed object's template", error))
}

// ————————————————————————————————————————————————————————————————————————
// 句柄
// ————————————————————————————————————————————————————————————————————————

/// `tag_hint` → 一个 owner 段里的持久句柄。
///
/// 用散列而不是计数器:句柄要能**从信封里那一条记录单独算回来**(记录里只存
/// 了一个 `u32`,没有别的上下文),所以它必须只依赖 `tag_hint` 本身,不能依赖
/// "这台机器上已经存了第几把钥匙"。
///
/// 23 位空间。碰撞的意思是两个信封共用一个密封对象 —— 后面那把会被
/// [`Tpm::seal`] 拒绝(那里的"已经有人占了"检查就是为这个),而不是悄悄覆盖
/// 掉前面的。
fn handle_for(tag_hint: &str) -> Result<u32> {
    let safe = !tag_hint.is_empty()
        && tag_hint.len() <= 128
        && tag_hint.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !safe {
        return Err(KeydError::Protocol(format!(
            "{tag_hint:?} is not usable as a TPM sealed-object name"
        )));
    }
    let digest = Sha2Digest::digest(tag_hint.as_bytes());
    let low = u32::from_be_bytes([0, digest[0], digest[1], digest[2]]);
    Ok(PERSISTENT_FIRST | (low & OWNER_MASK))
}

/// 那个持久句柄上是不是已经蹲着一个对象。
///
/// 用 `tr_from_tpm_public` 探 —— 它是**只读**的(只是把一个 TPM 句柄接进
/// ESYS 的会话表),探完立刻关掉;不会像"先试着 unseal 一下"那样动到任何
/// 计数器,也不会因为对象其实属于别的类型而读出什么来。
fn object_is_there(ctx: &mut Context, handle: u32) -> bool {
    let Ok(persistent) = PersistentTpmHandle::new(handle) else {
        return false;
    };
    let Ok(mut object) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) else {
        return false;
    };
    let _ = ctx.tr_close(&mut object);
    true
}

/// "这台机器上没有那个密封对象"—— 换机器的人最需要看到的一句话。
///
/// 和 `se.rs` / `software.rs` 里那句同一个形状,而且同样带上 `this machine
/// does not have`:三种根坏掉的方式不同,但**要传达的事**是同一件。
fn missing(handle: u32) -> KeydError {
    KeydError::HardwareMissing(format!(
        "this envelope is sealed to a TPM object at {handle:#010x}, and this machine does not have \
         it. A TPM sealed object is encrypted under the seed of the chip that made it, so it \
         cannot be copied between machines — this envelope was most likely made on a different \
         one. The only supported way to move a key is `export-seed` on the machine that still has \
         it — do that while that machine is alive."
    ))
}

// ————————————————————————————————————————————————————————————————————————
// 后端
// ————————————————————————————————————————————————————————————————————————

impl HardwareBackend for Tpm {
    fn describe(&self) -> &'static str {
        "Linux TPM 2.0 (TPM2_Create / TPM2_Unseal)"
    }

    fn is_hardware(&self) -> bool {
        true
    }

    fn seal(&self, tag_hint: &str) -> Result<SealedHardware> {
        let handle = handle_for(tag_hint)?;
        let mut ctx = context()?;

        // 句柄被占了就拒绝,不覆盖 —— 覆盖会把上一封信封的第三路熵悄悄换掉,
        // 症状是"那把钥匙突然打不开了",而不是任何一个报错。
        if object_is_there(&mut ctx, handle) {
            return Err(KeydError::KeyExists(format!(
                "the TPM already holds a persistent object at {handle:#010x}; refusing to replace \
                 it, because replacing it would silently break the envelope that is already bound \
                 to it"
            )));
        }

        // 这 32 字节是我们生成的(见模块头第 1 条),`LockedBytes` 保证它在这台
        // 机器的内存里被锁住、用完擦掉 —— 它唯一一次以明文离开这里,是进
        // `SensitiveData` 交给 TPM 的那一刻。
        let hs = LockedBytes::generate()?;

        let primary = ctx
            .create_primary(Hierarchy::Owner, primary_template()?, None, None, None, None)
            .map_err(|error| tpm_failed("create the primary key", error))?
            .key_handle;

        let sensitive = hs
            .expose(|bytes| SensitiveData::try_from(&bytes[..]))
            .map_err(|error| tpm_failed("hand the secret to the TPM", error))?;

        let created = ctx
            .create(primary, sealed_template()?, None, Some(sensitive), None, None)
            .map_err(|error| tpm_failed("seal the secret", error))?;

        let loaded = ctx
            .load(primary, created.out_private, created.out_public)
            .map_err(|error| tpm_failed("load the sealed object back", error))?;

        // 持久化:`create` 出来的是个 transient 对象,重启就没了,而"重启之后
        // 信封还在"是普通人对一台机器的预期(见 `HardwareRoot::Tpm` 的注释)。
        //
        // 走到这里失败时**不做清理**:留下的是一个 transient 对象,`Context` 的
        // `Drop` 会冲掉它;而且信封还没落盘,`hs` 随栈一起被擦除。没有半成品
        // 留在磁盘上,也没有半成品留在这颗芯片的持久存储里。
        let persistent = PersistentTpmHandle::new(handle)
            .map_err(|error| tpm_failed("address the persistent handle", error))?;
        ctx.evict_control(Provision::Owner, loaded.into(), Persistent::Persistent(persistent))
            .map_err(|error| tpm_failed("persist the sealed object", error))?;

        Ok(SealedHardware {
            root: HardwareRoot::Tpm { handle },
            // TPM 这一侧秘密整个留在芯片里,信封上不需要带任何东西 ——
            // `hs_ciphertext` 可以是空串,记录类型里就是这么写的。
            ciphertext: Vec::new(),
            hs,
        })
    }

    fn open(&self, root: &HardwareRoot, _ciphertext: &[u8]) -> Result<LockedBytes> {
        let HardwareRoot::Tpm { handle } = root else {
            return Err(KeydError::Protocol(
                "the TPM backend was handed a record for a different kind of root".into(),
            ));
        };

        // **先把记录本身验完,再去碰设备。** 记录里的句柄是 AAD 认证过的,但
        // 仍可能是一个不属于我们的数字(`PersistentTpmHandle::new` 会查高位
        // 是不是 0x81)。一份坏记录在这台机器上是不是坏记录,**和这台机器有
        // 没有 TPM 无关** —— 把它放到 `context()` 后面,一台没有 TPM 的机器
        // 就会把"信封是坏的"报成"你没有 TPM",而这两件事要做的动作完全不同。
        let persistent = PersistentTpmHandle::new(*handle).map_err(|_| {
            KeydError::Protocol(format!(
                "{handle:#010x} is not a valid TPM persistent handle; the envelope is corrupt"
            ))
        })?;

        let mut ctx = context()?;

        // 接不进来就是"这台机器上没有那个对象" —— 换机器、或者有人手动
        // `tpm2_evictcontrol` 清掉了,都是这一种。**不是**口令问题。
        let object = ctx
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
            .map_err(|_| missing(*handle))?;

        // 密封对象的授权值是空的,所以一个 password 会话就够。`Context` 的
        // `Drop` 会在最后把这个对象和会话一起收掉,这里不需要手工 `tr_close`。
        ctx.set_sessions((Some(AuthSession::Password), None, None));

        let sealed = ctx.unseal(object).map_err(|error| {
            KeydError::HardwareMissing(format!(
                "the TPM holds an object at {handle:#010x} but refused to unseal it ({error}); the \
                 object is not the sealed secret this envelope was made with"
            ))
        })?;

        let bytes = sealed.value();
        if bytes.len() != HS_LEN {
            return Err(KeydError::Protocol(format!(
                "the TPM unsealed {} bytes, expected {HS_LEN}",
                bytes.len()
            )));
        }
        let mut buf = [0u8; HS_LEN];
        buf.copy_from_slice(bytes);
        // `LockedBytes::new` 会把 `buf` 擦掉(它只留一份锁住内存里的副本);
        // `sealed` 是 `Zeroizing` 的,离开作用域时自己擦。
        LockedBytes::new(&mut buf)
    }
}

// ————————————————————————————————————————————————————————————————————————
// probe
// ————————————————————————————————————————————————————————————————————————

/// 这根根现在能不能用,以及不能用时**该做什么**。
///
/// 四件事分开量,因为它们各自独立地坏,而且指向四个不同的动作者:
///
/// 1. **设备在不在、TSS 连不连得上**(`Context::new`):坏了多半是
///    `/dev/tpmrm0` 不存在或没权限,或者 `swtpm` 没起来。
/// 2. **TPM 真的会算吗**:在 **Null 层级**建一把主键。Null 层级不存任何东西
///    (没有 owner auth、没有持久状态),所以这一步是免费的,而且它能分辨
///    "设备节点在,但那个东西不是个 TPM"。
/// 3. **能不能持久化**:在 [`PROBE_HANDLE`] 上封一个探针对象。这一步才验证
///    `TPM2_EvictControl` 和 owner auth —— 也就是 `seal`/`open` 真正依赖的东西。
/// 4. **清干净没有**:把第 3 步那个对象 evict 掉。
///
/// # 这一次体检会往 TPM 的持久存储里写东西
///
/// 第 3 步和 SE 那边的第 2 步一样,没法"只看不碰"。所以它用一个固定的
/// [`PROBE_HANDLE`]、一份和任何信封都无关的秘密、用完即删;删不掉也照实说
/// (那一句会进报告)。这是"`probe` 不改变被体检的东西"那条规矩的**又一处
/// 有意的例外**,范围同样写死在这里。
pub fn probe() -> RootProbe {
    let mut ctx = match context() {
        Ok(ctx) => ctx,
        Err(error) => {
            return RootProbe {
                kind: KIND,
                compiled: true,
                usable: false,
                detail: format!("no TPM session: {error}"),
                remedy: Some(
                    "Install and start `swtpm` and point this build at it with \
                     `TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321`, or — on a machine that \
                     really has a TPM 2.0 — check that /dev/tpmrm0 exists and that this user can \
                     read it. Without a TPM there is no TPM hardware root; run without \
                     `--hardware tpm` and accept that a copy of the disk plus the passphrase is \
                     enough."
                        .into(),
                ),
            };
        }
    };

    // ① Null 层级的主键:免费的、不留痕的"这玩意真的是个 TPM 吗"。
    let template = match primary_template() {
        Ok(template) => template,
        Err(error) => {
            return RootProbe {
                kind: KIND,
                compiled: true,
                usable: false,
                detail: format!("could not build a primary key template: {error}"),
                remedy: None,
            };
        }
    };
    if let Err(error) = ctx.create_primary(Hierarchy::Null, template, None, None, None, None) {
        return RootProbe {
            kind: KIND,
            compiled: true,
            usable: false,
            detail: format!(
                "a TPM session opened but the device did not act like a TPM: creating a primary \
                 key in the null hierarchy failed ({error})"
            ),
            remedy: Some(
                "This usually means the TCTI points at something that is not a working TPM 2.0 — \
                 a half-started `swtpm`, or a device node that is not the one you think it is. \
                 Check `tpm2_getcap properties-fixed` against the same TCTI."
                    .into(),
            ),
        };
    }

    // ② 封一个探针对象并持久化 —— 这一步才是 `seal`/`open` 真正依赖的能力。
    // 上一次崩溃留下的残留先清掉,再封。
    evict_probe(&mut ctx);

    let detail = match seal_probe(&mut ctx) {
        Err(error) => {
            return RootProbe {
                kind: KIND,
                compiled: true,
                usable: false,
                detail: format!(
                    "the TPM works, but a sealed object cannot be persisted on it: {error}"
                ),
                remedy: Some(
                    "Persisting needs the owner hierarchy's authorisation and free non-volatile \
                     space. If this is `swtpm`, restart it with a fresh state file; on real \
                     hardware, check whether the owner hierarchy has a non-empty auth value \
                     (`tpm2_getcap properties-fixed`) — this build uses the well-known empty one."
                        .into(),
                ),
            };
        }
        Ok(()) => "a sealed object was created, persisted, and read back".to_string(),
    };

    // ③ 别留痕 —— 而且删不掉要说出来,不能让报告看起来是干净的。
    let (usable, detail, remedy) = if evict_probe(&mut ctx) {
        (true, format!("{detail}, then removed again"), None)
    } else {
        (
            true,
            format!(
                "{detail}, but the probe could not remove its own object at \
                 {PROBE_HANDLE:#010x} again — that leftover protects nothing, but you may want to \
                 clear it by hand with `tpm2_evictcontrol -c {PROBE_HANDLE:#010x}`"
            ),
            None,
        )
    };

    RootProbe { kind: KIND, compiled: true, usable, detail, remedy }
}

/// 在 [`PROBE_HANDLE`] 上封一个探针对象。成不成返回 `Result`。
fn seal_probe(ctx: &mut Context) -> Result<()> {
    let primary = ctx
        .create_primary(Hierarchy::Owner, primary_template()?, None, None, None, None)
        .map_err(|error| tpm_failed("create the probe's primary key", error))?
        .key_handle;

    let probe_secret = [0u8; HS_LEN];
    let sensitive = SensitiveData::try_from(&probe_secret[..])
        .map_err(|error| tpm_failed("hand the probe secret to the TPM", error))?;

    let created = ctx
        .create(primary, sealed_template()?, None, Some(sensitive), None, None)
        .map_err(|error| tpm_failed("seal the probe secret", error))?;

    let loaded = ctx
        .load(primary, created.out_private, created.out_public)
        .map_err(|error| tpm_failed("load the probe object back", error))?;

    let persistent = PersistentTpmHandle::new(PROBE_HANDLE)
        .map_err(|error| tpm_failed("address the probe handle", error))?;
    ctx.evict_control(Provision::Owner, loaded.into(), Persistent::Persistent(persistent))
        .map_err(|error| tpm_failed("persist the probe object", error))?;
    Ok(())
}

/// 把 [`PROBE_HANDLE`] 上的探针对象清掉。返回"现在那儿是空的吗"。
///
/// 顺手也是幂等的:那儿本来就是空的也返回 `true`。
fn evict_probe(ctx: &mut Context) -> bool {
    if !object_is_there(ctx, PROBE_HANDLE) {
        return true;
    }
    let Ok(persistent) = PersistentTpmHandle::new(PROBE_HANDLE) else {
        return false;
    };
    let Ok(object) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) else {
        return false;
    };
    // `Persistent::Persistent` 传进去、同名的句柄传回来,就是"把这个持久对象
    // 抹掉"的写法(TPM 规范里 evict 就是"把一个持久句柄映射到 TPM_RH_NULL")。
    ctx.evict_control(Provision::Owner, object, Persistent::Persistent(persistent)).is_ok()
}

// ————————————————————————————————————————————————————————————————————————

#[cfg(test)]
mod tests {
    use super::*;

    /// 句柄只依赖 `tag_hint`,而且永远落在 **owner** 段里。
    ///
    /// 这一条在 macOS 上也跑不了(整个模块被 cfg 掉了),但它在 Linux 的 CI 上
    /// 是**纯函数**测试,不需要真芯片 —— 而这恰好是这段代码里最容易写错、
    /// 后果又最隐蔽的一处:一个落进平台段的句柄,写的时候需要 platformAuth,
    /// 症状是"别人机器上能存,我这台上存不了"。
    #[test]
    fn handles_land_in_the_owner_persistent_range() {
        let longest = "z".repeat(128);
        for name in ["e1_abc", "e1_xyz-1", "A", longest.as_str()] {
            let handle = handle_for(name).unwrap();
            assert!(
                (PERSISTENT_FIRST..=PERSISTENT_FIRST | OWNER_MASK).contains(&handle),
                "{name} produced {handle:#010x}, outside the owner persistent range"
            );
            // 而且它是一个**合法**句柄 —— `PersistentTpmHandle::new` 自己会再
            // 查一遍高位和范围。
            assert!(PersistentTpmHandle::new(handle).is_ok(), "{handle:#010x}");
        }
    }

    /// 同一个名字永远给同一个句柄 —— 记录里只有一个 `u32`,算不回来的话
    /// 信封就永远开不了了。
    #[test]
    fn the_same_name_always_gives_the_same_handle() {
        assert_eq!(handle_for("e1_abc").unwrap(), handle_for("e1_abc").unwrap());
    }

    /// 拿不到命令行上那种"一个 `../` 塞进来"的名字,和 `software.rs` 同一个把关。
    #[test]
    fn a_name_that_is_not_a_thumbprint_is_refused() {
        let too_long = "z".repeat(129);
        for bad in ["", "../escape", "has/slash", "has space", too_long.as_str()] {
            let error = handle_for(bad).expect_err("this name must not be usable");
            assert!(matches!(error, KeydError::Protocol(_)), "{bad:?} → {error:?}");
        }
    }

    /// 记录里的句柄先过 `PersistentTpmHandle::new`,不合法的是**坏记录**,
    /// 不是"这台机器上没有"。
    ///
    /// 两条错误消息指向两个完全不同的动作(去改信封 vs 去另一台机器导出),
    /// 混在一起人就不知道该干嘛。
    #[test]
    fn a_corrupt_handle_is_a_protocol_error_not_a_missing_root() {
        // 0 的高位不是 0x81,`PersistentTpmHandle::new` 会拒绝它。
        assert!(PersistentTpmHandle::new(0).is_err());
        let error = TPM
            .open(&HardwareRoot::Tpm { handle: 0 }, &[])
            .expect_err("a handle of 0 is not a persistent handle");
        assert!(matches!(error, KeydError::Protocol(_)), "{error:?}");
    }

    /// 递给 TPM 后端的记录必须是 TPM 的 —— 不是的话要**报错**,不是硬着头皮
    /// 去解。这条不需要芯片就能测:类型不匹配在连 TPM 之前就返回了。
    #[test]
    fn another_kinds_of_record_is_refused_before_any_tpm_call() {
        let error = TPM
            .open(&HardwareRoot::Software { tag: "/tmp/nope".into() }, &[])
            .expect_err("the TPM backend must not accept a software root");
        assert!(matches!(error, KeydError::Protocol(_)), "{error:?}");
    }
}
