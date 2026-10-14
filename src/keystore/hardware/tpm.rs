//! Linux 的 TPM 2.0 后端 —— `--features hardware-tpm`。第三路熵封在芯片里。
//!
//! ```text
//! seal:  生成 32 字节 → TPM2_Create(密封数据) → TPM2_Load → TPM2_EvictControl(0x81xxxxxx)
//! open:  TPM2_TRFromTPM(持久句柄) → TPM2_Unseal → 那 32 字节
//! ```
//!
//! # 它已经在 Linux 上编译过、也跑过端到端了(2026-10-14)
//!
//! 写它的机器是 macOS,`tss-esapi-sys` 的构建脚本在非 Linux 上直接 panic ——
//! 这里连 `cargo check` 都跑不了(交叉编译也不行,缺 `x86_64-linux-gnu-gcc`
//! 和 `pkg-config`)。所以最初那一版的每一个函数名、类型名、参数顺序都是
//! **照着 vendored 的 `tss-esapi 7.7.0` 源码逐个核对出来的**。
//!
//! 现在不是了。第一台 Linux 机器上:**`cargo test --features hardware-tpm`
//! 全绿(含 `tests/tpm.rs` 那三条),`swtpm` 的端到端也走通了** ——
//! `keygen --hardware tpm` → `probe` 报 USABLE → `publish` → `serve` →
//! `unlock` → `sign` 出真的 RFC 9421 头;`swtpm` 重启之后信封照旧打得开;
//! `tpm2_evictcontrol` 把对象删掉之后解锁**响亮地失败**(`HardwareMissing`),
//! 信封一个字节没动。
//!
//! ## 而"核对过源码"确实漏掉了东西 —— 三个,都只在真信封上才露头
//!
//! 这一节留着,是因为它说明**为什么**"核对过"不等于"验过":
//!
//! 1. **带会话调 `tr_from_tpm_public` 会段错误。** `tpm2-tss 3.2.1` 的
//!    `Esys_TR_FromTPMPublic_Finish` 有一处没查空指针的解引用,而密码会话
//!    恰好就是 `NULL`。详见 [`attach`]。触发条件是"那个句柄上真的有对象",
//!    所以 `probe` 自己的自我测试碰不到,只有**真信封**才炸 —— 症状是守护
//!    进程直接 SIGSEGV(退出码 139),客户端只看到连接断了。
//! 2. **`seal_probe` 以前只做到 `EvictControl` 就返回,报告里却写着
//!    "read back"。** 于是 `TPM2_Unseal` —— [`Tpm::open`] 唯一真正依赖的
//!    那条命令 —— 从来没被任何一次体检碰过。见 [`seal_probe`]。
//! 3. **芯片上能同时装载的对象很少**(`swtpm` 那类实现尤其少),而
//!    `create_primary` 每调一次就占一格。峰值超了会报 `out of memory for
//!    object contexts`(0x902),而那句话指向"这颗 TPM 不能持久化",和真正
//!    发生的事毫无关系。见 [`Tpm::seal`] 和 [`probe`] 第 ① 步。
//!
//! 这三条都不是类型错,编译器一条也拦不住 —— 它们是**运行时**的。
//!
//! 要重跑那套验证:见 `tests/tpm.rs` 的文件头(一条命令,外加它在哪三种
//! 情况下会红)。
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

use sha2::{Digest as _, Sha256};
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

/// 开一个和 TPM 说话的上下文,**并且已经装好授权要用的那个会话**。
///
/// **这一步失败的含义是"这台机器上没有能用的 TPM"**,不是"信封不对" ——
/// 所以它是 [`KeydError::HardwareUnavailable`]。分清楚这一点,人才知道该去
/// 看 `dmesg` / 装 `swtpm`,而不是去翻信封。
///
/// # 那一句 `set_sessions` 为什么钉在这儿
///
/// 这个文件里碰的每一个对象,**授权值都是空的**:主键(owner 或 null 层级)、
/// 密封对象、`probe` 那个探针,一个都没有 authValue。空授权值对应的就是一个
/// **password 会话**。而一个新建的 `Context` 一个会话都没有 —— 缺了它,
/// `TPM2_CreatePrimary` 会以
///
/// ```text
/// Not enough sessions provided for the command
/// ```
///
/// 收场。这个报错**不看 TPM 有没有毛病**(`swtpm` 也一样报),所以它曾经让
/// `probe` 得出"设备不像个 TPM"的结论,而真正的原因是我们自己没给会话。
///
/// 放在这里而不是让每个调用方自己记着:那正是这个错的原因 —— `open()` 记了,
/// `seal()` 和 `probe()` 没记,而这个函数的目的就是"给你一个能用的上下文"。
fn context() -> Result<Context> {
    let raw = tcti_string();
    let conf = TctiNameConf::from_str(&raw).map_err(|error| {
        KeydError::HardwareUnavailable(format!(
            "{raw:?} is not a TCTI string this build understands ({error}); expected something \
             like `device:/dev/tpmrm0` or `swtpm:host=localhost,port=2321`"
        ))
    })?;
    let mut ctx = Context::new(conf).map_err(|error| {
        KeydError::HardwareUnavailable(format!(
            "could not open a TPM session over {raw:?}: {error}. On a machine with a TPM 2.0 this \
             usually means /dev/tpmrm0 is missing or not readable by this user; without one, \
             `swtpm` can emulate it and `TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321` points \
             this build at the emulator"
        ))
    })?;
    ctx.set_sessions((Some(AuthSession::Password), None, None));
    Ok(ctx)
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
    let digest = Sha256::digest(tag_hint.as_bytes());
    let low = u32::from_be_bytes([0, digest[0], digest[1], digest[2]]);
    Ok(PERSISTENT_FIRST | (low & OWNER_MASK))
}

/// 把一个持久句柄接进 ESYS 的会话表,返回一个能用的 `ObjectHandle`。
///
/// # 这一次调用**刻意不带任何会话**,而且这不是可选的美化
///
/// `tpm2-tss 3.2.1` 的 `Esys_TR_FromTPMPublic_Finish` 里有一段"带了会话就
/// 再问 TPM 一次"的逻辑(为的是防中间人,先无会话取一份元数据、再带会话
/// 取一份 HMAC 验证过的)。那段代码把第二、第三个会话都做了空指针检查,
/// **第一个没有**:
///
/// ```c
/// r = Esys_TR_FromTPMPublic_Async(esys_context, objectHandleNode->rsrc.handle,
///                                 esys_context->session_tab[0]->esys_handle,  /* ← 没查 */
///                                 esys_context->session_tab[1] ? ... : ESYS_TR_NONE,
///                                 esys_context->session_tab[2] ? ... : ESYS_TR_NONE);
/// ```
///
/// 而同一个文件里的 `init_session_tab` 对 **password 会话**做的正好是
/// `session_tab[i] = NULL`(密码会话不是真会话,没有 HMAC 可算)。两者一碰
/// 就是 `NULL->esys_handle` —— **段错误**。
///
/// 实测过,不是照着源码推的:同一颗芯片上 `tpm2_readpublic -c 0x813258BA`
/// 一切正常,这边 `ldr w2, [x2]` / `si_addr = 0x0`,进程收 SIGSEGV。
/// 触发条件是"句柄上**真的**有对象"——没有对象的路径在更早的 `ReadPublic`
/// 就报错返回了,压根走不到那一段。所以这个 bug 只在**真信封**上炸,
/// 而 `probe` 那点自我测试碰不到它(见 [`seal_probe`])。
///
/// 绕开的办法就是不给它会话:走 [`Context::execute_with_session`] 传 `None`,
/// 跑完它自己把原来的会话放回去。这**不损失任何东西** —— `TPM2_ReadPublic`
/// 是公开命令,本来就不需要授权,递一个密码会话进去什么也证明不了
/// (ESYS 自己那段注释也写着要 HMAC 会话才有意义)。
fn attach(ctx: &mut Context, persistent: PersistentTpmHandle) -> tss_esapi::Result<ObjectHandle> {
    ctx.execute_with_session(None, |ctx| {
        ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent))
    })
}

/// 那个持久句柄上是不是已经蹲着一个对象。
///
/// 用 [`attach`] 探 —— 它是**只读**的(只是把一个 TPM 句柄接进 ESYS 的会话
/// 表),探完立刻关掉;不会像"先试着 unseal 一下"那样动到任何计数器,也不会
/// 因为对象其实属于别的类型而读出什么来。
///
/// **接不进来就当作"没有"** —— 判反了是安全的:说"有"只是让 [`Tpm::seal`]
/// 保守地拒绝,"说没有但其实有"不可能发生(接一个存在的句柄不会失败)。
fn object_is_there(ctx: &mut Context, handle: u32) -> bool {
    let Ok(persistent) = PersistentTpmHandle::new(handle) else {
        return false;
    };
    let Ok(mut object) = attach(ctx, persistent) else {
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

        // 主键的用处到此为止(`create` 和 `load` 各用了一次),还回去 —— 和
        // [`seal_probe`] 里同一条理由,而且这里更要紧:芯片上的对象表很小
        // (swtpm 那类实现尤其小,而且它是"**同时**装载几个"的上限,不是累计),
        // 而 `seal` 是可以**并发**跑的(守护进程把连接处理放在阻塞池上)。
        // 每次封存少占一格,几把钥匙同时生成时的余量就多一格。实测过:
        // 封存和探针同时在跑的那一轮把 swtpm 顶到 `out of memory for object
        // contexts`(0x902),而报出来的话是"这颗 TPM 不能持久化" ——
        // 指向错误的地方。
        let _ = ctx.flush_context(primary.into());

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
        // (`attach` 为什么不带会话,见它自己的注释:带会话会段错误。)
        let object = attach(&mut ctx, persistent).map_err(|_| missing(*handle))?;

        // 密封对象的授权值是空的,而 [`context`] 给的上下文已经装好了那个
        // password 会话 —— 这里不用再设一遍。`Context` 的 `Drop` 会在最后把
        // 这个对象和会话一起收掉,所以也不需要手工 `tr_close`。
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
    // **问完立刻冲掉。** 芯片上的对象表很小(swtpm 这类实现尤其小),而后面
    // 还要建自己的主键、密封对象、再解封回来 —— 把这把主键留在表里,实测会
    // 让第 ③ 步的 `ReadPublic` 以 `out of memory for object contexts`
    // (0x902)收场,报告出来却是"这颗 TPM 不能持久化",指向完全错误的地方。
    match ctx.create_primary(Hierarchy::Null, template, None, None, None, None) {
        Err(error) => {
            return RootProbe {
                kind: KIND,
                compiled: true,
                usable: false,
                detail: format!(
                    "a TPM session opened but the device did not act like a TPM: creating a primary \
                     key in the null hierarchy failed ({error})"
                ),
                remedy: Some(
                    "This usually means the TCTI points at something that is not a working TPM 2.0 \
                     — a half-started `swtpm`, or a device node that is not the one you think it \
                     is. Check `tpm2_getcap properties-fixed` against the same TCTI."
                        .into(),
                ),
            };
        }
        Ok(null_primary) => {
            let _ = ctx.flush_context(null_primary.key_handle.into());
        }
    }

    // ② 封一个探针对象并持久化 —— 这一步才是 `seal`/`open` 真正依赖的能力。
    // 上一次崩溃留下的残留先清掉,再封。
    let _ = evict_probe(&mut ctx);

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

    // ③ 别留痕 —— 而删不掉要说出来,不能让报告看起来是干净的。
    let (usable, detail, remedy) = match evict_probe(&mut ctx) {
        Ok(()) => (true, format!("{detail}, then removed again"), None),
        Err(error) => (
            true,
            format!(
                "{detail}, but the probe could not remove its own object at \
                 {PROBE_HANDLE:#010x} again: {error}. That leftover protects nothing, but you may \
                 want to clear it by hand with `tpm2_evictcontrol -c {PROBE_HANDLE:#010x}`"
            ),
            None,
        ),
    };

    RootProbe { kind: KIND, compiled: true, usable, detail, remedy }
}

/// 在 [`PROBE_HANDLE`] 上封一个探针对象,**持久化,再解封回来核对一遍**。
///
/// # 最后那一步解封不是走形式
///
/// 这里以前只做到 `EvictControl` 就返回了,报告里却写着 "read back" ——
/// 于是 `TPM2_Unseal`(也就是 [`Tpm::open`] **唯一**真正依赖的那条命令)
/// 从来没被任何一次体检碰过。一颗芯片上能不能存密封对象、和能不能解回来,
/// 是两件事,而这套代码的整个价值就压在后者上。
///
/// 这个空白是有代价的:`open()` 在真信封上段错误过一次,而 `probe` 报的是
/// "USABLE" —— 因为它压根没走到会崩的那条路。现在它走。
fn seal_probe(ctx: &mut Context) -> Result<()> {
    // **不是全零。** 全零的"封进去、解出来"连"数据真的走了一趟"都证明不了
    // —— 一块没被写过的缓冲区也是全零。用一个可辨认的花样,核对才有内容。
    let probe_secret: [u8; HS_LEN] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));

    let primary = ctx
        .create_primary(Hierarchy::Owner, primary_template()?, None, None, None, None)
        .map_err(|error| tpm_failed("create the probe's primary key", error))?
        .key_handle;

    let sensitive = SensitiveData::try_from(&probe_secret[..])
        .map_err(|error| tpm_failed("hand the probe secret to the TPM", error))?;

    let created = ctx
        .create(primary, sealed_template()?, None, Some(sensitive), None, None)
        .map_err(|error| tpm_failed("seal the probe secret", error))?;

    let loaded = ctx
        .load(primary, created.out_private, created.out_public)
        .map_err(|error| tpm_failed("load the probe object back", error))?;

    // 主键的用处到此为止(`create` 和 `load` 各用了一次),还回去 —— 对象表
    // 是芯片上很紧的一份资源,理由和 `probe()` 第 ① 步那段注释同一条。
    //
    // 失败的那几条路上不特意还:`Context` 收尾时会把它们一起冲掉(实测过:
    // 一次干净的运行之后 `tpm2_getcap handles-transient` 是空的)。**但崩掉的
    // 进程不是** —— 它没有收尾,那些 transient 对象就一直占在芯片上,直到
    // 有人重启 TPM(实测:一次 SIGSEGV 之后表里留着好几格,重启 `swtpm` 才
    // 清掉)。而 `probe` 第 ② 步开头那一下只能抹掉**持久**的探针对象,
    // 对崩溃留下的 transient 无能为力 —— 那种时候要报的就是 0x902。
    let _ = ctx.flush_context(primary.into());

    let persistent = PersistentTpmHandle::new(PROBE_HANDLE)
        .map_err(|error| tpm_failed("address the probe handle", error))?;
    ctx.evict_control(Provision::Owner, loaded.into(), Persistent::Persistent(persistent))
        .map_err(|error| tpm_failed("persist the probe object", error))?;

    // 现在它是一颗持久对象了 —— 走一遍 `open()` 的路:接进来,解封,比字节。
    let attached = attach(ctx, persistent)
        .map_err(|error| tpm_failed("attach the probe object it just persisted", error))?;
    let unsealed = ctx
        .unseal(attached)
        .map_err(|error| tpm_failed("unseal the probe object it just persisted", error))?;
    if unsealed.value() != probe_secret {
        return Err(KeydError::HardwareUnavailable(
            "the TPM sealed the probe secret and handed back different bytes; this chip cannot be \
             trusted to hold a key envelope"
                .into(),
        ));
    }
    Ok(())
}

/// 把 [`PROBE_HANDLE`] 上的探针对象清掉。
///
/// 幂等:那儿本来就是空的也算成功。
///
/// 失败时**返回理由**而不是一个光秃秃的 `false` —— 报告里那句"删不掉、你
/// 自己看着办"要能让人判断该不该管它,而"换个会话就删掉了"和"这块芯片
/// 根本不让你删"是两件事。
fn evict_probe(ctx: &mut Context) -> Result<()> {
    if !object_is_there(ctx, PROBE_HANDLE) {
        return Ok(());
    }
    let persistent = PersistentTpmHandle::new(PROBE_HANDLE)
        .map_err(|error| tpm_failed("address the probe handle", error))?;
    let object = attach(ctx, persistent)
        .map_err(|error| tpm_failed("attach the probe object in order to remove it", error))?;
    // `Persistent::Persistent` 传进去、同名的句柄传回来,就是"把这个持久对象
    // 抹掉"的写法(TPM 规范里 evict 就是"把一个持久句柄映射到 TPM_RH_NULL")。
    ctx.evict_control(Provision::Owner, object, Persistent::Persistent(persistent))
        .map_err(|error| tpm_failed("remove the probe object", error))?;
    Ok(())
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
