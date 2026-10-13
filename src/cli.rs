//! 命令行。
//!
//! ## 两组命令,两种信任关系
//!
//! **走 socket 的**:`sign` / `list` / `status` / `unlock` / `lock`。这些是
//! **给 agent 用的** —— 它们连上守护进程,拿签名,从始至终不碰私钥字节,
//! 也不需要口令(除了 `unlock`,那是人做的)。
//!
//! **不走 socket 的**:`serve` 之外的其余命令。`keygen` / `publish` /
//! `verify-doc` 是身份的生命周期操作,由人发起、在终端上做、当场打开信封
//! (或当场验签)。它们留在人类自己的进程里,agent 够不着。
//!
//! 为什么不把生命周期操作也做成 socket 消息:`publish` 要签的正是**一份
//! 文档**,如果把它做成消息类型,调用方就能让守护进程签任意一份文档 ——
//! 那等于把防盲签那套设计从后门拆掉。这个取舍和"导出不做成消息类型"是
//! 同一条道理。

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::client::Client;
use crate::crypto::kdf::Argon2Config;
use crate::daemon::peer::{BinaryIdentity, PeerPolicy};
use crate::daemon::state::{autolock_from_secs, thumbprint_of, DaemonState, Roots};
use crate::daemon::wire::{KeySummary, SignRequest};
use crate::daemon::{self, server, ServerConfig};
use crate::did::document::{self, DidDocumentSpec};
use crate::did::lifecycle;
use crate::did::did_url_path;
use crate::error::{KeydError, Result};
use crate::keystore::layout::KeydLayout;
use crate::keystore::{device, store};
use crate::tty;

/// 空闲多久自动上锁的默认值。15 分钟:够一次交互式调试,又短到不至于让
/// "昨晚开着的终端"今早还挂着一把解锁的钥匙。
const DEFAULT_IDLE_SECS: u64 = 900;

#[derive(Parser, Debug)]
#[command(
    name = "anp-keyd",
    version,
    about = "持有 did:wba Ed25519 私钥、替 agent 签 RFC 9421 消息签名的本地守护进程",
    long_about = "agent 手里从来没有私钥字节:私钥只住在守护进程的内存里,agent 通过 Unix \
                  socket 请求签名,而签名基由守护进程自己重建。"
)]
pub struct Cli {
    /// 覆盖密钥目录(默认 `~/.anp-keyd`)。
    #[arg(long, global = true, value_name = "DIR")]
    pub root: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// 常驻:在 Unix socket 上服务签名请求。
    Serve(ServeArgs),
    /// 生成一把新的 did:wba 密钥,把信封写进 `keys/`。
    Keygen(KeygenArgs),
    /// 给文档盖上自签 proof,写出 did.json。
    Publish(PublishArgs),
    /// 校验一份文档确实是它自称的那个 DID 的文档。
    VerifyDoc(VerifyDocArgs),
    /// 列出这台机器上的钥匙。
    List,
    /// 列出当前已解锁的钥匙,以及各自解锁了多久。
    Status,
    /// 解锁一把钥匙。
    Unlock(UnlockArgs),
    /// 上锁。
    Lock(LockArgs),
    /// 签一条 RFC 9421 请求,把签名头打到 stdout。
    Sign(SignArgs),
    /// 给一个 DID 加一把恢复密钥(预授权签一次迁移)。
    AddRecoveryKey(AddRecoveryKeyArgs),
    /// 轮换日常签名用的热密钥。
    RotateHotKey(RotateHotKeyArgs),
    /// 从文档里摘掉一把非绑定密钥。
    RemoveKey(RemoveKeyArgs),
    /// 迁移到一个新 DID:旧文档标记为已注销并指向它。
    Migrate(MigrateArgs),
    /// 永久注销一个 DID,可以顺手指向一个后继。
    Deactivate(DeactivateArgs),
    /// 从 24 个词恢复一把绑定密钥,并把它重新封进这台机器的信封。
    ImportMnemonic(ImportMnemonicArgs),
    /// 从一个加密归档恢复。
    ImportArchive(ImportArchiveArgs),
    /// 把一把钥匙的种子导出来 —— **只有带 `seed-export` 特性构建的二进制里
    /// 有这条命令**。
    ///
    /// 默认构建里它不存在,不是"被拒绝",是**没有这段代码**:没有分支、
    /// 没有环境变量、没有可翻的开关。理由见模块头 —— 简言之,一个能一键
    /// 把整把身份抽干的接口,是 agent 被注入之后最想找的那个东西。
    ///
    /// 这条命令**没有** `--password`:口令只从终端读。argv 会被 `ps` 看到,
    /// 环境变量会被同 uid 的进程在 `/proc/<pid>/environ` 里读到。
    #[cfg(feature = "seed-export")]
    ExportSeed(ExportSeedArgs),
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// socket 路径(默认按目录布局推导)。
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// 多用户系统服务:每个 uid 一个命名空间,根在 `/var/lib/anp-keyd/users/<uid>`。
    #[arg(long)]
    pub system: bool,

    /// 空闲多少秒后自动上锁。`0` 是**立刻**上锁,不是"永不"。
    #[arg(long, default_value_t = DEFAULT_IDLE_SECS, value_name = "SECS")]
    pub idle: u64,

    /// 打开原始字节签名那条路。默认关着 —— 打开之前请先读文档。
    #[arg(long)]
    pub allow_raw_signing: bool,

    /// 除本进程的 uid 之外,还允许哪些 uid 连上来(可重复)。
    #[arg(long = "allow-uid", value_name = "UID")]
    pub allow_uids: Vec<u32>,

    /// 允许的可执行文件身份,`cdhash:<hex>` 或 `sha256:<hex>`(可重复)。
    ///
    /// 不给就是**不启用第三层**。多用户部署里这一条不能省:同一个 uid 下
    /// 还可能有别的 agent,而它们正是"防同 uid"要防的对象。
    #[arg(long = "allow-binary", value_name = "PIN")]
    pub allow_binaries: Vec<String>,
}

impl ServeArgs {
    fn policy(&self) -> Result<PeerPolicy> {
        let mut allowed_binaries = Vec::new();
        for pin in &self.allow_binaries {
            allowed_binaries.push(BinaryIdentity::parse(pin)?);
        }
        Ok(PeerPolicy { allowed_uids: self.allow_uids.clone(), allowed_binaries })
    }
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// 你控制的域名。IP 字面量会被拒 —— did:wba 要求 FQDN。
    #[arg(long, value_name = "HOST")]
    pub host: String,

    /// 非默认端口。
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    /// `e1_` 段之前的路径,用 `/` 分隔(如 `agents/mybot`)。
    ///
    /// 没有默认值,因为 did:wba **要求**至少有一段:光秃秃的
    /// `did:wba:example.com:e1_...` 不是合法的 did:wba DID。与其给一个
    /// 会失败的默认值,不如让 clap 在解析参数时就把这条规则说出来。
    #[arg(long, value_name = "A/B")]
    pub path: String,

    /// 验证方法的 fragment。
    #[arg(long, default_value = document::ROOT_FRAGMENT, value_name = "NAME")]
    pub fragment: String,

    /// 人读的标签。它进 AAD,所以改它要重封,不是改个注释。
    #[arg(long, default_value = "default", value_name = "LABEL")]
    pub label: String,
}

#[derive(Args, Debug)]
pub struct PublishArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 写到哪里。不给就写进本地 `dids/`。
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct VerifyDocArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 要验的文档。不给就验本地那一份。
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct UnlockArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 只解这一把,写 fragment(`key-2`、`recovery-1`……)。
    ///
    /// 不给就是 `--did` 名下默认那把,也就是**绑定密钥** —— 一个 DID 上
    /// 后来挂的热密钥不会让老调用方不知不觉换了把钥匙签名。
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: Option<String>,

    /// socket 路径(默认按目录布局推导)。
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct LockArgs {
    /// 只锁这一个 DID 名下的。不给就全锁。
    #[arg(long, value_name = "DID")]
    pub did: Option<String>,

    /// 再加 `--did` 就精确到一把。单独给没意义(clap 会拦住)。
    #[arg(long, value_name = "FRAGMENT", requires = "did")]
    pub kid: Option<String>,

    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 用哪把钥匙签,写 fragment(`key-2`、`recovery-1`……)。
    ///
    /// 不给就是 `--did` 名下默认那把(绑定密钥)。
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: Option<String>,

    #[arg(long, default_value = "GET")]
    pub method: String,

    /// 完整的请求 URI —— RFC 9421 的 `@target-uri` 就是它。
    ///
    /// 只有 `--raw` 那条路不需要它,所以它只在 `--raw` 不出现时才是必填。
    #[arg(long, value_name = "URL", required_unless_present = "raw")]
    pub url: Option<String>,

    /// 请求里已有的头,`名字: 值`(可重复)。名字会转成小写。
    #[arg(long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,

    /// 请求体所在的文件。给了它,`content-digest` 一定进覆盖面,而且由
    /// 守护进程自己算 —— 请求里带的同名头会被忽略。
    #[arg(long, value_name = "PATH")]
    pub body: Option<PathBuf>,

    /// 额外要求覆盖的分量(可重复)。**只能加,不能减。**
    #[arg(long = "cover", value_name = "NAME")]
    pub cover: Vec<String>,

    /// 原始字节签名:直接签这个文件的内容,输出 base64。需要守护进程开着
    /// `--allow-raw-signing`,而且每一次都会留审计。
    ///
    /// 它和结构化那一套参数**互相排除**。不是洁癖:如果 `--raw` 能和
    /// `--body`/`--cover` 一起给,调用方就会以为那些东西也进了覆盖面,而
    /// 实际上原始签名的输入只有那个文件 —— 这正是"悄悄降级"的形状。
    /// 要么给一套,要么给另一套,让 clap 把话说清楚。
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["url", "headers", "body", "cover"]
    )]
    pub raw: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct AddRecoveryKeyArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 人读的标签。它进 AAD,所以改它要重封,不是改个注释。
    #[arg(long, default_value = "recovery", value_name = "LABEL")]
    pub label: String,
}

#[derive(Args, Debug)]
pub struct RotateHotKeyArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    #[arg(long, default_value = "hot", value_name = "LABEL")]
    pub label: String,

    /// 把旧的那把留在文档里。默认不留 —— 轮换的意思是"不再用它"。
    #[arg(long)]
    pub keep_old: bool,
}

#[derive(Args, Debug)]
pub struct RemoveKeyArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 要摘掉的那个 fragment(`key-2`、`recovery-1`……),不是完整的
    /// `did#key-2`。绑定密钥摘不掉 —— 它的指纹就是 DID,摘了文档就不再
    /// 绑定它自己了。
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: String,
}

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// 旧的 DID。它的文档会被改写,不会被删除。
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 新的 DID。
    #[arg(long, value_name = "DID")]
    pub to: String,

    /// 允许后继的 stable subject path 和旧的不一样(也就是换域名)。
    ///
    /// 默认拒,因为默认放行等于让一次打错字的 `--to` 变成一次无人察觉的
    /// 冒名:验证方认"同一个 stable subject path"是同一个主体,path 一变,
    /// 这条边就只能靠域名自己作证了。
    #[arg(long)]
    pub allow_different_subject: bool,
}

#[derive(Args, Debug)]
pub struct DeactivateArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 注销并指向这个后继。不给就是彻底到头。
    ///
    /// 这条路**不做**环检测,也不查 stable subject path —— 要那两样就用
    /// `migrate`。
    #[arg(long, value_name = "DID")]
    pub to: Option<String>,
}

#[derive(Args, Debug)]
pub struct ImportMnemonicArgs {
    /// 这个 DID。
    ///
    /// 词里推不出它:路径段是人选的,公钥只决定最后那一段 `e1_`。所以必须
    /// 由人给出,而给错会**当场**被指纹对上 —— 不匹配就是拒,不是"打不开"。
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 新信封的标签。
    #[arg(long, default_value = "imported", value_name = "LABEL")]
    pub label: String,

    /// 本地已经有同一把钥匙时也照做。
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ImportArchiveArgs {
    /// 归档文件。
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// 新信封的标签。
    #[arg(long, default_value = "imported", value_name = "LABEL")]
    pub label: String,

    /// 本地已经有同一把钥匙时也照做。
    #[arg(long)]
    pub force: bool,

    // 这里**没有** `--password`,而且是刻意的:归档的密码只从终端读。
    // 一个从 argv 传进来的密码会出现在 `ps` 的输出里,也会出现在 shell
    // 的历史里 —— 而它保护的是整把私钥。
}

#[cfg(feature = "seed-export")]
#[derive(Args, Debug)]
pub struct ExportSeedArgs {
    #[arg(long, value_name = "DID")]
    pub did: String,

    /// 导出哪一把。不给就是绑定密钥。
    #[arg(long, value_name = "FRAGMENT")]
    pub kid: Option<String>,

    /// 归档写到哪个目录。
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,

    /// 输出文件已存在时也照写。
    #[arg(long)]
    pub force: bool,

    /// 只要 24 个词,不写归档。
    #[arg(long, conflicts_with = "archive_only")]
    pub words_only: bool,

    /// 只要归档,不打那 24 个词。
    #[arg(long)]
    pub archive_only: bool,

    // 这里**没有** `--password`:口令只从终端读。argv 会被 `ps` 看到,
    // 环境变量会被同 uid 的进程读 `/proc/<pid>/environ`。少一个参数就是
    // 少一条泄露路径,而这个参数一旦存在,迟早会有人把它用起来。
}

/// 跑一条命令。
///
/// 先把 `Cli` 拆开:命令本身要被移出来交给各自的函数,而 `--root` 又要
/// 在后面继续用。拆开之后两者都是普通的局部变量,没有"部分移动"这回事。
pub fn run(cli: Cli) -> Result<()> {
    let Cli { root, command } = cli;
    let root = root.as_deref();
    match command {
        Command::Serve(args) => serve(root, args),
        Command::Keygen(args) => keygen(root, args),
        Command::Publish(args) => publish(root, args),
        Command::VerifyDoc(args) => verify_doc(root, args),
        Command::List => list(root),
        Command::Status => status(root),
        Command::Unlock(args) => unlock(root, args),
        Command::Lock(args) => lock(root, args),
        Command::Sign(args) => sign(root, args),
        Command::AddRecoveryKey(args) => crate::ops::keys::add_recovery_key(
            root,
            crate::ops::keys::AddRecoveryKey { did: args.did, label: args.label },
        ),
        Command::RotateHotKey(args) => crate::ops::keys::rotate_hot_key(
            root,
            crate::ops::keys::RotateHotKey {
                did: args.did,
                label: args.label,
                keep_old: args.keep_old,
            },
        ),
        Command::RemoveKey(args) => crate::ops::keys::remove_key(
            root,
            crate::ops::keys::RemoveKey { did: args.did, kid: args.kid },
        ),
        Command::Migrate(args) => crate::ops::identity::migrate(
            root,
            crate::ops::identity::Migrate {
                did: args.did,
                to: args.to,
                allow_different_subject: args.allow_different_subject,
            },
        ),
        Command::Deactivate(args) => crate::ops::identity::deactivate(
            root,
            crate::ops::identity::Deactivate { did: args.did, to: args.to },
        ),
        Command::ImportMnemonic(args) => crate::ops::import::import_mnemonic(
            root,
            crate::ops::import::ImportMnemonic {
                did: args.did,
                label: args.label,
                force: args.force,
            },
        ),
        Command::ImportArchive(args) => crate::ops::import::import_archive(
            root,
            crate::ops::import::ImportArchive {
                file: args.file,
                label: args.label,
                force: args.force,
            },
        ),
        #[cfg(feature = "seed-export")]
        Command::ExportSeed(args) => crate::ops::export::export_seed(
            root,
            crate::ops::export::ExportSeed {
                did: args.did,
                kid: args.kid,
                out: args.out,
                force: args.force,
                form: match (args.words_only, args.archive_only) {
                    (true, _) => crate::ops::export::Form::Words,
                    (_, true) => crate::ops::export::Form::Archive,
                    _ => crate::ops::export::Form::Both,
                },
            },
        ),
    }
}

// ————————————————————————————————————————————————————————————————————————
// 目录与连接
// ————————————————————————————————————————————————————————————————————————

fn layout(root: Option<&Path>) -> Result<KeydLayout> {
    match root {
        Some(root) => Ok(KeydLayout::at(root.to_path_buf())),
        None => KeydLayout::user_default(),
    }
}

fn connect(root: Option<&Path>, socket: Option<&Path>) -> Result<Client> {
    let path = match socket {
        Some(socket) => socket.to_path_buf(),
        None => layout(root)?.sock_path(),
    };
    Client::connect(&path)
}

// ————————————————————————————————————————————————————————————————————————
// serve
// ————————————————————————————————————————————————————————————————————————

fn serve(root: Option<&Path>, args: ServeArgs) -> Result<()> {
    let policy = args.policy()?;

    // 上次导出过就在启动时说一句。
    //
    // "家用路由器显示上次登录"那种东西,而这个比它重要:导出是把整把身份
    // 抽出来,抽出来之后**没有任何办法撤销**。守护进程是那个会被 agent
    // 够到的东西,所以它每一次被拉起来的时候都该把这件事说清楚 —— 哪怕
    // 大多数时候它只是进了服务管理器的日志,而人不会去看。
    //
    // 真正会被人看到的那一次在 `ops::Session::open` 里:导出这件事最后一定
    // 是被某个坐在终端前的人做掉的,而那里正是那个人眼前。
    if let Some(line) = crate::audit::log::export_tripwire(&layout(root)?.audit_dir()) {
        eprintln!("{line}");
    }

    if policy.allowed_binaries.is_empty() {
        // 这一条不能悄悄放过。只配了 uid 的"多用户"是**假的多用户**:
        // 同一个 uid 下的另一个 agent 照样连得上,而那正是要防的对象。
        eprintln!(
            "warning: no --allow-binary pin given, so any process running as uid {} can connect \
             and ask for signatures; the executable-identity layer is off",
            daemon::self_uid()
        );
    }

    let roots = if args.system { Roots::PerUid } else { Roots::Single(layout(root)?) };

    let sock_path = match (args.socket, args.system) {
        (Some(path), _) => path,
        // 系统服务的 socket 不属于任何单个 uid,所以它不能放在某个人的
        // 家目录里 —— 那个人一退出登录目录就没了,而服务还在跑。
        (None, true) => PathBuf::from("/var/run/anp-keyd.sock"),
        (None, false) => layout(root)?.sock_path(),
    };

    let state = std::sync::Arc::new(DaemonState::new(
        roots,
        policy,
        autolock_from_secs(args.idle),
        args.allow_raw_signing,
    ));
    let config = ServerConfig { sock_path, policy: state.policy().clone() };

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(async move {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(async move {
            wait_for_a_stop_signal().await;
            let _ = stop_tx.send(true);
        });

        server::serve(state, config, stop_rx).await
    })
}

/// 等 SIGINT 或 SIGTERM。
///
/// 两者都要:交互时人按的是 Ctrl-C,而 init 系统停服务时发的是 SIGTERM。
/// 只处理一个的话,另一种情况会**直接把进程打死** —— 内存里的钥匙来不及
/// 放掉,socket 文件也留在磁盘上,下一次启动还得先清那具尸体。
async fn wait_for_a_stop_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(stream) => stream,
        Err(error) => {
            tracing::error!("cannot listen for SIGINT: {error}");
            return;
        }
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(error) => {
            tracing::error!("cannot listen for SIGTERM: {error}");
            return;
        }
    };

    tokio::select! {
        _ = interrupt.recv() => tracing::info!("stopping: SIGINT"),
        _ = terminate.recv() => tracing::info!("stopping: SIGTERM"),
    }
}

// ————————————————————————————————————————————————————————————————————————
// keygen
// ————————————————————————————————————————————————————————————————————————

fn keygen(root: Option<&Path>, args: KeygenArgs) -> Result<()> {
    let layout = layout(root)?;
    let spec = spec_of(&args)?;

    let tty = tty::open()?;
    let passphrase =
        tty::read_secret_twice(&tty, "New passphrase for this key: ", "Repeat it: ")?;

    let created = crate::keystore::create::create(
        &layout,
        &spec,
        &args.label,
        passphrase.as_bytes(),
        Argon2Config::default(),
    )?;

    // 只打印 DID,不打印文档。文档还没签名,落盘只会让人以为它已经发布了;
    // 签名是 `publish` 的事,因为它需要私钥在场 —— 而这里已经没有私钥了。
    println!("{}", created.did);
    println!();
    println!("envelope written to {}", layout.key_path(&created.wrapped.id.thumbprint)?.display());
    println!();
    println!("publish it with:");
    println!("    anp-keyd publish --did {}", created.did);
    println!();
    println!("it must then be served at:");
    println!("    {}", did_url_path(&created.did)?);
    Ok(())
}

/// 把命令行参数变成一份文档规格,**在问口令之前**。
///
/// 这里检查的三条(主机非空、不是 IP 字面量、至少有一段路径)是 did:wba
/// 自己的规则,上游会再查一遍。提前查一遍的理由只有一个:人已经坐下来、
/// 敲完两遍口令之后才被告知"你这个域名不行",而这条错误本来在他敲第一个
/// 字符之前就成立。这里只是把同一句话挪到更早说。
fn spec_of(args: &KeygenArgs) -> Result<DidDocumentSpec> {
    let host = args.host.trim();
    if host.is_empty() {
        return Err(KeydError::Did(format!(
            "--host {} names no domain",
            args.host
        )));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(KeydError::Did(format!(
            "did:wba 按**托管这个 DID 文档的域名**来命名一把钥匙,所以 {host:?} 不能是 IP \
             字面量 —— 要给的是那个会被别人去请求 did.json 的域名"
        )));
    }
    if args.path.trim_matches('/').is_empty() {
        return Err(KeydError::Did(format!(
            "the path {} is empty, and did:wba requires at least one segment before the e1_ \
             one — a DID with no path segment ({host}:e1_...) is not a valid did:wba DID",
            args.path
        )));
    }

    let mut spec = DidDocumentSpec::new(host.to_string(), path_segments(&args.path)?)
        .with_fragment(args.fragment.clone());
    if let Some(port) = args.port {
        spec = spec.with_port(port);
    }
    Ok(spec)
}

/// `agents/mybot` → `["agents", "mybot"]`,两头的 `/` 容忍。
///
/// 空段直接拒:`a//b` 会被上游拼成一条带空段的路径,而那个 DID 解析出来
/// 的 URL 和它看起来的样子不一样。与其发布一个自己都念不准的 DID,现在说。
fn path_segments(path: &str) -> Result<Vec<String>> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Err(KeydError::Did(format!(
            "the path {path:?} has no segments; did:wba needs at least one (see --path)"
        )));
    }
    let segments: Vec<String> = trimmed.split('/').map(str::to_string).collect();
    if let Some(empty) = segments.iter().position(String::is_empty) {
        return Err(KeydError::Did(format!(
            "the path {path:?} has an empty segment at position {empty}"
        )));
    }
    Ok(segments)
}

// ————————————————————————————————————————————————————————————————————————
// publish / verify-doc
// ————————————————————————————————————————————————————————————————————————

fn publish(root: Option<&Path>, args: PublishArgs) -> Result<()> {
    let layout = layout(root)?;
    let thumbprint = thumbprint_of(&args.did)?;
    let wrapped = store::load(&layout, &thumbprint)?;

    let tty = tty::open()?;
    let passphrase = tty::read_secret(&tty, &format!("Passphrase for {}: ", args.did))?;
    let device_secret = device::load(&layout)?;
    let key = crate::keystore::unwrap::unlock(&wrapped, passphrase.as_bytes(), &device_secret)?;

    // 文档从 DID + **刚解出来的公钥**重建,不是从磁盘读回来的那一份。
    // 重建出来的一定是规范形式,而磁盘上那一份可能是上一次留下的、或者
    // 被人改过的;要签的是"这个 DID 应有的文档",不是"别人给我们的文档"。
    //
    // 但"应有的文档"里**包含**已经挂在这台机器上的热密钥和恢复密钥 ——
    // 光按 DID 重建会得到一份只有根密钥的文档,而它盖上去之后,那两把钥匙
    // 就从文档里消失了。覆盖写不会报错,只会静静地少掉东西,所以这里必须
    // 先把附加密钥捞回来一起重建(见 `rebuild_with` 的注释)。
    //
    // 本地那份文档不存在时没有可捞的东西:要么这个 DID 从没发布过,要么
    // 它是别的机器上的。两种情况都按"只有根密钥"重建。
    let unsigned = match store::read_did_document(&layout, &args.did) {
        Ok(existing) => {
            let extras = lifecycle::extra_keys(&existing, &args.did)?;
            if !extras.is_empty() {
                println!("keeping {} extra key(s) from the local document", extras.len());
            }
            lifecycle::rekey(&existing, &args.did, &key.verifying_key(), extras)?
        }
        Err(KeydError::KeyNotFound(_)) => document::rebuild(&args.did, &key.verifying_key())?,
        Err(error) => return Err(error),
    };
    let signed = document::sign_document(&unsigned, &key, &wrapped.id.kid)?;

    // 走出去之前先自己验一遍。一份签得出来却绑不上路径的文档,发布出去
    // 只会让**别人**发现我们在骗自己。
    document::verify_path_binding(&args.did, &signed)?;

    let bytes = serde_json::to_vec_pretty(&signed)?;
    let path = match &args.out {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let path = dir.join("did.json");
            std::fs::write(&path, &bytes)?;
            path
        }
        None => {
            store::write_did_document(&layout, &args.did, &signed)?;
            layout.did_path(&args.did)
        }
    };

    let url = did_url_path(&args.did)?;
    println!("wrote {}", path.display());
    println!();
    println!("it must be served at:");
    println!("    {url}");
    println!();
    println!("note: this tool cannot host anything — whoever controls {} has to put", host_of(&url));
    println!("      that file there.");
    Ok(())
}

fn verify_doc(root: Option<&Path>, args: VerifyDocArgs) -> Result<()> {
    let bytes = match &args.file {
        Some(path) => std::fs::read(path)?,
        None => {
            let layout = layout(root)?;
            std::fs::read(layout.did_path(&args.did)).map_err(|error| {
                KeydError::Protocol(format!(
                    "no local document for {} ({error}); pass --file to verify one you downloaded",
                    args.did
                ))
            })?
        }
    };

    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| KeydError::Protocol(format!("the document is not JSON: {error}")))?;

    document::verify_path_binding(&args.did, &document)?;

    println!("{} is valid", args.did);
    println!("    proof:        verified");
    println!("    path binding: the root key's thumbprint matches the e1_ segment of the DID");

    if args.file.is_none() {
        // 本地这一份验过,不代表线上那一份还在。托管方随时能把它换成 404
        // 或一份 deactivated —— 那不在本工具的边界里,但人得被告知去查。
        println!();
        println!("this is the LOCAL copy; check the live one with:");
        println!(
            "    curl -sS {} | anp-keyd verify-doc --did {} --file /dev/stdin",
            did_url_path(&args.did)?,
            args.did
        );
    }
    Ok(())
}

/// 从解析出来的 URL 里取主机(含端口)—— 只为了把"谁该去放这个文件"说清楚。
fn host_of(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    after_scheme.split('/').next().unwrap_or(after_scheme).to_string()
}

// ————————————————————————————————————————————————————————————————————————
// list / status / unlock / lock / sign
// ————————————————————————————————————————————————————————————————————————

fn list(root: Option<&Path>) -> Result<()> {
    let mut client = connect(root, None)?;
    let keys = client.list_keys()?;

    if keys.is_empty() {
        println!("no keys on this machine");
        return Ok(());
    }
    for KeySummary { did, kid, algorithm } in keys {
        println!("{did}\t{}\t{kid}", algorithm_label(algorithm));
    }
    Ok(())
}

fn algorithm_label(algorithm: crate::keystore::KeyAlgorithm) -> &'static str {
    match algorithm {
        crate::keystore::KeyAlgorithm::Ed25519 => "ed25519",
        crate::keystore::KeyAlgorithm::P256 => "p256",
    }
}

/// 只打印**已经解锁的**。没解锁的钥匙不在这个列表里 —— 守护进程不知道它
/// 现在长什么样,它只知道磁盘上有个信封。
fn status(root: Option<&Path>) -> Result<()> {
    let mut client = connect(root, None)?;
    let unlocked = client.status()?;

    if unlocked.is_empty() {
        println!("nothing is unlocked");
        return Ok(());
    }
    for key in unlocked {
        println!("{}\tunlocked {}s ago", key.did, key.unlocked_secs);
    }
    Ok(())
}

fn unlock(root: Option<&Path>, args: UnlockArgs) -> Result<()> {
    // 口令从终端读。**不走 argv** —— argv 对同机器上任何用户可见。
    let tty = tty::open()?;
    let passphrase = tty::read_secret(&tty, &format!("Passphrase for {}: ", args.did))?;

    let mut client = connect(root, args.socket.as_deref())?;
    client.unlock(&args.did, args.kid.as_deref(), &passphrase)?;
    println!("unlocked {}", args.did);
    Ok(())
}

fn lock(root: Option<&Path>, args: LockArgs) -> Result<()> {
    let mut client = connect(root, args.socket.as_deref())?;
    client.lock(args.did.as_deref(), args.kid.as_deref())?;
    match &args.did {
        Some(did) => println!("locked {did}"),
        None => println!("locked everything"),
    }
    Ok(())
}

/// 读一个"命令行指过来的文件",读不到时说清楚是**哪个**文件。
///
/// `std::fs::read(path)?` 展开成的是 `io: No such file or directory (os
/// error 2)`,一个字都没提那个路径。而 `--body` 最容易踩的就是这个坑:
/// 习惯上 `--header` 收的是字面量,于是很自然地把请求体也照着字面量写,
/// `--body '{"a":1}'` —— 得到的是一句没有任何上下文的话。说了文件名,
/// 人一眼就知道它要的是文件。
fn read_flag_file(path: &Path, flag: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| {
        KeydError::Protocol(format!(
            "cannot read {flag} {}: {error} (this flag takes a file, not the text itself)",
            path.display()
        ))
    })
}

fn sign(root: Option<&Path>, args: SignArgs) -> Result<()> {
    let mut client = connect(root, args.socket.as_deref())?;

    if let Some(path) = &args.raw {
        let payload = read_flag_file(path, "--raw")?;
        let signature = client.sign_raw(&args.did, args.kid.as_deref(), payload)?;
        println!("{}", base64(&signature));
        return Ok(());
    }

    let body = match &args.body {
        Some(path) => Some(read_flag_file(path, "--body")?),
        None => None,
    };

    // clap 保证了走到这里 `url` 一定在:要么给了 `--url`,要么给了 `--raw`
    // 而这个分支处理不了 —— 所以这里的 `ok_or` 不是"用户传错了",是"我们
    // 自己把两条路的分支写漏了",报出来比 unwrap 好。
    let target_uri = args.url.clone().ok_or_else(|| {
        KeydError::Protocol("no --url was given, so there is nothing to sign".into())
    })?;

    let signed = client.sign(SignRequest::Structured {
        did: args.did.clone(),
        kid: args.kid.clone(),
        method: args.method.clone(),
        target_uri,
        headers: parse_headers(&args.headers)?,
        body,
        covered: args.cover.clone(),
    })?;

    // **原样搬运。** 这份字节要挂到真实请求上去,改动其中任何一个字符
    // 签名就验不过 —— 所以这里不解析、不重排、不补引号。
    std::io::stdout().write_all(&signed)?;
    Ok(())
}

/// `name: value` → 头表。名字转小写。
///
/// 转小写不是洁癖:HTTP 头名不区分大小写,而 `BTreeMap` 区分 —— 不转的话
/// `Content-Type` 和 `content-type` 会成为两条记录,一条被签、另一条被
/// 忽略,而调用方以为自己两条都给了。
fn parse_headers(raw: &[String]) -> Result<BTreeMap<String, String>> {
    let mut headers = BTreeMap::new();
    for entry in raw {
        let (name, value) = entry
            .split_once(':')
            .ok_or_else(|| KeydError::Protocol(format!("{entry:?} is not `name: value`")))?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(KeydError::Protocol(format!("{entry:?} has an empty header name")));
        }
        if headers.insert(name.clone(), value.trim().to_string()).is_some() {
            return Err(KeydError::Protocol(format!(
                "the header {name} was given twice; the second one would silently win"
            )));
        }
    }
    Ok(headers)
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use clap::error::ErrorKind;

    fn parse(argv: &[&str]) -> std::result::Result<Cli, clap::Error> {
        let mut full = vec!["anp-keyd"];
        full.extend_from_slice(argv);
        Cli::try_parse_from(full)
    }

    /// **导出这条命令在默认构建里不存在 —— 不是被拒,是没有。**
    ///
    /// 计划 §六·七 的第三道收紧就是这个意思:一个运行期开关可以被补丁、
    /// 被漏掉的分支、被调试器翻过去;一个编译期不存在的子命令没有可翻的
    /// 东西。默认二进制里不但没有这条路径,连这个字符串都没有。
    #[cfg(not(feature = "seed-export"))]
    #[test]
    fn the_default_build_has_no_export_subcommand_at_all() {
        let error = parse(&["export-seed", "--did", "did:wba:example.com:u:a:e1_x"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand, "{error}");
    }

    /// 带上 `seed-export` 构建出来的二进制里,这条命令也没有 `--password`。
    ///
    /// 这一条测的**不是**"我们记得检查了密码在不在 argv 里",而是"这个参数
    /// 根本不存在":少了参数就少了一条泄露路径,而 argv 对同机器上任何用户
    /// 都是可读的(`ps`)。
    #[cfg(feature = "seed-export")]
    #[test]
    fn the_export_command_has_no_password_flag_even_when_it_exists() {
        let error = parse(&[
            "export-seed",
            "--did",
            "did:wba:example.com:u:a:e1_x",
            "--password",
            "hunter2",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{error}");
    }

    /// 两条导入路都进默认构建,而且**都没有** `--password` —— 同一条理由:
    /// 归档的密码只从终端读。
    #[test]
    fn neither_import_command_takes_a_password_on_the_command_line() {
        let mnemonic = parse(&[
            "import-mnemonic",
            "--did",
            "did:wba:example.com:u:a:e1_x",
            "--password",
            "hunter2",
        ])
        .unwrap_err();
        assert_eq!(mnemonic.kind(), ErrorKind::UnknownArgument, "{mnemonic}");

        let archive = parse(&["import-archive", "--file", "/tmp/a.json", "--password", "hunter2"])
            .unwrap_err();
        assert_eq!(archive.kind(), ErrorKind::UnknownArgument, "{archive}");
    }

    /// 导入是 v1 必做的一部分 —— 一个打不开的备份不算备份。这条钉住的是
    /// "它在默认构建里",而不是"它被实现了"(那由别的测试保证)。
    #[test]
    fn both_import_commands_are_in_the_default_build() {
        assert!(parse(&[
            "import-mnemonic",
            "--did",
            "did:wba:example.com:u:a:e1_x",
        ])
        .is_ok());
        assert!(parse(&["import-archive", "--file", "/tmp/a.json"]).is_ok());
    }

    /// `--words-only` 和 `--archive-only` 一起给是自相矛盾的要求,clap 就该
    /// 在启动前拒掉 —— 不给"两个都要"和"两个都不要"这两种读法留空间。
    #[cfg(feature = "seed-export")]
    #[test]
    fn asking_for_words_only_and_archive_only_at_once_is_refused() {
        let error = parse(&[
            "export-seed",
            "--did",
            "did:wba:example.com:u:a:e1_x",
            "--words-only",
            "--archive-only",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{error}");
    }

    fn spec(host: &str, path: &str) -> Result<DidDocumentSpec> {
        spec_of(&KeygenArgs {
            host: host.to_string(),
            port: None,
            path: path.to_string(),
            fragment: "key-1".to_string(),
            label: "default".to_string(),
        })
    }

    #[test]
    fn a_path_is_split_on_slashes_and_tolerates_surrounding_ones() {
        assert_eq!(path_segments("agents/mybot").unwrap(), ["agents", "mybot"]);
        assert_eq!(path_segments("/agents/mybot/").unwrap(), ["agents", "mybot"]);
    }

    /// 空段要拒 —— `a//b` 拼出来的 DID 和它看起来的样子不是一回事。
    #[test]
    fn an_empty_path_segment_is_refused() {
        let error = path_segments("a//b").unwrap_err();
        assert!(error.to_string().contains("empty segment"), "{error}");
    }

    /// **apex 不是合法的 did:wba DID。**
    ///
    /// `did:wba:example.com:e1_...` 看起来很像回事,但上游要求至少有一段
    /// 路径,所以它建不出文档。这条曾经是在人敲完两遍口令之后才炸的 ——
    /// 现在它在问口令之前就炸,而且说的话是"为什么"。
    #[test]
    fn a_did_with_no_path_segment_is_refused_before_the_prompt() {
        for path in ["", "/", "///"] {
            let error = spec("example.com", path).unwrap_err();
            let text = error.to_string();
            assert!(text.contains("at least one segment"), "{path:?}: {text}");
        }
    }

    /// IP 字面量要在问口令之前拒 —— did:wba 是按域名命名的。
    #[test]
    fn an_ip_literal_host_is_refused_before_the_prompt() {
        for host in ["127.0.0.1", "192.0.2.10", "::1"] {
            let error = spec(host, "agents/bot").unwrap_err();
            let text = error.to_string();
            assert!(text.contains("IP"), "{host}: {text}");
        }
    }

    #[test]
    fn an_empty_host_is_refused_before_the_prompt() {
        let error = spec("   ", "agents/bot").unwrap_err();
        assert!(error.to_string().contains("names no domain"), "{error}");
    }

    /// 主机两头的空白要削掉 —— 粘贴域名的时候很容易带进来。
    #[test]
    fn a_host_is_trimmed() {
        let spec = spec("  example.com  ", " agents/bot ").unwrap();
        assert_eq!(spec.host, "example.com");
    }

    #[test]
    fn header_names_are_lowercased_so_one_header_is_one_entry() {
        let headers = parse_headers(&["Content-Type: application/json".into()]).unwrap();
        assert_eq!(headers["content-type"], "application/json");
    }

    /// 大小写不同的同一个头必须被认出是重复,而不是悄悄变成两条。
    #[test]
    fn a_header_given_twice_is_refused() {
        let error = parse_headers(&[
            "Content-Type: application/json".into(),
            "content-type: text/plain".into(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("twice"), "{error}");
    }

    #[test]
    fn a_header_without_a_colon_is_refused() {
        let error = parse_headers(&["garbage".into()]).unwrap_err();
        assert!(error.to_string().contains("name: value"), "{error}");
    }

    /// 值里的冒号不能当分隔符 —— `Authorization: Bearer a:b` 是常见的。
    #[test]
    fn only_the_first_colon_splits_a_header() {
        let headers = parse_headers(&["authorization: Bearer a:b:c".into()]).unwrap();
        assert_eq!(headers["authorization"], "Bearer a:b:c");
    }

    #[test]
    fn a_binary_pin_that_is_not_a_pin_is_refused() {
        let error = ServeArgs {
            socket: None,
            system: false,
            idle: DEFAULT_IDLE_SECS,
            allow_raw_signing: false,
            allow_uids: vec![],
            allow_binaries: vec!["not-a-pin".into()],
        }
        .policy()
        .unwrap_err();
        assert!(error.to_string().contains("cdhash"), "{error}");
    }

    #[test]
    fn the_host_comes_out_of_a_resolution_url() {
        assert_eq!(host_of("https://example.com:3000/user/alice/did.json"), "example.com:3000");
        assert_eq!(host_of("https://example.com/.well-known/did.json"), "example.com");
    }
}
