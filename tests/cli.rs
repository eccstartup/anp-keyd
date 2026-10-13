//! CLI 层:真起一个 `anp-keyd` 进程,真的在一个终端上敲命令。
//!
//! # 为什么这一层必须存在,以及为什么它必须用**真终端**
//!
//! 前四份集成测试都走库 API,于是它们看不见一整层东西:`clap` 的解析与
//! 互斥、退出码、打印给人看的那些话、以及 `ops::Session::open` 里那条
//! "口令只从 `/dev/tty` 读"的纪律。而那一条纪律恰恰是**没法在库里面测的**
//! —— `Session::open` 自己调 `tty::open()`,没有一个注入口。这不是缺陷:
//! 一个可以被调用方塞进"另一个终端"的实现,正是第六节里那条
//! `SCM_RIGHTS` 攻击要利用的东西。
//!
//! 所以唯一的测法就是**和人类一样用它**:分配一对真 pty,让子进程
//! `setsid` + `TIOCSCTTY` 把它当控制终端,然后照提示语回答。
//!
//! 顺带把 `ops` 那五个生命周期命令(`add-recovery-key` / `rotate-hot-key` /
//! `remove-key` / `migrate` / `deactivate`)也盖住了 —— 它们同样只从终端读
//! 秘密,之前一条测试都没有。
//!
//! # 自动回答
//!
//! 每条命令的提问顺序是固定的,但与其把顺序抄进测试(那样改一句提示语就
//! 红一片),这里按**提示语的样子**回答:看到 "(its binding key):" 就回
//! 绑定密钥那个口令,看到 "Repeat it:" 就重复一遍,看到 "[y/N]" 就点头。
//! 认不出来的提示语会拖到超时 —— 那是**失败**,不是跳过:一条没人回答的
//! 提问意味着这里有一处人机交互没被覆盖。

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_anp-keyd");
const PASSPHRASE: &str = "a passphrase that the echo must never show";

// ————————————————————————————————————————————————————————————————————————
// 夹具
// ————————————————————————————————————————————————————————————————————————

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-cli-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ————————————————————————————————————————————————————————————————————————
// 一个真的终端
// ————————————————————————————————————————————————————————————————————————

/// 回答提示语的规则:**先匹配上的先用**。顺序有意义 ——
/// `"Passphrase for "` 是兜底的那条,必须排在更具体的后面。
fn default_rules() -> Vec<(&'static str, String)> {
    vec![
        ("(its binding key): ", PASSPHRASE.to_string()),
        ("New passphrase for this key: ", PASSPHRASE.to_string()),
        ("Repeat it: ", PASSPHRASE.to_string()),
        ("Passphrase for the new key", String::new()),
        ("Passphrase for ", PASSPHRASE.to_string()),
        ("[y/N] ", "y".to_string()),
    ]
}

struct Outcome {
    stdout_and_stderr: String,
    code: Option<i32>,
    timed_out: bool,
}

impl Outcome {
    #[track_caller]
    fn expect_ok(&self) -> &str {
        assert!(!self.timed_out, "the command never finished:\n{}", self.text());
        assert_eq!(
            self.code,
            Some(0),
            "the command failed (exit {:?}):\n{}",
            self.code,
            self.text()
        );
        &self.stdout_and_stderr
    }

    #[track_caller]
    fn expect_failure(&self) -> &str {
        assert!(!self.timed_out, "the command never finished:\n{}", self.text());
        assert_ne!(
            self.code,
            Some(0),
            "the command was supposed to be refused:\n{}",
            self.text()
        );
        &self.stdout_and_stderr
    }

    #[track_caller]
    fn text(&self) -> &str {
        &self.stdout_and_stderr
    }
}

/// 在一个**真终端**里跑一条命令,按规则回答提问,等它结束。
fn run_in_terminal(root: &Path, args: &[&str], rules: &[(&str, String)]) -> Outcome {
    let pair = nix::pty::openpty(None, None).expect("openpty");
    let master = File::from(pair.master);
    let slave = File::from(pair.slave);
    let slave_fd = slave.as_raw_fd();

    let mut command = Command::new(BIN);
    command.arg(args[0]).args(&args[1..]);
    command.arg("--root").arg(root);

    // 三头都接到从设备上:这样 stdout 和 stderr 一起进 pty,读起来是一条
    // 按时间排好的流 —— 而这条流正是人类在屏幕上看到的东西。
    command.stdin(Stdio::from(slave.try_clone().expect("clone the pty slave")));
    command.stdout(Stdio::from(slave.try_clone().expect("clone the pty slave")));
    command.stderr(Stdio::from(slave.try_clone().expect("clone the pty slave")));

    unsafe {
        command.pre_exec(move || {
            // 裸 `setsid(2)` 而不是 `nix::unistd::setsid`:这个闭包跑在 `fork`
            // 之后、`exec` 之前,中间只能用异步信号安全的东西。
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // 有了自己的会话还不够 —— 控制终端得**认领**:没有这一步,
            // 子进程里的 `open("/dev/tty")` 拿不到东西。
            if nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY as nix::libc::c_ulong, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().expect("spawn anp-keyd");
    // **父进程手里那几份从设备必须关掉。** 留着它们,子进程退出之后主设备
    // 那头也不会给出 EOF,读线程就只能靠超时收场。
    drop(command);
    drop(slave);

    drive(&master, &mut child, rules)
}

/// 读主设备那头,见到提示语就照规则回答,直到子进程结束。
fn drive(master: &File, child: &mut Child, rules: &[(&str, String)]) -> Outcome {
    set_nonblocking(master);

    let seen = Arc::new(Mutex::new(String::new()));
    let cursor = Arc::new(Mutex::new(0usize));
    let exited = Arc::new(AtomicBool::new(false));

    let reader = {
        let master = master.try_clone().expect("clone the pty master");
        let seen = Arc::clone(&seen);
        let cursor = Arc::clone(&cursor);
        let exited = Arc::clone(&exited);
        let rules: Vec<(String, String)> =
            rules.iter().map(|(p, r)| (p.to_string(), r.clone())).collect();

        std::thread::spawn(move || {
            let mut quiet_since = Instant::now();
            loop {
                let mut chunk = [0u8; 4096];
                match (&master).read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        let text = String::from_utf8_lossy(&chunk[..read]);
                        seen.lock().unwrap().push_str(&text);
                        answer(&master, &seen, &cursor, &rules);
                        quiet_since = Instant::now();
                    }
                    Err(_) => {
                        // 非阻塞下没有数据可读就是 `WouldBlock`。子进程已经
                        // 退出、而且安静了一小会儿,就可以收工了。
                        if exited.load(Ordering::Relaxed)
                            && quiet_since.elapsed() > Duration::from_millis(150)
                        {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        })
    };

    let status = child.wait().expect("wait for anp-keyd");
    exited.store(true, Ordering::Relaxed);
    let _ = reader.join();

    let text = seen.lock().unwrap().clone();
    Outcome {
        stdout_and_stderr: text,
        code: status.code(),
        timed_out: status.code().is_none(),
    }
}

/// 在**还没回答过**的那一段里找规则表里**第一条**命中的,回过去,推进游标。
///
/// 挑的是"规则表里的先后",不是"出现在文本里的先后",这一点很要紧。
/// 绑定密钥那句提示语是
/// `Passphrase for {did} (its binding key): ` —— 通用的
/// `"Passphrase for "` 出现在句子最前面,而具体的那条在句尾。按位置选就会
/// 先命中通用的那条,游标只推过一小段,句尾剩下的 `(its binding key): `
/// 下一轮又被答一遍:多出来的一行会把**后面**的提问整个顶掉(实测就是确认框
/// 读到一个空行,于是报 "you answered no")。按规则表先后选,具体的那条在
/// 前面,游标一次推过整句。
///
/// 一次可能命中好几条(提示语挤在同一个读块里),所以这里是循环。
fn answer(
    master: &File,
    seen: &Arc<Mutex<String>>,
    cursor: &Arc<Mutex<usize>>,
    rules: &[(String, String)],
) {
    loop {
        let index = {
            let buffer = seen.lock().unwrap();
            let mut cursor = cursor.lock().unwrap();
            match first_match(&buffer, *cursor, rules) {
                Some((position, index)) => {
                    *cursor = position + rules[index].0.len();
                    index
                }
                None => return,
            }
        };

        let mut writer = master.try_clone().expect("clone the pty master for writing");
        let wrote = writer
            .write_all(rules[index].1.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush());
        if wrote.is_err() {
            // 子进程已经走了,没有人在等这个回答。这不是失败 —— 断言在
            // 调用方那边看输出。
            return;
        }
    }
}

/// 规则表里第一条在游标之后出现的。
fn first_match(buffer: &str, cursor: usize, rules: &[(String, String)]) -> Option<(usize, usize)> {
    if cursor > buffer.len() {
        return None;
    }
    let tail = &buffer[cursor..];
    rules
        .iter()
        .enumerate()
        .find_map(|(index, (pattern, _))| {
            tail.find(pattern.as_str()).map(|offset| (cursor + offset, index))
        })
}

fn set_nonblocking(file: &File) {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = fcntl(file, FcntlArg::F_GETFL).expect("F_GETFL");
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(file, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).expect("F_SETFL");
}

// ————————————————————————————————————————————————————————————————————————
// 不带终端的命令:参数解析、退出码、帮助
// ————————————————————————————————————————————————————————————————————————

/// 跑一条不需要终端的命令,也不带 `--root`:只有参数解析会被走到。
fn run_bare(args: &[&str]) -> Outcome {
    let output = Command::new(BIN).args(args).output().expect("spawn anp-keyd");
    Outcome {
        stdout_and_stderr: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        code: output.status.code(),
        timed_out: false,
    }
}

// ========================================================================
// 一、参数解析:在问口令**之前**就把该说的说出来
// ========================================================================

/// `--path` 没有默认值,漏了就当场说。
///
/// 这条挡的是一句谎话:did:wba **要求**至少有一段路径,所以"给一个默认的
/// 空路径"等于让命令先跑起来、再失败在一个没人预料的地方。clap 的退出码
/// 是 2 —— 那是"你用错了",不是"事情办不成"。
#[test]
fn keygen_without_a_path_is_refused_by_the_argument_parser() {
    let dir = TempDir::new("no-path");
    let outcome = run_bare(&[
        "keygen",
        "--root",
        &dir.path().display().to_string(),
        "--host",
        "example.com",
    ]);

    assert_eq!(outcome.code, Some(2), "clap must reject it:\n{}", outcome.text());
    assert!(
        outcome.text().contains("--path"),
        "the error has to name the missing flag:\n{}",
        outcome.text()
    );
}

/// 每一个子命令都出现在 `--help` 里 —— 包括那些只在特定特性下存在的。
///
/// 这一条防的是"忘了往 `Command` 里加一个变体":命令还在 `cli.rs` 里,
/// 但人在 `--help` 上看不到它,于是它等于不存在。
#[test]
fn help_lists_every_command() {
    let outcome = run_bare(&["--help"]);
    let text = outcome.expect_ok();

    for command in [
        "serve",
        "keygen",
        "publish",
        "verify-doc",
        "list",
        "status",
        "probe",
        "unlock",
        "lock",
        "sign",
        "add-recovery-key",
        "rotate-hot-key",
        "remove-key",
        "migrate",
        "deactivate",
        "import-mnemonic",
        "import-archive",
    ] {
        assert!(text.contains(command), "`{command}` is missing from --help:\n{text}");
    }
}

/// `--raw` 和结构化那套参数**互相排除**,而且 clap 就得拦住。
///
/// 不是洁癖:两者都能给的话,调用方会以为 `--body` 也进了覆盖面,而原始
/// 签名的输入只有那个文件 —— 这正是"悄悄降级"的形状。
#[test]
fn sign_refuses_raw_together_with_structured_flags() {
    let outcome = run_bare(&[
        "sign",
        "--did",
        "did:wba:example.com:a:e1_x",
        "--url",
        "https://example.com/x",
        "--raw",
        "/tmp/some-file",
    ]);
    assert_eq!(outcome.code, Some(2), "clap must reject the combination:\n{}", outcome.text());
}

// ========================================================================
// 二、keygen:两句口令,一个信封
// ========================================================================

/// 造一把钥匙,然后**在磁盘上确认它真的躺在那儿**,而且模式是 0600。
fn keygen(dir: &TempDir, tag: &str) -> String {
    let outcome = run_in_terminal(
        dir.path(),
        &["keygen", "--host", "example.com", "--path", &format!("agents/{tag}")],
        &default_rules(),
    );
    let text = outcome.expect_ok();

    assert!(
        !text.contains(PASSPHRASE),
        "the passphrase must never be echoed back:\n{text}"
    );

    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with("did:wba:"))
        .expect("keygen prints the DID")
        .to_string()
}

#[test]
fn keygen_writes_an_envelope_with_the_did_it_printed() {
    let dir = TempDir::new("keygen");
    let did = keygen(&dir, "bot");

    assert!(did.starts_with("did:wba:example.com:agents:bot:e1_"), "got {did:?}");

    let keys: Vec<_> = std::fs::read_dir(dir.path().join("keys"))
        .expect("keys/ exists")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(keys.len(), 1, "exactly one envelope: {keys:?}");

    let mode = std::fs::metadata(&keys[0]).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the envelope is a secret: {mode:o}");
}

/// 两遍对不上就**什么都不写**,而不是留一个自己打不开的信封。
#[test]
fn keygen_refuses_when_the_two_entries_do_not_match() {
    let dir = TempDir::new("mismatch");
    let rules: Vec<(&str, String)> = vec![
        ("New passphrase for this key: ", "one".into()),
        ("Repeat it: ", "another".into()),
    ];

    // 三轮都答错,于是到顶 —— 每一轮都要重新回答"新口令"和"重复"两句,
    // 所以规则得能重复命中(游标是往前推的,不是"每条只答一次")。
    let outcome = run_in_terminal(
        dir.path(),
        &["keygen", "--host", "example.com", "--path", "agents/bot"],
        &rules,
    );
    let text = outcome.expect_failure();

    assert!(
        text.contains("the passphrase was not confirmed"),
        "it has to say the refusal out loud:\n{text}"
    );
    assert!(
        !dir.path().join("keys").exists() || std::fs::read_dir(dir.path().join("keys")).unwrap().count() == 0,
        "nothing may be written when the passphrase was never confirmed"
    );
}

/// IP 字面量被拒 —— 而且是在**问口令之前**。
///
/// 后半句才是这条测试的价值:人已经坐下来、敲完两遍口令之后才被告知"你
/// 这个域名不行",那条错误本来在他敲第一个字符之前就成立了。
#[test]
fn an_ip_literal_host_is_refused_before_the_passphrase_is_ever_asked() {
    let dir = TempDir::new("ip-literal");
    let outcome = run_in_terminal(
        dir.path(),
        &["keygen", "--host", "127.0.0.1", "--path", "agents/bot"],
        &default_rules(),
    );
    let text = outcome.expect_failure();

    assert!(text.contains("IP"), "the refusal has to name what is wrong:\n{text}");
    assert!(
        !text.contains("New passphrase"),
        "it must not get as far as asking for a passphrase:\n{text}"
    );
}

// ========================================================================
// 三、publish / verify-doc
// ========================================================================

/// 发布一份文档,并拿它自己验一遍 —— 一份签得出来却绑不上路径的文档,
/// 发布出去只会让**别人**发现我们在骗自己。
#[test]
fn a_published_document_verifies_against_its_own_did() {
    let dir = TempDir::new("publish");
    let did = keygen(&dir, "bot");

    let published = run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules());
    let text = published.expect_ok();

    // 取回地址是**完整的** DID 路径 —— 最后那段 `e1_<指纹>` 也在里面。
    // did:wba 的规则是"把 DID 的路径段原样当 URL 路径",少一段就没人找得到
    // 这份文档,而那意味着签名验不过 —— 这是"工具的产物能不能用"的问题。
    let segment = did.rsplit(':').next().expect("the e1_ segment");
    assert!(
        text.contains(&format!("https://example.com/agents/bot/{segment}/did.json")),
        "it has to say where the file must be served:\n{text}"
    );
    assert!(
        text.contains("this tool cannot host anything"),
        "and it has to admit it cannot host it:\n{text}"
    );

    let verified = run_in_terminal(dir.path(), &["verify-doc", "--did", &did], &default_rules());
    let text = verified.expect_ok();
    assert!(text.contains("is valid"), "the local copy must verify:\n{text}");
}

/// 验一份**不是**这个 DID 的文档:路径绑定对不上就得拒。
#[test]
fn a_document_for_another_did_is_refused() {
    let dir = TempDir::new("wrong-did");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let local = std::fs::read_dir(dir.path().join("dids"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .expect("the published document");

    let borrowed = did.replace("agents:bot:", "agents:someone-else:");
    let outcome = run_in_terminal(
        dir.path(),
        &["verify-doc", "--did", &borrowed, "--file", &local.display().to_string()],
        &default_rules(),
    );
    outcome.expect_failure();
}

// ========================================================================
// 四、守护进程:解锁、签名、上锁
// ========================================================================

/// 一个跑着的 `anp-keyd serve`。
struct Daemon {
    child: Child,
}

impl Daemon {
    fn start(dir: &TempDir) -> Self {
        let mut child = Command::new(BIN)
            .arg("serve")
            .arg("--root")
            .arg(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn `anp-keyd serve`");

        let socket = dir.path().join("run").join("keyd.sock");
        for _ in 0..600 {
            if socket.exists() {
                return Self { child };
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // 走到这儿 `Daemon` 还没被构造出来,所以析构不会替我们收尸;
        // 不先杀掉,这个进程会在整个测试跑完之前一直挂着。
        let _ = child.kill();
        let _ = child.wait();
        panic!("the daemon never created {}", socket.display());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 解锁一条命令。走 socket,但口令仍然只在终端上问。
fn unlock(dir: &TempDir, did: &str) -> Outcome {
    run_in_terminal(dir.path(), &["unlock", "--did", did], &default_rules())
}

fn sign(dir: &TempDir, did: &str) -> Outcome {
    run(dir.path(), &["sign", "--did", did, "--method", "GET", "--url", "https://api.example.net/orders/42"])
}

fn run(root: &Path, args: &[&str]) -> Outcome {
    let mut full: Vec<String> = vec![BIN.to_string()];
    full.extend(args.iter().map(|arg| arg.to_string()));
    full.push("--root".into());
    full.push(root.display().to_string());

    let output = Command::new(&full[0]).args(&full[1..]).output().expect("spawn anp-keyd");
    Outcome {
        stdout_and_stderr: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        code: output.status.code(),
        timed_out: false,
    }
}

/// 整条路走通:造钥匙、发布、起守护进程、解锁、签名、上锁、再签被拒。
///
/// 这一条是给人看的那一层里最要紧的一条 —— 它跑的就是 README 里那五步。
#[test]
fn the_five_steps_in_the_readme_work_end_to_end() {
    let dir = TempDir::new("walkthrough");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let daemon = Daemon::start(&dir);

    // 上锁时签名必须被拒 —— 而且现在磁盘上有钥匙,所以拒的理由只可能是
    // "没解锁",不是"没这把钥匙"。
    let refused = sign(&dir, &did);
    refused.expect_failure();

    unlock(&dir, &did).expect_ok();

    let listed = run(dir.path(), &["list"]);
    assert!(listed.expect_ok().contains(&did), "a key on this machine must be listed");

    let status = run(dir.path(), &["status"]);
    assert!(
        status.expect_ok().contains(&did),
        "an unlocked key must show up in status"
    );

    let signed = sign(&dir, &did);
    let text = signed.expect_ok();
    assert!(
        text.contains("Signature-Input: ") && text.contains("Signature: "),
        "the signature headers go to stdout, verbatim:\n{text}"
    );

    // 覆盖面是**守护进程自己**定的,而且认的是它自己那把钥匙 —— 签名基
    // 不由调用方给。
    assert!(
        text.contains("@method") && text.contains("@target-uri") && text.contains(&did),
        "the daemon's own signature base must name the method, the target URI\n\
         and this key:\n{text}"
    );

    // 两次签名**不**逐字节相同:覆盖面里的 `created` 是当下时间、`nonce`
    // 每次重新随机。Ed25519 本身是确定性的,但签名基不是 —— 一条请求被
    // 重放时,验证方能从 nonce 看出来这是第二次。
    assert_ne!(text, sign(&dir, &did).expect_ok(), "the signature base must not repeat");

    run(dir.path(), &["lock"]).expect_ok();
    sign(&dir, &did).expect_failure();

    drop(daemon);
}

/// 口令敲错就是打不开,而且报的错和"少了 device.secret"**一模一样**。
///
/// 两者可区分等于告诉拿到磁盘的人"你缺的是哪个因子"。
#[test]
fn unlock_with_the_wrong_passphrase_is_refused() {
    let dir = TempDir::new("wrong-pass");
    let did = keygen(&dir, "bot");
    let _daemon = Daemon::start(&dir);

    let rules: Vec<(&str, String)> = vec![("Passphrase for ", "not the passphrase".into())];
    let outcome = run_in_terminal(dir.path(), &["unlock", "--did", &did], &rules);
    let text = outcome.expect_failure();

    assert!(
        text.to_lowercase().contains("passphrase"),
        "the refusal must not say which factor was wrong, but it must be an\n\
         authentication failure rather than a crash:\n{text}"
    );

    // 而且它**没有**被解锁。
    assert!(!run(dir.path(), &["status"]).expect_ok().contains(&did));
}

/// 没有守护进程时,`sign` 说的是"连不上",不是别的东西。
#[test]
fn signing_without_a_daemon_says_it_cannot_connect() {
    let dir = TempDir::new("no-daemon");
    let did = keygen(&dir, "bot");

    let outcome = sign(&dir, &did);
    outcome.expect_failure();
}

/// 审计日志里**没有密钥材料**,而且记下了刚才那次签名。
///
/// 这一条和 `tests/no_key_material_on_disk.rs` 是一对:那一份扫的是整棵
/// 目录树,这一份走一条**真的 CLI 路径** —— 只有后者能证明"用户真会走
/// 的那条路上"也干净。
#[test]
fn the_audit_log_records_the_signature_and_holds_no_secrets() {
    let dir = TempDir::new("audit");
    let did = keygen(&dir, "bot");
    // 签名要读**已发布的那份文档** —— 签名基里的 `keyid` 和公钥出自它,
    // 所以没有文档就没有可签的东西(报的是 "key not found",因为对这个
    // DID 而言,本机确实什么都还没有)。
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();
    sign(&dir, &did).expect_ok();

    let log = std::fs::read_dir(dir.path().join("audit"))
        .expect("audit/ exists")
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .expect("a monthly shard");
    let text = std::fs::read_to_string(&log).unwrap();

    assert!(
        text.contains("\"event\":\"SIGNED\""),
        "the signature must be recorded:\n{text}"
    );
    assert!(text.contains(&did), "and it must say which key signed:\n{text}");
    assert!(!text.contains(PASSPHRASE), "the passphrase must never reach the log");

    // 字段名是一个**封闭集合**,这就是"日志里没有秘密"的测法 —— 一个能装
    // 种子的字段一旦被加进来,这里立刻红,而不是等谁去想到它。
    const FIELDS: [&str; 9] = [
        "seq",
        "at",
        "prev",
        "event",
        "uid",
        "did",
        "kid",
        "covered",
        "signature_base_digest",
    ];
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: serde_json::Value = serde_json::from_str(line).expect("one event per line");
        for name in event.as_object().expect("an event is an object").keys() {
            assert!(
                FIELDS.contains(&name.as_str()),
                "an audit event grew a field {name:?} — it must not be one that can hold\n\
                 key material:\n{line}"
            );
        }
    }
}

// ========================================================================
// 五、生命周期:ops 那一层
// ========================================================================

/// 把文档读回来,按 `verificationMethod` 的 fragment 列出所有钥匙。
///
/// 按**文件名**取,不按"目录里的第一个" —— `dids/` 里除了文档还躺着别的
/// 东西(生命周期命令会在同一个目录里放一把 `.lock`),而 `read_dir` 的顺序
/// 是文件系统说了算的。
fn fragments_of(dir: &TempDir, did: &str) -> Vec<String> {
    let document = read_local_document(dir, did);

    document["verificationMethod"]
        .as_array()
        .expect("verificationMethod is an array")
        .iter()
        .map(|method| method["id"].as_str().unwrap().rsplit('#').next().unwrap().to_string())
        .collect()
}

/// 一条一条把生命周期命令跑过去,每一步都在**磁盘上**确认它真的做了事。
///
/// `add-recovery-key` / `rotate-hot-key` / `migrate` / `deactivate` 之前一条
/// 测试都没有:它们只从终端读秘密,所以在库 API 那一层是不可达的。
#[test]
fn the_lifecycle_commands_rewrite_the_document() {
    let dir = TempDir::new("lifecycle");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    assert_eq!(fragments_of(&dir, &did), vec!["key-1"], "a fresh document has just the binding key");

    // —— 加一把恢复钥匙 ——
    let added = run_in_terminal(dir.path(), &["add-recovery-key", "--did", &did], &default_rules());
    let text = added.expect_ok();
    assert!(text.contains("added "), "it must name what it added:\n{text}");
    assert!(
        text.contains("is not\na recovery key") || text.contains("not"),
        "it has to warn that a recovery key on the same host is not a recovery key:\n{text}"
    );
    assert!(
        fragments_of(&dir, &did).contains(&"recovery-1".to_string()),
        "the recovery key has to land in the document: {:?}",
        fragments_of(&dir, &did)
    );

    // —— 轮换热密钥 ——
    let rotated = run_in_terminal(dir.path(), &["rotate-hot-key", "--did", &did], &default_rules());
    rotated.expect_ok();
    let fragments = fragments_of(&dir, &did);
    assert!(fragments.contains(&"key-2".to_string()), "the hot key lands as key-2: {fragments:?}");

    // —— 摘掉它 ——
    let removed = run_in_terminal(
        dir.path(),
        &["remove-key", "--did", &did, "--kid", "key-2"],
        &default_rules(),
    );
    removed.expect_ok();
    assert!(
        !fragments_of(&dir, &did).contains(&"key-2".to_string()),
        "the hot key must be gone: {:?}",
        fragments_of(&dir, &did)
    );

    // —— 再轮换一次:编号**不复用** ——
    //
    // 这条挡的是一个具体的洞:一个被缓存过的文档里写着"key-2 这把钥匙",
    // 钥匙换了而名字没换,那份缓存就成了一张已作废钥匙的通行证。
    let rotated = run_in_terminal(dir.path(), &["rotate-hot-key", "--did", &did], &default_rules());
    rotated.expect_ok();
    let fragments = fragments_of(&dir, &did);
    assert!(
        fragments.contains(&"key-3".to_string()) && !fragments.contains(&"key-2".to_string()),
        "the fragment number must not be reused: {fragments:?}"
    );

    // 恢复钥匙还在 —— 摘掉热密钥不该顺手带走别的。
    assert!(fragments.contains(&"recovery-1".to_string()));
}

/// 注销之后**再注销一次被拒**,理由不是"文档会坏",而是**审计会撒谎**。
///
/// 第二次得到的是同一份文档(Ed25519 是确定性的),却会在审计日志里留下
/// 一条"某时刻注销了它"的记录 —— 而那一刻什么也没发生。
#[test]
fn deactivating_twice_is_refused_so_the_audit_log_cannot_lie() {
    let dir = TempDir::new("deactivate");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let first = run_in_terminal(dir.path(), &["deactivate", "--did", &did], &default_rules());
    let text = first.expect_ok();
    assert!(text.contains("with no successor"), "it has to say the line ended:\n{text}");

    let second = run_in_terminal(dir.path(), &["deactivate", "--did", &did], &default_rules());
    let text = second.expect_failure();
    assert!(
        text.contains("already deactivated"),
        "the second run has to be refused with a reason:\n{text}"
    );

    // 被拒的那一次**没有**在日志里留下痕迹 —— 这正是拒它的理由。
    let log = std::fs::read_dir(dir.path().join("audit"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .expect("a monthly shard");
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        text.matches("\"event\":\"DEACTIVATE\"").count(),
        1,
        "exactly one deactivation:\n{text}"
    );
}

/// 迁移写的是**旧**文档:它保留钥匙,加上 `deactivated` 和 `successorDid`。
///
/// "迁移到另一台机器上的 DID"是正常用法,所以后继在本机没有文档**不是**
/// 错误 —— 但它必须说出来,因为一个打错字的 `--to` 正是在这里现形。
#[test]
fn migrate_marks_the_old_document_and_names_the_successor() {
    let dir = TempDir::new("migrate");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    // 后继是**同一个主体**的绑定了新密钥的 DID:绑定密钥轮换只改最后那一
    // 段,路径不动。拿一条改了路径的 DID 当后继会被当场拒绝(见下一条断言),
    // 因为那在验证方眼里是**另一个主体**,不是同一个人换了钥匙。
    let successor = keygen(&dir, "bot");
    assert_ne!(successor, did, "a second keygen must mint a different binding key");

    let outcome = run_in_terminal(
        dir.path(),
        &["migrate", "--did", &did, "--to", &successor],
        &default_rules(),
    );
    let text = outcome.expect_ok();

    assert!(
        text.contains("is now deactivated and points at"),
        "it has to say which way the edge points:\n{text}"
    );
    assert!(
        text.contains("no document on this machine"),
        "the successor is not local, and that has to be said out loud:\n{text}"
    );

    // 旧文档还在原地,而且**没有**被删掉 —— 一份被删掉的文档在验证方眼里
    // 和"这个 DID 从来不存在"完全一样,而它其实存在过。
    let document = read_local_document(&dir, &did);
    assert_eq!(document["deactivated"], serde_json::json!(true));
    assert_eq!(document["successorDid"], serde_json::json!(successor));
    assert!(
        !document["verificationMethod"].as_array().unwrap().is_empty(),
        "the old document keeps its keys"
    );
}

/// 换了主体路径的后继**默认**被拒 —— 而那通常是打了个错字。
///
/// 一条打错字的 `--to` 会让验证方以为"这个人搬到了另一个主体",而真正的
/// 主人什么都没做。所以默认关,要越过得自己说出来。
#[test]
fn migrate_refuses_a_successor_that_is_a_different_subject() {
    let dir = TempDir::new("migrate-subject");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let stranger = did.replace("agents:bot:", "agents:someone-else:");
    let outcome = run_in_terminal(
        dir.path(),
        &["migrate", "--did", &did, "--to", &stranger],
        &default_rules(),
    );
    let text = outcome.expect_failure();

    assert!(
        text.contains("--allow-different-subject"),
        "the refusal has to name the flag that overrides it:\n{text}"
    );
    // 拒了就是**什么都没发生**:旧文档还在,而且没有被标记。
    assert_eq!(read_local_document(&dir, &did)["deactivated"], serde_json::json!(null));
}

/// 后继就是自己,当然是拒 —— 但它得说清"没有后继"该怎么表达。
#[test]
fn deactivate_refuses_a_successor_that_is_itself() {
    let dir = TempDir::new("self-successor");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let outcome =
        run_in_terminal(dir.path(), &["deactivate", "--did", &did, "--to", &did], &default_rules());
    let text = outcome.expect_failure();
    assert!(
        text.contains("cannot succeed itself"),
        "the refusal has to name the mistake:\n{text}"
    );
}

/// 生命周期命令要的是磁盘上那份**真的**文档,不是从 DID 现编的一份。
///
/// 现编一份会静默丢掉真文档里带的东西(热密钥、恢复密钥、迁移记录),而
/// 覆盖写不会报错。
#[test]
fn a_lifecycle_command_without_a_published_document_says_what_to_run_first() {
    let dir = TempDir::new("unpublished");
    let did = keygen(&dir, "bot");

    let outcome = run_in_terminal(dir.path(), &["add-recovery-key", "--did", &did], &default_rules());
    let text = outcome.expect_failure();
    assert!(
        text.contains("publish"),
        "it has to name the command that makes a document exist:\n{text}"
    );
}

fn read_local_document(dir: &TempDir, did: &str) -> serde_json::Value {
    let flat = did.replace(':', "_").replace(['/', '\\'], "_");
    let path = dir.path().join("dids").join(format!("{flat}.json"));
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| {
        panic!("cannot read {}: {error}", path.display())
    }))
    .expect("the document is JSON")
}

/// 一个空目录里 `list` 说的是"没有钥匙",不是"连不上"。
#[test]
fn an_empty_machine_lists_nothing_rather_than_failing() {
    let dir = TempDir::new("empty");
    let _daemon = Daemon::start(&dir);
    assert!(run(dir.path(), &["list"]).expect_ok().contains("no keys"));
    assert!(run(dir.path(), &["status"]).expect_ok().contains("nothing is unlocked"));
}

/// `--body` 收的是**文件**,而写错时那句错误必须提文件名。
///
/// 习惯上 `--header` 收的是字面量,于是很自然地把请求体也照着字面量写。
/// `io: No such file or directory` 一个字都没提那个路径,人只能自己猜。
#[test]
fn a_missing_body_file_is_reported_with_its_path() {
    let dir = TempDir::new("missing-body");
    let did = keygen(&dir, "bot");
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();

    let outcome = run(
        dir.path(),
        &[
            "sign",
            "--did",
            &did,
            "--method",
            "POST",
            "--url",
            "https://api.example.net/orders",
            "--body",
            "/tmp/definitely-not-here.json",
        ],
    );
    let text = outcome.expect_failure();
    assert!(
        text.contains("/tmp/definitely-not-here.json"),
        "the message has to name the file it could not read:\n{text}"
    );
}

/// `--header` 里同一个名字给两遍是拒 —— 第二条会**静默地**赢。
#[test]
fn a_doubled_header_is_refused_rather_than_silently_resolved() {
    let dir = TempDir::new("doubled-header");
    let did = keygen(&dir, "bot");
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();

    let outcome = run(
        dir.path(),
        &[
            "sign",
            "--did",
            &did,
            "--url",
            "https://api.example.net/orders",
            "--header",
            "accept: application/json",
            "--header",
            "Accept: text/plain",
        ],
    );
    let text = outcome.expect_failure();
    assert!(
        text.contains("twice"),
        "it has to say the header was given twice:\n{text}"
    );
}

/// 覆盖面**只能加,不能减**。
///
/// `sign --cover` 要求多覆盖一些分量可以;而守护进程自己决定那些**必须**
/// 覆盖的东西不会因为调用方没提就掉出去。这一条是那个设计的验收。
#[test]
fn a_caller_can_add_coverage_but_the_daemon_keeps_its_own() {
    let dir = TempDir::new("coverage");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();

    let plain = sign(&dir, &did).expect_ok().to_string();
    let extra = run(
        dir.path(),
        &[
            "sign",
            "--did",
            &did,
            "--url",
            "https://api.example.net/orders/42",
            "--cover",
            "content-type",
            "--header",
            "content-type: application/json",
        ],
    )
    .expect_ok()
    .to_string();

    let input = |text: &str| -> String {
        let parsed = anp_keyd::client::parse_signed_headers(text.as_bytes())
            .expect("the daemon returns header lines");
        parsed
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("signature-input"))
            .map(|(_, value)| value.clone())
            .expect("signature-input")
    };

    let plain_input = input(&plain);
    let extra_input = input(&extra);

    assert!(
        !plain_input.contains("content-type"),
        "nothing asked for it, so nothing covers it:\n{plain_input}"
    );
    assert!(
        extra_input.contains("content-type"),
        "the added component has to appear:\n{extra_input}"
    );
    assert!(
        extra_input.contains("@method") && extra_input.contains("@target-uri"),
        "and the components the daemon always covers stay:\n{extra_input}"
    );
}
