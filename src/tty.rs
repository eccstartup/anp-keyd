//! 终端:读秘密,以及"只从终端读"这条纪律本身。
//!
//! ## 为什么这个模块存在
//!
//! 口令可以走很多条路进来,而其中大部分是错的:
//!
//! - **argv** —— `ps` 对同机器上任何用户可见。`--password hunter2` 是不可接受的。
//! - **环境变量** —— 同 uid 的进程能读 `/proc/<pid>/environ`(macOS 上
//!   `ps -E`)。而"同 uid 的另一个进程"正是这个项目要防的东西。
//! - **stdin** —— stdin 是可以被重定向的,而重定向由**启动方**决定。
//!   agent 起一个子进程,把 stdin 接到一个管道上,人类敲的字就进不来
//!   (或者更糟:agent 自己填)。
//! - **socket** —— 这一条被 [`crate::daemon::wire`] 明确排除:协议里没有
//!   任何一条消息能传口令给一个**导出**操作。
//!
//! 所以只剩一条路:**本进程自己 `open("/dev/tty")`**。
//!
//! 最后那句"自己"是关键。`/dev/tty` 打开的是**本进程的控制终端** ——
//! 它是内核按会话给的,不是调用方递进来的。绝不能接受一个通过
//! `SCM_RIGHTS` 传进来的 fd:那样 agent 可以自己开一个 pty,把 slave 端
//! 传过来,守护进程就会以为自己在跟人类说话,于是渲染一个假提示、把人类
//! 敲进去的东西读走。**"这一条 fd 是我自己开的"是唯一站得住的理由。**
//!
//! ## 已知边界
//!
//! 关回显的那一小段里如果进程被信号打死,终端会留着无回显的状态。捕获
//! 信号并把 termios 恢复回去需要在信号处理里碰全局状态,收益不抵复杂度;
//! 这里选择在文档里说清楚,并让错误路径提示 `stty echo`。

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{self, SetArg};
use zeroize::Zeroizing;

use crate::error::{KeydError, Result};

/// 打开**本进程自己的**控制终端。
///
/// 没有终端 = 失败,没有降级路径。理由:所有需要它的操作(生成、导入、
/// 导出)都会碰私钥,而"没有终端"的场合基本上就是"有人在自动化里调它"。
/// 那种场合下要么不该发生,要么应该由人类显式地在一个终端里做。
pub fn open() -> Result<File> {
    File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| {
            KeydError::Protocol(format!(
                "no controlling terminal to prompt on (/dev/tty: {error}); \
                 this command must be run by a person at a terminal"
            ))
        })
}

/// 读一行秘密:不显示在屏幕上,读完立刻交给调用方手上的 `Zeroizing`。
///
/// 返回的字符串**不含**结尾换行。
pub fn read_secret(tty: &File, prompt: &str) -> Result<Zeroizing<String>> {
    let mut out = tty.try_clone().map_err(KeydError::Io)?;

    // 顺序是**先关回显,再写提示语**。
    //
    // 反过来的话,从提示语出现到回显关上之间有一小段窗口,人在那期间打的字
    // 会被终端回显出来 —— 而人正是在看到提示语的瞬间开始打字的,所以那个
    // 窗口恰好是最容易命中的。先关再写,窗口就没有了:人在屏幕上看到问题
    // 的时候,回显已经是关的。
    let line = {
        let _echo = EchoOff::new(tty)?;
        out.write_all(prompt.as_bytes())?;
        out.flush()?;
        read_line(tty)?
    };

    // 回显已经恢复了,现在补一个换行 —— 否则人类的下一行输出会接在提示语
    // 后面,看起来像终端坏了。
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(line)
}

/// 读一行明文(24 个词、DID、各种确认)。仍然从终端读,但看得见。
pub fn read_line(tty: &File) -> Result<Zeroizing<String>> {
    let mut reader = BufReader::new(tty.try_clone().map_err(KeydError::Io)?);
    let mut line = Zeroizing::new(String::new());
    let read = reader.read_line(&mut line)?;
    if read == 0 {
        return Err(KeydError::Protocol("the terminal was closed while reading".into()));
    }
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// 问一次秘密,问两次,两次不一样就重来 —— 最多 [`ATTEMPTS`] 轮。
///
/// **不允许"我就问一次"**:敲错一个字符 = 生成一把自己打不开的钥匙,
/// 而那时候人已经在用别的东西了。确认这一步的成本是一秒钟。
pub fn read_secret_twice(tty: &File, prompt: &str, confirm: &str) -> Result<Zeroizing<String>> {
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        let first = read_secret(tty, prompt)?;
        if first.is_empty() {
            writeln!(tty_writer(tty)?, "the passphrase must not be empty")?;
            continue;
        }
        let second = read_secret(tty, confirm)?;
        if *first == *second {
            return Ok(first);
        }
        writeln!(
            tty_writer(tty)?,
            "the two entries do not match ({attempt} of {ATTEMPTS})"
        )?;
    }
    Err(KeydError::Protocol(
        "the passphrase was not confirmed; nothing was written".into(),
    ))
}

/// 一次 yes/no。默认是 **no** —— 回车不该等于同意。
pub fn confirm(tty: &File, question: &str) -> Result<bool> {
    let mut out = tty_writer(tty)?;
    write!(out, "{question} [y/N] ")?;
    out.flush()?;
    let answer = read_line(tty)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn tty_writer(tty: &File) -> Result<File> {
    // 提示语走 tty 而不是 stdout:stdout 可能是管道,而提问必须落在
    // 人类正看着的那个屏幕上,否则他看到的是一段没有问题的等待。
    tty.try_clone().map_err(KeydError::Io)
}

/// 关回显,并且在离开作用域时**无条件**恢复。
///
/// 用 guard 而不是"关掉…做事…打开":中间任何一条 `?` 提前返回都会把
/// 终端留在无回显状态,而那时候用户看到的是"这个工具把我的终端弄坏了"。
struct EchoOff {
    tty: File,
    saved: termios::Termios,
}

impl EchoOff {
    fn new(tty: &File) -> Result<Self> {
        let saved = termios::tcgetattr(tty).map_err(termios_error)?;
        let mut quiet = saved.clone();
        quiet.local_flags.remove(termios::LocalFlags::ECHO);

        // **`TCSANOW`,不是 `TCSAFLUSH`。**
        //
        // `TCSAFLUSH` 会把"已经到达但还没被读走"的输入**丢掉**。而到达的
        // 输入包括两种完全正当的东西:人看到提示语之前就打完的口令
        // (type-ahead),以及密码管理器**粘贴**进来的口令。两者都会被
        // 无声地扔掉,然后这个读操作就永远等在那里 —— 命令挂死,而屏幕上
        // 没有任何解释。
        //
        // 那为什么直觉上会想 flush:怕有别的进程预先往终端里塞了口令。
        // 这个担心在这里不成立,原因有两条。一,往终端的**输入**队列里塞
        // 字节需要 `TIOCSTI`,而它在现代 macOS 和 Linux 6.2+ 上默认就是
        // 关的。二 —— 更要紧的一条 —— **flush 也救不了**已经发生的事:
        // 那些字节在到达时就已经被回显出来了,而那时回显还开着。flush
        // 抹不掉屏幕上已经显示过的东西,只能抹掉人刚打进去的输入。
        //
        // 所以 flush 换不来任何安全性,只换来"你打的字不见了"。
        termios::tcsetattr(tty, SetArg::TCSANOW, &quiet).map_err(termios_error)?;
        Ok(Self { tty: tty.try_clone().map_err(KeydError::Io)?, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // 恢复也用 `TCSANOW`,理由和关掉时一样,而且这里更明显:确认那一步
        // 紧接着就是第二次读。人如果一次粘贴了 "口令\n口令\n",第二行会在
        // 第一次读的期间就到达队列里 —— 恢复时 flush 掉它,人就会卡在
        // "Repeat it: " 上,而他明明已经把两遍都给了。
        //
        // 恢复回显不会把队列里那些字节"补显示"出来(回显发生在字节到达的
        // 那一刻),所以不 flush 也不会漏出来。
        //
        // 这里**不能**失败到影响调用方:回显恢复不了是环境坏了,而调用方
        // 此时手上有一个好端端的口令。尽力恢复,失败就算了。
        let _ = termios::tcsetattr(&self.tty, SetArg::TCSANOW, &self.saved);
    }
}

fn termios_error(error: nix::errno::Errno) -> KeydError {
    KeydError::Protocol(format!(
        "could not change the terminal's echo setting: {error}; \
         is this a real terminal? (if the terminal is stuck, run `stty echo`)"
    ))
}

/// 这个 fd 是不是一个终端。**给测试和诊断用**,生产路径不看这个 ——
/// 生产路径直接试着改 termios,失败了就报错。
pub fn is_tty(tty: &File) -> bool {
    termios::tcgetattr(tty.as_fd()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::{Duration, Instant};

    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::pty::openpty;

    /// 一对真 pty。测试需要一个**真终端**:`tcgetattr` 在管道上是失败的,
    /// 而"回显开关"这件事只在终端上才有意义。
    fn pty() -> (File, File) {
        let pair = openpty(None, None).expect("openpty");
        (File::from(pair.master), File::from(pair.slave))
    }

    /// 把 master 那头设成非阻塞。
    ///
    /// 用 `fcntl` 而不是 `set_nonblocking`:`O_NONBLOCK` 是**打开文件描述**
    /// 的属性,而这个 fd 是从 `OwnedFd` 借出来的。用 fcntl 直接改它,不带
    /// 任何所有权上的弯子。
    fn set_nonblocking(file: &File) {
        let flags = fcntl(file, FcntlArg::F_GETFL).expect("F_GETFL");
        let flags = OFlag::from_bits_truncate(flags);
        fcntl(file, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).expect("F_SETFL");
    }

    /// 回显是不是关着的 —— 直接问内核,不猜。
    fn echo_is_on(tty: &File) -> bool {
        termios::tcgetattr(tty)
            .expect("tcgetattr")
            .local_flags
            .contains(termios::LocalFlags::ECHO)
    }

    /// 从 master 那头(也就是"屏幕")读,直到看见 `marker`。返回收到的全部字节。
    ///
    /// 带期限:测试挂死比测试失败难查得多,所以到点就报错退出,而不是
    /// 永远等在那里。
    fn read_screen_until(master: &mut File, marker: &str) -> String {
        set_nonblocking(master);
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut byte = [0u8; 1];
        while !String::from_utf8_lossy(&seen).contains(marker) {
            assert!(Instant::now() < deadline, "never saw {marker:?} on the screen");
            match master.read(&mut byte) {
                Ok(0) => std::thread::sleep(Duration::from_millis(1)),
                Ok(_) => seen.push(byte[0]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("reading from the pty failed: {error}"),
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// **这条测试守的是一个曾经真的挂死的 bug。**
    ///
    /// 关回显时如果用 `TCSAFLUSH`,已经到达但还没被读走的输入会被丢掉。
    /// 而"人看到提示之前就打完了"和"密码管理器粘贴"给出的正是这种输入 ——
    /// 于是口令被无声地扔掉,读操作永远等下去,`anp-keyd keygen` 就这么
    /// 挂在提示语后面,屏幕上没有半句解释。
    #[test]
    fn input_that_arrived_before_the_prompt_is_not_discarded() {
        let (mut master, slave) = pty();

        // 先写,再读 —— 这正是 type-ahead 和粘贴的形状。
        master.write_all(b"correct horse\n").unwrap();
        master.flush().unwrap();

        let line = read_secret(&slave, "Passphrase: ").unwrap();
        assert_eq!(*line, "correct horse");
    }

    /// 一次粘贴两行,第二行必须在确认那一步还在。
    ///
    /// 恢复回显时如果也 flush,第二行会在第一次读的期间被丢掉 —— 人就卡在
    /// `Repeat it: ` 上,而他明明已经给了两遍。
    #[test]
    fn a_pasted_pair_still_confirms() {
        let (mut master, slave) = pty();
        master.write_all(b"hunter2\nhunter2\n").unwrap();
        master.flush().unwrap();

        let passphrase = read_secret_twice(&slave, "Passphrase: ", "Repeat it: ").unwrap();
        assert_eq!(*passphrase, "hunter2");
    }

    /// 空口令要重来,不是收下。
    #[test]
    fn an_empty_passphrase_is_refused_and_asked_again() {
        let (mut master, slave) = pty();
        // 空一次(被拒),然后好好给两遍。
        master.write_all(b"\nhunter2\nhunter2\n").unwrap();
        master.flush().unwrap();

        let passphrase = read_secret_twice(&slave, "Passphrase: ", "Repeat it: ").unwrap();
        assert_eq!(*passphrase, "hunter2");
    }

    /// 读秘密的时候,回显必须是关的 —— 而且**关在提示语之前**。
    ///
    /// 顺序反过来的话,从提示语出现到回显关上之间有一小段窗口,人在那期间
    /// 打的字会被回显出来;而人正是在看到提示语的瞬间开始打字的。
    ///
    /// 断言的方式是"看见提示语的那一刻"直接问内核要 termios —— 不睡不等,
    /// 因为提示语本来就是回显关掉之后才写出来的。
    #[test]
    fn echo_is_off_before_the_prompt_appears() {
        let (mut master, slave) = pty();
        let reader_slave = slave.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret(&reader_slave, "Passphrase: "));

        let screen = read_screen_until(&mut master, "Passphrase: ");
        assert!(
            !echo_is_on(&slave),
            "echo was still on when the prompt appeared: {screen:?}"
        );

        master.write_all(b"s3cret\n").unwrap();
        master.flush().unwrap();
        assert_eq!(*reader.join().unwrap().unwrap(), "s3cret");

        // 回显得还回去 —— 否则这个工具的每一次提问都会把人的终端弄哑。
        assert!(echo_is_on(&slave), "echo was never restored");
    }

    /// 回显关着的时候打进去的东西,不许出现在屏幕上。
    #[test]
    fn a_passphrase_typed_while_echo_is_off_never_reaches_the_screen() {
        let (mut master, slave) = pty();
        let reader_slave = slave.try_clone().unwrap();
        let reader = std::thread::spawn(move || read_secret(&reader_slave, "Passphrase: "));

        let mut screen = read_screen_until(&mut master, "Passphrase: ");
        master.write_all(b"s3cret\n").unwrap();
        master.flush().unwrap();
        assert_eq!(*reader.join().unwrap().unwrap(), "s3cret");

        // 把线程返回后写的那个换行也收进来,免得断言跑在它前面。
        std::thread::sleep(Duration::from_millis(20));
        screen.push_str(&drain(&mut master));

        assert!(screen.contains("Passphrase: "), "the prompt must be visible: {screen:?}");
        assert!(!screen.contains("s3cret"), "the passphrase was echoed: {screen:?}");
    }

    /// 把 master 上已经到的东西全部取走(没有就立刻返回)。
    fn drain(master: &mut File) -> String {
        set_nonblocking(master);
        let mut seen = Vec::new();
        let mut buffer = [0u8; 256];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => seen.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("reading from the pty failed: {error}"),
            }
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// 没有控制终端时必须**失败**,而且要说清怎么办。
    ///
    /// 这条测试能跑是因为 cargo test 的进程一般没有控制终端 —— 但如果
    /// 有人在真终端里跑 `cargo test`,它就有一个。所以这里不假设环境,
    /// 只检查"打开成功 ⇒ 它确实是个 tty"这个不变量。
    #[test]
    fn whatever_open_returns_is_actually_a_terminal() {
        match open() {
            Ok(tty) => assert!(is_tty(&tty), "open() handed back something that is not a tty"),
            Err(error) => {
                let text = error.to_string();
                assert!(text.contains("/dev/tty"), "{text}");
                assert!(text.contains("person at a terminal"), "{text}");
            }
        }
    }

    /// 换行要被剥掉 —— 否则口令里会多一个 `\n`,而且用户永远猜不到。
    #[test]
    fn trailing_newlines_never_end_up_in_a_passphrase() {
        let line = "hunter2\n";
        let mut owned = Zeroizing::new(line.to_string());
        while owned.ends_with('\n') || owned.ends_with('\r') {
            owned.pop();
        }
        assert_eq!(*owned, "hunter2");
    }
}
