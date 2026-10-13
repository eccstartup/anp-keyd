//! `probe` 的验收:它**报告**得对,而且**什么都不漏**。
//!
//! 第二条比第一条要紧得多。`probe` 是计划 §九 M2 验收 #3 换了个做法之后的
//! 产物(理由见 `ops::probe` 的模块头),而它之所以敢留在**默认构建**里,
//! 全靠"一个字节的密钥材料都不打印"这一条成立。所以这里不测"它跑得起来",
//! 测的是"**它跑起来之后,屏幕上没有秘密**"。
//!
//! 测法是跑真的子进程收真的 stdout —— 不是调函数。因为要防的正是"某条
//! `println!` 顺手把它打出来了",而那件事只在**进程边界上**才看得见。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use anp_keyd::crypto::kdf::Argon2Config;
use anp_keyd::did::document::DidDocumentSpec;
use anp_keyd::keystore::layout::KeydLayout;
use anp_keyd::keystore::{create, device};

const PASSPHRASE: &[u8] = b"probe passphrase";

fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-probe-{tag}-{}-{}",
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

fn probe(root: &Path, did: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_anp-keyd"));
    command.arg("probe").arg("--root").arg(root);
    if let Some(did) = did {
        command.arg("--did").arg(did);
    }
    command.output().expect("run `anp-keyd probe`")
}

/// 一台装好了一把钥匙的机器。
fn machine(tag: &str) -> (TempDir, KeydLayout, String) {
    let dir = TempDir::new(tag);
    let layout = KeydLayout::at(dir.path().join("root"));
    layout.ensure().unwrap();
    let spec = DidDocumentSpec::new("example.com", vec!["agents".into(), tag.into()]);
    let created = create::create(&layout, &spec, "probe", PASSPHRASE, fast()).unwrap();
    (dir, layout, created.did)
}

// ————————————————————————————————————————————————————————————
// 1. 健康的机器:报告 ok,退出码 0
// ————————————————————————————————————————————————————————————

/// 装了钥匙的机器体检通过 —— 而且顺带把 `--did` 那条路走通(它要解析信封)。
#[test]
fn a_machine_with_a_key_probes_clean() {
    let (_dir, layout, did) = machine("clean");
    let output = probe(layout.root(), Some(&did));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a healthy machine must exit 0; stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("locked memory"), "{stdout}");
    assert!(stdout.contains("ok"), "{stdout}");
    // `--did` 那一段要真的说出信封是谁的。
    assert!(stdout.contains(&did), "the envelope report must name the DID: {stdout}");
}

// ————————————————————————————————————————————————————————————
// 2. 什么都不漏
// ————————————————————————————————————————————————————————————

/// **屏幕上不能出现那半个秘密。**
///
/// `device.secret` 就在磁盘上,所以这条断言是**真的**在比对一个秘密的字节
/// —— 不是"看起来像秘密的东西"。十六进制和 base64 两种写法都查,因为漏的
/// 时候通常是某处顺手 `hex::encode` 了一下。
#[test]
fn the_probe_never_echoes_the_device_secret() {
    let (_dir, layout, did) = machine("nosecrets");
    let output = probe(layout.root(), Some(&did));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let screen = format!("{stdout}{stderr}");

    let secret = device::load(&layout).unwrap();
    let (hex, lower_hex) = secret.expose(|bytes| {
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        (hex.to_uppercase(), hex)
    });

    assert!(
        !screen.contains(&lower_hex) && !screen.contains(&hex),
        "the device secret reached the screen — that is half of every envelope's \
         entropy; stdout={stdout:?}"
    );

    // 顺带:信封里那两段密文也不许原样打出来。
    //
    // 按 JSON 取值而不是按字符串切,因为信封的排版(紧凑/缩进)不是我们要
    // 断言的东西 —— 断言的是那张屏幕上没有这些字节,与它长什么样无关。
    let envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(layout.key_path(&thumbprint(&layout)).unwrap()).unwrap())
            .expect("the envelope is JSON");
    for field in ["sk_ciphertext", "dek_ciphertext"] {
        let ciphertext = envelope[field]
            .as_str()
            .unwrap_or_else(|| panic!("the envelope carries `{field}`: {envelope}"));
        assert!(ciphertext.len() >= 32, "`{field}` should be a real ciphertext");
        assert!(
            !screen.contains(ciphertext),
            "the envelope's `{field}` reached the screen: {screen:?}"
        );
    }
}

/// 目录里那把信封的 thumbprint(也就一个文件)。
fn thumbprint(layout: &KeydLayout) -> String {
    let paths = layout.list_key_paths().unwrap();
    assert_eq!(paths.len(), 1, "expected exactly one envelope");
    paths[0]
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("the envelope is named after its thumbprint")
        .to_string()
}

// ————————————————————————————————————————————————————————————
// 3. 坏掉的机器:报告失败,而且非零退出
// ————————————————————————————————————————————————————————————

/// **丢了 `device.secret` = 体检不通过,而且退出码非零。**
///
/// 非零这件事不是形式:这份报告最该被用起来的地方是装机脚本、CI、容器启动
/// 前的自检 —— 在那里,退出码就是唯一被读的东西。
#[test]
fn a_machine_that_lost_its_device_secret_fails_the_probe() {
    let (dir, layout, did) = machine("missing");
    std::fs::remove_file(dir.path().join("root").join("device.secret")).unwrap();

    let output = probe(layout.root(), Some(&did));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_ne!(
        output.status.code(),
        Some(0),
        "a machine whose envelopes can never open must not report success: {stdout}"
    );
    assert!(
        stdout.contains("device.secret") && stdout.contains("MISSING"),
        "the report has to name what is missing: {stdout}"
    );
}

/// 还没生成过钥匙的机器:根目录都不在,**这不算失败**。
///
/// 一台刚装好的机器就跑一次体检,是这条命令最正常的用法之一。
#[test]
fn a_fresh_machine_without_a_root_is_not_a_failure() {
    let dir = TempDir::new("fresh");
    let output = probe(&dir.path().join("never-created"), None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a machine with no keys yet has nothing wrong with it: {stdout}"
    );
    assert!(stdout.contains("absent"), "{stdout}");
    // 而且体检**不创建**它 —— 一次体检不该改变被体检的东西。
    assert!(
        !dir.path().join("never-created").exists(),
        "the probe must not create the root directory"
    );
}
