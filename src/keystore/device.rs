//! `device.secret` —— 2SKD 里的第二把钥匙。
//!
//! 它是 32 字节随机数,**不是**从口令派生的。磁盘上没有它,口令再对也推不出
//! KEK;有它没口令,同样推不出。它防的正是"谁能读备份,谁就能拿到私钥"。

use zeroize::Zeroize;

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};
use crate::keystore::layout::{self, KeydLayout, SECRET_FILE_MODE};

/// 设备密钥的长度。固定 32 字节,多一个少一个都算坏文件。
const DEVICE_SECRET_LEN: usize = 32;

/// 读设备密钥。
///
/// **文件不存在是 `BadDeviceSecret`,不是"顺手生成一个"** —— 如果这里悄悄
/// 生成,用户删掉 `device.secret` 之后会得到"口令错误"这种误导性的报错,
/// 而且会用一把新的设备密钥去解密一把旧的钥匙。永远失败,永远说清楚。
pub fn load(layout: &KeydLayout) -> Result<LockedBytes> {
    let path = layout.device_secret_path();
    if !path.exists() {
        return Err(KeydError::BadDeviceSecret);
    }

    let mut raw = layout::read_secret_file(&path)?;
    if raw.len() != DEVICE_SECRET_LEN {
        raw.zeroize();
        return Err(KeydError::BadDeviceSecret);
    }

    let mut buf = [0u8; DEVICE_SECRET_LEN];
    buf.copy_from_slice(&raw);
    raw.zeroize();

    LockedBytes::new(&mut buf)
}

/// 首次运行时生成并落盘。
///
/// **只允许 `init` / `create` / `import` 这类"建立"路径调用。** 签名路径上
/// 绝不能出现这个函数,否则就等于给"设备密钥丢了"准备了一个静默的假成功。
pub fn load_or_create(layout: &KeydLayout) -> Result<LockedBytes> {
    if layout.device_secret_path().exists() {
        return load(layout);
    }

    let secret = LockedBytes::generate()?;
    secret.expose(|bytes| {
        layout::write_atomic(&layout.device_secret_path(), bytes, SECRET_FILE_MODE)
    })?;
    Ok(secret)
}

pub fn exists(layout: &KeydLayout) -> bool {
    layout.device_secret_path().exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> KeydLayout {
        let dir = std::env::temp_dir().join(format!("keyd-device-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = KeydLayout::at(dir);
        layout.ensure().unwrap();
        layout
    }

    #[test]
    fn create_is_stable_and_load_reads_it_back() {
        let layout = scratch("stable");
        let first = load_or_create(&layout).unwrap();
        let second = load(&layout).unwrap();

        let same = first.expose(|a| second.expose(|b| a == b));
        assert!(same, "load must return the same secret load_or_create wrote");

        let _ = std::fs::remove_dir_all(layout.root());
    }

    #[test]
    fn load_or_create_does_not_regenerate() {
        let layout = scratch("noregen");
        let first = load_or_create(&layout).unwrap();
        let again = load_or_create(&layout).unwrap();
        let same = first.expose(|a| again.expose(|b| a == b));
        assert!(same, "a second call must not mint a new device secret");

        let _ = std::fs::remove_dir_all(layout.root());
    }

    /// 计划 M1 负例 B:给对的口令、但删掉 `device.secret` → `BadDeviceSecret`。
    #[test]
    fn deleting_the_file_yields_bad_device_secret() {
        let layout = scratch("missing");
        let _ = load_or_create(&layout).unwrap();
        std::fs::remove_file(layout.device_secret_path()).unwrap();

        assert!(matches!(load(&layout), Err(KeydError::BadDeviceSecret)));

        let _ = std::fs::remove_dir_all(layout.root());
    }

    #[test]
    fn truncated_file_yields_bad_device_secret() {
        let layout = scratch("truncated");
        layout::write_atomic(&layout.device_secret_path(), &[0u8; 16], SECRET_FILE_MODE).unwrap();
        assert!(matches!(load(&layout), Err(KeydError::BadDeviceSecret)));

        let _ = std::fs::remove_dir_all(layout.root());
    }

    #[test]
    fn world_readable_device_secret_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let layout = scratch("perms");
        let _ = load_or_create(&layout).unwrap();
        std::fs::set_permissions(
            layout.device_secret_path(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(load(&layout).is_err());

        let _ = std::fs::remove_dir_all(layout.root());
    }
}
