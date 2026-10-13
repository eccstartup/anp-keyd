//! 信封的落盘与读回。
//!
//! 这一层只做三件事:原子写、按指纹读、以及**确认文件自称的身份**。
//! 密码学不在这里 —— 这里读回来的东西仍然是加密的。

use std::fs;

use crate::error::{KeydError, Result};
use crate::keystore::layout::{self, KeydLayout, PUBLIC_FILE_MODE, SECRET_FILE_MODE};
use crate::keystore::record::WrappedKey;

/// 把一个信封写到 `keys/<thumbprint>.json`,权限 0600。
///
/// 已存在就**拒绝**(`KeyExists`)。覆写一个密钥信封是不可逆的:旧的那把
/// seed 只存在于这个文件里,盖掉就是永久丢失。
pub fn save_new(layout: &KeydLayout, wrapped: &WrappedKey) -> Result<()> {
    wrapped.validate()?;
    let path = layout.key_path(&wrapped.id.thumbprint)?;
    if path.exists() {
        return Err(KeydError::KeyExists(wrapped.id.thumbprint.clone()));
    }
    write(layout, wrapped)
}

/// 无条件写。旋转、迁移这类"我知道我在覆盖"的路径才用它。
pub fn write(layout: &KeydLayout, wrapped: &WrappedKey) -> Result<()> {
    wrapped.validate()?;
    let path = layout.key_path(&wrapped.id.thumbprint)?;
    let mut bytes = serde_json::to_vec_pretty(wrapped)?;
    let result = layout::write_atomic(&path, &bytes, SECRET_FILE_MODE);
    // 序列化出来的明文 JSON 里没有密钥材料,但没理由让它多留在内存里。
    zeroize::Zeroize::zeroize(&mut bytes);
    result
}

pub fn exists(layout: &KeydLayout, thumbprint: &str) -> bool {
    layout
        .key_path(thumbprint)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// 按指纹读回一个信封,并确认**文件名与文件内容说的是同一把钥匙**。
///
/// 这一条挡的是计划 M1 负例 C 的文件那一面:`cp A.json B.json` 之后,
/// 内容自洽(AAD 当然算得过),但 B 这个位置上是 A 的钥匙。守护进程只要
/// 按下标取钥匙,就会拿 A 的私钥去兑现 B 的 DID —— 必须在这里断掉。
///
/// 报 `Protocol` 而不是 `AadMismatch`:摘要本身没被改,是被搬了家。
/// "改名"和"改头"是两种事故,给两个不同的错才好查。
pub fn load(layout: &KeydLayout, thumbprint: &str) -> Result<WrappedKey> {
    let path = layout.key_path(thumbprint)?;
    if !path.exists() {
        return Err(KeydError::KeyNotFound(thumbprint.to_string()));
    }
    let bytes = layout::read_secret_file(&path)?;
    let wrapped: WrappedKey = serde_json::from_slice(&bytes)
        .map_err(|e| KeydError::Protocol(format!("{} is not a readable envelope: {e}", path.display())))?;

    wrapped.validate()?;
    if wrapped.id.thumbprint != thumbprint {
        return Err(KeydError::Protocol(format!(
            "{} was renamed: it contains {}'s key, not {thumbprint}'s",
            path.display(),
            wrapped.id.thumbprint
        )));
    }
    Ok(wrapped)
}

/// 读出所有信封,按指纹排序。
///
/// 读不懂的文件**不跳过** —— 静默略过等于让用户以为自己的钥匙不见了。
pub fn load_all(layout: &KeydLayout) -> Result<Vec<WrappedKey>> {
    let mut out = Vec::new();
    for path in layout.list_key_paths()? {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| KeydError::Protocol(format!("odd envelope filename: {}", path.display())))?;
        out.push(load(layout, stem)?);
    }
    out.sort_by(|a, b| a.id.thumbprint.cmp(&b.id.thumbprint));
    Ok(out)
}

/// 删掉一个信封。这是不可逆的 —— 调用方负责先确认用户真的要这么做。
pub fn delete(layout: &KeydLayout, thumbprint: &str) -> Result<()> {
    let path = layout.key_path(thumbprint)?;
    fs::remove_file(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            KeydError::KeyNotFound(thumbprint.to_string())
        } else {
            KeydError::Io(e)
        }
    })
}

/// 写一份可公开的 DID 文档(0644)。
pub fn write_did_document(layout: &KeydLayout, did: &str, doc: &serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(doc)?;
    let result = layout::write_atomic(&layout.did_path(did), &bytes, PUBLIC_FILE_MODE);
    zeroize::Zeroize::zeroize(&mut bytes);
    result
}

pub fn read_did_document(layout: &KeydLayout, did: &str) -> Result<serde_json::Value> {
    let path = layout.did_path(did);
    let bytes = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            KeydError::KeyNotFound(did.to_string())
        } else {
            KeydError::Io(e)
        }
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::crypto::kdf::Argon2Config;
    use crate::keystore::record::{KeyAlgorithm, KeyId};
    use crate::keystore::wrap::{seal, seed_to_public, SealRequest};

    fn fast() -> Argon2Config {
        Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    fn layout(name: &str) -> KeydLayout {
        let dir = std::env::temp_dir().join(format!("keyd-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let l = KeydLayout::at(dir);
        l.ensure().unwrap();
        l
    }

    fn envelope(thumbprint: &str) -> WrappedKey {
        let seed = LockedBytes::fill(|d| *d = [0x11; 32]).unwrap();
        let (_, multibase) = seed_to_public(&seed);
        let did = format!("did:wba:example.com:user:alice:{thumbprint}");
        let device = LockedBytes::fill(|d| *d = [0x22; 32]).unwrap();
        seal(SealRequest {
            id: KeyId { did: did.clone(), kid: format!("{did}#key-1"), thumbprint: thumbprint.into() },
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: multibase,
            label: "alice".into(),
            passphrase: b"pw",
            device_secret: &device,
            seed: &seed,
            argon: fast(),
        })
        .unwrap()
    }

    #[test]
    fn save_load_roundtrip() {
        let l = layout("roundtrip");
        let w = envelope("e1_one");
        save_new(&l, &w).unwrap();

        let back = load(&l, "e1_one").unwrap();
        assert_eq!(back.id.thumbprint, "e1_one");
        assert_eq!(back.public_multibase, w.public_multibase);
        assert!(back.verify_aad().is_ok());

        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn save_new_refuses_to_overwrite_a_live_key() {
        let l = layout("overwrite");
        save_new(&l, &envelope("e1_one")).unwrap();
        assert!(matches!(
            save_new(&l, &envelope("e1_one")),
            Err(KeydError::KeyExists(_))
        ));
        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn missing_key_is_key_not_found() {
        let l = layout("missing");
        assert!(matches!(load(&l, "e1_nope"), Err(KeydError::KeyNotFound(_))));
        let _ = fs::remove_dir_all(l.root());
    }

    /// 计划 M1 负例 C 的文件那一面:把 A 的信封复制成 B 的名字。
    #[test]
    fn a_renamed_envelope_is_refused_even_though_its_aad_still_checks_out() {
        let l = layout("renamed");
        let a = envelope("e1_aaa");
        save_new(&l, &a).unwrap();

        let b_path = l.key_path("e1_bbb").unwrap();
        fs::copy(l.key_path("e1_aaa").unwrap(), &b_path).unwrap();
        fs::set_permissions(&b_path, fs::Permissions::from_mode(0o600)).unwrap();

        // 内容本身是自洽的 —— 这正是危险之处。
        let raw: WrappedKey = serde_json::from_slice(&fs::read(&b_path).unwrap()).unwrap();
        assert!(raw.verify_aad().is_ok(), "the copied file is internally consistent");

        // 但按 B 的名字取,必须被拒。
        assert!(matches!(load(&l, "e1_bbb"), Err(KeydError::Protocol(_))));

        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn load_all_refuses_to_silently_skip_a_broken_file() {
        let l = layout("broken");
        save_new(&l, &envelope("e1_aaa")).unwrap();
        fs::write(l.key_path("e1_bad").unwrap(), b"{ not json").unwrap();

        assert!(
            load_all(&l).is_err(),
            "a key file we cannot read must not be silently ignored"
        );
        let _ = fs::remove_dir_all(l.root());
    }

    #[test]
    fn load_all_is_sorted_and_complete() {
        let l = layout("all");
        for t in ["e1_ccc", "e1_aaa", "e1_bbb"] {
            save_new(&l, &envelope(t)).unwrap();
        }
        let all = load_all(&l).unwrap();
        let stems: Vec<_> = all.iter().map(|w| w.id.thumbprint.as_str()).collect();
        assert_eq!(stems, ["e1_aaa", "e1_bbb", "e1_ccc"]);
        let _ = fs::remove_dir_all(l.root());
    }

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn did_documents_land_world_readable() {
        let l = layout("did");
        let did = "did:wba:example.com:user:alice:e1_one";
        write_did_document(&l, did, &serde_json::json!({"id": did})).unwrap();

        let mode = fs::metadata(l.did_path(did)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, PUBLIC_FILE_MODE);
        assert_eq!(read_did_document(&l, did).unwrap()["id"], did);

        let _ = fs::remove_dir_all(l.root());
    }
}
