//! 内存卫生:密钥材料在内存中的生存方式。
//!
//! 计划 §七 的两条硬要求在这里落实:
//!
//! 1. **预分配,不许 realloc。** 密钥容器一次到位,绝不扩容 —— `Vec` 扩容会把旧块
//!    留在分配器里且不再被擦。这里用 `ShroudedArray<32>`(定长)而非 `Vec`。
//! 2. **不给 `Clone`、不给 `Serialize`、不给 `Display`。** 唯一下的出口是
//!    `expose()`,它借用一个闭包,所以引用无法逃逸。

use shrouded::{Expose, Policy, ShroudBuilder};
use zeroize::Zeroize;

use crate::error::{KeydError, Result};

/// 32 字节的锁定缓冲。
///
/// 底层由 `shrouded` 用 `mlock` 锁页(不许换出到 swap)并加 guard page;
/// `Drop` 时擦除并 `munlock`。
///
/// **core dump 那一层只挡得住在 Linux 上。** `MADV_DONTDUMP` 是 Linux 才有的
/// 系统调用,`shrouded` 里那一段是 `#[cfg(target_os = "linux")]` —— 在 macOS
/// 上它整个不编译,这一层就只剩 `RLIMIT_CORE` 挡在中间。所以别把"锁定区不进
/// dump"当成跨平台成立的话(`ops::probe` 会把这两件事分开报,并且在不成立的
/// 平台上让体检不通过)。
///
/// 采用 `Policy::Strict`:拿不到内存保护就**失败**,不静默降级。对一个
/// "私钥不留痕"是唯一产品承诺的工具,降级后的成功比失败更危险。
pub struct LockedBytes(ShroudedArray32);

// `ShroudedArray` 是实现细节,不该出现在本 crate 的公开接口上,
// 也不该被 `Clone` / `Serialize`。
type ShroudedArray32 = shrouded::ShroudedArray<32>;

impl LockedBytes {
    /// 从一段明文搬进锁定区,并**擦除来源**。
    pub fn new(src: &mut [u8; 32]) -> Result<Self> {
        let inner = Self::fill(|dst| dst.copy_from_slice(src))?;
        src.zeroize();
        Ok(inner)
    }

    /// 直接用 CSPRNG 填一个锁定区 —— 明文只在锁定内存里出现过。
    ///
    /// 生成 `device.secret` 和 seed 都走这条路:先 `new()` 一个栈上数组再搬,
    /// 那段栈内存会在函数返回后留在栈上。
    pub fn generate() -> Result<Self> {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        Self::fill(|dst| rng.fill_bytes(dst))
    }

    /// 用闭包直接初始化锁定区,中间不产生普通堆/栈副本。
    pub fn fill<F>(f: F) -> Result<Self>
    where
        F: FnOnce(&mut [u8; 32]),
    {
        let inner = ShroudBuilder::new()
            .policy(Policy::Strict)
            .build_array_with::<32, _>(f)
            .map_err(|e| KeydError::Crypto(format!("memory protection failed: {e}")))?;
        Ok(Self(inner))
    }

    /// 借出密钥,不许带走。
    ///
    /// 闭包形式(而非返回 `&[u8; 32]`)是刻意的:引用无法逃逸到调用方,
    /// 所以密钥不能被抓进一个长生命周期的结构体、不能被日志打出来。
    pub fn expose<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(self.0.expose())
    }
}

impl std::fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 永不打印内容。
        f.write_str("LockedBytes(<protected>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_and_zeroizes_source() {
        let mut src = [7u8; 32];
        let locked = LockedBytes::new(&mut src).unwrap();
        // 来源必须已被擦除。
        assert_eq!(src, [0u8; 32], "source must be zeroized after moving in");
        locked.expose(|k| assert_eq!(k, &[7u8; 32]));
    }

    #[test]
    fn generated_secrets_differ() {
        let a = LockedBytes::generate().unwrap();
        let b = LockedBytes::generate().unwrap();
        let same = a.expose(|x| b.expose(|y| x == y));
        assert!(!same, "two generated secrets must not collide");
    }

    #[test]
    fn debug_never_leaks_bytes() {
        let locked = LockedBytes::fill(|d| *d = [0xAB; 32]).unwrap();
        let rendered = format!("{locked:?}");
        assert!(!rendered.contains("ab") && !rendered.contains("171"));
    }
}
