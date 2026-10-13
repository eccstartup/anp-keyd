//! 解锁超时。
//!
//! 一条**空闲**超时:每次用一把钥匙,它的计时就重新开始;搁着不用满
//! `idle`,它自己回到锁定。
//!
//! 为什么是空闲超时而不是绝对超时:解锁是**人的动作**。绝对超时会在一个
//! 长跑的 agent 会话中间把钥匙收走,而那个 agent 没有任何办法再去敲一次
//! 人的口令 —— 它能做的只有失败。空闲超时收走的是"没人用"的钥匙,
//! 那恰恰是我们想收的那一类。
//!
//! 这一模块只判断"该不该锁",不管谁在锁、锁什么。判断是纯函数,
//! 于是它可以被穷举式地测,而不需要真的等上几个小时。

use std::time::Duration;

/// 默认空闲超时。15 分钟 —— 和 1Password 的默认自动锁定一个量级。
pub const DEFAULT_IDLE: Duration = Duration::from_secs(15 * 60);

/// 空闲多久之后自动锁。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Autolock {
    idle: Duration,
}

impl Default for Autolock {
    fn default() -> Self {
        Self { idle: DEFAULT_IDLE }
    }
}

impl Autolock {
    pub fn idle(idle: Duration) -> Self {
        Self { idle }
    }

    pub fn idle_duration(&self) -> Duration {
        self.idle
    }

    /// 从不用钥匙起算,过了 `idle` 就该锁。
    ///
    /// `idle == 0` 是合法的,意思是"用完就锁" —— **不是**"永不锁"。
    /// 这个方向上的歧义很危险:把 0 读成"关掉自动锁",就是把一个想
    /// 收紧的人静悄悄地放松了。
    pub fn is_expired(&self, idle_for: Duration) -> bool {
        idle_for >= self.idle
    }

    /// 还剩多久失效。已经过期就是 0。
    pub fn remaining(&self, idle_for: Duration) -> Duration {
        self.idle.saturating_sub(idle_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_that_has_been_idle_past_the_limit_is_expired() {
        let lock = Autolock::idle(Duration::from_secs(60));
        assert!(!lock.is_expired(Duration::from_secs(59)));
        // 边界上算过期 —— 宁可早锁一秒,不可晚锁一秒。
        assert!(lock.is_expired(Duration::from_secs(60)));
        assert!(lock.is_expired(Duration::from_secs(3600)));
    }

    #[test]
    fn a_key_that_is_still_being_used_survives() {
        let lock = Autolock::idle(Duration::from_secs(60));
        for uses in 0..100 {
            let idle = Duration::from_secs(uses % 59);
            assert!(!lock.is_expired(idle), "{idle:?}");
        }
    }

    /// 0 是"用完就锁",不是"永不锁"。方向别搞反 —— 把想收紧的人放松,
    /// 是这类开关最容易出的错。
    #[test]
    fn zero_means_lock_immediately_not_never() {
        let lock = Autolock::idle(Duration::ZERO);
        assert!(lock.is_expired(Duration::ZERO));
        assert!(lock.is_expired(Duration::from_secs(1)));
    }

    #[test]
    fn remaining_counts_down_and_never_underflows() {
        let lock = Autolock::idle(Duration::from_secs(60));
        assert_eq!(lock.remaining(Duration::ZERO), Duration::from_secs(60));
        assert_eq!(lock.remaining(Duration::from_secs(59)), Duration::from_secs(1));
        assert_eq!(lock.remaining(Duration::from_secs(60)), Duration::ZERO);
        assert_eq!(lock.remaining(Duration::from_secs(9999)), Duration::ZERO);
    }

    #[test]
    fn the_default_is_a_quarter_of_an_hour() {
        assert_eq!(Autolock::default().idle_duration(), DEFAULT_IDLE);
    }
}
