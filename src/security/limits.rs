use crate::error::{KeydError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub data_connections: usize,
    pub admin_connections: usize,
    pub frame_seconds: u64,
    pub response_seconds: u64,
    pub principal_burst: u32,
    pub principal_per_second: u32,
    pub database_max_pages: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            data_connections: 16,
            admin_connections: 4,
            frame_seconds: 5,
            response_seconds: 5,
            principal_burst: 64,
            principal_per_second: 32,
            database_max_pages: 262144,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=64).contains(&self.data_connections)
            || !(3..=16).contains(&self.admin_connections)
            || !(1..=30).contains(&self.frame_seconds)
            || !(1..=30).contains(&self.response_seconds)
            || !(1..=1024).contains(&self.principal_burst)
            || !(1..=1024).contains(&self.principal_per_second)
            || !(256..=1048576).contains(&self.database_max_pages)
        {
            return Err(KeydError::Misuse(
                "invalid protected resource limits".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct RateLimit(BTreeMap<String, (u64, i64)>);
impl RateLimit {
    pub fn accept(&mut self, principal: &str, now: i64, limits: &Limits) -> bool {
        // Expire inactive entries so UID registration churn cannot grow memory forever.
        self.0
            .retain(|_, (_, last)| now.saturating_sub(*last) < 60_000);
        if !self.0.contains_key(principal) && self.0.len() >= 4096 {
            return false;
        }
        let cap = u64::from(limits.principal_burst) * 1000;
        let entry = self.0.entry(principal.into()).or_insert((cap, now));
        entry.0 = entry
            .0
            .saturating_add(
                now.saturating_sub(entry.1).max(0) as u64 * u64::from(limits.principal_per_second),
            )
            .min(cap);
        entry.1 = now;
        if entry.0 < 1000 {
            false
        } else {
            entry.0 -= 1000;
            true
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_are_finite_and_rates_are_per_principal() {
        let mut l = Limits::default();
        l.validate().unwrap();
        l.principal_burst = 2;
        l.principal_per_second = 1;
        let mut r = RateLimit::default();
        assert!(r.accept("a", 0, &l));
        assert!(r.accept("a", 0, &l));
        assert!(!r.accept("a", 0, &l));
        assert!(r.accept("b", 0, &l));
        assert!(r.accept("a", 1000, &l));
        l.database_max_pages = 0;
        assert!(l.validate().is_err());
    }
}
