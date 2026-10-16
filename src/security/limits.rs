use crate::error::{KeydError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub data_connections: usize,
    pub admin_connections: usize,
    pub principal_connections: usize,
    pub data_queue: usize,
    pub admin_queue: usize,
    pub queue_millis: u64,
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
            principal_connections: 4,
            data_queue: 8,
            admin_queue: 2,
            queue_millis: 2000,
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
            || !(1..=self.data_connections).contains(&self.principal_connections)
            || !(1..=64).contains(&self.data_queue)
            || !(2..=16).contains(&self.admin_queue)
            || !(1..=5000).contains(&self.queue_millis)
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
/// RAII limits cover reading, queueing, execution and response writing.
#[derive(Default)]
pub struct Connections(std::sync::Mutex<BTreeMap<u32, usize>>);
pub struct ConnectionPermit<'a> {
    owner: &'a Connections,
    uid: u32,
}
impl Connections {
    pub fn enter(&self, uid: u32, limit: usize) -> Result<ConnectionPermit<'_>> {
        let mut counts = self
            .0
            .lock()
            .map_err(|_| KeydError::Misuse("RESOURCE_BUSY".into()))?;
        let count = counts.entry(uid).or_default();
        if *count >= limit {
            return Err(KeydError::Misuse("RESOURCE_BUSY".into()));
        }
        *count += 1;
        Ok(ConnectionPermit { owner: self, uid })
    }
}
impl Drop for ConnectionPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.owner.0.lock() {
            if let Some(count) = counts.get_mut(&self.uid) {
                *count -= 1;
                if *count == 0 {
                    counts.remove(&self.uid);
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slow_principal_cannot_take_other_principal_slots() {
        let c = Connections::default();
        let a = c.enter(1001, 1).unwrap();
        assert!(c.enter(1001, 1).is_err());
        assert!(c.enter(1002, 1).is_ok());
        drop(a);
        assert!(c.enter(1001, 1).is_ok());
    }
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
