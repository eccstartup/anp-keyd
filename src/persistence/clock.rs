use crate::error::{KeydError, Result};

#[derive(Debug, Clone, Copy)]
pub struct Time {
    pub wall: i64,
    pub monotonic_ms: i64,
}

pub trait Clock {
    fn now(&self) -> Result<Time>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<Time> {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| KeydError::Misuse("wall clock predates epoch".into()))?
            .as_secs();
        #[cfg(target_os = "linux")]
        let monotonic_ms = {
            let mut value = nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // CLOCK_BOOTTIME includes suspend; pointer is valid for the syscall.
            if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_BOOTTIME, &mut value) } != 0 {
                return Err(KeydError::Misuse("CLOCK_BOOTTIME unavailable".into()));
            }
            value
                .tv_sec
                .checked_mul(1000)
                .and_then(|s| s.checked_add(value.tv_nsec / 1_000_000))
                .ok_or_else(|| KeydError::Misuse("monotonic clock overflow".into()))?
        };
        #[cfg(not(target_os = "linux"))]
        let monotonic_ms = {
            static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            i64::try_from(
                START
                    .get_or_init(std::time::Instant::now)
                    .elapsed()
                    .as_millis(),
            )
            .map_err(|_| KeydError::Misuse("monotonic clock overflow".into()))?
        };
        Ok(Time {
            wall: i64::try_from(wall)
                .map_err(|_| KeydError::Misuse("wall clock overflow".into()))?,
            monotonic_ms,
        })
    }
}
