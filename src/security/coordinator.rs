//! Bounded admission with reserved, priority management capacity.
use crate::error::{KeydError, Result};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};
#[derive(Default)]
struct State {
    busy: bool,
    data: usize,
    admin: usize,
}
pub struct Coordinator {
    state: Mutex<State>,
    ready: Condvar,
    data_capacity: usize,
    admin_capacity: usize,
    wait: Duration,
}
pub struct Permit<'a>(&'a Coordinator);
impl Default for Coordinator {
    fn default() -> Self {
        Self::new(&super::limits::Limits::default())
    }
}
impl Coordinator {
    pub fn new(limits: &super::limits::Limits) -> Self {
        Self {
            state: Mutex::new(State::default()),
            ready: Condvar::new(),
            data_capacity: limits.data_queue,
            admin_capacity: limits.admin_queue,
            wait: Duration::from_millis(limits.queue_millis),
        }
    }
    pub fn enter(&self, admin: bool) -> Result<Permit<'_>> {
        let denied = || KeydError::Misuse("RESOURCE_BUSY".into());
        let mut state = self.state.lock().map_err(|_| denied())?;
        if (admin && state.admin >= self.admin_capacity)
            || (!admin && state.data >= self.data_capacity)
        {
            return Err(denied());
        }
        if admin {
            state.admin += 1;
        } else {
            state.data += 1;
        }
        let end = Instant::now() + self.wait;
        while state.busy || (!admin && state.admin > 0) {
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if admin {
                    state.admin -= 1;
                } else {
                    state.data -= 1;
                }
                self.ready.notify_all();
                return Err(denied());
            }
            state = self
                .ready
                .wait_timeout(state, remaining)
                .map_err(|_| denied())?
                .0;
        }
        if admin {
            state.admin -= 1;
        } else {
            state.data -= 1;
        }
        state.busy = true;
        Ok(Permit(self))
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.busy = false;
            self.0.ready.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    fn waiting(c: &Coordinator, data: usize, admin: usize) {
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            {
                let s = c.state.lock().unwrap();
                if s.data == data && s.admin == admin {
                    return;
                }
            }
            assert!(Instant::now() < end, "coordinator waiter did not arrive");
            std::thread::yield_now();
        }
    }
    #[test]
    fn full_data_queue_preserves_priority_management_capacity() {
        let c = Arc::new(Coordinator::default());
        let active = c.enter(false).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let c = c.clone();
            let tx = tx.clone();
            workers.push(std::thread::spawn(move || {
                let _p = c.enter(false).unwrap();
                tx.send(false).unwrap();
            }));
        }
        waiting(&c, 8, 0);
        assert!(c.enter(false).is_err());
        let a = c.clone();
        let atx = tx.clone();
        workers.push(std::thread::spawn(move || {
            let _p = a.enter(true).unwrap();
            atx.send(true).unwrap();
        }));
        waiting(&c, 8, 1);
        drop(active);
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        for _ in 0..8 {
            assert!(!rx.recv_timeout(Duration::from_secs(1)).unwrap());
        }
        for worker in workers {
            worker.join().unwrap();
        }
    }
    #[test]
    fn queue_deadline_returns_capacity_without_stopping_service() {
        let c = Arc::new(Coordinator::default());
        let active = c.enter(false).unwrap();
        let a = c.clone();
        let thread = std::thread::spawn(move || a.enter(false).is_err());
        assert!(thread.join().unwrap());
        waiting(&c, 0, 0);
        drop(active);
        assert!(c.enter(true).is_ok());
        assert!(c.enter(false).is_ok());
    }
}
