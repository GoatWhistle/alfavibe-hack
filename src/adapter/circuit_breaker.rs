//! Circuit breaker.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Состояние circuit breaker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

/// Circuit breaker для зависимостей (NER, vault, upstream).
pub struct CircuitBreaker {
    failure_ratio: f64,
    window: usize,
    open_seconds: u64,
    state: AtomicU32,
    failures: AtomicU32,
    total: AtomicU32,
    opened_at: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(failure_ratio: f64, window: usize, open_seconds: u64) -> Self {
        Self {
            failure_ratio,
            window,
            open_seconds,
            state: AtomicU32::new(CircuitState::Closed as u32),
            failures: AtomicU32::new(0),
            total: AtomicU32::new(0),
            opened_at: AtomicU64::new(0),
        }
    }

    /// Проверяет, можно ли выполнять запрос.
    pub fn allow(&self) -> bool {
        match self.state() {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                let opened = self.opened_at.load(Ordering::Relaxed);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                if now_ms.saturating_sub(opened) >= self.open_seconds * 1000 {
                    self.state.store(CircuitState::HalfOpen as u32, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn state(&self) -> CircuitState {
        match self.state.load(Ordering::Relaxed) {
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    /// Регистрирует результат запроса.
    pub fn record(&self, success: bool) {
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        if !success {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        if total >= self.window as u32 {
            let failures = self.failures.swap(0, Ordering::Relaxed);
            self.total.store(0, Ordering::Relaxed);
            let ratio = failures as f64 / total as f64;
            if ratio >= self.failure_ratio {
                self.open();
            }
        }
    }

    fn open(&self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.opened_at.store(now_ms, Ordering::Relaxed);
        self.state.store(CircuitState::Open as u32, Ordering::Relaxed);
    }
}

/// Обёртка для Arc<CircuitBreaker>.
pub type SharedCircuitBreaker = Arc<CircuitBreaker>;