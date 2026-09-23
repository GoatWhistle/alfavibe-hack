//! Ограничение частоты запросов по системам (OPS-03): токенное ведро.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Токенное ведро для одной системы.
struct Bucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl Bucket {
    fn new(rps: u64) -> Self {
        let capacity = rps as f64;
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec: rps as f64,
            last: Instant::now(),
        }
    }

    /// Пытается взять один токен. Возвращает время ожидания до следующего токена.
    fn try_take(&mut self) -> Option<Duration> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            None
        } else {
            let wait = (1.0 - self.tokens) / self.refill_per_sec;
            Some(Duration::from_secs_f64(wait))
        }
    }
}

/// Реестр ведёр по системам.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Проверяет, можно ли пропустить запрос системы.
    /// Возвращает Ok(()) если можно, Err(retry_after) если превышен лимит.
    pub fn check(&self, system_id: &str, rps: u64) -> Result<(), Duration> {
        if rps == 0 {
            return Ok(());
        }
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets
            .entry(system_id.to_string())
            .or_insert_with(|| Bucket::new(rps));
        match bucket.try_take() {
            None => Ok(()),
            Some(wait) => Err(wait),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_rps() {
        let limiter = RateLimiter::new();
        // 3 RPS: первые 3 проходят, 4-й отклоняется.
        assert!(limiter.check("sys", 3).is_ok());
        assert!(limiter.check("sys", 3).is_ok());
        assert!(limiter.check("sys", 3).is_ok());
        assert!(limiter.check("sys", 3).is_err());
    }

    #[test]
    fn separate_buckets_per_system() {
        let limiter = RateLimiter::new();
        assert!(limiter.check("a", 1).is_ok());
        assert!(limiter.check("a", 1).is_err());
        assert!(limiter.check("b", 1).is_ok());
    }
}