//! In-process sliding-window rate limiter for auth / prepare routes (High #8/#12).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::domain::DomainError;

/// Per-principal quota: at most `limit` events inside `window`.
pub struct SlidingWindowLimiter {
    limit: u32,
    window: Duration,
    inner: Mutex<HashMap<String, Vec<Instant>>>,
}

impl SlidingWindowLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self { limit: limit.max(1), window, inner: Mutex::new(HashMap::new()) }
    }

    /// Defaults: 60 events / 60s per principal (auth routes + prepare).
    pub fn auth_defaults() -> Self {
        Self::new(60, Duration::from_secs(60))
    }

    /// Tighter prepare quota (anti-nonce / intent burn griefing).
    pub fn prepare_defaults() -> Self {
        Self::new(30, Duration::from_secs(60))
    }

    pub fn check(&self, principal: &str) -> Result<(), DomainError> {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = g.entry(principal.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() as u32 >= self.limit {
            return Err(DomainError::RequestRejected(format!(
                "rate limit exceeded for principal (max {}/{:?})",
                self.limit, self.window
            )));
        }
        entry.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_limit() {
        let lim = SlidingWindowLimiter::new(2, Duration::from_secs(60));
        lim.check("a").unwrap();
        lim.check("a").unwrap();
        assert!(lim.check("a").is_err());
        lim.check("b").unwrap();
    }
}
