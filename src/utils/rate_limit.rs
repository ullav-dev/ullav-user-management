/// In-memory per-IP rate limiter using a sliding-window (token-bucket) approach.
///
/// This is a per-process limiter — under multi-replica Kubernetes deployments,
/// each pod enforces limits independently. This is acceptable for Phase 2
/// (makes bulk registration/token-hammering expensive, not impossible at scale).
///
/// A shared Redis limiter can be swapped in later without changing call sites.
use dashmap::DashMap;
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

/// Shared rate limiter — cheaply cloneable (backed by an `Arc`).
#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<DashMap<String, IpState>>,
    max_requests: usize,
    window: Duration,
}

struct IpState {
    /// Timestamps of accepted requests within the window.
    timestamps: VecDeque<Instant>,
}

impl RateLimiter {
    /// Create a limiter that allows at most `max_requests` in `window`.
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: Arc::new(DashMap::new()),
            max_requests,
            window,
        }
    }

    /// Check and consume one request for `ip`. Returns `true` if allowed.
    pub fn check(&self, ip: &str) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);

        let mut entry = self.state.entry(ip.to_owned()).or_insert_with(|| IpState {
            timestamps: VecDeque::new(),
        });

        // Drop timestamps outside the window.
        while entry.timestamps.front().map(|t| *t < cutoff).unwrap_or(false) {
            entry.timestamps.pop_front();
        }

        if entry.timestamps.len() >= self.max_requests {
            return false;
        }

        entry.timestamps.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn allows_up_to_limit() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.check("1.2.3.4"));
        assert!(rl.check("1.2.3.4"));
        assert!(rl.check("1.2.3.4"));
        assert!(!rl.check("1.2.3.4"), "fourth request should be rejected");
    }

    #[test]
    fn different_ips_are_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        assert!(rl.check("1.2.3.4"));
        assert!(!rl.check("1.2.3.4"));
        assert!(rl.check("5.6.7.8"), "different IP should not be rate-limited");
    }

    #[test]
    fn window_expiry_allows_new_requests() {
        let rl = RateLimiter::new(1, Duration::from_millis(50));
        assert!(rl.check("1.2.3.4"));
        assert!(!rl.check("1.2.3.4"));
        std::thread::sleep(Duration::from_millis(60));
        assert!(rl.check("1.2.3.4"), "after window expired, request should be allowed again");
    }
}
