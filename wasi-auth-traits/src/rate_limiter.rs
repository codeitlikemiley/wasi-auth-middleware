use crate::{AuthError, RateLimiter};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// A thread-safe, in-memory implementation of the `RateLimiter` trait.
///
/// Tracks attempts using lists of Unix timestamps for each key and action combination.
/// Automatically cleans up expired timestamps upon action recording to prevent memory growth.
#[derive(Debug)]
pub struct InMemoryRateLimiter {
    history: RwLock<HashMap<String, Vec<u64>>>,
    window_secs: u64,
    limits: HashMap<String, u32>,
    default_limit: u32,
}

impl Default for InMemoryRateLimiter {
    fn default() -> Self {
        let mut limits = HashMap::new();
        limits.insert("send_otp".to_string(), 5);
        limits.insert("verify_otp".to_string(), 10);
        Self {
            history: RwLock::new(HashMap::new()),
            window_secs: 900, // 15 minutes
            limits,
            default_limit: 100,
        }
    }
}

impl InMemoryRateLimiter {
    /// Creates a new `InMemoryRateLimiter` with custom window duration and default limits.
    pub fn new(window_secs: u64, default_limit: u32) -> Self {
        Self {
            history: RwLock::new(HashMap::new()),
            window_secs,
            limits: HashMap::new(),
            default_limit,
        }
    }

    /// Configures a custom limit for a specific action name.
    pub fn with_limit(mut self, action: &str, limit: u32) -> Self {
        self.limits.insert(action.to_string(), limit);
        self
    }

    fn get_now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl RateLimiter for InMemoryRateLimiter {
    fn check_rate_limit(&self, key: &str, action: &str) -> Result<bool, AuthError> {
        let now = self.get_now();
        let map_key = format!("{}:{}", key, action);
        let limit = self
            .limits
            .get(action)
            .copied()
            .unwrap_or(self.default_limit);

        let read_guard = self.history.read().map_err(|e| {
            AuthError::Storage(format!("Failed to acquire rate limiter read lock: {}", e))
        })?;

        if let Some(timestamps) = read_guard.get(&map_key) {
            let cutoff = now.saturating_sub(self.window_secs);
            let valid_attempts = timestamps.iter().filter(|&&t| t > cutoff).count();
            Ok(valid_attempts < limit as usize)
        } else {
            Ok(true)
        }
    }

    fn record_action(&self, key: &str, action: &str) -> Result<(), AuthError> {
        let now = self.get_now();
        let map_key = format!("{}:{}", key, action);

        let mut write_guard = self.history.write().map_err(|e| {
            AuthError::Storage(format!("Failed to acquire rate limiter write lock: {}", e))
        })?;

        let entry = write_guard.entry(map_key).or_insert_with(Vec::new);
        entry.push(now);

        // Clean up timestamps outside the sliding window
        let cutoff = now.saturating_sub(self.window_secs);
        entry.retain(|&t| t > cutoff);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_rate_limiter_basics() {
        let limiter = InMemoryRateLimiter::new(1, 2); // 1-second window, limit 2

        assert!(limiter.check_rate_limit("user1", "login").unwrap());
        limiter.record_action("user1", "login").unwrap();

        assert!(limiter.check_rate_limit("user1", "login").unwrap());
        limiter.record_action("user1", "login").unwrap();

        // 3rd attempt should be rate limited
        assert!(!limiter.check_rate_limit("user1", "login").unwrap());

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Should be allowed again
        assert!(limiter.check_rate_limit("user1", "login").unwrap());
    }

    #[test]
    fn test_rate_limiter_custom_limits() {
        let limiter = InMemoryRateLimiter::default(); // default limits: send_otp = 5, verify_otp = 10

        for _ in 0..5 {
            assert!(
                limiter
                    .check_rate_limit("user@test.com", "send_otp")
                    .unwrap()
            );
            limiter.record_action("user@test.com", "send_otp").unwrap();
        }
        assert!(
            !limiter
                .check_rate_limit("user@test.com", "send_otp")
                .unwrap()
        );

        for _ in 0..10 {
            assert!(
                limiter
                    .check_rate_limit("user@test.com", "verify_otp")
                    .unwrap()
            );
            limiter
                .record_action("user@test.com", "verify_otp")
                .unwrap();
        }
        assert!(
            !limiter
                .check_rate_limit("user@test.com", "verify_otp")
                .unwrap()
        );
    }
}
