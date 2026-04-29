// ============================================================================
// File: rate_governor.rs
// Description: Adaptive per-IP rate limiter with token bucket and escalation levels

// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! Rate Governor — Adaptive rate limiting with behavioral escalation.
//!
//! Uses a token bucket algorithm per-IP with automatic escalation:
//! well-behaved clients get full capacity; repeat violators get progressively
//! restricted up to temporary bans.

use crate::config::RateConfig;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationLevel {
    None,
    Warn,
    Throttle,
    Block,
    Ban,
}

#[derive(Debug)]
pub struct RateCheckResult {
    /// Whether the request is allowed to proceed.
    pub allowed: bool,
    /// Current escalation level for this client.
    pub escalation: EscalationLevel,
    /// Remaining tokens in the bucket.
    pub remaining: f64,
    /// Seconds until ban expires (only set for EscalationLevel::Ban).
    pub retry_after: Option<u64>,
    /// Total violation count for this IP.
    pub violations: u32,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
    violations: u32,
    last_violation: Option<Instant>,
    ban_until: Option<Instant>,
}

impl TokenBucket {
    fn new(config: &RateConfig) -> Self {
        Self {
            tokens: config.burst_capacity,
            max_tokens: config.burst_capacity,
            refill_rate: config.requests_per_second,
            last_refill: Instant::now(),
            violations: 0,
            last_violation: None,
            ban_until: None,
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn decay_violations(&mut self, decay_secs: u64) {
        if let Some(last) = self.last_violation {
            let elapsed = last.elapsed().as_secs();
            if elapsed > decay_secs && self.violations > 0 {
                // Decay one violation per decay period
                let decay_count = (elapsed / decay_secs) as u32;
                self.violations = self.violations.saturating_sub(decay_count);
                if self.violations == 0 {
                    self.last_violation = None;
                }
            }
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            self.violations += 1;
            self.last_violation = Some(Instant::now());
            false
        }
    }

    fn escalation_level(&self, config: &RateConfig) -> EscalationLevel {
        if self.violations >= config.ban_after {
            EscalationLevel::Ban
        } else if self.violations >= config.block_after {
            EscalationLevel::Block
        } else if self.violations >= config.throttle_after {
            EscalationLevel::Throttle
        } else if self.violations >= config.warn_after {
            EscalationLevel::Warn
        } else {
            EscalationLevel::None
        }
    }
}

pub struct RateGovernor {
    config: RateConfig,
    buckets: RwLock<HashMap<String, TokenBucket>>,
}

impl RateGovernor {
    pub fn new(config: &crate::config::ShieldConfig) -> Self {
        Self {
            config: config.rate.clone(),
            buckets: RwLock::new(HashMap::new()),
        }
    }

    pub fn check(&self, client_ip: &str) -> RateCheckResult {
        let mut buckets = self.buckets.write();
        let bucket = buckets
            .entry(client_ip.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config));

        // Decay old violations
        bucket.decay_violations(self.config.violation_decay_secs);

        // Check for active ban
        if let Some(ban_until) = bucket.ban_until {
            if Instant::now() < ban_until {
                let retry_after = ban_until.duration_since(Instant::now()).as_secs();
                return RateCheckResult {
                    allowed: false,
                    escalation: EscalationLevel::Ban,
                    remaining: 0.0,
                    retry_after: Some(retry_after),
                    violations: bucket.violations,
                };
            } else {
                // Ban expired — clear it but keep violation count for escalation
                bucket.ban_until = None;
            }
        }

        let consumed = bucket.try_consume();
        let escalation = bucket.escalation_level(&self.config);

        // Apply ban if escalation reaches Ban level
        if escalation == EscalationLevel::Ban && bucket.ban_until.is_none() {
            bucket.ban_until =
                Some(Instant::now() + Duration::from_secs(self.config.ban_duration_secs));
            return RateCheckResult {
                allowed: false,
                escalation: EscalationLevel::Ban,
                remaining: 0.0,
                retry_after: Some(self.config.ban_duration_secs),
                violations: bucket.violations,
            };
        }

        let allowed = match escalation {
            EscalationLevel::None | EscalationLevel::Warn => consumed,
            EscalationLevel::Throttle => {
                // Throttled: only allow if bucket is at least 50% full
                consumed && bucket.tokens > bucket.max_tokens * 0.5
            }
            EscalationLevel::Block | EscalationLevel::Ban => false,
        };

        RateCheckResult {
            allowed,
            escalation,
            remaining: bucket.tokens,
            retry_after: None,
            violations: bucket.violations,
        }
    }

    /// Get the current escalation level for an IP without consuming a token.
    pub fn peek_escalation(&self, client_ip: &str) -> EscalationLevel {
        let buckets = self.buckets.read();
        buckets
            .get(client_ip)
            .map(|b| b.escalation_level(&self.config))
            .unwrap_or(EscalationLevel::None)
    }

    /// Manually ban an IP address for the configured ban duration.
    pub fn ban_ip(&self, client_ip: &str) {
        let mut buckets = self.buckets.write();
        let bucket = buckets
            .entry(client_ip.to_string())
            .or_insert_with(|| TokenBucket::new(&self.config));
        bucket.ban_until =
            Some(Instant::now() + Duration::from_secs(self.config.ban_duration_secs));
        bucket.violations = self.config.ban_after;
        tracing::warn!(ip = client_ip, "IP manually banned");
    }

    /// Remove an IP ban.
    pub fn unban_ip(&self, client_ip: &str) {
        let mut buckets = self.buckets.write();
        if let Some(bucket) = buckets.get_mut(client_ip) {
            bucket.ban_until = None;
            bucket.violations = 0;
            tracing::info!(ip = client_ip, "IP unbanned");
        }
    }

    /// Prune stale entries (clients that haven't been seen in a while).
    pub fn prune_stale(&self, max_age: Duration) {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ShieldConfig;

    fn make_governor() -> RateGovernor {
        let mut config = ShieldConfig::default();
        config.rate.requests_per_second = 10.0;
        config.rate.burst_capacity = 10.0;
        config.rate.warn_after = 2;
        config.rate.block_after = 5;
        config.rate.ban_after = 8;
        RateGovernor::new(&config)
    }

    #[test]
    fn allows_under_limit() {
        let governor = make_governor();
        for _ in 0..10 {
            let result = governor.check("1.2.3.4");
            assert!(result.allowed);
        }
    }

    #[test]
    fn blocks_over_limit() {
        let governor = make_governor();
        // Drain the bucket
        for _ in 0..10 {
            governor.check("1.2.3.4");
        }
        // Next request should fail
        let result = governor.check("1.2.3.4");
        assert!(!result.allowed);
    }

    #[test]
    fn escalates_on_violations() {
        let governor = make_governor();
        // Drain the bucket to cause violations
        for _ in 0..20 {
            governor.check("5.6.7.8");
        }
        let level = governor.peek_escalation("5.6.7.8");
        assert!(
            matches!(level, EscalationLevel::Block | EscalationLevel::Ban),
            "Should escalate after many violations: {:?}",
            level
        );
    }

    #[test]
    fn manual_ban_works() {
        let governor = make_governor();
        governor.ban_ip("9.8.7.6");
        let result = governor.check("9.8.7.6");
        assert!(!result.allowed);
        assert_eq!(result.escalation, EscalationLevel::Ban);
        assert!(result.retry_after.is_some());
    }

    #[test]
    fn different_ips_independent() {
        let governor = make_governor();
        // Drain bucket for IP A
        for _ in 0..15 {
            governor.check("1.1.1.1");
        }
        // IP B should still be fine
        let result = governor.check("2.2.2.2");
        assert!(result.allowed);
    }

    // ── Escalation level progression ───────────────────────

    #[test]
    fn escalation_starts_at_none() {
        let governor = make_governor();
        let level = governor.peek_escalation("fresh_ip");
        assert_eq!(level, EscalationLevel::None);
    }

    #[test]
    fn peek_escalation_does_not_consume_token() {
        let governor = make_governor();
        // Peek many times, should still be allowed
        for _ in 0..100 {
            governor.peek_escalation("peek_ip");
        }
        let result = governor.check("peek_ip");
        assert!(result.allowed);
    }

    #[test]
    fn remaining_tokens_decrease_on_check() {
        let governor = make_governor();
        let r1 = governor.check("drain_ip");
        let r2 = governor.check("drain_ip");
        assert!(r2.remaining < r1.remaining, "Tokens should decrease");
    }

    #[test]
    fn violations_count_increases_when_denied() {
        let governor = make_governor();
        // Drain all tokens
        for _ in 0..10 {
            governor.check("violations_ip");
        }
        // Next checks should be denied and increase violations
        let result = governor.check("violations_ip");
        assert!(!result.allowed);
        assert!(result.violations > 0, "Violations should be > 0");
    }

    // ── Manual ban/unban ───────────────────────────────────

    #[test]
    fn unban_ip_allows_requests() {
        let governor = make_governor();
        governor.ban_ip("ban_test");
        let result = governor.check("ban_test");
        assert!(!result.allowed);

        governor.unban_ip("ban_test");
        let result = governor.check("ban_test");
        assert!(result.allowed, "Unbanned IP should be allowed");
    }

    #[test]
    fn unban_ip_resets_violations() {
        let governor = make_governor();
        governor.ban_ip("violation_reset");
        governor.unban_ip("violation_reset");
        let level = governor.peek_escalation("violation_reset");
        assert_eq!(level, EscalationLevel::None, "Violations should be reset after unban");
    }

    #[test]
    fn ban_ip_has_retry_after() {
        let governor = make_governor();
        governor.ban_ip("retry_after_ip");
        let result = governor.check("retry_after_ip");
        assert!(result.retry_after.is_some());
        assert!(result.retry_after.unwrap() > 0);
    }

    #[test]
    fn unban_unknown_ip_is_noop() {
        let governor = make_governor();
        governor.unban_ip("never_seen"); // should not panic
    }

    // ── Prune stale ────────────────────────────────────────

    #[test]
    fn prune_stale_removes_old_buckets() {
        let governor = make_governor();
        governor.check("stale_bucket");
        // Prune with zero max age — everything is stale
        governor.prune_stale(Duration::from_secs(0));
        // After pruning, the IP should be treated as new
        let level = governor.peek_escalation("stale_bucket");
        assert_eq!(level, EscalationLevel::None);
    }

    #[test]
    fn prune_stale_keeps_recent_buckets() {
        let governor = make_governor();
        governor.check("recent_bucket");
        // Prune with large max age
        governor.prune_stale(Duration::from_secs(3600));
        // Bucket should still exist — peek should not panic
        let _level = governor.peek_escalation("recent_bucket");
    }

    // ── Escalation level ordering ──────────────────────────

    #[test]
    fn escalation_level_equality() {
        assert_eq!(EscalationLevel::None, EscalationLevel::None);
        assert_eq!(EscalationLevel::Ban, EscalationLevel::Ban);
        assert_ne!(EscalationLevel::Warn, EscalationLevel::Block);
    }

    #[test]
    fn rate_check_result_initial_values() {
        let governor = make_governor();
        let result = governor.check("initial_check");
        assert!(result.allowed);
        assert_eq!(result.escalation, EscalationLevel::None);
        assert!(result.retry_after.is_none());
        assert_eq!(result.violations, 0);
    }

    // ── Burst behavior ─────────────────────────────────────

    #[test]
    fn burst_capacity_matches_config() {
        let mut config = ShieldConfig::default();
        config.rate.burst_capacity = 5.0;
        config.rate.requests_per_second = 0.0; // no refill
        let governor = RateGovernor::new(&config);

        let mut allowed_count = 0;
        for _ in 0..10 {
            if governor.check("burst_ip").allowed {
                allowed_count += 1;
            }
        }
        assert_eq!(allowed_count, 5, "Should allow exactly burst_capacity requests");
    }

    #[test]
    fn ban_escalation_blocks_all_subsequent() {
        let mut config = ShieldConfig::default();
        config.rate.burst_capacity = 2.0;
        config.rate.requests_per_second = 0.0;
        config.rate.warn_after = 1;
        config.rate.throttle_after = 2;
        config.rate.block_after = 3;
        config.rate.ban_after = 4;
        config.rate.ban_duration_secs = 600;
        let governor = RateGovernor::new(&config);

        // Drain bucket and trigger escalation to ban
        for _ in 0..20 {
            governor.check("escalate_ip");
        }

        let result = governor.check("escalate_ip");
        assert!(!result.allowed);
        assert!(
            matches!(result.escalation, EscalationLevel::Block | EscalationLevel::Ban),
            "Should be blocked or banned: {:?}", result.escalation
        );
    }
}