/// Policy enforcement engine.
///
/// Evaluates spending/rate-limit policies before allowing actions.
/// Tracks rolling daily/monthly spending totals and per-secret usage rates.

use crate::types::{Policy, SpendingSummary};
use serde_json::Value;
use std::collections::HashMap;

/// Per-secret usage tracking.
#[derive(Debug, Clone)]
pub struct SecretUsage {
    pub calls_this_minute: u32,
    pub calls_today: u32,
    pub last_minute_reset: u64,
    pub last_day_reset: u64,
}

impl SecretUsage {
    pub fn new(now: u64) -> Self {
        Self {
            calls_this_minute: 0,
            calls_today: 0,
            last_minute_reset: now,
            last_day_reset: now,
        }
    }
}

/// The policy engine holds policy configuration and runtime counters.
pub struct PolicyEngine {
    policy: Policy,
    spending_today: u64,
    total_all_time: u64,
    last_day_reset: u64,
    secret_usage: HashMap<String, SecretUsage>,
}

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_DAY: u64 = 86_400;

impl PolicyEngine {
    /// Create a new PolicyEngine with the given policy and current timestamp.
    pub fn new(policy: Policy, now: u64) -> Self {
        Self {
            policy,
            spending_today: 0,
            total_all_time: 0,
            last_day_reset: now,
            secret_usage: HashMap::new(),
        }
    }

    /// Update the policy configuration.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// Get a reference to the current policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Reset rolling counters if time windows have elapsed.
    pub fn reset_if_needed(&mut self, now: u64) {
        // Reset daily spending if a day has passed
        if now >= self.last_day_reset + SECONDS_PER_DAY {
            self.spending_today = 0;
            self.last_day_reset = now;
        }

        // Reset per-secret counters
        for usage in self.secret_usage.values_mut() {
            if now >= usage.last_minute_reset + SECONDS_PER_MINUTE {
                usage.calls_this_minute = 0;
                usage.last_minute_reset = now;
            }
            if now >= usage.last_day_reset + SECONDS_PER_DAY {
                usage.calls_today = 0;
                usage.last_day_reset = now;
            }
        }
    }

    /// Check if a spending amount is within policy limits (local pre-flight).
    /// Does NOT record the spending; call `record_spending` separately on success.
    pub fn check_spending(&self, amount: u64, now: u64) -> Result<(), String> {
        // Check mandate expiry (fast pre-flight rejection)
        if let Some(expires_at) = self.policy.spending.expires_at {
            if now > expires_at {
                return Err(format!(
                    "mandate expired at {} (current time: {})",
                    expires_at, now
                ));
            }
        }

        if amount > self.policy.spending.max_per_tx {
            return Err(format!(
                "amount {} exceeds max_per_tx {}",
                amount, self.policy.spending.max_per_tx
            ));
        }

        if self.spending_today + amount > self.policy.spending.max_daily {
            return Err(format!(
                "amount {} would exceed daily limit {} (already spent {})",
                amount, self.policy.spending.max_daily, self.spending_today
            ));
        }

        Ok(())
    }

    /// Record a spending amount (add to rolling totals).
    pub fn record_spending(&mut self, amount: u64) {
        self.spending_today += amount;
        self.total_all_time += amount;
    }

    /// Check if a secret can be used (rate limits and domain allowlist).
    pub fn check_secret_usage(&self, secret_name: &str, target_url: &str) -> Result<(), String> {
        // If no policy for this secret, allow by default
        let secret_policy = match self.policy.secrets.get(secret_name) {
            Some(p) => p,
            None => return Ok(()),
        };

        // Check domain allowlist
        if !secret_policy.allowed_domains.is_empty() {
            let domain_allowed = secret_policy
                .allowed_domains
                .iter()
                .any(|domain| target_url.contains(domain));
            if !domain_allowed {
                return Err(format!(
                    "secret '{}' not allowed for domain in URL '{}'",
                    secret_name, target_url
                ));
            }
        }

        // Check rate limits
        if let Some(usage) = self.secret_usage.get(secret_name) {
            if usage.calls_this_minute >= secret_policy.rate_limit {
                return Err(format!(
                    "secret '{}' rate limit exceeded ({}/min)",
                    secret_name, secret_policy.rate_limit
                ));
            }
            if usage.calls_today >= secret_policy.daily_limit {
                return Err(format!(
                    "secret '{}' daily limit exceeded ({}/day)",
                    secret_name, secret_policy.daily_limit
                ));
            }
        }

        Ok(())
    }

    /// Record a secret usage (increment counters).
    pub fn record_secret_usage(&mut self, secret_name: &str, now: u64) {
        let usage = self
            .secret_usage
            .entry(secret_name.to_string())
            .or_insert_with(|| SecretUsage::new(now));
        usage.calls_this_minute += 1;
        usage.calls_today += 1;
    }

    /// Return a summary of spending usage.
    pub fn get_spending_summary(&self) -> SpendingSummary {
        SpendingSummary {
            today: self.spending_today,
            total_all_time: self.total_all_time,
        }
    }
}

/// Check whether an action is permitted under the given policy.
/// Returns a JSON object: `{ "allowed": bool, "reason": string }`.
///
/// Supported actions:
/// - "spend" with params: { "amount": u64 }
/// - "use_secret" with params: { "secret_name": string, "target_url": string }
pub fn check(policy: &Policy, action: &str, params: &Value) -> Value {
    match action {
        "spend" => {
            let amount = params
                .get("amount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if amount > policy.spending.max_per_tx {
                return serde_json::json!({
                    "allowed": false,
                    "reason": format!("amount {} exceeds max_per_tx {}", amount, policy.spending.max_per_tx)
                });
            }

            serde_json::json!({
                "allowed": true,
                "reason": "within per-tx limit"
            })
        }
        "use_secret" => {
            let secret_name = params
                .get("secret_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target_url = params
                .get("target_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if let Some(secret_policy) = policy.secrets.get(secret_name) {
                if !secret_policy.allowed_domains.is_empty() {
                    let domain_allowed = secret_policy
                        .allowed_domains
                        .iter()
                        .any(|domain| target_url.contains(domain));
                    if !domain_allowed {
                        return serde_json::json!({
                            "allowed": false,
                            "reason": format!("secret '{}' not allowed for URL '{}'", secret_name, target_url)
                        });
                    }
                }
            }

            serde_json::json!({
                "allowed": true,
                "reason": "allowed"
            })
        }
        _ => serde_json::json!({
            "allowed": false,
            "reason": format!("unknown action: {}", action)
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SecretPolicy, SpendingPolicy};

    fn test_policy() -> Policy {
        let mut secrets = HashMap::new();
        secrets.insert(
            "openai_key".to_string(),
            SecretPolicy {
                rate_limit: 5,
                daily_limit: 100,
                allowed_domains: vec!["api.openai.com".to_string()],
            },
        );
        Policy {
            spending: SpendingPolicy {
                max_per_tx: 100_000_000, // 100 USDC
                max_daily: 500_000_000,  // 500 USDC
                expires_at: None,
            },
            secrets,
        }
    }

    #[test]
    fn allow_spending_within_limits() {
        let engine = PolicyEngine::new(test_policy(), 1000);
        assert!(engine.check_spending(50_000_000, 1000).is_ok()); // 50 USDC
    }

    #[test]
    fn deny_spending_over_per_tx() {
        let engine = PolicyEngine::new(test_policy(), 1000);
        assert!(engine.check_spending(200_000_000, 1000).is_err()); // 200 USDC > 100 max
    }

    #[test]
    fn deny_spending_over_daily_limit() {
        let mut engine = PolicyEngine::new(test_policy(), 1000);
        // Spend 400 USDC (within per-tx and daily)
        engine.record_spending(400_000_000);
        // Now 200 more would exceed daily 500
        assert!(engine.check_spending(100_000_000, 1000).is_ok()); // 500 total = ok
        engine.record_spending(100_000_000);
        assert!(engine.check_spending(1_000_000, 1000).is_err()); // 501 total = denied
    }

    #[test]
    fn daily_limit_resets_on_new_day() {
        let mut engine = PolicyEngine::new(test_policy(), 1000);
        engine.record_spending(400_000_000);
        // Advance time by a full day
        engine.reset_if_needed(1000 + SECONDS_PER_DAY);
        assert!(engine.check_spending(100_000_000, 1000 + SECONDS_PER_DAY).is_ok());
    }

    #[test]
    fn deny_spending_when_expired() {
        let mut policy = test_policy();
        policy.spending.expires_at = Some(2000);
        let engine = PolicyEngine::new(policy, 1000);
        // Before expiry — ok
        assert!(engine.check_spending(50_000_000, 1500).is_ok());
        // After expiry — denied
        assert!(engine.check_spending(50_000_000, 2001).is_err());
    }

    #[test]
    fn allow_spending_when_no_expiry() {
        let engine = PolicyEngine::new(test_policy(), 1000);
        // Far future — no expiry set, should be fine
        assert!(engine.check_spending(50_000_000, 999_999_999).is_ok());
    }

    #[test]
    fn secret_rate_limit_check() {
        let mut engine = PolicyEngine::new(test_policy(), 1000);
        // Use openai_key 5 times (rate_limit = 5)
        for _ in 0..5 {
            assert!(engine
                .check_secret_usage("openai_key", "https://api.openai.com/v1/chat")
                .is_ok());
            engine.record_secret_usage("openai_key", 1000);
        }
        // 6th should fail
        assert!(engine
            .check_secret_usage("openai_key", "https://api.openai.com/v1/chat")
            .is_err());
    }

    #[test]
    fn secret_domain_allowlist() {
        let engine = PolicyEngine::new(test_policy(), 1000);
        // Allowed domain
        assert!(engine
            .check_secret_usage("openai_key", "https://api.openai.com/v1/chat")
            .is_ok());
        // Disallowed domain
        assert!(engine
            .check_secret_usage("openai_key", "https://evil.com/steal")
            .is_err());
    }

    #[test]
    fn unknown_secret_allowed_by_default() {
        let engine = PolicyEngine::new(test_policy(), 1000);
        assert!(engine
            .check_secret_usage("unknown_key", "https://anything.com")
            .is_ok());
    }

    #[test]
    fn spending_summary_tracks_totals() {
        let mut engine = PolicyEngine::new(test_policy(), 1000);
        engine.record_spending(10_000_000);
        engine.record_spending(20_000_000);
        let summary = engine.get_spending_summary();
        assert_eq!(summary.today, 30_000_000);
        assert_eq!(summary.total_all_time, 30_000_000);
    }

    #[test]
    fn check_function_spend_action() {
        let policy = test_policy();
        let result = check(&policy, "spend", &serde_json::json!({"amount": 50_000_000}));
        assert_eq!(result["allowed"], true);

        let result = check(&policy, "spend", &serde_json::json!({"amount": 200_000_000}));
        assert_eq!(result["allowed"], false);
    }

    #[test]
    fn check_function_use_secret_action() {
        let policy = test_policy();
        let result = check(
            &policy,
            "use_secret",
            &serde_json::json!({"secret_name": "openai_key", "target_url": "https://api.openai.com/v1/chat"}),
        );
        assert_eq!(result["allowed"], true);

        let result = check(
            &policy,
            "use_secret",
            &serde_json::json!({"secret_name": "openai_key", "target_url": "https://evil.com/steal"}),
        );
        assert_eq!(result["allowed"], false);
    }
}
