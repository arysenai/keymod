use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level policy governing mandate behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub spending: SpendingPolicy,
    pub secrets: HashMap<String, SecretPolicy>,
}

/// Spending limits (amounts in USDC with 6 decimals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingPolicy {
    /// Max USDC per transaction.
    pub max_per_tx: u64,
    /// Max USDC per 24h rolling window.
    pub max_daily: u64,
    /// Max USDC per 30d rolling window.
    pub max_monthly: u64,
}

/// Per-secret access policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    /// Max calls per minute.
    pub rate_limit: u32,
    /// Max calls per day.
    pub daily_limit: u32,
    /// Restrict which URLs can use this secret.
    pub allowed_domains: Vec<String>,
}

/// A stored secret (name + encrypted blob).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub name: String,
    pub encrypted_value: Vec<u8>,
}

/// An HTTP request template with `{PLACEHOLDER}` tokens for credential injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTemplate {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// An HTTP response from the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Summary of spending usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingSummary {
    pub today: u64,
    pub this_month: u64,
    pub total_all_time: u64,
}
