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
    /// Unix timestamp when this mandate expires (None = no expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
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
    pub total_all_time: u64,
}

// ---------------------------------------------------------------------------
// Backend communication types (used by Phase 9+)
// ---------------------------------------------------------------------------

/// Configuration for authenticated backend calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Base URL of the Arysen backend (e.g. "https://api.arysen.ai").
    pub base_url: String,
    /// Agent UUID (used in X-ARYSEN-AGENT-ID header).
    pub agent_id: String,
    /// Key ID of the worker keypair for signing requests.
    pub worker_key_id: String,
    /// Key ID of the session keypair for signing transactions.
    pub session_key_id: String,
}

/// Extended config for mandate_init — includes worker private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitConfig {
    pub base_url: String,
    pub agent_id: String,
    pub worker_key_id: String,
    pub session_key_id: String,
    pub worker_private_key_hex: String,
}

/// Mandate info returned by GET /mandates/mine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateInfo {
    pub mandate_id: String,
    pub max_per_tx: String,
    pub max_daily: String,
    pub daily_spent: f64,
    pub wallet_address: String,
    pub expires_at: String,
    pub serialized_permission: String,
}

/// Result of POST /transactions/prepare.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareResponse {
    pub tx_id: String,
    pub user_op_hash: String,
}

/// Result of a USDC transfer or DealOrder escrow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferResult {
    pub tx_hash: String,
}

/// Parameters for creating a DealOrder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DealOrderParams {
    pub executor_agent_id: String,
    pub bounty_amount: String,
    pub task_cid: String,
    pub delivery_deadline: u64,
}
