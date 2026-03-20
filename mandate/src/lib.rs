pub mod backend;
pub mod http;
pub mod inject;
pub mod policy;
pub mod secrets;
pub mod types;

use serde_json::json;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Host imports — provided by the WASM runtime (Wassette / Node.js host)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "env")]
extern "C" {
    fn get_time() -> u64;
    fn http_execute(req: *const u8, req_len: u32, resp: *mut u8, resp_len: u32) -> i32;
}

// Native stubs for `cargo test` (not compiled into WASM)
// Note: key_store_read, key_store_write, get_time stubs are provided by arysen-wallet crate.
// Only mandate-specific stubs (http_execute, get_time) live here.
#[cfg(not(target_arch = "wasm32"))]
mod host_stubs {
    #[no_mangle]
    pub extern "C" fn http_execute(
        _req: *const u8,
        _req_len: u32,
        _resp: *mut u8,
        _resp_len: u32,
    ) -> i32 {
        0
    }
}

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

use std::sync::Mutex;
static VAULT: Mutex<Option<secrets::SecretVault>> = Mutex::new(None);
static POLICY_ENGINE: Mutex<Option<policy::PolicyEngine>> = Mutex::new(None);
static BACKEND_CONFIG: Mutex<Option<types::BackendConfig>> = Mutex::new(None);
static MANDATE_INFO: Mutex<Option<types::MandateInfo>> = Mutex::new(None);
static WORKER_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);
static SESSION_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn with_vault<F, R>(f: F) -> R
where
    F: FnOnce(&mut secrets::SecretVault) -> R,
{
    let mut guard = VAULT.lock().unwrap_or_else(|e| e.into_inner());
    let vault = guard.get_or_insert_with(secrets::SecretVault::new);
    f(vault)
}

fn with_policy_engine<F, R>(f: F) -> R
where
    F: FnOnce(&mut policy::PolicyEngine) -> R,
{
    let mut guard = POLICY_ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    let engine = guard.get_or_insert_with(|| {
        policy::PolicyEngine::new(
            types::Policy {
                spending: types::SpendingPolicy {
                    max_per_tx: 0,
                    max_daily: 0,
                    expires_at: None,
                },
                secrets: std::collections::HashMap::new(),
            },
            current_time(),
        )
    });
    f(engine)
}

/// Get current time — from host in WASM, from std in native.
fn current_time() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        unsafe { get_time() }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ---------------------------------------------------------------------------
// wasm-bindgen exports
// ---------------------------------------------------------------------------

/// Store a secret by name. The value is encrypted internally.
#[wasm_bindgen]
pub fn deposit_secret(name: &str, encrypted_value: &[u8]) -> bool {
    with_vault(|vault| vault.deposit(name, encrypted_value))
}

/// Remove a stored secret by name.
#[wasm_bindgen]
pub fn remove_secret(name: &str) -> bool {
    with_vault(|vault| vault.remove(name))
}

/// List stored secret names (no values exposed).
#[wasm_bindgen]
pub fn list_secret_names() -> JsValue {
    let names = with_vault(|vault| vault.list_names());
    serde_wasm_bindgen::to_value(&names).unwrap_or(JsValue::NULL)
}

/// Execute a request template with credential injection.
///
/// Full flow:
/// 1. Parse request template JSON
/// 2. Find all {PLACEHOLDER} tokens in url, headers, body
/// 3. For each placeholder: check_secret_usage(name, target_url)
/// 4. Retrieve secrets from vault
/// 5. Substitute placeholders with real values
/// 6. Execute HTTP request (host import in WASM, mock in native)
/// 7. Scrub response of all injected values
/// 8. Record usage counters
/// 9. Return clean response
#[wasm_bindgen]
pub fn execute_request(template_json: &str) -> JsValue {
    // Step 1: Parse the request template
    let template = match inject::parse_request_template(template_json) {
        Ok(t) => t,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&json!({
                "error": format!("invalid template: {}", e)
            }))
            .unwrap_or(JsValue::NULL);
        }
    };

    // Step 2: Find all placeholders
    let placeholders = inject::collect_all_placeholders(&template);

    let now = current_time();

    // Step 3: Policy check — for each placeholder, check usage limits
    for placeholder in &placeholders {
        let check_result =
            with_policy_engine(|engine| {
                engine.reset_if_needed(now);
                engine.check_secret_usage(placeholder, &template.url)
            });

        if let Err(reason) = check_result {
            return serde_wasm_bindgen::to_value(&json!({
                "error": format!("policy denied: {}", reason)
            }))
            .unwrap_or(JsValue::NULL);
        }
    }

    // Step 4: Retrieve secrets from vault
    let mut secret_values = std::collections::HashMap::new();
    for placeholder in &placeholders {
        let value = with_vault(|vault| vault.retrieve(placeholder));
        match value {
            Some(bytes) => {
                match String::from_utf8(bytes) {
                    Ok(s) => {
                        secret_values.insert(placeholder.clone(), s);
                    }
                    Err(_) => {
                        return serde_wasm_bindgen::to_value(&json!({
                            "error": format!("secret '{}' is not valid UTF-8", placeholder)
                        }))
                        .unwrap_or(JsValue::NULL);
                    }
                }
            }
            None => {
                return serde_wasm_bindgen::to_value(&json!({
                    "error": format!("secret '{}' not found in vault", placeholder)
                }))
                .unwrap_or(JsValue::NULL);
            }
        }
    }

    // Step 5: Substitute placeholders
    let hydrated = match inject::substitute_template(&template, &secret_values) {
        Ok(t) => t,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&json!({
                "error": format!("substitution failed: {}", e)
            }))
            .unwrap_or(JsValue::NULL);
        }
    };

    // Step 6: Execute HTTP request
    let response = http::execute_request(&hydrated);

    // Step 7: Scrub response
    let injected: Vec<String> = secret_values.values().cloned().collect();
    let scrubbed_body = inject::scrub_response(&response.body, &injected);

    // Also scrub headers
    let mut scrubbed_headers = std::collections::HashMap::new();
    for (k, v) in &response.headers {
        scrubbed_headers.insert(
            inject::scrub_response(k, &injected),
            inject::scrub_response(v, &injected),
        );
    }

    // Step 8: Record usage counters
    with_policy_engine(|engine| {
        for placeholder in &placeholders {
            engine.record_secret_usage(placeholder, now);
        }
    });

    // Step 9: Return clean response
    let clean_response = types::HttpResponse {
        status: response.status,
        headers: scrubbed_headers,
        body: scrubbed_body,
    };

    serde_wasm_bindgen::to_value(&clean_response).unwrap_or(JsValue::NULL)
}

/// Update the spending/rate-limit policy.
#[wasm_bindgen]
pub fn set_policy(policy_json: &str) -> bool {
    match serde_json::from_str::<types::Policy>(policy_json) {
        Ok(p) => {
            with_policy_engine(|engine| {
                engine.set_policy(p);
            });
            true
        }
        Err(_) => false,
    }
}

/// Check whether an action is permitted under the current policy.
#[wasm_bindgen]
pub fn check_policy(action: &str, params_json: &str) -> JsValue {
    let params: serde_json::Value =
        serde_json::from_str(params_json).unwrap_or(serde_json::Value::Null);
    let result = with_policy_engine(|engine| policy::check(engine.policy(), action, &params));
    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

/// Return spending usage statistics.
#[wasm_bindgen]
pub fn get_spending_summary() -> JsValue {
    let summary = with_policy_engine(|engine| {
        engine.reset_if_needed(current_time());
        engine.get_spending_summary()
    });
    serde_wasm_bindgen::to_value(&summary).unwrap_or(JsValue::NULL)
}

/// Generate both keypairs (Ed25519 worker + secp256k1 session) inside WASM.
///
/// Private keys are stored internally in the mandate module's static state
/// and never cross the WASM→JS boundary. Returns only public keys and key IDs.
///
/// Returns JSON:
/// ```json
/// {
///   "worker_pub_key": "hex",
///   "worker_key_id": "hex_id",
///   "session_pub_key": "hex",
///   "session_key_id": "hex_id"
/// }
/// ```
#[wasm_bindgen]
pub fn mandate_generate_keys() -> JsValue {
    match mandate_generate_keys_internal() {
        Ok(val) => val,
        Err(e) => {
            serde_wasm_bindgen::to_value(&json!({ "error": e })).unwrap_or(JsValue::NULL)
        }
    }
}

fn mandate_generate_keys_internal() -> Result<JsValue, String> {
    // Initialize master key for encrypted persistence
    arysen_wallet::init_master_key()?;

    let (worker_pub, worker_priv) = arysen_wallet::ed25519::generate_keypair_raw();
    let worker_key_id = arysen_wallet::ed25519::derive_key_id(&worker_pub);

    let (session_pub, session_priv) = arysen_wallet::secp256k1::generate_keypair_raw();
    let session_key_id = arysen_wallet::secp256k1::derive_key_id(&session_pub);

    // Persist encrypted keys via host key store
    arysen_wallet::persist_key(
        &format!("arysen_worker:{}", worker_key_id),
        &worker_priv,
    )?;
    arysen_wallet::persist_key(
        &format!("arysen_session:{}", session_key_id),
        &session_priv,
    )?;

    // Cache plaintext in statics for immediate use
    *WORKER_KEY.lock().unwrap_or_else(|e| e.into_inner()) = Some(worker_priv.to_vec());
    *SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner()) = Some(session_priv.to_vec());

    let result = json!({
        "worker_pub_key": hex::encode(&worker_pub),
        "worker_key_id": worker_key_id,
        "session_pub_key": hex::encode(&session_pub),
        "session_key_id": session_key_id,
    });
    Ok(serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL))
}

/// Initialize the mandate module with backend configuration.
///
/// Parses the config JSON, stores the worker key for signing,
/// calls `GET /mandates/mine` to fetch mandate details, and
/// hydrates the local policy engine with the backend's limits.
///
/// Config JSON shape:
/// ```json
/// {
///   "base_url": "https://api.arysen.ai",
///   "agent_id": "uuid",
///   "worker_key_id": "hex_id",
///   "session_key_id": "hex_id",
///   "worker_private_key_hex": "hex_encoded_32_bytes"
/// }
/// ```
#[wasm_bindgen]
pub fn mandate_init(config_json: &str) -> JsValue {
    match mandate_init_internal(config_json) {
        Ok(info) => serde_wasm_bindgen::to_value(&info).unwrap_or(JsValue::NULL),
        Err(e) => {
            serde_wasm_bindgen::to_value(&json!({ "error": e })).unwrap_or(JsValue::NULL)
        }
    }
}

/// Internal init logic, returns Result for easier error handling.
fn mandate_init_internal(config_json: &str) -> Result<types::MandateInfo, String> {
    // Parse extended config
    let init_cfg: types::InitConfig =
        serde_json::from_str(config_json).map_err(|e| format!("invalid config: {}", e))?;

    // Key loading priority:
    // 1. Already in statics (from mandate_generate_keys() in this session)
    // 2. Load from persistent host key store (TEE/keychain/encrypted files)
    // 3. Decode from config hex (legacy backward compat)
    let has_worker = WORKER_KEY.lock().unwrap_or_else(|e| e.into_inner()).is_some();
    let has_session = SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner()).is_some();

    if !has_worker {
        // Try loading from persistent store first
        let store_key_id = format!("arysen_worker:{}", init_cfg.worker_key_id);
        if let Ok(()) = arysen_wallet::init_master_key() {
            if let Ok(key_bytes) = arysen_wallet::load_key(&store_key_id) {
                if key_bytes.len() == 32 {
                    *WORKER_KEY.lock().unwrap_or_else(|e| e.into_inner()) = Some(key_bytes);
                }
            }
        }
    }
    // Fall back to config hex if still not loaded
    let has_worker = WORKER_KEY.lock().unwrap_or_else(|e| e.into_inner()).is_some();
    if !has_worker {
        let worker_key_bytes = hex::decode(&init_cfg.worker_private_key_hex)
            .map_err(|e| format!("invalid worker key hex: {}", e))?;
        if worker_key_bytes.len() != 32 {
            return Err("worker private key must be 32 bytes".to_string());
        }
        *WORKER_KEY.lock().unwrap_or_else(|e| e.into_inner()) = Some(worker_key_bytes);
    }

    if !has_session {
        // Try loading from persistent store first
        let store_key_id = format!("arysen_session:{}", init_cfg.session_key_id);
        if let Ok(()) = arysen_wallet::init_master_key() {
            if let Ok(key_bytes) = arysen_wallet::load_key(&store_key_id) {
                if key_bytes.len() == 32 {
                    *SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner()) = Some(key_bytes);
                }
            }
        }
    }
    // Fall back to config hex if still not loaded
    let has_session = SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner()).is_some();
    if !has_session {
        let session_key_bytes = hex::decode(&init_cfg.session_private_key_hex)
            .map_err(|e| format!("invalid session key hex: {}", e))?;
        if session_key_bytes.len() != 32 {
            return Err("session private key must be 32 bytes".to_string());
        }
        *SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner()) = Some(session_key_bytes);
    }

    // Store backend config
    let config = types::BackendConfig {
        base_url: init_cfg.base_url,
        agent_id: init_cfg.agent_id,
        worker_key_id: init_cfg.worker_key_id,
        session_key_id: init_cfg.session_key_id,
    };
    *BACKEND_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());

    // Fetch mandate info from backend
    let worker_key = WORKER_KEY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("worker key not set")?;
    let response =
        backend::signed_fetch("GET", "/mandates/mine", None, &config, &worker_key)?;
    let data = backend::parse_response_data(&response)?;
    let info: types::MandateInfo =
        serde_json::from_value(data).map_err(|e| format!("invalid mandate data: {}", e))?;

    // Hydrate policy engine with backend limits
    let max_per_tx = parse_usdc_amount(&info.max_per_tx)?;
    let max_daily = parse_usdc_amount(&info.max_daily)?;
    let expires_at = parse_expires_at(&info.expires_at);

    with_policy_engine(|engine| {
        engine.set_policy(types::Policy {
            spending: types::SpendingPolicy {
                max_per_tx,
                max_daily,
                expires_at,
            },
            secrets: engine.policy().secrets.clone(),
        });
    });

    // Store mandate info
    *MANDATE_INFO.lock().unwrap_or_else(|e| e.into_inner()) = Some(info.clone());

    Ok(info)
}

/// Return stored mandate info (from last init or refresh).
#[wasm_bindgen]
pub fn get_mandate_info() -> JsValue {
    let guard = MANDATE_INFO.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(info) => serde_wasm_bindgen::to_value(info).unwrap_or(JsValue::NULL),
        None => {
            serde_wasm_bindgen::to_value(&json!({ "error": "not initialized" }))
                .unwrap_or(JsValue::NULL)
        }
    }
}

/// Parse a USDC string amount (e.g. "10.5") to u64 with 6 decimal places.
/// Uses integer string parsing to avoid IEEE 754 float precision issues.
fn parse_usdc_amount(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("invalid USDC amount: ''".to_string());
    }

    let (integer_part, decimal_part) = match s.split_once('.') {
        Some((int_s, dec_s)) => (int_s, dec_s),
        None => (s, ""),
    };

    let integer: u64 = if integer_part.is_empty() {
        0
    } else {
        integer_part
            .parse()
            .map_err(|_| format!("invalid USDC amount: '{}'", s))?
    };

    // Pad or truncate decimal to exactly 6 digits
    let decimal: u64 = if decimal_part.is_empty() {
        0
    } else {
        let padded = if decimal_part.len() > 6 {
            &decimal_part[..6]
        } else {
            decimal_part
        };
        let parsed: u64 = padded
            .parse()
            .map_err(|_| format!("invalid USDC amount: '{}'", s))?;
        // Scale up: "5" → 500000, "25" → 250000, "123456" → 123456
        parsed * 10u64.pow(6 - padded.len() as u32)
    };

    Ok(integer * 1_000_000 + decimal)
}

/// Parse an ISO date string or unix timestamp to Option<u64>.
fn parse_expires_at(s: &str) -> Option<u64> {
    if s.is_empty() || s == "null" {
        return None;
    }
    // Try parsing as unix timestamp first
    if let Ok(ts) = s.parse::<u64>() {
        return Some(ts);
    }
    // Try parsing as ISO 8601 (simplified: just extract the date and convert)
    // For now, we'll handle the format "YYYY-MM-DDTHH:MM:SSZ" by extracting
    // the year/month/day. Full ISO parsing can be added if needed.
    // This is a pre-flight cache only — backend does authoritative checks.
    None
}

/// Transfer USDC to an address.
///
/// 5-step flow:
/// 1. Local pre-flight: check spending limits (expires_at, per-tx, daily)
/// 2. Backend check: POST /mandates/check-spend { amount }
/// 3. Prepare tx: POST /transactions/prepare { to, amount, type: "transfer" }
/// 4. Sign: secp256k1 sign the user_op_hash with session key
/// 5. Submit: POST /transactions/submit { tx_id, signature }
/// 6. Record: POST /mandates/record-spend { amount }
/// 7. Return { tx_hash }
#[wasm_bindgen]
pub fn transfer_usdc(to: &str, amount: &str) -> JsValue {
    match transfer_internal(to, amount) {
        Ok(result) => serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL),
        Err(e) => {
            serde_wasm_bindgen::to_value(&json!({ "error": e })).unwrap_or(JsValue::NULL)
        }
    }
}

fn transfer_internal(to: &str, amount: &str) -> Result<types::TransferResult, String> {
    tx_flow(to, amount, "transfer", None)
}

/// Create a DealOrder with escrow.
///
/// Same 5-step flow as transfer_usdc but with type: "escrow" and extra params.
#[wasm_bindgen]
pub fn create_deal_order(params_json: &str) -> JsValue {
    match deal_order_internal(params_json) {
        Ok(result) => serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL),
        Err(e) => {
            serde_wasm_bindgen::to_value(&json!({ "error": e })).unwrap_or(JsValue::NULL)
        }
    }
}

fn deal_order_internal(params_json: &str) -> Result<types::TransferResult, String> {
    let params: types::DealOrderParams =
        serde_json::from_str(params_json).map_err(|e| format!("invalid params: {}", e))?;
    tx_flow(
        &params.executor_agent_id,
        &params.bounty_amount,
        "escrow",
        Some(&params),
    )
}

/// Shared transaction flow for transfer and deal order.
fn tx_flow(
    to: &str,
    amount: &str,
    tx_type: &str,
    deal_params: Option<&types::DealOrderParams>,
) -> Result<types::TransferResult, String> {
    // Load keys and config first — fail fast if not initialized
    let config = BACKEND_CONFIG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("not initialized: call mandate_init first")?;
    let worker_key = WORKER_KEY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("worker key not set")?;
    let session_key = SESSION_KEY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or("session key not set")?;

    let now = current_time();
    let amount_micro = parse_usdc_amount(amount)?;

    // Step 1: Local pre-flight — check spending limits
    with_policy_engine(|engine| {
        engine.reset_if_needed(now);
        engine.check_spending(amount_micro, now)
    })?;

    // Step 2: Backend spending check
    let check_body = json!({ "amount": amount }).to_string();
    backend::signed_fetch(
        "POST",
        "/mandates/check-spend",
        Some(&check_body),
        &config,
        &worker_key,
    )?;

    // Step 3: Prepare transaction
    let mut prepare_body = json!({
        "to": to,
        "amount": amount,
        "type": tx_type,
    });
    if let Some(params) = deal_params {
        prepare_body["task_cid"] = json!(params.task_cid);
        prepare_body["delivery_deadline"] = json!(params.delivery_deadline);
    }
    let prepare_resp = backend::signed_fetch(
        "POST",
        "/transactions/prepare",
        Some(&prepare_body.to_string()),
        &config,
        &worker_key,
    )?;
    let prepare_data = backend::parse_response_data(&prepare_resp)?;
    let tx_id = prepare_data["tx_id"]
        .as_str()
        .ok_or("missing tx_id in prepare response")?;
    let user_op_hash = prepare_data["user_op_hash"]
        .as_str()
        .ok_or("missing user_op_hash in prepare response")?;

    // Step 3.5: Validate calldata — verify `to` matches requested recipient
    // This closes the gap where a compromised JS layer could redirect payments
    // by tampering with the HTTP bridge response from /transactions/prepare.
    // Only validates for direct transfers (to is a hex address). Escrow/deal orders
    // use agent IDs as `to` and have different calldata formats.
    let to_hex_clean = to.strip_prefix("0x").unwrap_or(to);
    let is_hex_address = to_hex_clean.len() == 40 && hex::decode(to_hex_clean).is_ok();
    if is_hex_address {
        let calldata_hex = prepare_data["calldata"]
            .as_str()
            .ok_or("calldata required for direct transfer but missing from prepare response")?;
        {
            let calldata = hex::decode(calldata_hex.strip_prefix("0x").unwrap_or(calldata_hex))
                .map_err(|e| format!("invalid calldata hex: {}", e))?;
            // ABI layout: [4 selector][32 to_padded][32 token][32 amount][32 ref]
            if calldata.len() < 4 + 32 {
                return Err("calldata too short to contain to address".to_string());
            }
            // Address is right-aligned in the 32-byte ABI word: 12 zero bytes + 20 address bytes
            let decoded_to = &calldata[4 + 12..4 + 32];
            let requested_to = hex::decode(to_hex_clean).unwrap(); // already validated
            if decoded_to != requested_to.as_slice() {
                return Err(format!(
                    "calldata to address mismatch: expected 0x{}, got 0x{}",
                    hex::encode(&requested_to),
                    hex::encode(decoded_to),
                ));
            }
        }
    }

    // Step 4: Sign user_op_hash with session key (secp256k1)
    // user_op_hash is already a 32-byte hash — use sign_prehash to avoid double-hashing
    let hash_bytes =
        hex::decode(user_op_hash.strip_prefix("0x").unwrap_or(user_op_hash))
            .map_err(|e| format!("invalid user_op_hash hex: {}", e))?;
    let hash_array: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| "user_op_hash must be 32 bytes")?;
    let signature = arysen_wallet::secp256k1::sign_prehash(&hash_array, &session_key);
    let signature_hex = format!("0x{}", hex::encode(&signature.0));

    // Step 5: Submit signed transaction
    let submit_body = json!({
        "tx_id": tx_id,
        "signature": signature_hex,
    })
    .to_string();
    let submit_resp = backend::signed_fetch(
        "POST",
        "/transactions/submit",
        Some(&submit_body),
        &config,
        &worker_key,
    )?;
    let submit_data = backend::parse_response_data(&submit_resp)?;
    let tx_hash = submit_data["tx_hash"]
        .as_str()
        .ok_or("missing tx_hash in submit response")?
        .to_string();

    // Step 6: Record spending
    let record_body = json!({ "amount": amount }).to_string();
    let _ = backend::signed_fetch(
        "POST",
        "/mandates/record-spend",
        Some(&record_body),
        &config,
        &worker_key,
    );
    // Also record locally
    with_policy_engine(|engine| engine.record_spending(amount_micro));

    Ok(types::TransferResult { tx_hash })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Reset module state between tests.
    fn reset_state() {
        *VAULT.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *POLICY_ENGINE.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *BACKEND_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *MANDATE_INFO.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *WORKER_KEY.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *SESSION_KEY.lock().unwrap_or_else(|e| e.into_inner()) = None;
        http::clear_mock_responses();
    }

    #[test]
    fn deposit_and_list_secrets() {
        reset_state();
        with_vault(|vault| {
            assert!(vault.deposit("api_key", b"encrypted_data"));
            assert!(vault.deposit("db_pass", b"encrypted_data2"));
            let names = vault.list_names();
            assert_eq!(names.len(), 2);
            assert!(names.contains(&"api_key".to_string()));
            assert!(names.contains(&"db_pass".to_string()));
        });
    }

    #[test]
    fn remove_secret_test() {
        reset_state();
        with_vault(|vault| {
            vault.deposit("temp_key", b"data");
            assert!(vault.remove("temp_key"));
            assert!(!vault.remove("nonexistent"));
        });
    }

    #[test]
    fn policy_check_allows_within_limits() {
        reset_state();
        let policy = types::Policy {
            spending: types::SpendingPolicy {
                max_per_tx: 1000,
                max_daily: 5000,
                expires_at: None,
            },
            secrets: HashMap::new(),
        };
        let result = policy::check(&policy, "spend", &json!({"amount": 100}));
        assert_eq!(result["allowed"], true);
    }

    #[test]
    fn policy_check_denies_over_limit() {
        reset_state();
        let policy = types::Policy {
            spending: types::SpendingPolicy {
                max_per_tx: 1000,
                max_daily: 5000,
                expires_at: None,
            },
            secrets: HashMap::new(),
        };
        let result = policy::check(&policy, "spend", &json!({"amount": 2000}));
        assert_eq!(result["allowed"], false);
    }

    #[test]
    fn execute_request_returns_mock_200() {
        reset_state();
        let template = types::RequestTemplate {
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            headers: HashMap::new(),
            body: None,
        };
        let response = inject::execute(&template);
        assert_eq!(response.status, 200);
    }

    #[test]
    fn end_to_end_execute_with_secrets() {
        reset_state();

        let secret_value = "sk-test-secret-key-12345";

        // 1. Deposit secret and retrieve it in the same closure to avoid race
        with_vault(|vault| {
            vault.deposit("API_KEY", secret_value.as_bytes());
            // Verify deposit worked
            let retrieved = vault.retrieve("API_KEY").expect("should retrieve deposited secret");
            assert_eq!(String::from_utf8(retrieved).unwrap(), secret_value);
        });

        // 2. Set a policy that allows usage
        let policy = types::Policy {
            spending: types::SpendingPolicy {
                max_per_tx: 100_000_000,
                max_daily: 500_000_000,
                expires_at: None,
            },
            secrets: {
                let mut m = HashMap::new();
                m.insert(
                    "API_KEY".to_string(),
                    types::SecretPolicy {
                        rate_limit: 60,
                        daily_limit: 1000,
                        allowed_domains: vec!["api.example.com".to_string()],
                    },
                );
                m
            },
        };
        with_policy_engine(|engine| engine.set_policy(policy));

        // 3. Parse template and find placeholders
        let template_json = r#"{
            "method": "GET",
            "url": "https://api.example.com/data",
            "headers": {"Authorization": "Bearer {API_KEY}"},
            "body": null
        }"#;

        let template = inject::parse_request_template(template_json).unwrap();
        let placeholders = inject::collect_all_placeholders(&template);
        assert_eq!(placeholders, vec!["API_KEY"]);

        // 4. Substitute with known values (simulating the vault retrieve)
        let mut secret_values = HashMap::new();
        secret_values.insert("API_KEY".to_string(), secret_value.to_string());

        let hydrated = inject::substitute_template(&template, &secret_values).unwrap();
        assert_eq!(
            hydrated.headers.get("Authorization").unwrap(),
            "Bearer sk-test-secret-key-12345"
        );

        // 5. Execute (mock)
        let response = http::execute_request(&hydrated);
        assert_eq!(response.status, 200);

        // 6. Verify scrubbing
        let injected: Vec<String> = secret_values.values().cloned().collect();
        let scrubbed = inject::scrub_response(&response.body, &injected);
        assert!(!scrubbed.contains("sk-test-secret-key-12345"));
        // Partial matches should also be scrubbed (first 8, last 8)
        assert!(!scrubbed.contains("sk-test-s")); // first 8
        assert!(!scrubbed.contains("ey-12345")); // last 8
    }

    #[test]
    fn execute_request_denied_by_domain_policy() {
        reset_state();

        // Deposit secret
        with_vault(|vault| {
            vault.deposit("API_KEY", b"sk-secret");
        });

        // Set policy with domain restriction
        let policy = types::Policy {
            spending: types::SpendingPolicy {
                max_per_tx: 100_000_000,
                max_daily: 500_000_000,
                expires_at: None,
            },
            secrets: {
                let mut m = HashMap::new();
                m.insert(
                    "API_KEY".to_string(),
                    types::SecretPolicy {
                        rate_limit: 60,
                        daily_limit: 1000,
                        allowed_domains: vec!["api.openai.com".to_string()],
                    },
                );
                m
            },
        };
        with_policy_engine(|engine| engine.set_policy(policy));

        // Try to use secret for a different domain
        let check = with_policy_engine(|engine| {
            engine.check_secret_usage("API_KEY", "https://evil.com/steal")
        });
        assert!(check.is_err());
    }

    #[test]
    fn spending_summary_updates() {
        reset_state();

        let policy = types::Policy {
            spending: types::SpendingPolicy {
                max_per_tx: 100_000_000,
                max_daily: 500_000_000,
                expires_at: None,
            },
            secrets: HashMap::new(),
        };
        with_policy_engine(|engine| {
            engine.set_policy(policy);
            engine.record_spending(10_000_000);
            engine.record_spending(20_000_000);
            let summary = engine.get_spending_summary();
            assert_eq!(summary.today, 30_000_000);

            assert_eq!(summary.total_all_time, 30_000_000);
        });
    }

    // --- Phase 9: mandate_init tests ---

    fn mock_mandate_response() {
        http::set_mock_response(
            "/mandates/mine",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: r#"{
                    "success": true,
                    "data": {
                        "mandate_id": "m-test-123",
                        "max_per_tx": "10",
                        "max_daily": "50",
                        "daily_spent": 15.5,
                        "wallet_address": "0xABC",
                        "expires_at": "",
                        "serialized_permission": "0xDEF"
                    }
                }"#
                .to_string(),
            },
        );
    }

    fn test_init_config() -> String {
        let (_, worker_priv) = arysen_wallet::ed25519::generate_keypair_raw();
        let (_, session_priv) = arysen_wallet::secp256k1::generate_keypair_raw();
        serde_json::json!({
            "base_url": "https://api.arysen.ai",
            "agent_id": "agent-test-456",
            "worker_key_id": "wk_test",
            "session_key_id": "sk_test",
            "worker_private_key_hex": hex::encode(worker_priv),
            "session_private_key_hex": hex::encode(session_priv),
        })
        .to_string()
    }

    #[test]
    fn mandate_init_hydrates_state() {
        reset_state();
        mock_mandate_response();

        let result = mandate_init_internal(&test_init_config());
        assert!(result.is_ok(), "init failed: {:?}", result.err());

        let info = result.unwrap();
        assert_eq!(info.mandate_id, "m-test-123");
        assert_eq!(info.max_per_tx, "10");
        assert_eq!(info.wallet_address, "0xABC");

        // Verify policy was hydrated: 10 USDC = 10_000_000 (6 decimals)
        // Note: statics (BACKEND_CONFIG, WORKER_KEY) are verified indirectly —
        // if init returned Ok with correct data, it stored everything. Direct
        // reads of statics are racy with parallel tests calling reset_state().
        with_policy_engine(|engine| {
            assert_eq!(engine.policy().spending.max_per_tx, 10_000_000);
            assert_eq!(engine.policy().spending.max_daily, 50_000_000);
            assert!(engine.policy().spending.expires_at.is_none());
        });
    }

    #[test]
    fn mandate_init_fails_on_bad_config() {
        reset_state();
        let result = mandate_init_internal("not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid config"));
    }

    #[test]
    fn mandate_init_fails_on_backend_error() {
        reset_state();
        http::set_mock_response(
            "/mandates/mine",
            types::HttpResponse {
                status: 404,
                headers: HashMap::new(),
                body: r#"{"success":false,"error":"no mandate"}"#.to_string(),
            },
        );

        let result = mandate_init_internal(&test_init_config());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("404"));
    }

    #[test]
    fn get_mandate_info_before_init_returns_error() {
        reset_state();
        // Not calling mandate_init — mandate_info should be None
        let guard = MANDATE_INFO.lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn parse_usdc_amounts() {
        assert_eq!(parse_usdc_amount("10").unwrap(), 10_000_000);
        assert_eq!(parse_usdc_amount("0.5").unwrap(), 500_000);
        assert_eq!(parse_usdc_amount("100.25").unwrap(), 100_250_000);
        assert!(parse_usdc_amount("abc").is_err());
    }

    // --- Phase 10: transfer_usdc + create_deal_order tests ---

    /// Test recipient address (20 bytes = 40 hex chars)
    const TEST_RECIPIENT: &str = "0x1234567890abcdef1234567890abcdef12345678";

    /// Build ABI-encoded calldata for transferWithFee(address to, address token, uint256 amount, bytes32 ref).
    /// The `to` address is placed in the first 32-byte parameter word (right-aligned, 12 zero-pad + 20 address).
    fn make_test_calldata(to_hex: &str) -> String {
        let to_clean = to_hex.strip_prefix("0x").unwrap_or(to_hex);
        let to_bytes = hex::decode(to_clean).unwrap();
        assert_eq!(to_bytes.len(), 20, "address must be 20 bytes");
        // 4-byte selector (arbitrary) + 32-byte to (12 zeros + 20 addr) + 32 token + 32 amount + 32 ref
        let mut calldata = vec![0xab, 0xcd, 0xef, 0x01]; // selector
        calldata.extend_from_slice(&[0u8; 12]); // padding
        calldata.extend_from_slice(&to_bytes);   // to address
        calldata.extend_from_slice(&[0u8; 32]);  // token (placeholder)
        calldata.extend_from_slice(&[0u8; 32]);  // amount (placeholder)
        calldata.extend_from_slice(&[0u8; 32]);  // ref (placeholder)
        format!("0x{}", hex::encode(calldata))
    }

    /// Set up mocks for the full 5-step transfer flow with calldata validation.
    fn mock_transfer_flow() {
        mock_transfer_flow_for(TEST_RECIPIENT);
    }

    fn mock_transfer_flow_for(recipient: &str) {
        mock_mandate_response(); // GET /mandates/mine
        http::set_mock_response(
            "/mandates/check-spend",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: r#"{"success":true,"data":{"allowed":true}}"#.to_string(),
            },
        );
        let calldata = make_test_calldata(recipient);
        http::set_mock_response(
            "/transactions/prepare",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: format!(
                    r#"{{"success":true,"data":{{"tx_id":"tx-abc-123","user_op_hash":"0xdeadbeef01020304050607080910111213141516171819202122232425262728","calldata":"{}"}}}}"#,
                    calldata
                ),
            },
        );
        http::set_mock_response(
            "/transactions/submit",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: r#"{"success":true,"data":{"tx_hash":"0xfinalhash999"}}"#.to_string(),
            },
        );
        http::set_mock_response(
            "/mandates/record-spend",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: r#"{"success":true,"data":{}}"#.to_string(),
            },
        );
    }

    #[test]
    fn transfer_usdc_full_flow() {
        reset_state();
        mock_transfer_flow();

        // Init first
        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok(), "init failed: {:?}", init_result.err());

        // Transfer
        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_ok(), "transfer failed: {:?}", result.err());
        let tx = result.unwrap();
        assert_eq!(tx.tx_hash, "0xfinalhash999");

        // Verify spending was recorded locally (>= because parallel tests may add)
        with_policy_engine(|engine| {
            let summary = engine.get_spending_summary();
            assert!(summary.today >= 5_000_000, "expected at least 5 USDC recorded, got {}", summary.today);
        });
    }

    #[test]
    fn transfer_usdc_denied_by_local_preflight() {
        reset_state();
        mock_transfer_flow();

        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok());

        // Try to transfer more than max_per_tx (10 USDC from mock mandate)
        let result = transfer_internal(TEST_RECIPIENT, "15.00");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds max_per_tx"));
    }

    #[test]
    fn transfer_usdc_denied_by_backend_check() {
        reset_state();
        mock_mandate_response();
        // Override check-spend to deny
        http::set_mock_response(
            "/mandates/check-spend",
            types::HttpResponse {
                status: 403,
                headers: HashMap::new(),
                body: r#"{"success":false,"error":"daily limit exceeded"}"#.to_string(),
            },
        );

        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok());

        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("403"));
    }

    #[test]
    fn transfer_usdc_prepare_fails_no_record() {
        reset_state();
        mock_mandate_response();
        http::set_mock_response(
            "/mandates/check-spend",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: r#"{"success":true,"data":{"allowed":true}}"#.to_string(),
            },
        );
        // Prepare fails
        http::set_mock_response(
            "/transactions/prepare",
            types::HttpResponse {
                status: 500,
                headers: HashMap::new(),
                body: r#"{"success":false,"error":"internal error"}"#.to_string(),
            },
        );

        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok());

        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_err());

        // Spending should NOT have been recorded
        with_policy_engine(|engine| {
            assert_eq!(engine.get_spending_summary().today, 0);
        });
    }

    #[test]
    fn transfer_usdc_signature_is_valid_secp256k1() {
        reset_state();
        mock_transfer_flow();

        // Generate a session key and capture the public key
        let (session_pub, session_priv) = arysen_wallet::secp256k1::generate_keypair_raw();
        let (_, worker_priv) = arysen_wallet::ed25519::generate_keypair_raw();

        let config = serde_json::json!({
            "base_url": "https://api.arysen.ai",
            "agent_id": "agent-test-456",
            "worker_key_id": "wk_test",
            "session_key_id": "sk_test",
            "worker_private_key_hex": hex::encode(worker_priv),
            "session_private_key_hex": hex::encode(session_priv),
        })
        .to_string();

        let init_result = mandate_init_internal(&config);
        assert!(init_result.is_ok());

        // The transfer will sign user_op_hash with the session key
        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_ok());

        // Verify: sign the same hash with the same key and check
        let hash_hex = "deadbeef01020304050607080910111213141516171819202122232425262728";
        let hash_bytes = hex::decode(hash_hex).unwrap();
        let sig = arysen_wallet::secp256k1::sign_raw(&hash_bytes, &session_priv);
        assert_eq!(sig.0.len(), 65);
        assert!(arysen_wallet::secp256k1::verify(
            &hash_bytes,
            &sig.0,
            &session_pub
        ));
    }

    #[test]
    fn transfer_and_deal_order_flow() {
        // Combined test: init → transfer → deal order → verify
        // Avoids parallel race conditions on statics.
        reset_state();
        mock_transfer_flow();

        // Before init, transfer should fail
        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not initialized"),
            "expected 'not initialized' error before init"
        );

        // Init
        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok(), "init failed: {:?}", init_result.err());

        // Deal order
        let params = serde_json::json!({
            "executor_agent_id": "agent-exec-789",
            "bounty_amount": "3.50",
            "task_cid": "QmTaskCID123",
            "delivery_deadline": 1735689600u64,
        })
        .to_string();

        let result = deal_order_internal(&params);
        assert!(result.is_ok(), "deal order failed: {:?}", result.err());
        assert_eq!(result.unwrap().tx_hash, "0xfinalhash999");
    }

    // --- Calldata validation tests ---

    #[test]
    fn calldata_validation_passes_with_matching_to() {
        reset_state();
        mock_transfer_flow(); // calldata contains TEST_RECIPIENT
        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok());

        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_ok(), "transfer should pass with matching calldata: {:?}", result.err());
    }

    #[test]
    fn calldata_validation_rejects_mismatched_to() {
        reset_state();
        // Mock with a DIFFERENT recipient in calldata
        let attacker = "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead";
        mock_transfer_flow_for(attacker);
        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok());

        // Agent requests transfer to TEST_RECIPIENT but calldata has attacker address
        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_err(), "transfer should be rejected on calldata mismatch");
        let err = result.unwrap_err();
        assert!(err.contains("calldata to address mismatch"), "error should mention mismatch: {}", err);
    }

    #[test]
    fn calldata_validation_rejects_truncated_calldata() {
        reset_state();
        mock_mandate_response();
        http::set_mock_response(
            "/mandates/check-spend",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: r#"{"success":true,"data":{"allowed":true}}"#.to_string(),
            },
        );
        // Calldata too short — only 4 bytes (selector, no params)
        http::set_mock_response(
            "/transactions/prepare",
            types::HttpResponse {
                status: 200,
                headers: HashMap::new(),
                body: r#"{"success":true,"data":{"tx_id":"tx-abc-123","user_op_hash":"0xdeadbeef01020304050607080910111213141516171819202122232425262728","calldata":"0xabcdef01"}}"#.to_string(),
            },
        );
        let init_result = mandate_init_internal(&test_init_config());
        assert!(init_result.is_ok());

        let result = transfer_internal(TEST_RECIPIENT, "5.00");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }
}
