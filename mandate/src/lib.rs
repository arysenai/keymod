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
    fn key_store_read(key_id: *const u8, key_id_len: u32, buf: *mut u8, buf_len: u32) -> i32;
    fn key_store_write(key_id: *const u8, key_id_len: u32, data: *const u8, data_len: u32) -> i32;
    fn get_random_bytes(buf: *mut u8, len: u32) -> i32;
    fn get_time() -> u64;
    fn http_execute(req: *const u8, req_len: u32, resp: *mut u8, resp_len: u32) -> i32;
}

// Native stubs for `cargo test` (not compiled into WASM)
#[cfg(not(target_arch = "wasm32"))]
mod host_stubs {
    #[no_mangle]
    pub extern "C" fn key_store_read(
        _key_id: *const u8,
        _key_id_len: u32,
        _buf: *mut u8,
        _buf_len: u32,
    ) -> i32 {
        -1
    }

    #[no_mangle]
    pub extern "C" fn key_store_write(
        _key_id: *const u8,
        _key_id_len: u32,
        _data: *const u8,
        _data_len: u32,
    ) -> i32 {
        0
    }

    #[no_mangle]
    pub extern "C" fn get_random_bytes(_buf: *mut u8, _len: u32) -> i32 {
        0
    }

    #[no_mangle]
    pub extern "C" fn get_time() -> u64 {
        0
    }

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
                    max_monthly: 0,
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

/// Return the SHA-256 hash of this WASM module's binary.
/// Stub: returns 32 zero bytes.
#[wasm_bindgen]
pub fn get_module_hash() -> Vec<u8> {
    vec![0u8; 32]
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
                max_monthly: 50000,
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
                max_monthly: 50000,
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
    fn module_hash_is_32_bytes() {
        assert_eq!(get_module_hash().len(), 32);
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
                max_monthly: 5_000_000_000,
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
                max_monthly: 5_000_000_000,
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
                max_monthly: 5_000_000_000,
            },
            secrets: HashMap::new(),
        };
        with_policy_engine(|engine| {
            engine.set_policy(policy);
            engine.record_spending(10_000_000);
            engine.record_spending(20_000_000);
            let summary = engine.get_spending_summary();
            assert_eq!(summary.today, 30_000_000);
            assert_eq!(summary.this_month, 30_000_000);
            assert_eq!(summary.total_all_time, 30_000_000);
        });
    }
}
