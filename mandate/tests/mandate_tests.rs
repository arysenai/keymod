use arysen_mandate::inject;
use arysen_mandate::policy::PolicyEngine;
use arysen_mandate::secrets::SecretVault;
use arysen_mandate::types::*;
use std::collections::HashMap;

// ============================================================================
// Secrets vault tests
// ============================================================================

#[test]
fn secret_vault_deposit_and_list() {
    let mut vault = SecretVault::new();
    vault.deposit("key1", b"encrypted1");
    vault.deposit("key2", b"encrypted2");

    let names = vault.list_names();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"key1".to_string()));
    assert!(names.contains(&"key2".to_string()));
}

#[test]
fn secret_vault_remove() {
    let mut vault = SecretVault::new();
    vault.deposit("temp", b"data");
    assert!(vault.remove("temp"));
    assert!(!vault.remove("temp")); // already removed
    assert_eq!(vault.list_names().len(), 0);
}

#[test]
fn secret_vault_list_returns_names_only() {
    let mut vault = SecretVault::new();
    vault.deposit("api_key", b"super_secret_value_123");
    vault.deposit("db_password", b"another_secret_456");

    let names = vault.list_names();
    // Names are returned, but there's no way to get values via list_names
    assert!(names.contains(&"api_key".to_string()));
    assert!(names.contains(&"db_password".to_string()));
    // Values are not exposed
    for name in &names {
        assert!(!name.contains("super_secret"));
        assert!(!name.contains("another_secret"));
    }
}

#[test]
fn secret_vault_deposit_retrieve_cycle() {
    // retrieve is pub(crate), so integration tests verify via deposit + list
    let mut vault = SecretVault::new();
    assert!(vault.deposit("key", b"my_secret_value"));
    let names = vault.list_names();
    assert_eq!(names.len(), 1);
    assert!(names.contains(&"key".to_string()));
}

#[test]
fn secret_vault_overwrite() {
    let mut vault = SecretVault::new();
    vault.deposit("key", b"value1");
    vault.deposit("key", b"value2");
    // Overwrite should keep only one entry
    assert_eq!(vault.list_names().len(), 1);
}

// ============================================================================
// Policy serialization tests
// ============================================================================

#[test]
fn policy_serialization_roundtrip() {
    let policy = Policy {
        spending: SpendingPolicy {
            max_per_tx: 100_000_000,
            max_daily: 500_000_000,
            max_monthly: 5_000_000_000,
        },
        secrets: {
            let mut m = HashMap::new();
            m.insert(
                "openai_key".to_string(),
                SecretPolicy {
                    rate_limit: 60,
                    daily_limit: 1000,
                    allowed_domains: vec!["api.openai.com".to_string()],
                },
            );
            m
        },
    };

    let json = serde_json::to_string(&policy).unwrap();
    let parsed: Policy = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.spending.max_per_tx, 100_000_000);
    assert!(parsed.secrets.contains_key("openai_key"));
}

#[test]
fn request_template_deserialization() {
    let json = r#"{
        "method": "POST",
        "url": "https://api.example.com/v1/chat",
        "headers": {"Authorization": "Bearer {API_KEY}"},
        "body": "{\"prompt\": \"hello\"}"
    }"#;

    let template: RequestTemplate = serde_json::from_str(json).unwrap();
    assert_eq!(template.method, "POST");
    assert!(template.headers.contains_key("Authorization"));
    assert!(template.body.is_some());
}

#[test]
fn http_response_structure() {
    let response = HttpResponse {
        status: 200,
        headers: HashMap::new(),
        body: String::from("{\"ok\": true}"),
    };
    assert_eq!(response.status, 200);
}

// ============================================================================
// Policy engine tests
// ============================================================================

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
            max_per_tx: 100_000_000,
            max_daily: 500_000_000,
            max_monthly: 5_000_000_000,
        },
        secrets,
    }
}

#[test]
fn policy_allow_spending_within_limits() {
    let engine = PolicyEngine::new(test_policy(), 1000);
    assert!(engine.check_spending(50_000_000).is_ok());
}

#[test]
fn policy_deny_spending_over_per_tx() {
    let engine = PolicyEngine::new(test_policy(), 1000);
    let result = engine.check_spending(200_000_000);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("max_per_tx"));
}

#[test]
fn policy_deny_spending_over_daily() {
    let mut engine = PolicyEngine::new(test_policy(), 1000);
    engine.record_spending(400_000_000);
    // 100 more = 500 total = exactly the limit
    assert!(engine.check_spending(100_000_000).is_ok());
    engine.record_spending(100_000_000);
    // Any more should be denied
    assert!(engine.check_spending(1_000_000).is_err());
}

#[test]
fn policy_daily_limit_resets() {
    let mut engine = PolicyEngine::new(test_policy(), 1000);
    engine.record_spending(400_000_000);
    // Advance past one day
    engine.reset_if_needed(1000 + 86_400);
    // Should be able to spend again
    assert!(engine.check_spending(100_000_000).is_ok());
}

#[test]
fn policy_secret_rate_limit() {
    let mut engine = PolicyEngine::new(test_policy(), 1000);
    // Rate limit is 5/min for openai_key
    for _ in 0..5 {
        assert!(engine
            .check_secret_usage("openai_key", "https://api.openai.com/v1/chat")
            .is_ok());
        engine.record_secret_usage("openai_key", 1000);
    }
    // 6th call should be denied
    let result = engine.check_secret_usage("openai_key", "https://api.openai.com/v1/chat");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("rate limit"));
}

#[test]
fn policy_secret_rate_limit_resets() {
    let mut engine = PolicyEngine::new(test_policy(), 1000);
    for _ in 0..5 {
        engine.record_secret_usage("openai_key", 1000);
    }
    // Rate limit hit
    assert!(engine
        .check_secret_usage("openai_key", "https://api.openai.com/v1/chat")
        .is_err());
    // Reset after a minute
    engine.reset_if_needed(1000 + 61);
    assert!(engine
        .check_secret_usage("openai_key", "https://api.openai.com/v1/chat")
        .is_ok());
}

#[test]
fn policy_domain_allowlist_allows() {
    let engine = PolicyEngine::new(test_policy(), 1000);
    assert!(engine
        .check_secret_usage("openai_key", "https://api.openai.com/v1/chat")
        .is_ok());
}

#[test]
fn policy_domain_allowlist_denies() {
    let engine = PolicyEngine::new(test_policy(), 1000);
    let result = engine.check_secret_usage("openai_key", "https://evil.com/steal");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not allowed"));
}

#[test]
fn policy_spending_summary() {
    let mut engine = PolicyEngine::new(test_policy(), 1000);
    engine.record_spending(10_000_000);
    engine.record_spending(20_000_000);
    let summary = engine.get_spending_summary();
    assert_eq!(summary.today, 30_000_000);
    assert_eq!(summary.this_month, 30_000_000);
    assert_eq!(summary.total_all_time, 30_000_000);
}

// ============================================================================
// Inject tests — placeholder parsing
// ============================================================================

#[test]
fn inject_parse_single_placeholder() {
    let placeholders = inject::parse_placeholders("Bearer {API_KEY}");
    assert_eq!(placeholders, vec!["API_KEY"]);
}

#[test]
fn inject_parse_multiple_placeholders() {
    let placeholders =
        inject::parse_placeholders("https://{HOST}/v1/{RESOURCE}?key={API_KEY}");
    assert_eq!(placeholders.len(), 3);
    assert!(placeholders.contains(&"HOST".to_string()));
    assert!(placeholders.contains(&"RESOURCE".to_string()));
    assert!(placeholders.contains(&"API_KEY".to_string()));
}

#[test]
fn inject_parse_nested_in_url() {
    let placeholders = inject::parse_placeholders(
        "https://api.example.com/v1/chat?token={AUTH_TOKEN}&user={USER_ID}",
    );
    assert_eq!(placeholders.len(), 2);
    assert!(placeholders.contains(&"AUTH_TOKEN".to_string()));
    assert!(placeholders.contains(&"USER_ID".to_string()));
}

#[test]
fn inject_parse_no_placeholders() {
    let placeholders = inject::parse_placeholders("no placeholders here");
    assert!(placeholders.is_empty());
}

#[test]
fn inject_parse_deduplicates() {
    let placeholders = inject::parse_placeholders("{KEY} and {KEY}");
    assert_eq!(placeholders.len(), 1);
    assert_eq!(placeholders[0], "KEY");
}

// ============================================================================
// Inject tests — substitution
// ============================================================================

#[test]
fn inject_substitute_single() {
    let mut secrets = HashMap::new();
    secrets.insert("API_KEY".to_string(), "sk-12345".to_string());
    let result = inject::substitute("Bearer {API_KEY}", &secrets).unwrap();
    assert_eq!(result, "Bearer sk-12345");
}

#[test]
fn inject_substitute_multiple() {
    let mut secrets = HashMap::new();
    secrets.insert("HOST".to_string(), "api.example.com".to_string());
    secrets.insert("TOKEN".to_string(), "abc123".to_string());
    let result = inject::substitute("https://{HOST}/data?t={TOKEN}", &secrets).unwrap();
    assert_eq!(result, "https://api.example.com/data?t=abc123");
}

#[test]
fn inject_substitute_fails_on_unknown() {
    let secrets = HashMap::new();
    let result = inject::substitute("Bearer {MISSING_KEY}", &secrets);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("MISSING_KEY"));
}

// ============================================================================
// Inject tests — scrubbing
// ============================================================================

#[test]
fn inject_scrub_exact_match() {
    let response = "your key is sk-12345 and it works";
    let scrubbed = inject::scrub_response(response, &["sk-12345".to_string()]);
    assert!(!scrubbed.contains("sk-12345"));
    assert!(scrubbed.contains("[REDACTED]"));
}

#[test]
fn inject_scrub_partial_match() {
    // 24 chars, long enough for partial scrubbing
    let secret = "abcdefghijklmnopqrstuvwx".to_string();
    let response = "found abcdefgh in the log and qrstuvwx elsewhere";
    let scrubbed = inject::scrub_response(response, &[secret]);
    // first 8 = "abcdefgh", last 8 = "qrstuvwx"
    assert!(!scrubbed.contains("abcdefgh"));
    assert!(!scrubbed.contains("qrstuvwx"));
}

#[test]
fn inject_scrub_no_match() {
    let response = "safe response with no secrets";
    let scrubbed = inject::scrub_response(response, &["not_here".to_string()]);
    assert_eq!(scrubbed, response);
}

#[test]
fn inject_scrub_multiple_secrets() {
    let response = "key1=abc123 key2=xyz789";
    let scrubbed = inject::scrub_response(
        response,
        &["abc123".to_string(), "xyz789".to_string()],
    );
    assert!(!scrubbed.contains("abc123"));
    assert!(!scrubbed.contains("xyz789"));
}

// ============================================================================
// End-to-end tests
// ============================================================================

#[test]
fn end_to_end_with_mock_http() {
    // This test exercises the full flow using only public APIs.
    // The vault's retrieve is pub(crate), so we simulate the inject flow
    // using the substitute functions directly with known values.

    let secret_value = "sk-test-secret-key-12345";

    // 1. Create policy engine and verify policy checks pass
    let policy = Policy {
        spending: SpendingPolicy {
            max_per_tx: 100_000_000,
            max_daily: 500_000_000,
            max_monthly: 5_000_000_000,
        },
        secrets: {
            let mut m = HashMap::new();
            m.insert(
                "API_KEY".to_string(),
                SecretPolicy {
                    rate_limit: 60,
                    daily_limit: 1000,
                    allowed_domains: vec!["api.example.com".to_string()],
                },
            );
            m
        },
    };
    let mut engine = PolicyEngine::new(policy, 1000);

    // 2. Parse template
    let template_json = r#"{
        "method": "GET",
        "url": "https://api.example.com/data",
        "headers": {"Authorization": "Bearer {API_KEY}"},
        "body": null
    }"#;
    let template = inject::parse_request_template(template_json).unwrap();

    // 3. Find placeholders
    let placeholders = inject::collect_all_placeholders(&template);
    assert_eq!(placeholders, vec!["API_KEY"]);

    // 4. Policy check
    for p in &placeholders {
        assert!(engine.check_secret_usage(p, &template.url).is_ok());
    }

    // 5. Substitute with known values
    let mut secret_values = HashMap::new();
    secret_values.insert("API_KEY".to_string(), secret_value.to_string());

    let hydrated = inject::substitute_template(&template, &secret_values).unwrap();
    assert!(hydrated
        .headers
        .get("Authorization")
        .unwrap()
        .contains(secret_value));

    // 6. Execute (mock)
    let response = arysen_mandate::http::execute_request(&hydrated);
    assert_eq!(response.status, 200);

    // 7. Scrub
    let injected: Vec<String> = secret_values.values().cloned().collect();
    let scrubbed = inject::scrub_response(&response.body, &injected);

    // The secret should be completely removed
    assert!(!scrubbed.contains(secret_value));
    // Partial matches too (first 8 = "sk-test-s", last 8 = "ey-12345")
    assert!(!scrubbed.contains("sk-test-s"));
    assert!(!scrubbed.contains("ey-12345"));

    // 8. Record usage
    for p in &placeholders {
        engine.record_secret_usage(p, 1000);
    }
}

#[test]
fn end_to_end_domain_denied() {
    let policy = Policy {
        spending: SpendingPolicy {
            max_per_tx: 100_000_000,
            max_daily: 500_000_000,
            max_monthly: 5_000_000_000,
        },
        secrets: {
            let mut m = HashMap::new();
            m.insert(
                "API_KEY".to_string(),
                SecretPolicy {
                    rate_limit: 60,
                    daily_limit: 1000,
                    allowed_domains: vec!["api.openai.com".to_string()],
                },
            );
            m
        },
    };
    let engine = PolicyEngine::new(policy, 1000);

    // Trying to use API_KEY for evil.com should be denied
    let result = engine.check_secret_usage("API_KEY", "https://evil.com/steal");
    assert!(result.is_err());
}

#[test]
fn spending_summary_serialization() {
    let summary = SpendingSummary {
        today: 10_000_000,
        this_month: 50_000_000,
        total_all_time: 200_000_000,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: SpendingSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.today, 10_000_000);
    assert_eq!(parsed.this_month, 50_000_000);
    assert_eq!(parsed.total_all_time, 200_000_000);
}
