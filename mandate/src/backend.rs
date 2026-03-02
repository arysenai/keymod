/// Authenticated HTTP calls to the Arysen backend.
///
/// `signed_fetch` builds X-ARYSEN-* auth headers and signs with the
/// worker key (Ed25519). All backend communication goes through this layer.

use crate::http;
use crate::types::{BackendConfig, HttpResponse, RequestTemplate};
use std::collections::HashMap;

/// Make an authenticated request to the Arysen backend.
///
/// Builds the full URL from `config.base_url + "/api/v1" + path`,
/// adds auth headers (agent-id, timestamp, nonce, Ed25519 signature),
/// and executes via `http::execute_request`.
pub fn signed_fetch(
    method: &str,
    path: &str,
    body_json: Option<&str>,
    config: &BackendConfig,
    worker_private_key: &[u8],
) -> Result<HttpResponse, String> {
    let url = format!("{}/api/v1{}", config.base_url, path);
    let timestamp = crate::current_time().to_string();
    let nonce = generate_nonce();

    // Build signature message: body + nonce + timestamp
    let body_part = body_json.unwrap_or("");
    let message = format!("{}{}{}", body_part, nonce, timestamp);

    // Sign with Ed25519 worker key
    let signature = arysen_wallet::ed25519::sign_raw(message.as_bytes(), worker_private_key);
    let signature_hex = hex::encode(&signature.0);

    // Build request
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("X-ARYSEN-AGENT-ID".to_string(), config.agent_id.clone());
    headers.insert("X-ARYSEN-TIMESTAMP".to_string(), timestamp);
    headers.insert("X-ARYSEN-NONCE".to_string(), nonce);
    headers.insert("X-ARYSEN-SIGNATURE".to_string(), signature_hex);

    let template = RequestTemplate {
        method: method.to_string(),
        url,
        headers,
        body: body_json.map(|s| s.to_string()),
    };

    let response = http::execute_request(&template);

    if response.status >= 400 {
        return Err(format!(
            "backend returned HTTP {}: {}",
            response.status, response.body
        ));
    }

    Ok(response)
}

/// Parse the `data` field from a standard backend JSON response.
/// Backend responses follow the shape: `{ "success": bool, "data": ... }`.
pub fn parse_response_data(response: &HttpResponse) -> Result<serde_json::Value, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(&response.body).map_err(|e| format!("invalid JSON: {}", e))?;

    let success = parsed
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !success {
        let msg = parsed
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(format!("backend error: {}", msg));
    }

    parsed
        .get("data")
        .cloned()
        .ok_or_else(|| "missing 'data' field in response".to_string())
}

/// Generate a random 16-byte hex nonce.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{clear_mock_responses, set_mock_response};
    use crate::types::HttpResponse as HR;

    fn test_config() -> BackendConfig {
        BackendConfig {
            base_url: "https://api.arysen.ai".to_string(),
            agent_id: "agent-uuid-123".to_string(),
            worker_key_id: "wk_test".to_string(),
            session_key_id: "sk_test".to_string(),
        }
    }

    fn test_worker_key() -> [u8; 32] {
        let (_, priv_key) = arysen_wallet::ed25519::generate_keypair_raw();
        priv_key
    }

    #[test]
    fn signed_fetch_includes_auth_headers() {
        clear_mock_responses();
        let config = test_config();
        let priv_key = test_worker_key();

        let resp = signed_fetch("GET", "/mandates/mine", None, &config, &priv_key).unwrap();

        // Default echo mock — body contains the request headers
        assert!(resp.body.contains("X-ARYSEN-AGENT-ID"));
        assert!(resp.body.contains("agent-uuid-123"));
        assert!(resp.body.contains("X-ARYSEN-TIMESTAMP"));
        assert!(resp.body.contains("X-ARYSEN-NONCE"));
        assert!(resp.body.contains("X-ARYSEN-SIGNATURE"));
    }

    #[test]
    fn signed_fetch_builds_correct_url() {
        clear_mock_responses();
        let config = test_config();
        let priv_key = test_worker_key();

        let resp = signed_fetch("POST", "/transactions/prepare", Some("{}"), &config, &priv_key)
            .unwrap();

        assert!(resp.body.contains("https://api.arysen.ai/api/v1/transactions/prepare"));
    }

    #[test]
    fn signed_fetch_signature_is_valid() {
        clear_mock_responses();
        let config = test_config();
        let (pub_key, priv_key) = arysen_wallet::ed25519::generate_keypair_raw();

        let body = r#"{"amount":"5.00"}"#;
        let resp = signed_fetch("POST", "/mandates/check-spend", Some(body), &config, &priv_key)
            .unwrap();

        // Extract the signature, nonce, and timestamp from the echoed headers
        let parsed: serde_json::Value = serde_json::from_str(&resp.body).unwrap();
        let headers = &parsed["echo"]["headers"];
        let sig_hex = headers["X-ARYSEN-SIGNATURE"].as_str().unwrap();
        let nonce = headers["X-ARYSEN-NONCE"].as_str().unwrap();
        let timestamp = headers["X-ARYSEN-TIMESTAMP"].as_str().unwrap();

        // Reconstruct the signed message
        let message = format!("{}{}{}", body, nonce, timestamp);
        let sig_bytes = hex::decode(sig_hex).unwrap();

        // Verify the signature
        assert!(arysen_wallet::ed25519::verify(
            message.as_bytes(),
            &sig_bytes,
            &pub_key
        ));
    }

    #[test]
    fn signed_fetch_returns_error_on_4xx() {
        clear_mock_responses();
        set_mock_response(
            "/mandates/check-spend",
            HR {
                status: 403,
                headers: HashMap::new(),
                body: r#"{"success":false,"error":"daily limit exceeded"}"#.to_string(),
            },
        );

        let config = test_config();
        let priv_key = test_worker_key();

        let result =
            signed_fetch("POST", "/mandates/check-spend", Some("{}"), &config, &priv_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("403"));

        clear_mock_responses();
    }

    #[test]
    fn parse_response_data_success() {
        let response = HR {
            status: 200,
            headers: HashMap::new(),
            body: r#"{"success":true,"data":{"mandate_id":"abc"}}"#.to_string(),
        };
        let data = parse_response_data(&response).unwrap();
        assert_eq!(data["mandate_id"], "abc");
    }

    #[test]
    fn parse_response_data_error() {
        let response = HR {
            status: 200,
            headers: HashMap::new(),
            body: r#"{"success":false,"error":"not found"}"#.to_string(),
        };
        let result = parse_response_data(&response);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn configurable_mock_responds_correctly() {
        clear_mock_responses();
        set_mock_response(
            "/mandates/mine",
            HR {
                status: 200,
                headers: HashMap::new(),
                body: r#"{"success":true,"data":{"mandate_id":"m-123"}}"#.to_string(),
            },
        );

        let config = test_config();
        let priv_key = test_worker_key();

        let resp = signed_fetch("GET", "/mandates/mine", None, &config, &priv_key).unwrap();
        assert_eq!(resp.status, 200);
        let data = parse_response_data(&resp).unwrap();
        assert_eq!(data["mandate_id"], "m-123");

        clear_mock_responses();
    }
}
