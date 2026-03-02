/// HTTP execution via host import.
///
/// In WASM: serializes a request, calls the `http_execute` host import,
/// and deserializes the response.
///
/// In native (tests): returns a mock response that echoes back the request
/// details for verification.

use crate::types::{HttpResponse, RequestTemplate};
use std::collections::HashMap;

/// Execute an HTTP request.
///
/// In WASM builds, this calls the host-provided `http_execute` import.
/// In native builds (tests), it returns a mock response.
pub fn execute_request(template: &RequestTemplate) -> HttpResponse {
    #[cfg(target_arch = "wasm32")]
    {
        execute_wasm(template)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        execute_mock(template)
    }
}

/// Execute via host import (WASM only).
#[cfg(target_arch = "wasm32")]
fn execute_wasm(template: &RequestTemplate) -> HttpResponse {
    use crate::http_execute;

    // Serialize the request to JSON for the host
    let request_json = serde_json::json!({
        "method": template.method,
        "url": template.url,
        "headers": template.headers,
        "body": template.body,
    });

    let req_bytes = serde_json::to_vec(&request_json).unwrap_or_default();
    let mut resp_buf = vec![0u8; 65536]; // 64KB response buffer

    let result = unsafe {
        http_execute(
            req_bytes.as_ptr(),
            req_bytes.len() as u32,
            resp_buf.as_mut_ptr(),
            resp_buf.len() as u32,
        )
    };

    if result < 0 {
        return HttpResponse {
            status: 502,
            headers: HashMap::new(),
            body: format!("host http_execute error: {}", result),
        };
    }

    let resp_len = result as usize;
    if resp_len > resp_buf.len() {
        return HttpResponse {
            status: 502,
            headers: HashMap::new(),
            body: "response too large".to_string(),
        };
    }

    // Parse response JSON from host
    match serde_json::from_slice::<HttpResponse>(&resp_buf[..resp_len]) {
        Ok(response) => response,
        Err(e) => HttpResponse {
            status: 502,
            headers: HashMap::new(),
            body: format!("failed to parse host response: {}", e),
        },
    }
}

/// Mock HTTP execution for native tests.
///
/// Returns a canned 200 response that includes the request URL in the body,
/// making it possible to verify the request was constructed correctly.
#[cfg(not(target_arch = "wasm32"))]
fn execute_mock(template: &RequestTemplate) -> HttpResponse {
    let body = serde_json::json!({
        "mock": true,
        "echo": {
            "method": template.method,
            "url": template.url,
            "headers": template.headers,
            "body": template.body,
        }
    });

    HttpResponse {
        status: 200,
        headers: {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "application/json".to_string());
            h
        },
        body: serde_json::to_string(&body).unwrap_or_default(),
    }
}

/// Execute a raw HTTP request (lower-level API).
pub fn execute_raw(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> HttpResponse {
    let mut header_map = HashMap::new();
    for (k, v) in headers {
        header_map.insert(k.to_string(), v.to_string());
    }

    let template = RequestTemplate {
        method: method.to_string(),
        url: url.to_string(),
        headers: header_map,
        body: body.map(|b| String::from_utf8_lossy(b).to_string()),
    };

    execute_request(&template)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_returns_200() {
        let template = RequestTemplate {
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            headers: HashMap::new(),
            body: None,
        };
        let resp = execute_request(&template);
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn mock_echoes_url() {
        let template = RequestTemplate {
            method: "POST".to_string(),
            url: "https://api.openai.com/v1/chat".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Authorization".to_string(), "Bearer test".to_string());
                h
            },
            body: Some(r#"{"prompt": "hello"}"#.to_string()),
        };
        let resp = execute_request(&template);
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("api.openai.com"));
        assert!(resp.body.contains("POST"));
    }

    #[test]
    fn execute_raw_works() {
        let resp = execute_raw(
            "GET",
            "https://example.com",
            &[("Accept", "application/json")],
            None,
        );
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("example.com"));
    }
}
