/// Credential injection engine.
///
/// Replaces `{PLACEHOLDER}` tokens in request templates with decrypted
/// secret values, executes the HTTP request via host import, then scrubs
/// secrets from the response before returning it.

use crate::types::{HttpResponse, RequestTemplate};
use std::collections::HashMap;

/// Find all `{PLACEHOLDER_NAME}` tokens in a string.
/// Matches pattern `{[A-Z_][A-Z0-9_]*}`.
pub fn parse_placeholders(template: &str) -> Vec<String> {
    let mut placeholders = Vec::new();
    let bytes = template.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'{' {
            // Check if this could be a valid placeholder
            let start = i + 1;
            if start < len && is_placeholder_start(bytes[start]) {
                let mut end = start + 1;
                while end < len && is_placeholder_continue(bytes[end]) {
                    end += 1;
                }
                if end < len && bytes[end] == b'}' {
                    let name = &template[start..end];
                    if !placeholders.contains(&name.to_string()) {
                        placeholders.push(name.to_string());
                    }
                    i = end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }

    placeholders
}

fn is_placeholder_start(b: u8) -> bool {
    b.is_ascii_uppercase() || b == b'_'
}

fn is_placeholder_continue(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'
}

/// Replace each `{NAME}` with the corresponding value from secrets map.
/// Returns an error if any placeholder has no matching secret.
pub fn substitute(template: &str, secrets: &HashMap<String, String>) -> Result<String, String> {
    let placeholders = parse_placeholders(template);
    let mut result = template.to_string();

    for name in &placeholders {
        match secrets.get(name) {
            Some(value) => {
                let token = format!("{{{}}}", name);
                result = result.replace(&token, value);
            }
            None => {
                return Err(format!("no secret found for placeholder '{{{}}}'", name));
            }
        }
    }

    Ok(result)
}

/// Remove any occurrence of injected secret values from the response string.
/// Also scrubs partial matches: first 8 chars and last 8 chars if value is
/// long enough (>= 16 chars).
pub fn scrub_response(response: &str, injected_values: &[String]) -> String {
    let mut result = response.to_string();

    for value in injected_values {
        // Scrub exact matches
        result = result.replace(value.as_str(), "[REDACTED]");

        // Scrub partial matches for long values
        if value.len() >= 16 {
            let prefix = &value[..8];
            let suffix = &value[value.len() - 8..];
            result = result.replace(prefix, "[REDACTED]");
            result = result.replace(suffix, "[REDACTED]");
        }
    }

    result
}

/// Parse a JSON string into a RequestTemplate.
pub fn parse_request_template(json: &str) -> Result<RequestTemplate, String> {
    serde_json::from_str(json).map_err(|e| format!("invalid request template JSON: {}", e))
}

/// Collect all placeholders from all fields of a RequestTemplate.
pub fn collect_all_placeholders(template: &RequestTemplate) -> Vec<String> {
    let mut all = Vec::new();

    // From URL
    for p in parse_placeholders(&template.url) {
        if !all.contains(&p) {
            all.push(p);
        }
    }

    // From headers (both keys and values)
    for (key, value) in &template.headers {
        for p in parse_placeholders(key) {
            if !all.contains(&p) {
                all.push(p);
            }
        }
        for p in parse_placeholders(value) {
            if !all.contains(&p) {
                all.push(p);
            }
        }
    }

    // From body
    if let Some(body) = &template.body {
        for p in parse_placeholders(body) {
            if !all.contains(&p) {
                all.push(p);
            }
        }
    }

    all
}

/// Substitute placeholders in all fields of a RequestTemplate.
pub fn substitute_template(
    template: &RequestTemplate,
    secrets: &HashMap<String, String>,
) -> Result<RequestTemplate, String> {
    let url = substitute(&template.url, secrets)?;

    let mut headers = HashMap::new();
    for (key, value) in &template.headers {
        let new_key = substitute(key, secrets)?;
        let new_value = substitute(value, secrets)?;
        headers.insert(new_key, new_value);
    }

    let body = match &template.body {
        Some(b) => Some(substitute(b, secrets)?),
        None => None,
    };

    Ok(RequestTemplate {
        method: template.method.clone(),
        url,
        headers,
        body,
    })
}

/// Execute a request template with credential injection (stub/mock for native).
///
/// The full flow is implemented in lib.rs using the vault and policy engine.
/// This is the simple version that returns a mock response.
pub fn execute(template: &RequestTemplate) -> HttpResponse {
    crate::http::execute_request(template)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_placeholder() {
        let placeholders = parse_placeholders("Bearer {API_KEY}");
        assert_eq!(placeholders, vec!["API_KEY"]);
    }

    #[test]
    fn parse_multiple_placeholders() {
        let placeholders =
            parse_placeholders("https://{HOST}/v1/{RESOURCE}?key={API_KEY}");
        assert_eq!(placeholders.len(), 3);
        assert!(placeholders.contains(&"HOST".to_string()));
        assert!(placeholders.contains(&"RESOURCE".to_string()));
        assert!(placeholders.contains(&"API_KEY".to_string()));
    }

    #[test]
    fn parse_placeholder_in_url() {
        let placeholders =
            parse_placeholders("https://api.example.com/v1/chat?token={AUTH_TOKEN}&user={USER_ID}");
        assert_eq!(placeholders.len(), 2);
        assert!(placeholders.contains(&"AUTH_TOKEN".to_string()));
        assert!(placeholders.contains(&"USER_ID".to_string()));
    }

    #[test]
    fn parse_no_placeholders() {
        let placeholders = parse_placeholders("no placeholders here");
        assert!(placeholders.is_empty());
    }

    #[test]
    fn parse_ignores_lowercase() {
        // {lowercase} should not match the pattern [A-Z_][A-Z0-9_]*
        let placeholders = parse_placeholders("{lowercase} {UPPER}");
        assert_eq!(placeholders, vec!["UPPER"]);
    }

    #[test]
    fn parse_deduplicates() {
        let placeholders = parse_placeholders("{KEY} and {KEY} again");
        assert_eq!(placeholders, vec!["KEY"]);
    }

    #[test]
    fn substitute_replaces_values() {
        let mut secrets = HashMap::new();
        secrets.insert("API_KEY".to_string(), "sk-12345".to_string());
        let result = substitute("Bearer {API_KEY}", &secrets).unwrap();
        assert_eq!(result, "Bearer sk-12345");
    }

    #[test]
    fn substitute_multiple_values() {
        let mut secrets = HashMap::new();
        secrets.insert("HOST".to_string(), "api.example.com".to_string());
        secrets.insert("TOKEN".to_string(), "abc123".to_string());
        let result = substitute("https://{HOST}/data?t={TOKEN}", &secrets).unwrap();
        assert_eq!(result, "https://api.example.com/data?t=abc123");
    }

    #[test]
    fn substitute_fails_on_missing_secret() {
        let secrets = HashMap::new();
        let result = substitute("Bearer {MISSING_KEY}", &secrets);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MISSING_KEY"));
    }

    #[test]
    fn scrub_exact_match() {
        let response = "your key is sk-12345 and it works";
        let scrubbed = scrub_response(response, &["sk-12345".to_string()]);
        assert!(!scrubbed.contains("sk-12345"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn scrub_partial_match_long_value() {
        let secret = "abcdefghijklmnopqrstuvwxyz123456".to_string(); // 32 chars
        let response = "prefix abcdefgh something qrstuvwxyz123456 in middle uvwx1234 suffix";
        // first 8 = "abcdefgh", last 8 = "yz123456"
        let scrubbed = scrub_response(response, &[secret]);
        assert!(!scrubbed.contains("abcdefgh"));
        assert!(!scrubbed.contains("yz123456"));
    }

    #[test]
    fn scrub_no_match_leaves_unchanged() {
        let response = "safe response with no secrets";
        let scrubbed = scrub_response(response, &["not_present".to_string()]);
        assert_eq!(scrubbed, response);
    }

    #[test]
    fn parse_request_template_valid() {
        let json = r#"{
            "method": "POST",
            "url": "https://api.example.com/v1/chat",
            "headers": {"Authorization": "Bearer {API_KEY}"},
            "body": "{\"prompt\": \"hello\"}"
        }"#;
        let template = parse_request_template(json).unwrap();
        assert_eq!(template.method, "POST");
        assert_eq!(template.url, "https://api.example.com/v1/chat");
    }

    #[test]
    fn parse_request_template_invalid() {
        let result = parse_request_template("not json");
        assert!(result.is_err());
    }

    #[test]
    fn collect_all_placeholders_from_template() {
        let template = RequestTemplate {
            method: "POST".to_string(),
            url: "https://{HOST}/v1/chat".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Authorization".to_string(), "Bearer {API_KEY}".to_string());
                h
            },
            body: Some(r#"{"user": "{USER_ID}"}"#.to_string()),
        };
        let placeholders = collect_all_placeholders(&template);
        assert_eq!(placeholders.len(), 3);
        assert!(placeholders.contains(&"HOST".to_string()));
        assert!(placeholders.contains(&"API_KEY".to_string()));
        assert!(placeholders.contains(&"USER_ID".to_string()));
    }

    #[test]
    fn substitute_template_all_fields() {
        let template = RequestTemplate {
            method: "POST".to_string(),
            url: "https://api.example.com/v1/{ENDPOINT}".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Authorization".to_string(), "Bearer {TOKEN}".to_string());
                h
            },
            body: Some(r#"{"key": "{BODY_KEY}"}"#.to_string()),
        };

        let mut secrets = HashMap::new();
        secrets.insert("ENDPOINT".to_string(), "chat".to_string());
        secrets.insert("TOKEN".to_string(), "sk-abc123".to_string());
        secrets.insert("BODY_KEY".to_string(), "value123".to_string());

        let result = substitute_template(&template, &secrets).unwrap();
        assert_eq!(result.url, "https://api.example.com/v1/chat");
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Bearer sk-abc123"
        );
        assert_eq!(result.body.unwrap(), r#"{"key": "value123"}"#);
    }
}
