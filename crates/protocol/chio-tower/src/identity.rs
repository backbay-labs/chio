//! Caller identity extraction from HTTP requests.

use chio_http_core::{AuthMethod, CallerIdentity};

/// Function that extracts caller identity from HTTP request headers.
pub type IdentityExtractor = fn(&http::HeaderMap) -> CallerIdentity;

/// Extract caller identity from HTTP headers.
///
/// Checks in order:
/// 1. Authorization: Bearer <token>
/// 2. X-API-Key header
/// 3. Cookie header
/// 4. Anonymous fallback
pub fn extract_identity(headers: &http::HeaderMap) -> CallerIdentity {
    // 1. Bearer token
    if let Some(auth) = headers.get(http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str
                .strip_prefix("Bearer ")
                .and_then(valid_secret_value)
            {
                let token_hash = chio_http_core::sha256_hex(token.as_bytes());
                let subject = format!("bearer:{}", &token_hash[..16]);
                return CallerIdentity {
                    subject,
                    auth_method: AuthMethod::Bearer { token_hash },
                    verified: false,
                    tenant: None,
                    agent_id: None,
                };
            }
        }
    }

    // 2. API key
    for key_header in &["x-api-key", "X-Api-Key", "X-API-Key"] {
        if let Some(key_value) = headers.get(*key_header) {
            if let Ok(key_str) = key_value.to_str().map(valid_secret_value) {
                let Some(key_str) = key_str else {
                    continue;
                };
                let key_hash = chio_http_core::sha256_hex(key_str.as_bytes());
                let subject = format!("apikey:{}", &key_hash[..16]);
                return CallerIdentity {
                    subject,
                    auth_method: AuthMethod::ApiKey {
                        key_name: key_header.to_string(),
                        key_hash,
                    },
                    verified: false,
                    tenant: None,
                    agent_id: None,
                };
            }
        }
    }

    // 3. Cookie
    if let Some(cookie) = headers.get(http::header::COOKIE) {
        if let Ok(cookie_str) = cookie.to_str() {
            if let Some(first) = cookie_str.split(';').next() {
                let parts: Vec<&str> = first.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let cookie_name = parts[0].trim().to_string();
                    let cookie_value = parts[1].trim();
                    if !cookie_value.is_empty() {
                        let cookie_hash = chio_http_core::sha256_hex(cookie_value.as_bytes());
                        let subject = format!("cookie:{}", &cookie_hash[..16]);
                        return CallerIdentity {
                            subject,
                            auth_method: AuthMethod::Cookie {
                                cookie_name,
                                cookie_hash,
                            },
                            verified: false,
                            tenant: None,
                            agent_id: None,
                        };
                    }
                }
            }
        }
    }

    // 4. Anonymous
    CallerIdentity::anonymous()
}

fn valid_secret_value(value: &str) -> Option<&str> {
    if value.trim().is_empty() || value.trim() != value {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bearer() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer my-test-token"),
        );
        let caller = extract_identity(&headers);
        assert!(caller.subject.starts_with("bearer:"));
        assert!(matches!(caller.auth_method, AuthMethod::Bearer { .. }));
        assert!(!caller.verified);
    }

    #[test]
    fn extract_api_key() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-api-key", http::HeaderValue::from_static("secret-key"));
        let caller = extract_identity(&headers);
        assert!(caller.subject.starts_with("apikey:"));
        assert!(matches!(caller.auth_method, AuthMethod::ApiKey { .. }));
    }

    #[test]
    fn extract_anonymous() {
        let headers = http::HeaderMap::new();
        let caller = extract_identity(&headers);
        assert_eq!(caller.subject, "anonymous");
        assert!(matches!(caller.auth_method, AuthMethod::Anonymous));
    }

    #[test]
    fn extract_cookie_identity() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("session_id=abc123xyz"),
        );
        let caller = extract_identity(&headers);
        assert!(caller.subject.starts_with("cookie:"));
        match &caller.auth_method {
            AuthMethod::Cookie {
                cookie_name,
                cookie_hash,
            } => {
                assert_eq!(cookie_name, "session_id");
                assert_eq!(cookie_hash.len(), 64); // SHA-256 hex
            }
            other => panic!("expected Cookie, got {other:?}"),
        }
    }

    #[test]
    fn bearer_takes_precedence_over_cookie() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer my-token"),
        );
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("session_id=abc123"),
        );
        let caller = extract_identity(&headers);
        // Bearer should take precedence
        assert!(caller.subject.starts_with("bearer:"));
    }

    #[test]
    fn non_bearer_authorization_falls_through() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let caller = extract_identity(&headers);
        // Basic auth is not recognized, should fall through to anonymous
        assert_eq!(caller.subject, "anonymous");
    }

    #[test]
    fn blank_bearer_token_falls_through() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer    "),
        );
        let caller = extract_identity(&headers);
        assert_eq!(caller.subject, "anonymous");
        assert!(matches!(caller.auth_method, AuthMethod::Anonymous));
    }

    #[test]
    fn blank_api_key_falls_through() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-api-key", http::HeaderValue::from_static("   "));
        let caller = extract_identity(&headers);
        assert_eq!(caller.subject, "anonymous");
        assert!(matches!(caller.auth_method, AuthMethod::Anonymous));
    }

    #[test]
    fn empty_cookie_value_falls_through() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("session_id="),
        );
        let caller = extract_identity(&headers);
        // Empty cookie value should not be used
        assert_eq!(caller.subject, "anonymous");
    }
}
