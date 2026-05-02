use chio_mcp_adapter_integration::{authorization_url, pkce_challenge, AuthorizationRequest};

#[test]
fn pkce_challenge_matches_s256_shape() -> Result<(), Box<dyn std::error::Error>> {
    let challenge = pkce_challenge("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")?;
    assert_eq!(challenge.method, "S256");
    assert_eq!(challenge.challenge.len(), 43);

    let request = AuthorizationRequest {
        authorization_endpoint: "https://auth.chio.example/oauth2/authorize".to_string(),
        client_id: "chio-mcp-registry".to_string(),
        redirect_uri: "https://mcp.chio.example/oauth/callback".to_string(),
        resource: "https://mcp.chio.example/mcp".to_string(),
        scopes: vec!["tools.call".to_string(), "receipts.read".to_string()],
        state: "state-123".to_string(),
        pkce: challenge,
    };
    let url = authorization_url(&request)?;
    assert!(url.contains("response_type=code"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("resource=https%3A%2F%2Fmcp.chio.example%2Fmcp"));
    Ok(())
}

#[test]
fn pkce_verifier_rejects_invalid_shape() {
    assert!(pkce_challenge("too-short").is_err());
    assert!(pkce_challenge("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG!").is_err());
}
