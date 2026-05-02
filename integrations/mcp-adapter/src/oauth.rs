use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OAuthError {
    #[error("PKCE verifier length must be between 43 and 128 characters")]
    InvalidVerifierLength,
    #[error("PKCE verifier contains a character outside RFC7636 unreserved set")]
    InvalidVerifierCharacter,
    #[error("authorization URL is invalid: {0}")]
    InvalidUrl(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub authorization_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub pkce: PkceChallenge,
}

pub fn pkce_challenge(verifier: impl Into<String>) -> Result<PkceChallenge, OAuthError> {
    let verifier = verifier.into();
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(OAuthError::InvalidVerifierLength);
    }
    if !verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
    {
        return Err(OAuthError::InvalidVerifierCharacter);
    }
    let digest = Sha256::digest(verifier.as_bytes());
    Ok(PkceChallenge {
        verifier,
        challenge: URL_SAFE_NO_PAD.encode(digest),
        method: "S256".to_string(),
    })
}

pub fn authorization_url(request: &AuthorizationRequest) -> Result<String, OAuthError> {
    let mut url = Url::parse(&request.authorization_endpoint)
        .map_err(|error| OAuthError::InvalidUrl(error.to_string()))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &request.client_id)
        .append_pair("redirect_uri", &request.redirect_uri)
        .append_pair("resource", &request.resource)
        .append_pair("scope", &request.scopes.join(" "))
        .append_pair("state", &request.state)
        .append_pair("code_challenge", &request.pkce.challenge)
        .append_pair("code_challenge_method", &request.pkce.method);
    Ok(url.to_string())
}
