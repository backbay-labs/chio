use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrmError {
    #[error("resource URL is invalid: {0}")]
    InvalidResource(String),
    #[error("authorization server URL is invalid: {0}")]
    InvalidAuthorizationServer(String),
    #[error("at least one OAuth scope is required")]
    MissingScopes,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub resource_signing_alg_values_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    pub fn new(
        resource: impl Into<String>,
        authorization_server: impl Into<String>,
        scopes_supported: Vec<String>,
    ) -> Result<Self, PrmError> {
        let resource = resource.into();
        let authorization_server = authorization_server.into();
        Url::parse(&resource).map_err(|error| PrmError::InvalidResource(error.to_string()))?;
        Url::parse(&authorization_server)
            .map_err(|error| PrmError::InvalidAuthorizationServer(error.to_string()))?;
        if scopes_supported.is_empty() {
            return Err(PrmError::MissingScopes);
        }
        Ok(Self {
            resource,
            authorization_servers: vec![authorization_server],
            scopes_supported,
            bearer_methods_supported: vec!["header".to_string()],
            resource_signing_alg_values_supported: vec!["Ed25519".to_string()],
        })
    }

    pub fn well_known_path(&self) -> String {
        "/.well-known/oauth-protected-resource".to_string()
    }
}
