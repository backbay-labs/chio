use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::crypto::{canonical_json_bytes, sha256_hex};
use crate::error::Result;

use super::ownership::SessionTransport;

/// Authentication method used to admit a session at the transport layer.
///
/// This is intentionally separate from Chio capability authorization. A session
/// may be transport-authenticated and still be denied by capability or guard
/// checks later during operation evaluation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionAuthMethod {
    Anonymous,
    StaticBearer {
        principal: String,
        token_fingerprint: String,
    },
    OAuthBearer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        #[serde(
            default,
            skip_serializing_if = "OAuthBearerFederatedClaims::is_empty",
            rename = "federatedClaims"
        )]
        federated_claims: OAuthBearerFederatedClaims,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "enterpriseIdentity"
        )]
        enterprise_identity: Option<EnterpriseIdentityContext>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_fingerprint: Option<String>,
    },
}

impl SessionAuthMethod {
    #[must_use]
    pub fn token_fingerprint(&self) -> Option<&str> {
        match self {
            Self::Anonymous => None,
            Self::StaticBearer {
                token_fingerprint, ..
            } => Some(token_fingerprint.as_str()),
            Self::OAuthBearer {
                token_fingerprint, ..
            } => token_fingerprint.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OAuthBearerFederatedClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

impl OAuthBearerFederatedClaims {
    pub fn is_empty(&self) -> bool {
        self.client_id.is_none()
            && self.object_id.is_none()
            && self.tenant_id.is_none()
            && self.organization_id.is_none()
            && self.groups.is_empty()
            && self.roles.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseFederationMethod {
    #[default]
    Jwt,
    Introspection,
    Scim,
    Saml,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseIdentityContext {
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    pub provider_kind: String,
    pub federation_method: EnterpriseFederationMethod,
    pub principal: String,
    pub subject_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subject: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attribute_sources: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_material_ref: Option<String>,
}

/// Optional continuity or login assertion carried across verifier-facing flows.
///
/// Chio treats this as bounded continuity metadata rather than ambient identity
/// truth. Callers must still bind it to the enclosing verifier and replay
/// boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChioIdentityAssertion {
    pub verifier_id: String,
    pub subject: String,
    pub continuity_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_request_id: Option<String>,
}

impl ChioIdentityAssertion {
    pub fn validate(&self) -> core::result::Result<(), String> {
        if self.verifier_id.trim().is_empty() {
            return Err("identityAssertion.verifierId must not be empty".to_string());
        }
        if self.subject.trim().is_empty() {
            return Err("identityAssertion.subject must not be empty".to_string());
        }
        if self.continuity_id.trim().is_empty() {
            return Err("identityAssertion.continuityId must not be empty".to_string());
        }
        if self.issued_at > self.expires_at {
            return Err(
                "identityAssertion.issuedAt must be before or equal to identityAssertion.expiresAt"
                    .to_string(),
            );
        }
        if self
            .provider
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("identityAssertion.provider must not be empty when present".to_string());
        }
        if self
            .session_hint
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("identityAssertion.sessionHint must not be empty when present".to_string());
        }
        if self
            .bound_request_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(
                "identityAssertion.boundRequestId must not be empty when present".to_string(),
            );
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> core::result::Result<(), String> {
        self.validate()?;
        if now >= self.expires_at {
            return Err("identityAssertion is stale".to_string());
        }
        Ok(())
    }
}

/// Normalized transport-authentication context bound to a logical session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAuthContext {
    pub transport: SessionTransport,
    pub method: SessionAuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OAuthBearerSessionAuthInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub federated_claims: OAuthBearerFederatedClaims,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_identity: Option<EnterpriseIdentityContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl SessionAuthContext {
    pub fn in_process_anonymous() -> Self {
        Self {
            transport: SessionTransport::InProcess,
            method: SessionAuthMethod::Anonymous,
            origin: None,
        }
    }

    pub fn stdio_anonymous() -> Self {
        Self {
            transport: SessionTransport::Stdio,
            method: SessionAuthMethod::Anonymous,
            origin: None,
        }
    }

    pub fn streamable_http_static_bearer(
        principal: impl Into<String>,
        token_fingerprint: impl Into<String>,
        origin: Option<String>,
    ) -> Self {
        Self {
            transport: SessionTransport::StreamableHttp,
            method: SessionAuthMethod::StaticBearer {
                principal: principal.into(),
                token_fingerprint: token_fingerprint.into(),
            },
            origin,
        }
    }

    pub fn streamable_http_oauth_bearer(
        principal: Option<String>,
        issuer: Option<String>,
        subject: Option<String>,
        audience: Option<String>,
        scopes: Vec<String>,
        token_fingerprint: Option<String>,
        origin: Option<String>,
    ) -> Self {
        Self::streamable_http_oauth_bearer_with_claims(OAuthBearerSessionAuthInput {
            principal,
            issuer,
            subject,
            audience,
            scopes,
            federated_claims: OAuthBearerFederatedClaims::default(),
            enterprise_identity: None,
            token_fingerprint,
            origin,
        })
    }

    pub fn streamable_http_oauth_bearer_with_claims(input: OAuthBearerSessionAuthInput) -> Self {
        Self {
            transport: SessionTransport::StreamableHttp,
            method: SessionAuthMethod::OAuthBearer {
                principal: input.principal,
                issuer: input.issuer,
                subject: input.subject,
                audience: input.audience,
                scopes: input.scopes,
                federated_claims: input.federated_claims,
                enterprise_identity: input.enterprise_identity,
                token_fingerprint: input.token_fingerprint,
            },
            origin: input.origin,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        !matches!(self.method, SessionAuthMethod::Anonymous)
    }

    pub fn canonical_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(self)?;
        Ok(sha256_hex(&canonical))
    }

    pub fn auth_method_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(&self.method)?;
        Ok(sha256_hex(&canonical))
    }

    pub fn principal(&self) -> Option<&str> {
        match &self.method {
            SessionAuthMethod::Anonymous => None,
            SessionAuthMethod::StaticBearer { principal, .. } => Some(principal.as_str()),
            SessionAuthMethod::OAuthBearer { principal, .. } => principal.as_deref(),
        }
    }
}
