use serde::{Deserialize, Serialize};

use crate::error::GovernanceAuthorizationError;
use crate::receipt::SignedExportEnvelope;
use crate::validation::{validate_non_empty, validate_sha256_hex};

pub const CAPABILITY_LEASE_SCHEMA_V1: &str = "chio.capability-lease.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLeaseActionClass {
    ScopedObservation,
    DelegatedAction,
    NarrowDestructive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityLeaseArtifact {
    pub schema: String,
    pub lease_id: String,
    pub issuer: String,
    pub subject: String,
    pub scope_digest: String,
    pub action_class: CapabilityLeaseActionClass,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl CapabilityLeaseArtifact {
    pub fn validate(&self) -> Result<(), GovernanceAuthorizationError> {
        if self.schema != CAPABILITY_LEASE_SCHEMA_V1 {
            return Err(GovernanceAuthorizationError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        validate_non_empty(&self.lease_id, "lease_id")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.issuer, "issuer")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_non_empty(&self.subject, "subject")
            .map_err(GovernanceAuthorizationError::InvalidArtifact)?;
        validate_sha256_hex(&self.scope_digest, "scope_digest")?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(GovernanceAuthorizationError::InvalidArtifact(
                "expires_at_unix_ms must be greater than issued_at_unix_ms".to_string(),
            ));
        }
        Ok(())
    }
}

pub type SignedCapabilityLease = SignedExportEnvelope<CapabilityLeaseArtifact>;

pub fn verify_capability_lease(
    lease: &SignedCapabilityLease,
    now_unix_ms: u64,
    expected_scope_digest: Option<String>,
) -> Result<(), GovernanceAuthorizationError> {
    lease.body.validate()?;
    if !lease
        .verify_signature()
        .map_err(|e| GovernanceAuthorizationError::Crypto(e.to_string()))?
    {
        return Err(GovernanceAuthorizationError::InvalidSignature);
    }
    if lease.body.issued_at_unix_ms > now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseNotYetValid(
            lease.body.lease_id.clone(),
        ));
    }
    if lease.body.expires_at_unix_ms <= now_unix_ms {
        return Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(
            lease.body.lease_id.clone(),
        ));
    }
    if let Some(expected) = expected_scope_digest {
        validate_sha256_hex(&expected, "expected_scope_digest")?;
        if lease.body.scope_digest != expected {
            return Err(GovernanceAuthorizationError::ScopeDigestMismatch);
        }
    }
    Ok(())
}
