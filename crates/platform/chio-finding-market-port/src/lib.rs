//! Store-neutral boundaries for the hosted cognition market.
//!
//! Hosted edge and application code depend on these ports instead of a
//! concrete database implementation. Storage adapters translate their own
//! errors into the bounded error vocabulary below and must fail closed.

#![forbid(unsafe_code)]

mod backend;
mod grammar;

pub use backend::{
    HostedAuthenticatedFindingDelivery, HostedDomainMutation, HostedHttpPage, HostedHttpProjection,
    HostedMarketBackend, HostedMarketBackendError, HostedMarketBackendOutcome,
    HOSTED_AUTHENTICATED_DELIVERY_SCHEMA,
};
pub use grammar::{HostedAggregateKind, HostedMarketDomainEventKind};

use std::collections::BTreeSet;
use std::str::FromStr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub const HOSTED_API_KEY_ISSUED_EVENT_KIND: &str = "hosted.api_key.issued";
pub const HOSTED_API_KEY_REVOKED_EVENT_KIND: &str = "hosted.api_key.revoked";

const MAX_TENANT_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostedMarketPortError {
    #[error("hosted market port input is invalid")]
    Invalid,
    #[error("hosted market tenant identity is invalid")]
    Tenant,
    #[error("hosted market tenant was not found")]
    TenantNotFound,
    #[error("hosted market tenant is disabled")]
    TenantDisabled,
    #[error("hosted market mutation conflicts with durable state")]
    Conflict,
    #[error("hosted market capacity is exhausted")]
    Capacity,
    #[error("hosted market resource was not found")]
    NotFound,
    #[error("hosted market lease was lost")]
    LeaseLost,
    #[error("hosted market durable state failed validation")]
    Integrity,
    #[error("hosted market retention target is held")]
    RetentionHeld,
    #[error("hosted market dependency is unavailable")]
    Unavailable,
}

/// A validated opaque tenant identity, always bound separately from resource
/// identifiers in storage keys and authenticated request contexts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostedTenantId(String);

impl HostedTenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, HostedMarketPortError> {
        let value = value.into();
        if !valid_identifier(&value, MAX_TENANT_ID_BYTES) {
            return Err(HostedMarketPortError::Tenant);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostedPrincipalRole {
    Buyer,
    Seller,
    Evaluator,
    Auditor,
    Operator,
}

impl HostedPrincipalRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Buyer => "buyer",
            Self::Seller => "seller",
            Self::Evaluator => "evaluator",
            Self::Auditor => "auditor",
            Self::Operator => "operator",
        }
    }
}

impl FromStr for HostedPrincipalRole {
    type Err = HostedMarketPortError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "buyer" => Ok(Self::Buyer),
            "seller" => Ok(Self::Seller),
            "evaluator" => Ok(Self::Evaluator),
            "auditor" => Ok(Self::Auditor),
            "operator" => Ok(Self::Operator),
            _ => Err(HostedMarketPortError::Integrity),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedPrincipal {
    pub tenant_id: HostedTenantId,
    pub principal_id: String,
    pub role: HostedPrincipalRole,
    pub capability_public_key_hex: Option<String>,
    pub enabled: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedApiKeyRecord {
    pub tenant_id: HostedTenantId,
    pub key_id: String,
    pub principal_id: String,
    pub verifier_sha256: String,
    pub allowed_actions: BTreeSet<String>,
    pub active_from: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    pub rotated_from_key_id: Option<String>,
    pub created_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedPortWriteOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedCapabilityAdmissionOutcome {
    Admitted,
    /// This capability already admitted this exact request. The caller may
    /// proceed: the request carries an idempotency key and its effect is
    /// idempotent, so this is the original request resuming rather than a
    /// replay of a different one.
    RetriedSameRequest,
    Replay,
    BudgetExceeded,
}

#[async_trait]
pub trait HostedAuthPort: Send + Sync {
    async fn principal_by_capability_key(
        &self,
        tenant: &HostedTenantId,
        public_key_hex: &str,
        now: u64,
    ) -> Result<Option<HostedPrincipal>, HostedMarketPortError>;

    async fn principal(
        &self,
        tenant: &HostedTenantId,
        principal_id: &str,
    ) -> Result<Option<HostedPrincipal>, HostedMarketPortError>;

    async fn active_api_key(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        now: u64,
    ) -> Result<Option<HostedApiKeyRecord>, HostedMarketPortError>;

    #[allow(clippy::too_many_arguments)]
    /// Consume one DPoP admission. `request_sha256` carries the request
    /// binding for a resumable mutation and is `None` for a request that
    /// must never be resumed from its proof alone.
    async fn consume_capability_dpop_admission(
        &self,
        tenant: &HostedTenantId,
        capability_id: &str,
        nonce_sha256: &str,
        request_sha256: Option<&str>,
        valid_through: u64,
        max_invocations: u32,
        expires_at: u64,
        now: u64,
        tenant_nonce_capacity: u64,
    ) -> Result<HostedCapabilityAdmissionOutcome, HostedMarketPortError>;
}

#[async_trait]
pub trait HostedApiKeyLifecyclePort: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn issue_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        principal_id: &str,
        verifier_sha256: &str,
        allowed_actions: &BTreeSet<String>,
        active_from: u64,
        expires_at: u64,
        rotated_from_key_id: Option<&str>,
        event_id: &str,
        artifact_json: &[u8],
        now: u64,
    ) -> Result<HostedPortWriteOutcome, HostedMarketPortError>;

    async fn revoke_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        revoked_at: u64,
        event_id: &str,
        artifact_json: &[u8],
    ) -> Result<HostedPortWriteOutcome, HostedMarketPortError>;
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_identity_is_canonical_and_bounded() {
        assert!(HostedTenantId::new("tenant:acme-1").is_ok());
        assert_eq!(
            HostedTenantId::new(" tenant-a"),
            Err(HostedMarketPortError::Tenant)
        );
        assert_eq!(
            HostedTenantId::new("x".repeat(MAX_TENANT_ID_BYTES + 1)),
            Err(HostedMarketPortError::Tenant)
        );
    }

    #[test]
    fn role_storage_values_are_closed() {
        assert_eq!(
            "seller".parse::<HostedPrincipalRole>(),
            Ok(HostedPrincipalRole::Seller)
        );
        assert_eq!(
            "administrator".parse::<HostedPrincipalRole>(),
            Err(HostedMarketPortError::Integrity)
        );
    }
}
