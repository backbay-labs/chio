//! Storage-side domain port for the hosted market's event-sourced writes
//! and projections.
//!
//! The hosted HTTP edge validates and authenticates requests, then hands the
//! domain write to a [`HostedMarketBackend`]. Storage adapters implement the
//! trait over their own durable representation and translate failures into
//! [`HostedMarketBackendError`]; every error denies the write.

use std::collections::BTreeSet;

use async_trait::async_trait;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::body::ChioReceipt;
use serde::{Deserialize, Serialize};

use crate::HostedTenantId;

/// Schema identifier pinned by every hosted authenticated-delivery artifact.
pub const HOSTED_AUTHENTICATED_DELIVERY_SCHEMA: &str =
    "chio.finding.hosted-authenticated-delivery.v1";

/// One optimistic-concurrency domain write: the aggregate it targets, the
/// caller-chosen idempotent event identity, the revision it expects, and the
/// signed artifact payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedDomainMutation {
    pub aggregate_id: String,
    pub event_id: String,
    pub expected_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_event_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_signer_key: Option<PublicKey>,
    /// Authority identity resolved by the edge from the authenticated
    /// principal, never from the wire payload.
    #[serde(skip)]
    pub artifact_authority_id: Option<String>,
    pub payload: serde_json::Value,
}

/// Delivery artifact carrying the kernel-signed receipt that authenticates a
/// hosted delivery write.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedAuthenticatedFindingDelivery {
    pub schema: String,
    pub receipt: ChioReceipt,
}

/// Idempotency outcome of one domain write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedMarketBackendOutcome {
    Inserted,
    ExactReplay,
}

/// One committed domain event projected for read surfaces.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedHttpProjection {
    pub event_kind: String,
    pub aggregate_kind: String,
    pub aggregate_id: String,
    pub event_id: String,
    pub revision: u64,
    pub previous_event_sha256: Option<String>,
    pub event_sha256: String,
    pub artifact_schema: String,
    pub artifact_sha256: String,
    pub payload: serde_json::Value,
    pub committed_at: u64,
}

/// One keyset-paginated projection page.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedHttpPage {
    pub items: Vec<HostedHttpProjection>,
    pub next_cursor: Option<String>,
}

/// Bounded backend failure vocabulary. Adapters map their own errors into
/// these variants and must fail closed on anything they cannot classify.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostedMarketBackendError {
    #[error("hosted backend input is invalid")]
    Invalid,
    #[error("hosted backend resource was not found")]
    NotFound,
    #[error("hosted backend mutation conflicts")]
    Conflict,
    #[error("hosted backend capacity is exhausted")]
    Capacity,
    #[error("hosted backend integrity check failed")]
    Integrity,
    #[error("hosted backend is unavailable")]
    Unavailable,
}

/// Durable domain backend behind the hosted market edge.
#[async_trait]
pub trait HostedMarketBackend: Send + Sync {
    async fn ready(&self) -> Result<(), HostedMarketBackendError>;

    async fn append(
        &self,
        tenant: &HostedTenantId,
        event_kind: &str,
        aggregate_kind: &str,
        mutation: &HostedDomainMutation,
        committed_at: u64,
    ) -> Result<HostedMarketBackendOutcome, HostedMarketBackendError>;

    async fn finding(
        &self,
        tenant: &HostedTenantId,
        finding_id: &str,
    ) -> Result<Option<HostedHttpProjection>, HostedMarketBackendError>;

    async fn findings(
        &self,
        tenant: &HostedTenantId,
        after: Option<&str>,
        limit: u32,
    ) -> Result<HostedHttpPage, HostedMarketBackendError>;

    async fn non_live_findings(
        &self,
        tenant: &HostedTenantId,
        finding_ids: &[String],
    ) -> Result<BTreeSet<String>, HostedMarketBackendError>;
}
