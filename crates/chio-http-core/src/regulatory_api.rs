//! Read-only regulatory API over the receipt store.
//!
//! This module exposes a substrate-agnostic handler that accepts a
//! filter description, pulls receipts from a pluggable store, and
//! wraps the result in a signed envelope. Every response is a
//! [`SignedExportEnvelope`] signed with the kernel's receipt-signing
//! keypair, so regulators can verify every export against the
//! kernel's public key.
//!
//! `chio-http-core` does not embed an HTTP server; substrate adapters
//! wire [`handle_regulatory_receipts`] into their framework-native
//! routing layer and forward query-string fields through
//! [`RegulatoryReceiptsQuery`].

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::{ChioReceipt, SignedExportEnvelope};
use chio_kernel::ReceiptReadContext;
use serde::{Deserialize, Serialize};

/// Stable schema identifier for regulatory receipt exports.
pub const REGULATORY_RECEIPT_EXPORT_SCHEMA: &str = "chio.regulatory.receipt-export.v1";

/// Maximum number of receipts returned by one regulatory export.
pub const MAX_REGULATORY_EXPORT_LIMIT: usize = 200;

/// Body of a regulatory receipt export. Wrapped in a
/// `SignedExportEnvelope` so the signature covers every field of the
/// body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegulatoryReceiptExport {
    /// Stable schema identifier.
    pub schema: String,
    /// Agent subject that was queried. `None` means "all agents".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Unix timestamp (seconds) the client used as the lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    /// Upper timestamp bound, if the caller supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<u64>,
    /// Total receipts that matched the query (pre-limit).
    pub matching_receipts: u64,
    /// Unix timestamp the export was generated at.
    pub generated_at: u64,
    /// The receipts themselves, ordered by seq ascending.
    pub receipts: Vec<ChioReceipt>,
}

/// Signed envelope alias for regulatory receipt exports.
pub type SignedRegulatoryReceiptExport = SignedExportEnvelope<RegulatoryReceiptExport>;

/// Query parameters for `GET /regulatory/receipts`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegulatoryReceiptsQuery {
    /// Filter by agent subject (hex-encoded Ed25519 public key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Include only receipts with `timestamp >= after`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    /// Include only receipts with `timestamp <= before`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<u64>,
    /// Maximum rows to return (capped at
    /// [`MAX_REGULATORY_EXPORT_LIMIT`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl RegulatoryReceiptsQuery {
    #[must_use]
    pub fn limit_or_default(&self) -> usize {
        self.limit
            .unwrap_or(MAX_REGULATORY_EXPORT_LIMIT)
            .clamp(1, MAX_REGULATORY_EXPORT_LIMIT)
    }
}

/// Error surface returned by [`handle_regulatory_receipts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegulatoryApiError {
    /// Malformed query or body.
    BadRequest(String),
    /// The handler was invoked without an authorized regulator token.
    Unauthorized,
    /// The handler could not access the backing receipt store.
    StoreUnavailable(String),
    /// Canonical-JSON signing failed (unexpected).
    Signing(String),
}

impl RegulatoryApiError {
    /// HTTP status code for this error.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized => 401,
            Self::StoreUnavailable(_) => 503,
            Self::Signing(_) => 500,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::StoreUnavailable(_) => "store_unavailable",
            Self::Signing(_) => "signing_error",
        }
    }

    /// Human-readable message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(reason) => reason.clone(),
            Self::Unauthorized => "regulatory API access denied".to_string(),
            Self::StoreUnavailable(reason) => reason.clone(),
            Self::Signing(reason) => reason.clone(),
        }
    }

    /// Wire-format body mirroring the emergency/plan handler error shape.
    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "message": self.message(),
        })
    }
}

/// Pluggable source for regulatory receipt queries.
///
/// Substrate adapters pass a concrete implementation (usually an
/// `chio-store-sqlite` wrapper) into [`handle_regulatory_receipts`].
/// Keeping this as a trait avoids an `chio-http-core -> chio-store-sqlite`
/// dependency while letting callers back the endpoint with any
/// storage layer.
pub trait RegulatoryReceiptSource: Send + Sync {
    /// Return receipts matching the query. Implementations should
    /// respect the caller's limit and return the `matching_receipts`
    /// count independent of the limit.
    fn query_receipts(
        &self,
        query: &RegulatoryReceiptsQuery,
        read_context: &ReceiptReadContext,
    ) -> Result<RegulatoryReceiptQueryResult, RegulatoryApiError>;
}

/// Raw query result handed back to the handler.
#[derive(Debug, Clone, Default)]
pub struct RegulatoryReceiptQueryResult {
    /// Total receipts matching the filter (pre-limit).
    pub matching_receipts: u64,
    /// Receipts (length <= `limit_or_default`).
    pub receipts: Vec<ChioReceipt>,
}

/// Authorization surface for the regulatory API.
///
/// The regulatory endpoint must only be reachable by caller identities
/// that the operator has explicitly trusted. Adapters validate the
/// caller's credential (typically an `X-Regulatory-Token` header) and
/// hand in an authorized [`RegulatorIdentity`] on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegulatorIdentity {
    /// Stable identifier for audit logging (e.g. regulator name,
    /// agency id).
    pub id: String,
}

/// Build, sign, and return a regulatory receipt export envelope.
///
/// `ChioKernel` intentionally only exposes its public key, not its
/// private keypair. To keep the regulatory endpoint fail-closed
/// without broadening the kernel's public API, the operator plumbs
/// the kernel's signing keypair in alongside the kernel handle. This
/// matches the existing evidence-export pattern. Regulators later
/// verify the envelope against `ChioKernel::public_key()`.
///
/// # Parameters
///
/// * `source` -- pluggable receipt feed implementation.
/// * `identity` -- caller identity (None = unauthenticated = 401).
/// * `query` -- filter the caller sent on the URL.
/// * `keypair` -- the kernel's receipt-signing keypair.
/// * `now` -- unix timestamp for the `generated_at` field.
pub fn handle_regulatory_receipts_signed(
    source: &dyn RegulatoryReceiptSource,
    identity: Option<&RegulatorIdentity>,
    query: &RegulatoryReceiptsQuery,
    keypair: &Keypair,
    now: u64,
) -> Result<SignedRegulatoryReceiptExport, RegulatoryApiError> {
    let _identity = identity.ok_or(RegulatoryApiError::Unauthorized)?;

    if let (Some(after), Some(before)) = (query.after, query.before) {
        if after > before {
            return Err(RegulatoryApiError::BadRequest(
                "after must be <= before".to_string(),
            ));
        }
    }

    let read_context = ReceiptReadContext::admin_service();
    let raw = source.query_receipts(query, &read_context)?;

    let body = RegulatoryReceiptExport {
        schema: REGULATORY_RECEIPT_EXPORT_SCHEMA.to_string(),
        agent_id: query.agent.clone(),
        after: query.after,
        before: query.before,
        matching_receipts: raw.matching_receipts,
        generated_at: now,
        receipts: raw.receipts,
    };

    sign_regulatory_export(body, keypair)
}

/// Sign a prebuilt export body with the kernel's keypair. Exposed so
/// callers that have already materialized the body elsewhere (e.g. a
/// batch job) can produce a verifiable envelope without re-running
/// the query pipeline.
pub fn sign_regulatory_export(
    body: RegulatoryReceiptExport,
    keypair: &Keypair,
) -> Result<SignedRegulatoryReceiptExport, RegulatoryApiError> {
    SignedExportEnvelope::sign(body, keypair)
        .map_err(|e| RegulatoryApiError::Signing(e.to_string()))
}

/// Verify a regulatory export envelope against the kernel's public key.
///
/// Thin wrapper that additionally checks the schema identifier and
/// canonical-JSON integrity of the body.
pub fn verify_regulatory_export(
    envelope: &SignedRegulatoryReceiptExport,
    expected_signer: &PublicKey,
) -> Result<bool, RegulatoryApiError> {
    if envelope.body.schema != REGULATORY_RECEIPT_EXPORT_SCHEMA {
        return Err(RegulatoryApiError::BadRequest(format!(
            "unexpected schema {:?}",
            envelope.body.schema
        )));
    }
    if &envelope.signer_key != expected_signer {
        return Ok(false);
    }
    // Ensure canonical-JSON is computable before asking the library to
    // verify. Any failure here is reported as a signing error so the
    // caller can distinguish malformed bodies from bad signatures.
    canonical_json_bytes(&envelope.body).map_err(|e| RegulatoryApiError::Signing(e.to_string()))?;
    envelope
        .verify_signature()
        .map_err(|e| RegulatoryApiError::Signing(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    struct FixedSource {
        result: RegulatoryReceiptQueryResult,
    }

    impl RegulatoryReceiptSource for FixedSource {
        fn query_receipts(
            &self,
            _query: &RegulatoryReceiptsQuery,
            _read_context: &ReceiptReadContext,
        ) -> Result<RegulatoryReceiptQueryResult, RegulatoryApiError> {
            Ok(self.result.clone())
        }
    }

    #[test]
    fn signed_export_verifies_with_matching_keypair() {
        let keypair = Keypair::generate();
        let source = FixedSource {
            result: RegulatoryReceiptQueryResult::default(),
        };
        let identity = RegulatorIdentity {
            id: "regulator".to_string(),
        };
        let envelope = handle_regulatory_receipts_signed(
            &source,
            Some(&identity),
            &RegulatoryReceiptsQuery::default(),
            &keypair,
            42,
        )
        .unwrap();

        assert!(verify_regulatory_export(&envelope, &keypair.public_key()).unwrap());
    }

    #[test]
    fn unauthorized_caller_is_rejected() {
        let keypair = Keypair::generate();
        let source = FixedSource {
            result: RegulatoryReceiptQueryResult::default(),
        };
        let err = handle_regulatory_receipts_signed(
            &source,
            None,
            &RegulatoryReceiptsQuery::default(),
            &keypair,
            0,
        )
        .expect_err("unauthorized must reject");
        assert_eq!(err.status(), 401);
    }

    #[test]
    fn stale_time_window_is_rejected() {
        let keypair = Keypair::generate();
        let source = FixedSource {
            result: RegulatoryReceiptQueryResult::default(),
        };
        let identity = RegulatorIdentity {
            id: "regulator".to_string(),
        };
        let err = handle_regulatory_receipts_signed(
            &source,
            Some(&identity),
            &RegulatoryReceiptsQuery {
                after: Some(100),
                before: Some(50),
                ..Default::default()
            },
            &keypair,
            0,
        )
        .expect_err("after>before must reject");
        assert_eq!(err.status(), 400);
    }
}
