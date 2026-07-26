//! Capability lineage index for Chio kernel.
//!
//! This module provides persistence and query functions for capability snapshots.
//! Snapshots are recorded at issuance time and co-located with the receipt database
//! for efficient JOINs. The delegation chain can be walked via WITH RECURSIVE CTE.

use serde::{Deserialize, Serialize};

use chio_core::capability::{scope::ChioScope, token::CapabilityToken};
use chio_core::crypto::PublicKey;

use crate::receipt_store::ReceiptStoreError;

/// A point-in-time snapshot of a capability token persisted at issuance.
///
/// Stored in the `capability_lineage` table alongside `chio_tool_receipts`
/// for efficient JOINs during audit queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySnapshotProvenance {
    /// Projection derived from and bound to an exact signed capability token.
    SignedToken,
    /// Unsigned local anchor derived from a verified federated delegation policy.
    SyntheticAnchor,
    /// Pre-provenance local projection retained only for migration compatibility.
    #[default]
    LegacyProjection,
}

impl CapabilitySnapshotProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignedToken => "signed_token",
            Self::SyntheticAnchor => "synthetic_anchor",
            Self::LegacyProjection => "legacy_projection",
        }
    }
}

impl std::str::FromStr for CapabilitySnapshotProvenance {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "signed_token" => Ok(Self::SignedToken),
            "synthetic_anchor" => Ok(Self::SyntheticAnchor),
            "legacy_projection" => Ok(Self::LegacyProjection),
            _ => Err(format!(
                "unsupported capability snapshot provenance {value:?}"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// The unique token ID (matches CapabilityToken.id).
    pub capability_id: String,
    /// Hex-encoded subject public key (agent bound to this capability).
    pub subject_key: String,
    /// Hex-encoded issuer public key (Capability Authority or delegating agent).
    pub issuer_key: String,
    /// Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    /// JSON-serialized ChioScope (grants, resource_grants, prompt_grants).
    pub grants_json: String,
    /// Depth in the delegation chain. Root capabilities have depth 0.
    pub delegation_depth: u64,
    /// Parent capability_id if this was delegated from another token.
    pub parent_capability_id: Option<String>,
    /// Unsigned cross-federation parent edge, separate from signed token lineage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated_parent_capability_id: Option<String>,
    /// Evidence source for this projection. Missing legacy payloads deserialize
    /// as `LegacyProjection` and are rejected at transport boundaries.
    #[serde(default)]
    pub provenance: CapabilitySnapshotProvenance,
    /// Exact signed capability token, when the snapshot originated from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_capability: Option<CapabilityToken>,
}

impl CapabilitySnapshot {
    /// Validate a snapshot crossing a replication or evidence trust boundary.
    pub fn validate_for_transport(&self) -> Result<(), ReceiptStoreError> {
        self.validate(false)
    }

    /// Validate a row read from the local store, including migrated projections
    /// whose original signed token was not retained.
    pub fn validate_for_local_read(&self) -> Result<(), ReceiptStoreError> {
        self.validate(true)
    }

    fn validate(&self, allow_legacy: bool) -> Result<(), ReceiptStoreError> {
        if self
            .federated_parent_capability_id
            .as_deref()
            .is_some_and(|parent| parent == self.capability_id)
        {
            return Err(self.conflict("uses itself as its federated parent"));
        }

        match self.provenance {
            CapabilitySnapshotProvenance::SignedToken => self.validate_signed_token(),
            CapabilitySnapshotProvenance::SyntheticAnchor => self.validate_synthetic_anchor(),
            CapabilitySnapshotProvenance::LegacyProjection if allow_legacy => {
                if self.signed_capability.is_some() {
                    return Err(self.conflict("marks a signed token as a legacy projection"));
                }
                Ok(())
            }
            CapabilitySnapshotProvenance::LegacyProjection => Err(self.conflict(
                "uses legacy projection provenance outside the local migration boundary",
            )),
        }
    }

    fn validate_signed_token(&self) -> Result<(), ReceiptStoreError> {
        let Some(token) = self.signed_capability.as_ref() else {
            return Err(self.conflict("claims signed-token provenance without a signed token"));
        };
        token.validate_schema().map_err(|error| {
            self.conflict(&format!(
                "contains a signed token with an invalid schema: {error}"
            ))
        })?;
        if !token.verify_signature().map_err(|error| {
            self.conflict(&format!(
                "contains a signed token that could not be verified: {error}"
            ))
        })? {
            return Err(self.conflict("contains a signed token with an invalid signature"));
        }

        let persisted_scope: ChioScope = serde_json::from_str(&self.grants_json)?;
        let scope_matches =
            serde_json::to_value(&persisted_scope)? == serde_json::to_value(&token.scope)?;
        let fields_match = self.capability_id == token.id
            && self.subject_key == token.subject.to_hex()
            && self.issuer_key == token.issuer.to_hex()
            && self.issued_at == token.issued_at
            && self.expires_at == token.expires_at
            && scope_matches;
        if !fields_match {
            return Err(self.conflict("does not match its signed token projection"));
        }

        let expected_parent = token
            .delegation_chain
            .last()
            .map(|link| link.capability_id.as_str());
        if self.parent_capability_id.as_deref() != expected_parent
            || self.delegation_depth != token.delegation_chain.len() as u64
        {
            return Err(self.conflict("does not match its signed delegation lineage"));
        }
        Ok(())
    }

    fn validate_synthetic_anchor(&self) -> Result<(), ReceiptStoreError> {
        if self.signed_capability.is_some() {
            return Err(self.conflict("marks a signed token as a synthetic anchor"));
        }
        let digest = self.capability_id.strip_prefix("fed-del-");
        if !digest.is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(self.conflict("is not a structurally valid fed-del anchor"));
        }
        if self.parent_capability_id.is_some() || self.delegation_depth != 0 {
            return Err(self.conflict("places unsigned federation data in signed lineage fields"));
        }
        if self.issued_at >= self.expires_at {
            return Err(self.conflict("has an empty or reversed validity window"));
        }
        PublicKey::from_hex(&self.subject_key)
            .map_err(|error| self.conflict(&format!("has an invalid subject key: {error}")))?;
        PublicKey::from_hex(&self.issuer_key)
            .map_err(|error| self.conflict(&format!("has an invalid issuer key: {error}")))?;
        let _: ChioScope = serde_json::from_str(&self.grants_json)?;
        Ok(())
    }

    fn conflict(&self, reason: &str) -> ReceiptStoreError {
        ReceiptStoreError::Conflict(format!(
            "capability lineage {} {reason}",
            self.capability_id
        ))
    }
}

/// A capability snapshot with the source database sequence used for cluster sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCapabilitySnapshot {
    pub seq: u64,
    pub snapshot: CapabilitySnapshot,
}

/// Errors from capability lineage operations.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityLineageError {
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_snapshot_json_defaults_to_local_only_provenance(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let snapshot: CapabilitySnapshot = serde_json::from_value(serde_json::json!({
            "capability_id": "legacy-capability",
            "subject_key": "legacy-subject",
            "issuer_key": "legacy-issuer",
            "issued_at": 1,
            "expires_at": 2,
            "grants_json": "{}",
            "delegation_depth": 0,
            "parent_capability_id": null
        }))?;

        assert_eq!(
            snapshot.provenance,
            CapabilitySnapshotProvenance::LegacyProjection
        );
        assert!(snapshot.federated_parent_capability_id.is_none());
        assert!(snapshot.validate_for_local_read().is_ok());
        assert!(snapshot.validate_for_transport().is_err());
        Ok(())
    }
}
