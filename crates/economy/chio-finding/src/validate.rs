//! Fail-closed validation for finding-family artifacts.

use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::crypto::sha256_hex;

use crate::types::{Finding, FindingEvidenceClass, FindingGuaranteeClass, FINDING_SCHEMA_V1};

/// Validation failures. Every variant is a rejection; there are no
/// warning-grade outcomes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FindingError {
    #[error("unsupported finding schema: {0}")]
    UnsupportedSchema(String),
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    #[error("field is not a lowercase 64-char hex digest: {0}")]
    MalformedDigest(&'static str),
    #[error("deterministic_replay findings require replay_recipe_sha256")]
    MissingReplayRecipe,
    #[error("non-asserted evidence class requires evidence receipts")]
    MissingEvidence,
    #[error("expires_at must be strictly after issued_at")]
    InvalidValidityWindow,
    #[error("canonical JSON serialization failed")]
    Canonicalization,
    #[error("finding signing failed")]
    Signing,
    #[error("finding signature invalid")]
    SignatureInvalid,
}

pub(crate) fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), FindingError> {
    if value.trim().is_empty() {
        Err(FindingError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingError> {
    if is_hex64(value) {
        Ok(())
    } else {
        Err(FindingError::MalformedDigest(field))
    }
}

impl Finding {
    /// Structural validation. Signature and cross-artifact checks (bond
    /// existence, receipt verification, status freshness) live in later
    /// milestones; this validator is pure over the artifact alone. It is
    /// also CLOCKLESS by design: it checks the window shape
    /// (expires_at > issued_at) but not liveness - publish/search (M2)
    /// and buy (M4) must reject `now >= expires_at` themselves.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.finding_id, "finding_id")?;
        require_non_empty(&self.descriptor.topic, "descriptor.topic")?;
        require_hex64(&self.descriptor.context_sha256, "descriptor.context_sha256")?;
        require_hex64(&self.payload_sha256, "payload_sha256")?;
        require_non_empty(&self.payload_media_type, "payload_media_type")?;
        require_non_empty(&self.evidence_checkpoint_ref, "evidence_checkpoint_ref")?;
        require_non_empty(&self.evidence_cost.currency, "evidence_cost.currency")?;
        require_non_empty(&self.bond_ref, "bond_ref")?;
        require_non_empty(&self.status_feed_ref, "status_feed_ref")?;
        if self.guarantee_class == FindingGuaranteeClass::DeterministicReplay {
            match &self.replay_recipe_sha256 {
                Some(recipe) => require_hex64(recipe, "replay_recipe_sha256")?,
                None => return Err(FindingError::MissingReplayRecipe),
            }
        } else if let Some(recipe) = &self.replay_recipe_sha256 {
            require_hex64(recipe, "replay_recipe_sha256")?;
        }
        // Any attestation-quality signal (non-asserted guarantee class,
        // non-asserted evidence class, or a non-None runtime tier) needs
        // receipts to verify against; an asserted finding claiming
        // `Verified` runtime with no receipts is exactly the D3 lie.
        let claims_attestation = self.guarantee_class != FindingGuaranteeClass::Asserted
            || self.evidence_class != FindingEvidenceClass::Asserted
            || matches!(
                self.runtime_assurance_tier,
                Some(tier) if tier != RuntimeAssuranceTier::None
            );
        if claims_attestation && self.evidence_receipt_ids.is_empty() {
            return Err(FindingError::MissingEvidence);
        }
        for receipt_id in &self.evidence_receipt_ids {
            require_non_empty(receipt_id, "evidence_receipt_ids[]")?;
        }
        if let Some(receipt_id) = &self.intent_commitment_receipt_id {
            require_non_empty(receipt_id, "intent_commitment_receipt_id")?;
        }
        if let Some(license_ref) = &self.license_ref {
            require_non_empty(license_ref, "license_ref")?;
        }
        if let Some(price_hint_ref) = &self.price_hint_ref {
            require_non_empty(price_hint_ref, "price_hint_ref")?;
        }
        if self.expires_at <= self.issued_at {
            return Err(FindingError::InvalidValidityWindow);
        }
        self.verify_finding_id()
    }

    /// Recompute and compare the content-addressed id, fail-closed.
    pub fn verify_finding_id(&self) -> Result<(), FindingError> {
        let expected = compute_finding_id(self)?;
        if expected == self.finding_id {
            Ok(())
        } else {
            Err(FindingError::MalformedDigest("finding_id"))
        }
    }
}

/// Compute the content-addressed finding id: sha256 over the canonical
/// JSON of the body with `finding_id` and `signature` cleared.
pub fn compute_finding_id(finding: &Finding) -> Result<String, FindingError> {
    let mut body = finding.clone();
    body.finding_id = String::new();
    body.signature = String::new();
    let bytes = canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(sha256_hex(&bytes))
}
