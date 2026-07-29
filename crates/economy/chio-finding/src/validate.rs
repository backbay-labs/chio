//! Fail-closed validation for finding-family artifacts.

use std::collections::BTreeSet;

use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::crypto::{sha256_hex, Keypair, Signature, SigningAlgorithm};

use crate::types::{Finding, FindingEvidenceClass, FindingGuaranteeClass, FINDING_SCHEMA_V1};

const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

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
    #[error("finding_id does not match the canonical artifact body")]
    FindingIdMismatch,
    #[error("field exceeds the I-JSON maximum safe integer: {0}")]
    IJsonIntegerOutOfRange(&'static str),
    #[error("runtime_assurance_tier must be omitted when assurance is none")]
    NonCanonicalRuntimeAssuranceTier,
    #[error("finding issuer must use Ed25519")]
    UnsupportedIssuerAlgorithm,
    #[error("finding issuer must not be a weak Ed25519 key")]
    WeakIssuerKey,
    #[error("currency must be a three-letter uppercase ISO 4217-style code: {0}")]
    InvalidCurrency(&'static str),
    #[error("deterministic_replay findings require replay_recipe_sha256")]
    MissingReplayRecipe,
    #[error("non-asserted evidence class requires evidence receipts")]
    MissingEvidence,
    #[error("evidence receipt ids must be unique")]
    DuplicateEvidenceReceiptId,
    #[error("expires_at must be strictly after issued_at")]
    InvalidValidityWindow,
    #[error("canonical JSON serialization failed")]
    Canonicalization,
    #[error("finding signing failed")]
    Signing,
    #[error("finding signature invalid")]
    SignatureInvalid,
    #[error("value exceeds its size bound: {0}")]
    SizeLimitExceeded(&'static str),
    #[error("content-addressed id does not match the canonical body: {0}")]
    ArtifactIdMismatch(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate entry: {0}")]
    DuplicateEntry(&'static str),
    #[error("missing required entry: {0}")]
    MissingEntry(&'static str),
    #[error("value must be nonzero: {0}")]
    NonZeroRequired(&'static str),
    #[error("authority key rejected (algorithm or weak-key): {0}")]
    InvalidAuthorityKey(&'static str),
    #[error("envelope signer does not match the pinned authority: {0}")]
    AuthorityMismatch(&'static str),
    #[error("envelope signature invalid: {0}")]
    EnvelopeSignatureInvalid(&'static str),
    #[error("currency mismatch: {0}")]
    CurrencyMismatch(&'static str),
    #[error("amount arithmetic overflow: {0}")]
    AmountOverflow(&'static str),
    #[error("value exceeds its size bound: {0}")]
    SizeLimitExceeded(&'static str),
    #[error("value is not canonical JSON: {0}")]
    NonCanonicalBytes(&'static str),
}

/// Upper bound on opaque identifiers carried by finding-market artifacts.
pub const MAX_FINDING_IDENTIFIER_BYTES: usize = 512;

/// Upper bound on searchable or display-oriented text carried by finding-market artifacts.
pub const MAX_FINDING_TEXT_BYTES: usize = 512;

/// Upper bound on receipt references carried by a finding.
pub const MAX_FINDING_EVIDENCE_RECEIPTS: usize = 256;

/// Upper bound on variable-length collections carried by market artifacts.
pub const MAX_FINDING_ARTIFACT_ITEMS: usize = 256;
pub(crate) fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

pub(crate) fn require_non_empty(value: &str, field: &'static str) -> Result<(), FindingError> {
    if value.trim().is_empty() {
        Err(FindingError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn require_bounded_non_empty(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), FindingError> {
    require_non_empty(value, field)?;
    if value.len() > max_bytes {
        return Err(FindingError::SizeLimitExceeded(field));
    }
    Ok(())
}

pub(crate) fn require_bounded_id(value: &str, field: &'static str) -> Result<(), FindingError> {
    require_bounded_non_empty(value, field, MAX_FINDING_IDENTIFIER_BYTES)
}

pub(crate) fn require_bounded_text(value: &str, field: &'static str) -> Result<(), FindingError> {
    require_bounded_non_empty(value, field, MAX_FINDING_TEXT_BYTES)
}

pub(crate) fn require_max_items(
    len: usize,
    field: &'static str,
    max_items: usize,
) -> Result<(), FindingError> {
    if len > max_items {
        return Err(FindingError::SizeLimitExceeded(field));
    }
    Ok(())
}

pub(crate) fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingError> {
    if is_hex64(value) {
        Ok(())
    } else {
        Err(FindingError::MalformedDigest(field))
    }
}

pub(crate) fn require_i_json_u64(value: u64, field: &'static str) -> Result<(), FindingError> {
    if value <= I_JSON_MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(FindingError::IJsonIntegerOutOfRange(field))
    }
}

pub(crate) fn require_nonzero(value: u64, field: &'static str) -> Result<(), FindingError> {
    if value == 0 {
        Err(FindingError::NonZeroRequired(field))
    } else {
        require_i_json_u64(value, field)
    }
}

pub(crate) fn require_currency(currency: &str, field: &'static str) -> Result<(), FindingError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(FindingError::InvalidCurrency(field));
    }
    Ok(())
}

pub(crate) fn require_window(
    issued_at: u64,
    expires_at: u64,
    issued_field: &'static str,
    expires_field: &'static str,
) -> Result<(), FindingError> {
    require_i_json_u64(issued_at, issued_field)?;
    require_i_json_u64(expires_at, expires_field)?;
    if expires_at <= issued_at {
        return Err(FindingError::InvalidValidityWindow);
    }
    Ok(())
}

impl Finding {
    /// Structural validation. Signature and cross-artifact checks (bond
    /// existence, receipt verification, status freshness) are surface
    /// obligations, not wire-type checks; this validator is pure over the
    /// artifact alone. It is also CLOCKLESS by design: it checks the
    /// window shape (expires_at > issued_at) but not liveness - callers
    /// that resolve a Finding for publish, search, or purchase must
    /// reject `now >= expires_at` themselves.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.finding_id, "finding_id")?;
        if self.issuer.algorithm() != SigningAlgorithm::Ed25519 {
            return Err(FindingError::UnsupportedIssuerAlgorithm);
        }
        if self.issuer.is_weak_ed25519() {
            return Err(FindingError::WeakIssuerKey);
        }
        require_i_json_u64(self.evidence_cost.units, "evidence_cost.units")?;
        require_i_json_u64(self.issued_at, "issued_at")?;
        require_i_json_u64(self.expires_at, "expires_at")?;
        if self.runtime_assurance_tier == Some(RuntimeAssuranceTier::None) {
            return Err(FindingError::NonCanonicalRuntimeAssuranceTier);
        }
        require_bounded_non_empty(
            &self.descriptor.topic,
            "descriptor.topic",
            MAX_FINDING_TEXT_BYTES,
        )?;
        require_hex64(&self.descriptor.context_sha256, "descriptor.context_sha256")?;
        require_hex64(&self.payload_sha256, "payload_sha256")?;
        require_bounded_non_empty(
            &self.payload_media_type,
            "payload_media_type",
            MAX_FINDING_TEXT_BYTES,
        )?;
        require_bounded_id(&self.evidence_checkpoint_ref, "evidence_checkpoint_ref")?;
        require_currency(&self.evidence_cost.currency, "evidence_cost.currency")?;
        require_bounded_id(&self.bond_ref, "bond_ref")?;
        require_bounded_id(&self.status_feed_ref, "status_feed_ref")?;
        if self.guarantee_class == FindingGuaranteeClass::DeterministicReplay {
            match &self.replay_recipe_sha256 {
                Some(recipe) => require_hex64(recipe, "replay_recipe_sha256")?,
                None => return Err(FindingError::MissingReplayRecipe),
            }
        } else if let Some(recipe) = &self.replay_recipe_sha256 {
            require_hex64(recipe, "replay_recipe_sha256")?;
        }
        // Any attestation-quality signal requires at least one receipt
        // reference. This is a structural requirement only: this
        // validator does not resolve the reference, verify
        // receipt/checkpoint/revocation evidence, bind issuer lineage, or
        // establish the claimed tier/class.
        let claims_attestation = self.guarantee_class != FindingGuaranteeClass::Asserted
            || self.evidence_class != FindingEvidenceClass::Asserted
            || matches!(
                self.runtime_assurance_tier,
                Some(tier) if tier != RuntimeAssuranceTier::None
            );
        if claims_attestation && self.evidence_receipt_ids.is_empty() {
            return Err(FindingError::MissingEvidence);
        }
        if self.evidence_receipt_ids.len() > MAX_FINDING_EVIDENCE_RECEIPTS {
            return Err(FindingError::SizeLimitExceeded("evidence_receipt_ids"));
        }
        let mut unique_receipt_ids = BTreeSet::new();
        for receipt_id in &self.evidence_receipt_ids {
            require_bounded_id(receipt_id, "evidence_receipt_ids[]")?;
            if !unique_receipt_ids.insert(receipt_id) {
                return Err(FindingError::DuplicateEvidenceReceiptId);
            }
        }
        if let Some(receipt_id) = &self.intent_commitment_receipt_id {
            require_bounded_id(receipt_id, "intent_commitment_receipt_id")?;
        }
        if let Some(license_ref) = &self.license_ref {
            require_bounded_id(license_ref, "license_ref")?;
        }
        if let Some(price_hint_ref) = &self.price_hint_ref {
            require_bounded_id(price_hint_ref, "price_hint_ref")?;
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
            Err(FindingError::FindingIdMismatch)
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

/// Sign the finding inline: signature is over the canonical body with
/// `signature` cleared. The signer must be the artifact's issuer.
pub fn sign_finding(mut finding: Finding, keypair: &Keypair) -> Result<Finding, FindingError> {
    if finding.issuer != keypair.public_key() {
        return Err(FindingError::Signing);
    }
    finding.signature.clear();
    finding.validate()?;
    let (signature, _) = keypair
        .sign_canonical(&finding)
        .map_err(|_| FindingError::Signing)?;
    finding.signature = signature.to_hex();
    Ok(finding)
}

pub(crate) fn is_hex128(value: &str) -> bool {
    value.len() == 128
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Verify the inline signature against the embedded issuer, fail-closed.
/// The exact-encoding precheck matters:
/// `Signature::from_hex` tolerates `0x` and algorithm prefixes that the
/// registered JSON schema rejects, and the signature field is cleared
/// before canonical verification, so without this check an alternate
/// encoding would verify here while failing the `chio.finding.v1`
/// schema - publish would accept artifacts the schema refuses.
pub fn verify_finding_signature(finding: &Finding) -> Result<(), FindingError> {
    if !is_hex128(&finding.signature) {
        return Err(FindingError::SignatureInvalid);
    }
    let signature =
        Signature::from_hex(&finding.signature).map_err(|_| FindingError::SignatureInvalid)?;
    let mut body = finding.clone();
    body.signature = String::new();
    match finding.issuer.verify_canonical_strict(&body, &signature) {
        Ok(true) => Ok(()),
        _ => Err(FindingError::SignatureInvalid),
    }
}

/// Verify artifact integrity for an already-deserialized finding:
/// structural invariants, content-address binding, and the embedded issuer
/// signature.
///
/// This does not authenticate evidence receipts or checkpoints, bind the
/// issuer to evidence lineage, verify bond/status/pricing references, check
/// wall-clock liveness, or establish the truth of the guarantee/evidence
/// classes. Market and trust decisions must perform those checks
/// separately.
///
/// IMPORTANT: this operates on an ALREADY-DESERIALIZED
/// `Finding` and reserializes canonically to check the signature and id.
/// It is NOT a substitute for validating the raw request JSON against the
/// registered `chio.finding.v1` schema: `PublicKey::from_hex` tolerates
/// `0x`/uppercase and `Option` fields accept explicit `null`, so an
/// artifact whose only deviation is `issuer: "0x.."` or
/// `runtime_assurance_tier: null` would pass here (canonicalized to the
/// accepted form) while failing the schema. The publish boundary MUST
/// run `chio-spec-validate` against the raw bytes BEFORE deserializing
/// and calling this.
pub fn verify_finding(finding: &Finding) -> Result<(), FindingError> {
    finding.validate()?;
    verify_finding_signature(finding)
}
