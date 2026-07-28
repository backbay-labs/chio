//! Artifact shapes for the cognition market.
//!
//! Field semantics: docs/research/cognition-market/ARCHITECTURE.md section 4.

use chio_core_types::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// Signed information-good artifact.
pub const FINDING_SCHEMA_V1: &str = chio_core_types::CHIO_FINDING_V1_SCHEMA;

/// What kind of claim is being sold.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingOutcomeClass {
    /// "Doing X fails / has no effect": the negative result.
    NullResult,
    /// "This change makes the committed check pass": the verified fix.
    VerifiedFix,
    /// Positive measurement or artifact with a checkable predicate.
    PositiveResult,
}

/// What "verified" means for this finding, truthful to its backing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingGuaranteeClass {
    /// Claim re-checkable by deterministic re-execution of the committed
    /// recipe. Requires `replay_recipe_sha256`.
    DeterministicReplay,
    /// Execution, cost, and output digest attested by mediated receipts;
    /// claim semantics not re-checkable.
    MeteredAttested,
    /// Seller-asserted only. Never silently upgraded.
    Asserted,
}

/// Evidence-class linkage of the claim to its receipts, mirroring the
/// normative asserted/observed/verified taxonomy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingEvidenceClass {
    Asserted,
    Observed,
    Verified,
}

/// Machine-matchable statement of what question this finding answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingDescriptor {
    /// Prefix-searchable topic key.
    pub topic: String,
    /// Digest of the full context object; the match key for buyers.
    pub context_sha256: String,
    pub outcome_class: FindingOutcomeClass,
}

/// A tradeable unit of cognition: sealed payload commitment plus the
/// metered evidence that produced it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Finding {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with `finding_id`
    /// and `signature` empty. See `compute_finding_id`.
    pub finding_id: String,
    pub descriptor: FindingDescriptor,
    pub guarantee_class: FindingGuaranteeClass,
    /// Digest of the canonical reveal ENVELOPE, not of raw payload bytes:
    /// sha256_hex(canonical_json_bytes(&reveal_envelope)) where the
    /// envelope is {media_type, payload_b64}. The envelope excludes
    /// finding_id so this commitment and the content-addressed id do not
    /// form a hash cycle. Must equal the kernel's content_hash for the
    /// reveal response (ARCHITECTURE 4.5).
    pub payload_sha256: String,
    pub payload_media_type: String,
    pub evidence_receipt_ids: Vec<String>,
    pub evidence_checkpoint_ref: String,
    /// Issuer-asserted production-cost rollup (bucketed for public
    /// descriptors; see the side-channel note in the threat model). This
    /// type does not prove compute burn or semantically verify this
    /// amount; callers that need that assurance must resolve it against
    /// the metered receipts separately.
    pub evidence_cost: MonetaryAmount,
    /// Attestation-quality tier from appraisal, as the existing CLOSED
    /// vocabulary so unsupported tier names fail at parse time
    /// (chio-core-types/src/capability/runtime_attestation.rs:15-23,
    /// serde snake_case: none/basic/attested/verified). Absent means the
    /// producing runtime was not attested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    pub evidence_class: FindingEvidenceClass,
    /// Required when `guarantee_class` is `DeterministicReplay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_recipe_sha256: Option<String>,
    /// Receipt id of a pre-outcome intent commitment, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_commitment_receipt_id: Option<String>,
    /// Opaque collateral reference; this type does not resolve or verify
    /// it. Publication admission must resolve and verify live backing
    /// before advertising a slashable guarantee.
    pub bond_ref: String,
    pub status_feed_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_hint_ref: Option<String>,
    /// Producing agent subject. Malformed encodings reject during typed
    /// deserialization. The raw schema plus `Finding::validate` enforce the
    /// canonical bare Ed25519 form and reject weak keys.
    pub issuer: PublicKey,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Lowercase-hex Ed25519 signature over the canonical body with
    /// `signature` cleared, verifiable against `issuer`. Empty string =
    /// unsigned draft; published artifacts are signed. Inline signature
    /// (disclosure-family precedent, SignedLineageSubgraph) so the
    /// registered JSON schema validates the artifact as-serialized; no
    /// SignedExportEnvelope wrapper is used for this family.
    pub signature: String,
}
