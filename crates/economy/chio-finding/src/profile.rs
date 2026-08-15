//! `chio.finding.challenge-verifier-profile.v1`: the reusable,
//! governance-signed trust profile every recipe commits before a Finding
//! is authored (ARCHITECTURE F1 prerequisite).
//!
//! The profile carries role and trust policy ONLY. It has no field that
//! could name a Finding, recipe, listing, report, or backing: a
//! Finding-scoped profile would recreate the hash cycle the publication
//! order forbids, so the exclusion is structural, not a validation rule.
//! Role keys named here are additionally pinned by deployment governance;
//! appearing in the profile never self-authorizes a role.

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::report::FindingFacetKind;
use crate::validate::{
    require_bounded_id, require_hex64, require_max_items, require_nonzero, require_window,
    FindingError, MAX_FINDING_ARTIFACT_ITEMS,
};

/// Governance-signed reusable challenge-verifier profile.
pub const FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_CHALLENGE_VERIFIER_PROFILE_V1_SCHEMA;

/// Predicate engine implemented by the shipped finding verifier.
pub const FINDING_PREDICATE_ENGINE_CHIO_REPLAY_V1: &str = "chio-replay-v1";

/// Receipt signer roles the profile pins.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingReceiptRole {
    Production,
    Delivery,
    Replay,
}

/// Closed replay predicate vocabulary. Unknown predicate names fail at
/// parse time; exactly one predicate is defined so far.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingPredicate {
    BaselineFailsCandidatePassesV1,
}

/// One pinned authority key with its full lifecycle policy. Naming a key
/// here is a commitment to its epoch, validity window, rotation policy,
/// and revocation source; verification always cross-checks the
/// independently configured deployment pin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingAuthorityKeyPolicy {
    pub authority_id: String,
    pub key: PublicKey,
    pub key_epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub rotation_policy_ref: String,
    pub revocation_status_ref: String,
}

impl FindingAuthorityKeyPolicy {
    pub fn validate(&self, label: &'static str) -> Result<(), FindingError> {
        require_bounded_id(&self.authority_id, label)?;
        require_ed25519(&self.key, label)?;
        require_window(self.valid_from, self.valid_until, label, label)?;
        require_nonzero(self.key_epoch, label)?;
        require_bounded_id(&self.rotation_policy_ref, label)?;
        require_bounded_id(&self.revocation_status_ref, label)?;
        Ok(())
    }
}

/// Receipt signer pinned by role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingReceiptSignerRole {
    pub role: FindingReceiptRole,
    pub policy: FindingAuthorityKeyPolicy,
}

/// Checkpoint log identity plus its pinned signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingCheckpointLogPolicy {
    /// Log identity in `checkpoint_log_id` form; the verifier maps the
    /// locally derived id through this pin.
    pub log_id: String,
    pub signer: FindingAuthorityKeyPolicy,
}

/// Deterministic checkpoint log identity used by the kernel for an
/// Ed25519 signer. Profiles reject any caller-chosen alias so a pinned
/// signer always resolves to the log its checkpoints actually inhabit.
#[must_use]
pub fn finding_checkpoint_log_id(signer: &PublicKey) -> String {
    format!(
        "local-log-{}",
        chio_core_types::crypto::sha256_hex(signer.as_bytes())
    )
}

/// Externally trusted BBS projection issuer pin. The registry reference
/// is the trusted registry the deployment resolves; an embedded issuer
/// key inside a proof never self-authorizes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingBbsIssuerPolicy {
    pub issuer_fingerprint: String,
    pub key_hex: String,
    pub registry_ref: String,
    pub key_epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub revocation_status_ref: String,
}

impl FindingBbsIssuerPolicy {
    fn validate(&self) -> Result<(), FindingError> {
        require_bounded_id(
            &self.issuer_fingerprint,
            "bbs_projection_issuer.issuer_fingerprint",
        )?;
        require_bounded_id(&self.key_hex, "bbs_projection_issuer.key_hex")?;
        require_bounded_id(&self.registry_ref, "bbs_projection_issuer.registry_ref")?;
        require_nonzero(self.key_epoch, "bbs_projection_issuer.key_epoch")?;
        require_window(
            self.valid_from,
            self.valid_until,
            "bbs_projection_issuer.valid_from",
            "bbs_projection_issuer.valid_until",
        )?;
        require_bounded_id(
            &self.revocation_status_ref,
            "bbs_projection_issuer.revocation_status_ref",
        )?;
        Ok(())
    }
}

/// Resource caps replay execution must fit inside.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingResourceCaps {
    pub max_recipe_bytes: u64,
    pub max_evidence_receipts: u64,
    pub max_runtime_secs: u64,
    pub max_memory_bytes: u64,
}

impl FindingResourceCaps {
    pub fn validate(&self) -> Result<(), FindingError> {
        require_nonzero(self.max_recipe_bytes, "resource_caps.max_recipe_bytes")?;
        require_nonzero(
            self.max_evidence_receipts,
            "resource_caps.max_evidence_receipts",
        )?;
        require_nonzero(self.max_runtime_secs, "resource_caps.max_runtime_secs")?;
        require_nonzero(self.max_memory_bytes, "resource_caps.max_memory_bytes")?;
        Ok(())
    }
}

/// Reusable governance-signed challenge-verifier profile body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingChallengeVerifierProfile {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with `profile_id`
    /// cleared (the envelope signature lives outside the body).
    pub profile_id: String,
    /// Governance root that must sign the enclosing envelope; the
    /// deployment pin must agree.
    pub governance_authority: PublicKey,
    pub operator: String,
    pub receipt_signers: Vec<FindingReceiptSignerRole>,
    pub checkpoint_logs: Vec<FindingCheckpointLogPolicy>,
    pub bbs_projection_issuer: FindingBbsIssuerPolicy,
    /// Allowed runner manifest digests (sha256 of the tool manifest).
    pub allowed_runner_manifests: Vec<String>,
    /// Required receipt semantics profile, e.g. `chio.mediated_spend.v1`.
    pub required_receipt_semantics: String,
    pub resolver_policy_ref: String,
    pub retention_policy_ref: String,
    pub resource_caps: FindingResourceCaps,
    pub predicate_engine: String,
    pub allowed_predicates: Vec<FindingPredicate>,
    /// Facets a report must have exactly `verified` for admission under
    /// this profile, in addition to whatever a present Finding claim
    /// requires. May be empty only in the sense that claim-derived
    /// requirements still apply; this list is the profile's own floor.
    pub required_facets: Vec<FindingFacetKind>,
    pub verifier_report_signer: FindingAuthorityKeyPolicy,
    /// Purchase and failed-delivery authority roles, pinned before any
    /// Finding is authored so admission can bind them ahead of the first
    /// sale.
    pub purchase_authority: FindingAuthorityKeyPolicy,
    pub failed_delivery_authority: FindingAuthorityKeyPolicy,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Governance-signed envelope for the profile.
pub type SignedFindingChallengeVerifierProfile =
    SignedExportEnvelope<FindingChallengeVerifierProfile>;

impl FindingChallengeVerifierProfile {
    /// Structural validation, clockless like the whole family.
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.profile_id, "profile_id")?;
        require_ed25519(&self.governance_authority, "governance_authority")?;
        require_bounded_id(&self.operator, "operator")?;
        // Exactly one signer per role, all three roles present, so the
        // verifier never has to disambiguate role collisions.
        let mut roles = std::collections::BTreeSet::new();
        for signer in &self.receipt_signers {
            signer.policy.validate("receipt_signers[].policy")?;
            if !roles.insert(signer.role) {
                return Err(FindingError::DuplicateEntry("receipt_signers[].role"));
            }
        }
        for (index, signer) in self.receipt_signers.iter().enumerate() {
            for other in &self.receipt_signers[index + 1..] {
                let validity_overlaps = signer.policy.valid_from < other.policy.valid_until
                    && other.policy.valid_from < signer.policy.valid_until;
                if signer.policy.key == other.policy.key && validity_overlaps {
                    return Err(FindingError::InvalidField("receipt_signers[].policy.key"));
                }
            }
        }
        for role in [
            FindingReceiptRole::Production,
            FindingReceiptRole::Delivery,
            FindingReceiptRole::Replay,
        ] {
            if !roles.contains(&role) {
                return Err(FindingError::MissingEntry("receipt_signers[].role"));
            }
        }
        if self.checkpoint_logs.is_empty() {
            return Err(FindingError::MissingEntry("checkpoint_logs"));
        }
        require_max_items(
            self.checkpoint_logs.len(),
            "checkpoint_logs",
            MAX_FINDING_ARTIFACT_ITEMS,
        )?;
        let mut log_ids = std::collections::BTreeSet::new();
        for log in &self.checkpoint_logs {
            require_bounded_id(&log.log_id, "checkpoint_logs[].log_id")?;
            log.signer.validate("checkpoint_logs[].signer")?;
            if log.log_id != finding_checkpoint_log_id(&log.signer.key) {
                return Err(FindingError::InvalidField("checkpoint_logs[].log_id"));
            }
            if !log_ids.insert(log.log_id.as_str()) {
                return Err(FindingError::DuplicateEntry("checkpoint_logs[].log_id"));
            }
        }
        self.bbs_projection_issuer.validate()?;
        if self.allowed_runner_manifests.is_empty() {
            return Err(FindingError::MissingEntry("allowed_runner_manifests"));
        }
        require_max_items(
            self.allowed_runner_manifests.len(),
            "allowed_runner_manifests",
            MAX_FINDING_ARTIFACT_ITEMS,
        )?;
        let mut manifests = std::collections::BTreeSet::new();
        for manifest in &self.allowed_runner_manifests {
            require_hex64(manifest, "allowed_runner_manifests[]")?;
            if !manifests.insert(manifest.as_str()) {
                return Err(FindingError::DuplicateEntry("allowed_runner_manifests[]"));
            }
        }
        require_bounded_id(
            &self.required_receipt_semantics,
            "required_receipt_semantics",
        )?;
        require_bounded_id(&self.resolver_policy_ref, "resolver_policy_ref")?;
        require_bounded_id(&self.retention_policy_ref, "retention_policy_ref")?;
        self.resource_caps.validate()?;
        require_bounded_id(&self.predicate_engine, "predicate_engine")?;
        if self.allowed_predicates.is_empty() {
            return Err(FindingError::MissingEntry("allowed_predicates"));
        }
        let mut predicates = std::collections::BTreeSet::new();
        for predicate in &self.allowed_predicates {
            if !predicates.insert(*predicate) {
                return Err(FindingError::DuplicateEntry("allowed_predicates[]"));
            }
        }
        let mut required_facets = std::collections::BTreeSet::new();
        for facet in &self.required_facets {
            if !required_facets.insert(*facet) {
                return Err(FindingError::DuplicateEntry("required_facets[]"));
            }
        }
        self.verifier_report_signer
            .validate("verifier_report_signer")?;
        self.purchase_authority.validate("purchase_authority")?;
        self.failed_delivery_authority
            .validate("failed_delivery_authority")?;
        require_window(self.issued_at, self.expires_at, "issued_at", "expires_at")?;
        self.verify_profile_id()
    }

    /// Recompute and compare the content-addressed profile id.
    pub fn verify_profile_id(&self) -> Result<(), FindingError> {
        let expected = compute_profile_id(self)?;
        if expected == self.profile_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("profile_id"))
        }
    }
}

/// Content-addressed profile id: sha256 over the canonical body with
/// `profile_id` cleared. All other members remain present.
pub fn compute_profile_id(
    profile: &FindingChallengeVerifierProfile,
) -> Result<String, FindingError> {
    let mut body = profile.clone();
    body.profile_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a profile against the externally configured governance root.
pub fn verify_signed_profile(
    signed: &SignedFindingChallengeVerifierProfile,
    pinned_governance_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    if signed.body.governance_authority != *pinned_governance_authority {
        return Err(FindingError::AuthorityMismatch("profile"));
    }
    crate::envelope::verify_pinned_envelope(signed, pinned_governance_authority, "profile")
}
