//! `chio.finding.verifier-report.v1`: the signed per-facet evidence
//! verdict that authorizes venue admission.
//!
//! The report is a typed 13-facet result, never one Boolean, and never a
//! caller-authored blob. Only an externally pinned, profile-authorized
//! verifier key that was valid and unrevoked at evaluation may sign it;
//! the body authority must equal the envelope signer. A report may claim
//! `bond_backing: verified` only for a named allocation that already
//! existed when it was evaluated (enforced mechanically at activation).

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{
    require_bounded_id, require_bounded_text, require_hex64, require_i_json_u64, require_max_items,
    require_nonzero, FindingError, MAX_FINDING_ARTIFACT_ITEMS,
};

/// Verifier-authority-signed facet report.
pub const FINDING_VERIFIER_REPORT_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_VERIFIER_REPORT_V1_SCHEMA;

/// The closed 13-facet vocabulary (ARCHITECTURE 4.1.1).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingFacetKind {
    ArtifactIntegrity,
    ReceiptAuthenticity,
    CheckpointMembership,
    KernelAndRevocationTrust,
    IssuerLineage,
    RecipeBinding,
    IntentBinding,
    MeteredExposureBacking,
    SettledSpendBacking,
    RuntimeAssuranceBacking,
    BondBacking,
    StatusLiveness,
    GuaranteeConsistency,
}

impl FindingFacetKind {
    /// Every facet, in canonical report order.
    pub const ALL: [FindingFacetKind; 13] = [
        FindingFacetKind::ArtifactIntegrity,
        FindingFacetKind::ReceiptAuthenticity,
        FindingFacetKind::CheckpointMembership,
        FindingFacetKind::KernelAndRevocationTrust,
        FindingFacetKind::IssuerLineage,
        FindingFacetKind::RecipeBinding,
        FindingFacetKind::IntentBinding,
        FindingFacetKind::MeteredExposureBacking,
        FindingFacetKind::SettledSpendBacking,
        FindingFacetKind::RuntimeAssuranceBacking,
        FindingFacetKind::BondBacking,
        FindingFacetKind::StatusLiveness,
        FindingFacetKind::GuaranteeConsistency,
    ];
}

/// Facet outcomes. `Failed` always denies admission because a check ran
/// and contradicted its evidence. `Asserted` and `Unavailable` deny a
/// facet required by the profile or by a present Finding claim; nothing
/// ever collapses them into a verified badge.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingFacetOutcome {
    Verified,
    Asserted,
    Unavailable,
    Failed,
}

/// One facet result with its reason and evidence references.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingFacetResult {
    pub facet: FindingFacetKind,
    pub outcome: FindingFacetOutcome,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

/// Verifier report body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingVerifierReport {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with `report_id`
    /// cleared.
    pub report_id: String,
    pub finding_id: String,
    pub finding_artifact_sha256: String,
    pub verifier_profile_id: String,
    pub verifier_profile_envelope_sha256: String,
    pub verifier_implementation_id: String,
    pub resolved_evidence_bundle_sha256: String,
    /// Exact canonical replay-recipe input bytes independently rechecked by
    /// the verifier. The unsigned input remains a non-authority attachment;
    /// this digest is the signed commitment to those bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_recipe_input_sha256: Option<String>,
    /// Exact canonical portable status-proof input bytes independently
    /// rechecked by the verifier. The proof input is not promoted to a signed
    /// artifact role; the report commits its bytes here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_proof_input_sha256: Option<String>,
    /// Post-purchase delivery receipt that the verifier authenticated as a
    /// successful delivery of this exact Finding and found in a pinned
    /// checkpoint log. Absent on pre-sale admission reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_delivery_receipt_id: Option<String>,
    pub trust_root_snapshot_sha256: String,
    pub resolver_policy_sha256: String,
    pub trusted_time_input_sha256: String,
    /// Exactly one result per facet, in `FindingFacetKind::ALL` order.
    pub facets: Vec<FindingFacetResult>,
    /// Required when the `bond_backing` facet is `verified`: the exact
    /// live allocation the verdict is about. The allocation must already
    /// have existed when the report was evaluated; a report cannot claim
    /// backing from an allocation created afterward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backing_allocation_id: Option<String>,
    /// Verifier authority that must sign the enclosing envelope; the
    /// deployment pin and the profile's named report signer must agree.
    pub verifier_authority: PublicKey,
    pub verifier_key_epoch: u64,
    pub evaluation_time: u64,
}

/// Verifier-authority-signed envelope for the report.
pub type SignedFindingVerifierReport = SignedExportEnvelope<FindingVerifierReport>;

impl FindingVerifierReport {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_VERIFIER_REPORT_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.report_id, "report_id")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_hex64(&self.finding_artifact_sha256, "finding_artifact_sha256")?;
        require_hex64(&self.verifier_profile_id, "verifier_profile_id")?;
        require_hex64(
            &self.verifier_profile_envelope_sha256,
            "verifier_profile_envelope_sha256",
        )?;
        require_bounded_id(
            &self.verifier_implementation_id,
            "verifier_implementation_id",
        )?;
        require_hex64(
            &self.resolved_evidence_bundle_sha256,
            "resolved_evidence_bundle_sha256",
        )?;
        if let Some(digest) = &self.replay_recipe_input_sha256 {
            require_hex64(digest, "replay_recipe_input_sha256")?;
        }
        if let Some(digest) = &self.status_proof_input_sha256 {
            require_hex64(digest, "status_proof_input_sha256")?;
        }
        if let Some(receipt_id) = &self.finding_delivery_receipt_id {
            require_hex64(receipt_id, "finding_delivery_receipt_id")?;
        }
        require_hex64(
            &self.trust_root_snapshot_sha256,
            "trust_root_snapshot_sha256",
        )?;
        require_hex64(&self.resolver_policy_sha256, "resolver_policy_sha256")?;
        require_hex64(&self.trusted_time_input_sha256, "trusted_time_input_sha256")?;
        if self.facets.len() != FindingFacetKind::ALL.len() {
            return Err(FindingError::InvalidField("facets"));
        }
        for (result, expected) in self.facets.iter().zip(FindingFacetKind::ALL) {
            if result.facet != expected {
                return Err(FindingError::InvalidField("facets"));
            }
            require_bounded_text(&result.reason, "facets[].reason")?;
            require_max_items(
                result.evidence_refs.len(),
                "facets[].evidence_refs",
                MAX_FINDING_ARTIFACT_ITEMS,
            )?;
            for evidence_ref in &result.evidence_refs {
                require_bounded_id(evidence_ref, "facets[].evidence_refs[]")?;
            }
        }
        let bond_backing_verified = self.facets.iter().any(|result| {
            result.facet == FindingFacetKind::BondBacking
                && result.outcome == FindingFacetOutcome::Verified
        });
        match (&self.backing_allocation_id, bond_backing_verified) {
            (Some(allocation_id), true) => {
                require_hex64(allocation_id, "backing_allocation_id")?;
            }
            (None, false) => {}
            (Some(_), false) => {
                return Err(FindingError::InvalidField("backing_allocation_id"));
            }
            (None, true) => {
                return Err(FindingError::MissingEntry("backing_allocation_id"));
            }
        }
        require_ed25519(&self.verifier_authority, "verifier_authority")?;
        require_nonzero(self.verifier_key_epoch, "verifier_key_epoch")?;
        require_i_json_u64(self.evaluation_time, "evaluation_time")?;
        if self.evaluation_time == 0 {
            return Err(FindingError::NonZeroRequired("evaluation_time"));
        }
        self.verify_report_id()
    }

    /// Outcome for one facet kind (exactly one row exists per kind once
    /// `validate` has passed).
    pub fn facet_outcome(&self, kind: FindingFacetKind) -> Option<FindingFacetOutcome> {
        self.facets
            .iter()
            .find(|result| result.facet == kind)
            .map(|result| result.outcome)
    }

    /// Recompute and compare the content-addressed report id.
    pub fn verify_report_id(&self) -> Result<(), FindingError> {
        let expected = compute_report_id(self)?;
        if expected == self.report_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("report_id"))
        }
    }
}

/// Content-addressed report id: sha256 over the canonical body with
/// `report_id` cleared.
pub fn compute_report_id(report: &FindingVerifierReport) -> Result<String, FindingError> {
    let mut body = report.clone();
    body.report_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed verifier report against the externally pinned verifier
/// authority.
pub fn verify_signed_verifier_report(
    signed: &SignedFindingVerifierReport,
    pinned_verifier_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    if signed.body.verifier_authority != *pinned_verifier_authority {
        return Err(FindingError::AuthorityMismatch("verifier_report"));
    }
    crate::envelope::verify_pinned_envelope(signed, pinned_verifier_authority, "verifier_report")
}
