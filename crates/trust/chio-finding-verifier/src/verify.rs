//! The `FindingEvidenceVerifier` orchestration: raw finding bytes plus
//! pinned trust roots and a resolved evidence bundle, out comes the
//! 13-facet draft in canonical order plus the report signing helper.
//!
//! Facet semantics are exact: `verified` only when the check ran to
//! completion on supplied evidence; `unavailable` when a required input
//! was not supplied (which DENIES wherever the facet is required);
//! `failed` when supplied evidence positively fails; `asserted` for
//! seller labels this verifier has no independent evidence to check.
//! Nothing here collapses one into another, and required-facet policy is
//! evaluated by the caller against the profile plus the finding's own
//! claims.

use std::collections::BTreeSet;

use chio_appraisal::{
    verify_runtime_attestation_record, SignedRuntimeAttestationAppraisalReport,
    RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA,
};
use chio_core_types::canonical_json_bytes;
use chio_core_types::canonical_json_bytes_from_str;
use chio_core_types::capability::runtime_attestation::RuntimeAttestationEvidence;
use chio_core_types::capability::trust_policy::AttestationTrustPolicy;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;
use chio_core_types::receipt::body::{chio_receipt_id, ChioReceipt};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::metadata::{
    DeliveryResult, FindingDelivery, FindingMediaTypeCheck, FINDING_DELIVERY_METADATA_KEY,
};
use chio_core_types::receipt::MEDIATED_SPEND_PROFILE;
use chio_finding::{
    compute_report_id, signed_envelope_sha256, verify_finding, verify_pinned_envelope,
    verify_signed_authority_status, verify_signed_bond_backing, verify_signed_profile,
    verify_status_proof_input, Finding, FindingAuthorityKeyPolicy, FindingChallengeVerifierProfile,
    FindingEvidenceClass, FindingFacetKind, FindingFacetOutcome, FindingFacetResult,
    FindingGuaranteeClass, FindingPredicate, FindingReceiptRole, FindingReplayRecipeInput,
    FindingStatusFreshnessPolicy, FindingStatusOperatorAuthorization, FindingStatusProofInput,
    FindingVerifierReport, SignedFindingAuthorityStatus, SignedFindingBondBacking,
    SignedFindingChallengeVerifierProfile, SignedFindingVerifierReport,
    FINDING_PREDICATE_ENGINE_CHIO_REPLAY_V1, FINDING_VERIFIER_REPORT_SCHEMA_V1,
};
use chio_kernel::checkpoint::{
    CheckpointTransparencySummary, KernelCheckpoint, ReceiptInclusionProof,
};

use crate::checkpoints::{
    verify_post_finding_checkpoint_membership, verify_production_checkpoint_membership,
};
use crate::cost::FindingNonceResolver;
use crate::cost::{evaluate_metered_exposure, evaluate_settled_spend, CostFacetOutcome};
use crate::receipts::verify_receipt_strict;

mod bond;
use bond::verify_bond_requirement;

/// Size bound on the raw finding submitted to the verifier. Matches the
/// publish surface's route-level cap so both boundaries reject the same
/// inputs.
pub const MAX_RAW_FINDING_BYTES: usize = 256 * 1024;

/// Schema for the collateral-authority-signed store view used during one
/// verifier evaluation.
pub const FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1: &str = "chio.finding.bond-store-snapshot.v1";

/// Fresh, independently authenticated revocation standing for every
/// receipt or checkpoint signer a verifier may accept during this evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingCheckpointSignerStatusTrust {
    pub signed_statuses: Vec<SignedFindingAuthorityStatus>,
    pub status_authority: PublicKey,
    pub max_age_secs: u64,
}

/// Terminal verifier failures: conditions under which no report draft can
/// be produced at all (facet-level failures are report content instead).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FindingVerifierError {
    #[error("raw finding exceeds the size bound")]
    RawTooLarge,
    #[error("raw finding is not strict canonical I-JSON")]
    RawNotCanonical,
    #[error("raw finding bytes are not the canonical serialization")]
    RawBytesNotCanonical,
    #[error("raw finding failed typed deserialization")]
    Deserialization,
    #[error("verifier profile envelope failed pinned verification")]
    ProfileInvalid,
    #[error("report evaluation is outside the Finding validity window")]
    FindingInactive,
    #[error("no admitted kernel keys configured")]
    NoAdmittedKernelKeys,
    #[error("report body construction failed canonicalization")]
    Canonicalization,
    #[error("report profile does not match the profile used for evaluation")]
    ReportProfileMismatch,
    #[error("report signer does not match the pinned verifier authority")]
    ReportSignerMismatch,
    #[error("report evaluation is outside the profile-authorized signer window")]
    ReportSignerInactive,
    #[error("report signing failed")]
    ReportSigning,
}

/// Externally pinned trust inputs. Every list is a positive allowlist:
/// empty means nothing is trusted, never everything.
pub struct FindingVerifierTrustRoots {
    /// Governance root that must have signed the profile envelope.
    pub governance_authority: PublicKey,
    /// The admitted reusable verifier profile.
    pub profile: SignedFindingChallengeVerifierProfile,
    /// Kernel keys admitted for authoritative-spend accounting.
    pub admitted_kernel_keys: Vec<PublicKey>,
    /// Collateral authority whose signature makes an allocation evidence.
    pub collateral_authority: PublicKey,
    /// Fee-schedule authorities independently pinned by deployment policy.
    pub fee_schedule_authorities: Vec<PublicKey>,
    /// Runtime-attestation statement signer pinned by deployment
    /// governance. The profile cannot self-authorize this role.
    pub runtime_attestation_authority: Option<PublicKey>,
    /// Appraisal report signer pinned independently from the attestation
    /// statement signer.
    pub appraisal_authority: Option<PublicKey>,
    /// Local rules that map signed attestation evidence to an effective
    /// assurance tier. An absent or empty policy never accepts the raw
    /// seller-carried tier.
    pub attestation_trust_policy: Option<AttestationTrustPolicy>,
    /// Governance-pinned status-feed authority. A proof without this
    /// independent authorization cannot establish status freshness.
    pub status_operator_authorization: Option<FindingStatusOperatorAuthorization>,
    /// Trusted-time freshness policy applied to the portable status proof.
    pub status_freshness_policy: Option<FindingStatusFreshnessPolicy>,
    /// Current authenticated standing for the profile-pinned receipt and
    /// checkpoint signers. The historical field name is retained for input
    /// compatibility. Missing or stale standing denies the affected evidence.
    pub checkpoint_signer_status: Option<FindingCheckpointSignerStatusTrust>,
    /// Venue trusted time for the evaluation stamp.
    pub trusted_time: u64,
    /// Digest of the trust-root snapshot the caller resolved (pinned
    /// into the report so admission binds the exact inputs).
    pub trust_root_snapshot_sha256: String,
    /// Digest of the resolver policy in force.
    pub resolver_policy_sha256: String,
    /// Digest of the trusted-time input evidence.
    pub trusted_time_input_sha256: String,
}

/// One resolved evidence receipt: the EXACT canonical receipt envelope
/// bytes plus its inclusion proof. The typed receipt is deserialized from
/// those bytes by the resolver; both travel together so the canonical
/// leaf and the typed view cannot drift.
pub struct ResolvedReceiptEvidence {
    pub receipt: ChioReceipt,
    pub canonical_receipt_bytes: Vec<u8>,
    pub inclusion_proof: ReceiptInclusionProof,
}

/// Optional post-purchase delivery evidence. It is separate from the
/// Finding's production receipts because the Finding is signed before its
/// first sale and therefore cannot commit a later delivery checkpoint.
pub struct ResolvedFindingDeliveryEvidence {
    pub receipt: ResolvedReceiptEvidence,
    /// Complete checkpoint prefix through the delivery receipt's checkpoint.
    pub checkpoints: Vec<KernelCheckpoint>,
    pub checkpoint_transparency: CheckpointTransparencySummary,
}

/// Signed collateral-store state for one exact backing envelope.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingBondStoreSnapshot {
    pub schema: String,
    pub finding_id: String,
    pub bond_ref: String,
    pub allocation_id: String,
    pub backing_envelope_sha256: String,
    pub live: bool,
    pub accepted_at: u64,
    /// Venue trusted time at which this store state was observed.
    pub observed_at: u64,
}

/// Collateral-authority-signed store snapshot.
pub type SignedFindingBondStoreSnapshot = SignedExportEnvelope<FindingBondStoreSnapshot>;

/// Fresh authority view of the named collateral allocation, resolved by
/// the caller from the venue collateral store immediately before
/// evaluation. A stale, unsigned, or absent snapshot reports bond backing
/// unavailable or failed, never verified.
pub struct FindingBondSnapshot {
    /// The collateral-authority-signed allocation envelope. The body
    /// alone is a seller-supplied assertion; only the signature under the
    /// pinned authority makes it evidence.
    pub backing: SignedFindingBondBacking,
    /// Exact authority-signed schedule carrying the referenced requirement.
    pub fee_schedule: chio_fiscal::fee_schedule::SignedOpenMarketFeeSchedule,
    /// Signed store state for this exact backing envelope. Liveness and
    /// acceptance time are authority statements, not caller booleans.
    pub store_snapshot: SignedFindingBondStoreSnapshot,
}

/// The resolved evidence bundle. Resolution happens at the owning
/// surface; absent members degrade the matching facets to unavailable.
pub struct FindingEvidenceBundle<'a> {
    pub receipts: Vec<ResolvedReceiptEvidence>,
    pub checkpoints: Vec<KernelCheckpoint>,
    /// Transparency records resolved with the checkpoint set. These are
    /// re-derived and compared before any checkpoint can back a facet.
    pub checkpoint_transparency: CheckpointTransparencySummary,
    /// Post-purchase proof used only for a delivery-bound claim. Admission
    /// verification before the first sale leaves this absent.
    pub finding_delivery: Option<ResolvedFindingDeliveryEvidence>,
    /// Raw replay-recipe preimage bytes, when the finding commits one.
    pub recipe_preimage: Option<&'a [u8]>,
    /// Exact canonical portable status-proof input bytes. This unsigned input
    /// remains a non-authority attachment and is independently rechecked.
    pub status_proof_input: Option<&'a [u8]>,
    /// Exact runtime-attestation evidence under the separately pinned
    /// attestation authority, when the Finding claims an assurance tier.
    pub runtime_attestation: Option<SignedExportEnvelope<RuntimeAttestationEvidence>>,
    /// Exact appraisal of `runtime_attestation`, signed by the separately
    /// pinned appraisal authority.
    pub runtime_appraisal: Option<SignedRuntimeAttestationAppraisalReport>,
    pub bond_snapshot: Option<FindingBondSnapshot>,
    pub nonce_resolver: &'a dyn FindingNonceResolver,
}

/// The draft the venue turns into a signed report: the parsed finding,
/// the 13 facets in canonical order, and the evaluation metadata.
pub struct FindingVerifierDraft {
    pub finding: Finding,
    pub finding_artifact_sha256: String,
    pub facets: Vec<FindingFacetResult>,
    pub resolved_evidence_bundle_sha256: String,
    /// Exact raw attachment digests copied into the signed report.
    pub replay_recipe_input_sha256: Option<String>,
    pub status_proof_input_sha256: Option<String>,
    /// Authenticated, checkpointed post-purchase receipt for this Finding.
    /// Absent for ordinary pre-sale admission reports.
    pub finding_delivery_receipt_id: Option<String>,
    /// Exact governance-signed verifier profile used for facet evaluation.
    /// Kept private so callers cannot relabel an evaluated draft before
    /// report signing.
    verifier_profile_envelope_sha256: String,
    trust_root_snapshot_sha256: String,
    resolver_policy_sha256: String,
    trusted_time_input_sha256: String,
    pub evaluation_time: u64,
    /// Allocation id carried to the report when bond backing verified.
    pub backing_allocation_id: Option<String>,
}

impl FindingVerifierDraft {
    /// Outcome for one facet kind.
    pub fn facet_outcome(&self, kind: FindingFacetKind) -> Option<FindingFacetOutcome> {
        self.facets
            .iter()
            .find(|result| result.facet == kind)
            .map(|result| result.outcome)
    }

    /// The facets this finding REQUIRES to be exactly verified: the
    /// profile's floor plus every claim the artifact makes. Nothing here
    /// waives a facet the profile lists.
    pub fn required_facets(
        &self,
        profile: &FindingChallengeVerifierProfile,
    ) -> Vec<FindingFacetKind> {
        let mut required: BTreeSet<FindingFacetKind> =
            profile.required_facets.iter().copied().collect();
        required.insert(FindingFacetKind::ArtifactIntegrity);
        if self.finding.guarantee_class == FindingGuaranteeClass::DeterministicReplay {
            required.insert(FindingFacetKind::RecipeBinding);
        }
        if self.finding.evidence_class == FindingEvidenceClass::Verified {
            required.insert(FindingFacetKind::ReceiptAuthenticity);
            required.insert(FindingFacetKind::CheckpointMembership);
        }
        if self.finding.runtime_assurance_tier.is_some() {
            required.insert(FindingFacetKind::RuntimeAssuranceBacking);
        }
        required.into_iter().collect()
    }

    /// True when no facet failed and every required facet is exactly
    /// `verified`. `Failed` records a check that ran and contradicted its
    /// evidence, so it denies even when the profile did not require that
    /// facet. Optional `asserted` and `unavailable` results remain visible
    /// without being upgraded to verified.
    pub fn satisfies_required_facets(&self, profile: &FindingChallengeVerifierProfile) -> bool {
        !self
            .facets
            .iter()
            .any(|result| result.outcome == FindingFacetOutcome::Failed)
            && self
                .required_facets(profile)
                .into_iter()
                .all(|kind| self.facet_outcome(kind) == Some(FindingFacetOutcome::Verified))
    }
}

fn facet(
    kind: FindingFacetKind,
    outcome: FindingFacetOutcome,
    reason: impl Into<String>,
) -> FindingFacetResult {
    FindingFacetResult {
        facet: kind,
        outcome,
        reason: reason.into(),
        evidence_refs: Vec::new(),
    }
}

pub(crate) const fn policy_covers(policy: &FindingAuthorityKeyPolicy, instant: u64) -> bool {
    instant >= policy.valid_from && instant < policy.valid_until
}

fn verify_required_receipt_semantics(
    receipt: &ChioReceipt,
    required_semantics: &str,
    admitted_kernel_keys: &[PublicKey],
    nonce_resolver: &dyn FindingNonceResolver,
) -> Result<(), String> {
    if required_semantics != MEDIATED_SPEND_PROFILE {
        return Err("unsupported receipt semantics profile".to_string());
    }
    let nonce = nonce_resolver
        .nonce_for(receipt)
        .ok_or_else(|| "execution nonce evidence not supplied".to_string())?;
    is_authoritative_spend_receipt(receipt, admitted_kernel_keys, nonce)
        .map_err(|reason| format!("receipt is not authoritative mediated spend: {reason:?}"))?;
    let issued_at = u64::try_from(nonce.nonce.issued_at)
        .map_err(|_| "execution nonce validity interval is invalid".to_string())?;
    let expires_at = u64::try_from(nonce.nonce.expires_at)
        .map_err(|_| "execution nonce validity interval is invalid".to_string())?;
    if issued_at >= expires_at || receipt.timestamp < issued_at || receipt.timestamp >= expires_at {
        return Err("execution nonce was not active at receipt issuance".to_string());
    }
    Ok(())
}

fn verify_receipt_signer_status(
    policy: &FindingAuthorityKeyPolicy,
    acted_at: u64,
    evaluated_at: u64,
    trust: Option<&FindingCheckpointSignerStatusTrust>,
) -> Result<(), String> {
    if evaluated_at >= policy.valid_until {
        return Err("receipt signer authority expired before evaluation".to_string());
    }
    let trust = trust.ok_or_else(|| "receipt signer status evidence not supplied".to_string())?;
    if trust.max_age_secs == 0 {
        return Err("receipt signer status freshness policy is invalid".to_string());
    }
    let mut matching = trust.signed_statuses.iter().filter(|signed| {
        let status = &signed.body;
        status.status_ref == policy.revocation_status_ref
            && status.authority_id == policy.authority_id
            && status.key == policy.key
            && status.key_epoch == policy.key_epoch
    });
    let signed_status = matching
        .next()
        .ok_or_else(|| "receipt signer status evidence not supplied".to_string())?;
    if matching.next().is_some() {
        return Err("duplicate receipt signer status evidence".to_string());
    }
    verify_signed_authority_status(signed_status, &trust.status_authority)
        .map_err(|_| "receipt signer status signature is invalid".to_string())?;
    let status = &signed_status.body;
    if status.observed_at < acted_at
        || status.observed_at > evaluated_at
        || evaluated_at.saturating_sub(status.observed_at) > trust.max_age_secs
    {
        return Err("receipt signer status evidence is stale".to_string());
    }
    // A receipt timestamp is signer-controlled. Without an authenticated
    // pre-revocation publication anchor at this stage, a revoked signer could
    // create a new backdated receipt, so any observed revocation denies it.
    if status.revoked_from.is_some() {
        return Err("receipt signer is revoked".to_string());
    }
    Ok(())
}

fn verify_finding_delivery_receipt(
    finding: &Finding,
    profile: &FindingChallengeVerifierProfile,
    evidence: &ResolvedReceiptEvidence,
    admitted_kernel_keys: &[PublicKey],
    nonce_resolver: &dyn FindingNonceResolver,
    signer_status: Option<&FindingCheckpointSignerStatusTrust>,
    evaluation_time: u64,
) -> Result<String, String> {
    let receipt = &evidence.receipt;
    verify_receipt_strict(receipt)
        .map_err(|error| format!("delivery receipt {}: {error}", receipt.id))?;
    let canonical = canonical_json_bytes(receipt).map_err(|_| {
        format!(
            "delivery receipt {} failed canonical serialization",
            receipt.id
        )
    })?;
    if canonical != evidence.canonical_receipt_bytes {
        return Err(format!(
            "delivery receipt {} canonical bytes drift from resolved leaf bytes",
            receipt.id
        ));
    }
    if receipt.timestamp > evaluation_time {
        return Err(format!(
            "delivery receipt {} was issued after report evaluation",
            receipt.id
        ));
    }
    if receipt.timestamp < finding.issued_at {
        return Err(format!(
            "delivery receipt {} predates the Finding",
            receipt.id
        ));
    }
    let delivery_policy = profile.receipt_signers.iter().find(|signer| {
        signer.role == FindingReceiptRole::Delivery
            && signer.policy.key == receipt.kernel_key
            && policy_covers(&signer.policy, receipt.timestamp)
    });
    let has_other_role = profile.receipt_signers.iter().any(|signer| {
        signer.role != FindingReceiptRole::Delivery
            && signer.policy.key == receipt.kernel_key
            && policy_covers(&signer.policy, receipt.timestamp)
    });
    let Some(delivery_policy) = delivery_policy else {
        return Err(format!(
            "delivery receipt {} is not an unambiguous profile-pinned delivery allow receipt",
            receipt.id
        ));
    };
    if has_other_role || !receipt.is_allowed() {
        return Err(format!(
            "delivery receipt {} is not an unambiguous profile-pinned delivery allow receipt",
            receipt.id
        ));
    }
    verify_receipt_signer_status(
        &delivery_policy.policy,
        receipt.timestamp,
        evaluation_time,
        signer_status,
    )
    .map_err(|error| format!("delivery receipt {} {error}", receipt.id))?;
    verify_required_receipt_semantics(
        receipt,
        &profile.required_receipt_semantics,
        admitted_kernel_keys,
        nonce_resolver,
    )
    .map_err(|error| {
        format!(
            "delivery receipt {} violates required receipt semantics: {error}",
            receipt.id
        )
    })?;
    let contract = receipt.delivery_contract().ok_or_else(|| {
        format!(
            "delivery receipt {} has no signed delivery contract",
            receipt.id
        )
    })?;
    contract.validate().map_err(|error| {
        format!(
            "delivery receipt {} contract is invalid: {error}",
            receipt.id
        )
    })?;
    if contract.result != DeliveryResult::Matched
        || contract.expected_digest != finding.payload_sha256
        || contract.observed_digest != finding.payload_sha256
        || receipt.content_hash != finding.payload_sha256
    {
        return Err(format!(
            "delivery receipt {} does not bind the Finding payload digest",
            receipt.id
        ));
    }
    let overlay_value = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get(FINDING_DELIVERY_METADATA_KEY))
        .cloned()
        .ok_or_else(|| {
            format!(
                "delivery receipt {} has no signed Finding delivery overlay",
                receipt.id
            )
        })?;
    let overlay: FindingDelivery = serde_json::from_value(overlay_value).map_err(|error| {
        format!(
            "delivery receipt {} Finding delivery overlay is malformed: {error}",
            receipt.id
        )
    })?;
    overlay.validate().map_err(|error| {
        format!(
            "delivery receipt {} Finding delivery overlay is invalid: {error}",
            receipt.id
        )
    })?;
    if overlay.finding_id != finding.finding_id
        || overlay.digest_check != DeliveryResult::Matched
        || overlay.media_type_check != FindingMediaTypeCheck::Matched
    {
        return Err(format!(
            "delivery receipt {} Finding delivery overlay does not bind a successful delivery for this Finding",
            receipt.id
        ));
    }
    Ok(receipt.id.clone())
}

/// Run the offline evidence verifier. The normative order from
/// ARCHITECTURE 4.1.1: strict raw parse, receipt resolution and strict
/// verification, checkpoint membership, issuer lineage, recipe binding,
/// intent binding, cost facets, bond backing, status, assurance, and
/// guarantee consistency, producing all 13 facets in canonical order.
pub fn verify_finding_evidence(
    raw_finding: &str,
    trust: &FindingVerifierTrustRoots,
    bundle: &FindingEvidenceBundle<'_>,
) -> Result<FindingVerifierDraft, FindingVerifierError> {
    // Step 1: strict raw ingress. Canonical bytes from the raw text
    // reject duplicate keys and non-I-JSON numbers; byte equality then
    // rejects noncanonical spellings outright, and the typed view must
    // reserialize to the same bytes.
    if raw_finding.len() > MAX_RAW_FINDING_BYTES {
        return Err(FindingVerifierError::RawTooLarge);
    }
    let strict_bytes = canonical_json_bytes_from_str(raw_finding)
        .map_err(|_| FindingVerifierError::RawNotCanonical)?;
    if strict_bytes.as_slice() != raw_finding.as_bytes() {
        return Err(FindingVerifierError::RawBytesNotCanonical);
    }
    let finding: Finding =
        serde_json::from_str(raw_finding).map_err(|_| FindingVerifierError::Deserialization)?;
    let typed_bytes =
        canonical_json_bytes(&finding).map_err(|_| FindingVerifierError::Canonicalization)?;
    if typed_bytes != strict_bytes {
        return Err(FindingVerifierError::RawBytesNotCanonical);
    }
    let finding_artifact_sha256 = sha256_hex(&strict_bytes);

    // Pinned profile and kernel keys are preconditions, not facets: with
    // an unverified profile no facet below is meaningful.
    verify_signed_profile(&trust.profile, &trust.governance_authority)
        .map_err(|_| FindingVerifierError::ProfileInvalid)?;
    if trust.profile.body.required_receipt_semantics != MEDIATED_SPEND_PROFILE
        || trust.profile.body.predicate_engine != FINDING_PREDICATE_ENGINE_CHIO_REPLAY_V1
        || trust.profile.body.required_facets.iter().any(|facet| {
            matches!(
                facet,
                FindingFacetKind::KernelAndRevocationTrust
                    | FindingFacetKind::IssuerLineage
                    | FindingFacetKind::IntentBinding
            )
        })
    {
        return Err(FindingVerifierError::ProfileInvalid);
    }
    if trust.trusted_time < trust.profile.body.issued_at
        || trust.trusted_time >= trust.profile.body.expires_at
    {
        return Err(FindingVerifierError::ProfileInvalid);
    }
    if trust.admitted_kernel_keys.is_empty() {
        return Err(FindingVerifierError::NoAdmittedKernelKeys);
    }
    if trust.trusted_time < finding.issued_at || trust.trusted_time >= finding.expires_at {
        return Err(FindingVerifierError::FindingInactive);
    }
    let profile = &trust.profile.body;
    let profile_envelope_bytes =
        canonical_json_bytes(&trust.profile).map_err(|_| FindingVerifierError::Canonicalization)?;
    let profile_envelope_sha256 = sha256_hex(&profile_envelope_bytes);

    let mut facets = Vec::with_capacity(FindingFacetKind::ALL.len());

    // Facet 1: artifact integrity (verify_finding over the parsed view).
    let artifact_integrity = match verify_finding(&finding) {
        Ok(()) => facet(
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetOutcome::Verified,
            "structure, content address, and issuer signature verified",
        ),
        Err(error) => facet(
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetOutcome::Failed,
            format!("artifact verification failed: {error}"),
        ),
    };
    let artifact_ok = artifact_integrity.outcome == FindingFacetOutcome::Verified;
    facets.push(artifact_integrity);

    // Step 2: strict receipt verification plus exact binding to
    // `evidence_receipt_ids` (order and cardinality, whole-vector
    // equality; a set comparison would admit reorderings). Optional purchase
    // delivery is evaluated through its separate post-Finding evidence path.
    let mut production_receipt_indexes = Vec::new();
    let mut failure: Option<String> = None;
    let mut recomputed_ids = Vec::with_capacity(bundle.receipts.len());
    let production_signers: Vec<&FindingAuthorityKeyPolicy> = profile
        .receipt_signers
        .iter()
        .filter(|signer| signer.role == FindingReceiptRole::Production)
        .map(|signer| &signer.policy)
        .collect();
    for (index, evidence) in bundle.receipts.iter().enumerate() {
        if let Err(error) = verify_receipt_strict(&evidence.receipt) {
            failure = Some(format!("receipt {}: {error}", evidence.receipt.id));
            break;
        }
        if let Err(error) = verify_required_receipt_semantics(
            &evidence.receipt,
            &profile.required_receipt_semantics,
            &trust.admitted_kernel_keys,
            bundle.nonce_resolver,
        ) {
            failure = Some(format!(
                "receipt {} violates required receipt semantics: {error}",
                evidence.receipt.id
            ));
            break;
        }
        match canonical_json_bytes(&evidence.receipt) {
            Ok(bytes) if bytes == evidence.canonical_receipt_bytes => {}
            _ => {
                failure = Some(format!(
                    "receipt {} canonical bytes drift from resolved leaf bytes",
                    evidence.receipt.id
                ));
                break;
            }
        }
        if evidence.receipt.timestamp > trust.trusted_time {
            failure = Some(format!(
                "receipt {} was issued after report evaluation",
                evidence.receipt.id
            ));
            break;
        }
        if evidence.receipt.timestamp > finding.issued_at {
            failure = Some(format!(
                "receipt {} was issued after the Finding",
                evidence.receipt.id
            ));
            break;
        }
        let production_signer = production_signers.iter().find(|policy| {
            policy.key == evidence.receipt.kernel_key
                && policy_covers(policy, evidence.receipt.timestamp)
        });
        let Some(production_signer) = production_signer else {
            failure = Some(format!(
                "receipt {} signer is not a profile-pinned production key active at the receipt timestamp",
                evidence.receipt.id
            ));
            break;
        };
        if let Err(error) = verify_receipt_signer_status(
            production_signer,
            evidence.receipt.timestamp,
            trust.trusted_time,
            trust.checkpoint_signer_status.as_ref(),
        ) {
            failure = Some(format!("receipt {} {error}", evidence.receipt.id));
            break;
        }
        production_receipt_indexes.push(index);
        match chio_receipt_id(&evidence.receipt.body()) {
            Ok(id) => recomputed_ids.push(id),
            Err(_) => {
                failure = Some(format!(
                    "receipt {} id recomputation failed",
                    evidence.receipt.id
                ));
                break;
            }
        }
    }
    if failure.is_none()
        && production_receipt_indexes.len() as u64 > profile.resource_caps.max_evidence_receipts
    {
        failure = Some("production evidence receipt count exceeds the profile cap".to_string());
    }
    if failure.is_none() && recomputed_ids != finding.evidence_receipt_ids {
        failure = Some(
            "recomputed receipt ids do not equal evidence_receipt_ids in order and cardinality"
                .to_string(),
        );
    }
    let mut authenticated_delivery_receipt_id = None;
    if failure.is_none() {
        if let Some(delivery) = bundle.finding_delivery.as_ref() {
            match verify_finding_delivery_receipt(
                &finding,
                profile,
                &delivery.receipt,
                &trust.admitted_kernel_keys,
                bundle.nonce_resolver,
                trust.checkpoint_signer_status.as_ref(),
                trust.trusted_time,
            ) {
                Ok(receipt_id) => authenticated_delivery_receipt_id = Some(receipt_id),
                Err(reason) => failure = Some(reason),
            }
        }
    }
    let has_production_receipts = !bundle.receipts.is_empty();
    let has_authenticated_delivery = authenticated_delivery_receipt_id.is_some();
    let receipt_authenticity = match failure {
        Some(reason) => facet(
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetOutcome::Failed,
            reason,
        ),
        None if !has_production_receipts && !has_authenticated_delivery => facet(
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetOutcome::Unavailable,
            "no production or Finding-specific delivery receipts resolved",
        ),
        None => facet(
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetOutcome::Verified,
            if has_production_receipts {
                if has_authenticated_delivery {
                    "production evidence and Finding-specific delivery receipt verified strictly"
                } else {
                    "production evidence receipts verified strictly"
                }
            } else {
                "Finding-specific delivery receipt verified strictly"
            },
        ),
    };
    let receipts_ok = receipt_authenticity.outcome == FindingFacetOutcome::Verified;
    facets.push(receipt_authenticity);

    // Step 3: checkpoint membership with the full wrapper cross-check.
    let checkpoint_membership = if !receipts_ok {
        if bundle.receipts.is_empty() && bundle.finding_delivery.is_none() {
            facet(
                FindingFacetKind::CheckpointMembership,
                FindingFacetOutcome::Unavailable,
                "no production or Finding-specific delivery receipts resolved",
            )
        } else {
            facet(
                FindingFacetKind::CheckpointMembership,
                FindingFacetOutcome::Failed,
                "receipts did not verify; membership not evaluated",
            )
        }
    } else if bundle.receipts.is_empty() {
        match bundle.finding_delivery.as_ref() {
            Some(delivery) => match verify_post_finding_checkpoint_membership(
                std::slice::from_ref(&delivery.receipt),
                &delivery.checkpoints,
                &delivery.checkpoint_transparency,
                profile,
                trust.trusted_time,
                trust.checkpoint_signer_status.as_ref(),
            ) {
                Ok(()) => facet(
                    FindingFacetKind::CheckpointMembership,
                    FindingFacetOutcome::Verified,
                    "Finding delivery receipt is a member of a pinned, signature-valid checkpoint",
                ),
                Err(error) => facet(
                    FindingFacetKind::CheckpointMembership,
                    FindingFacetOutcome::Failed,
                    format!("delivery membership failed: {error}"),
                ),
            },
            None => facet(
                FindingFacetKind::CheckpointMembership,
                FindingFacetOutcome::Unavailable,
                "no production or Finding-specific delivery receipts resolved",
            ),
        }
    } else {
        match verify_production_checkpoint_membership(
            &bundle.receipts,
            &bundle.checkpoints,
            &bundle.checkpoint_transparency,
            profile,
            &finding.evidence_checkpoint_ref,
            finding.issued_at,
            (
                trust.trusted_time,
                trust.checkpoint_signer_status.as_ref(),
            ),
        ) {
            Ok(()) => match bundle.finding_delivery.as_ref() {
                Some(delivery) => match verify_post_finding_checkpoint_membership(
                    std::slice::from_ref(&delivery.receipt),
                    &delivery.checkpoints,
                    &delivery.checkpoint_transparency,
                    profile,
                    trust.trusted_time,
                    trust.checkpoint_signer_status.as_ref(),
                ) {
                    Ok(()) => facet(
                        FindingFacetKind::CheckpointMembership,
                        FindingFacetOutcome::Verified,
                        "production and Finding delivery receipts are members of pinned, signature-valid checkpoints",
                    ),
                    Err(error) => facet(
                        FindingFacetKind::CheckpointMembership,
                        FindingFacetOutcome::Failed,
                        format!("delivery membership failed: {error}"),
                    ),
                },
                None => facet(
                    FindingFacetKind::CheckpointMembership,
                    FindingFacetOutcome::Verified,
                    "every production receipt is a member of a pinned, signature-valid checkpoint",
                ),
            },
            Err(error) => facet(
                FindingFacetKind::CheckpointMembership,
                FindingFacetOutcome::Failed,
                format!("membership failed: {error}"),
            ),
        }
    };
    let finding_delivery_receipt_id = (checkpoint_membership.outcome
        == FindingFacetOutcome::Verified)
        .then_some(authenticated_delivery_receipt_id)
        .flatten();
    facets.push(checkpoint_membership);

    // Facet 4: kernel and revocation trust. Checkpoint signers are pinned
    // through the profile (checked above); callers supply no revocation
    // feed and no resolver for revocation freshness exists yet, so this
    // facet reports unavailable.
    facets.push(facet(
        FindingFacetKind::KernelAndRevocationTrust,
        FindingFacetOutcome::Unavailable,
        "revocation freshness evidence not supplied",
    ));

    // Facet 5: issuer lineage. Callers supply no signed capability
    // snapshot for transport validation; a payload digest match alone is
    // NOT provenance, so the facet stays unavailable.
    facets.push(facet(
        FindingFacetKind::IssuerLineage,
        FindingFacetOutcome::Unavailable,
        "signed capability snapshot evidence not supplied",
    ));

    // Step 4 / facet 6: recipe binding.
    let recipe_binding = match (&finding.replay_recipe_sha256, bundle.recipe_preimage) {
        (None, _) => facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Unavailable,
            "finding commits no replay recipe",
        ),
        (Some(_), None) => facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Unavailable,
            "replay recipe preimage not supplied",
        ),
        (Some(committed), Some(raw)) => {
            evaluate_recipe_binding(&finding, profile, &profile_envelope_sha256, committed, raw)
        }
    };
    facets.push(recipe_binding);

    // Facet 7: intent binding. Callers supply no single-log ordering
    // proof over the intent receipt, so this facet reports unavailable.
    facets.push(facet(
        FindingFacetKind::IntentBinding,
        FindingFacetOutcome::Unavailable,
        "intent commitment ordering evidence not supplied",
    ));

    // Step 6 / facets 8-9: cost floors.
    let receipts: Vec<&ChioReceipt> = production_receipt_indexes
        .iter()
        .map(|index| &bundle.receipts[*index].receipt)
        .collect();
    let metered = if receipts_ok {
        evaluate_metered_exposure(
            &receipts,
            &trust.admitted_kernel_keys,
            bundle.nonce_resolver,
            &finding.evidence_cost,
        )
    } else {
        CostFacetOutcome::Unavailable {
            reason: "receipts did not verify",
        }
    };
    facets.push(cost_facet(
        FindingFacetKind::MeteredExposureBacking,
        &metered,
    ));
    let settled = evaluate_settled_spend(&receipts, &metered);
    facets.push(cost_facet(FindingFacetKind::SettledSpendBacking, &settled));

    // Facet 10: runtime assurance. The seller tier is never a source of
    // truth. Signed attestation and appraisal artifacts must re-verify
    // under independent deployment pins and a non-empty local policy,
    // then match the assurance metadata signed into every producing
    // receipt.
    facets.push(evaluate_runtime_assurance(
        &finding,
        trust,
        bundle,
        &receipts,
        receipts_ok,
    ));

    // Step 7 / facet 11: bond backing against the fresh store snapshot.
    let (bond_backing, backing_allocation_id) =
        evaluate_bond_backing(&finding, trust, bundle, &profile_envelope_sha256);
    facets.push(bond_backing);

    // Facet 12: status liveness. Only a fresh, governance-authorized portable
    // non-inclusion proof establishes that the named Finding was live at the
    // checked time. Inclusion is an authenticated retraction and denies.
    facets.push(evaluate_status_liveness(&finding, trust, bundle));

    // Facet 13: guarantee and evidence-class consistency, without
    // upgrading any facet from another.
    facets.push(evaluate_guarantee_consistency(
        &finding,
        artifact_ok,
        &facets,
    ));

    debug_assert_eq!(facets.len(), FindingFacetKind::ALL.len());
    let resolved_evidence_bundle_sha256 = bundle_digest(bundle, trust)?;
    Ok(FindingVerifierDraft {
        finding,
        finding_artifact_sha256,
        facets,
        resolved_evidence_bundle_sha256,
        replay_recipe_input_sha256: bundle.recipe_preimage.map(sha256_hex),
        status_proof_input_sha256: bundle.status_proof_input.map(sha256_hex),
        finding_delivery_receipt_id,
        verifier_profile_envelope_sha256: profile_envelope_sha256,
        trust_root_snapshot_sha256: trust.trust_root_snapshot_sha256.clone(),
        resolver_policy_sha256: trust.resolver_policy_sha256.clone(),
        trusted_time_input_sha256: trust.trusted_time_input_sha256.clone(),
        evaluation_time: trust.trusted_time,
        backing_allocation_id,
    })
}

fn evaluate_status_liveness(
    finding: &Finding,
    trust: &FindingVerifierTrustRoots,
    bundle: &FindingEvidenceBundle<'_>,
) -> FindingFacetResult {
    let Some(raw) = bundle.status_proof_input else {
        return facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Unavailable,
            "portable status non-inclusion proof not supplied",
        );
    };
    let (Some(authorization), Some(freshness)) = (
        trust.status_operator_authorization.as_ref(),
        trust.status_freshness_policy,
    ) else {
        return facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Failed,
            "status proof supplied without pinned operator authorization and freshness policy",
        );
    };
    if freshness.now != trust.trusted_time {
        return facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Failed,
            "status freshness clock does not match the report evaluation time",
        );
    }
    let proof = match chio_finding::parse_status_proof_input(raw) {
        Ok(proof) => proof,
        Err(error) => {
            return facet(
                FindingFacetKind::StatusLiveness,
                FindingFacetOutcome::Failed,
                format!("status proof failed strict canonical parsing: {error}"),
            );
        }
    };
    if proof.finding_id() != finding.finding_id {
        return facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Failed,
            "status proof finding id does not match the verified Finding",
        );
    }
    let proof_feed_id = match &proof {
        FindingStatusProofInput::NonInclusion(value) => &value.feed_id,
        FindingStatusProofInput::Inclusion(value) => &value.feed_id,
    };
    if proof_feed_id != &finding.status_feed_ref || authorization.feed_id != finding.status_feed_ref
    {
        return facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Failed,
            "status proof and operator authorization do not bind the Finding status feed",
        );
    }
    if matches!(proof, FindingStatusProofInput::Inclusion(_)) {
        return facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Failed,
            "status proof authenticates a retracted Finding",
        );
    }
    match verify_status_proof_input(&proof, authorization, freshness) {
        Ok(_) => facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Verified,
            "fresh governance-authorized status non-inclusion proof verified",
        ),
        Err(error) => facet(
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Failed,
            format!("status proof verification failed: {error}"),
        ),
    }
}

fn cost_facet(kind: FindingFacetKind, outcome: &CostFacetOutcome) -> FindingFacetResult {
    match outcome {
        CostFacetOutcome::Verified { accounted_units } => facet(
            kind,
            FindingFacetOutcome::Verified,
            format!("kernel-accounted floor established: {accounted_units} units"),
        ),
        CostFacetOutcome::Unavailable { reason } => {
            facet(kind, FindingFacetOutcome::Unavailable, *reason)
        }
        CostFacetOutcome::Failed { reason } => {
            facet(kind, FindingFacetOutcome::Failed, reason.clone())
        }
    }
}

fn evaluate_recipe_binding(
    finding: &Finding,
    profile: &FindingChallengeVerifierProfile,
    profile_envelope_sha256: &str,
    committed_sha256: &str,
    raw_preimage: &[u8],
) -> FindingFacetResult {
    if raw_preimage.len() as u64 > profile.resource_caps.max_recipe_bytes {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe preimage exceeds the profile size cap",
        );
    }
    let Ok(raw_text) = std::str::from_utf8(raw_preimage) else {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe preimage is not UTF-8",
        );
    };
    let Ok(strict_bytes) = canonical_json_bytes_from_str(raw_text) else {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe preimage is not strict canonical I-JSON",
        );
    };
    if strict_bytes.as_slice() != raw_preimage {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe preimage bytes are not canonical",
        );
    }
    if sha256_hex(&strict_bytes) != committed_sha256 {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe digest does not equal the committed replay_recipe_sha256",
        );
    }
    let recipe: FindingReplayRecipeInput = match serde_json::from_str(raw_text) {
        Ok(recipe) => recipe,
        Err(_) => {
            return facet(
                FindingFacetKind::RecipeBinding,
                FindingFacetOutcome::Failed,
                "recipe preimage failed typed deserialization",
            )
        }
    };
    if let Err(error) = recipe.validate() {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            format!("recipe validation failed: {error}"),
        );
    }
    // A digest-valid recipe proves nothing unless it is a recipe FOR
    // this artifact under this profile: without these equalities any
    // admitted recipe could be committed by any finding.
    if recipe.context_sha256 != finding.descriptor.context_sha256 {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe context digest does not match the finding descriptor",
        );
    }
    if recipe.payload_sha256 != finding.payload_sha256 {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe payload commitment does not match the finding",
        );
    }
    if recipe.verifier_profile_envelope_sha256 != profile_envelope_sha256 {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe commits a different verifier profile",
        );
    }
    if recipe.resource_bounds.max_runtime_secs > profile.resource_caps.max_runtime_secs
        || recipe.resource_bounds.max_memory_bytes > profile.resource_caps.max_memory_bytes
        || recipe.resource_bounds.max_recipe_bytes > profile.resource_caps.max_recipe_bytes
        || recipe.resource_bounds.max_evidence_receipts
            > profile.resource_caps.max_evidence_receipts
    {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe resource bounds exceed the profile caps",
        );
    }
    if !profile
        .allowed_runner_manifests
        .contains(&recipe.runner_manifest_sha256)
    {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe runner manifest is not allowed by the profile",
        );
    }
    let supported: bool = matches!(
        recipe.predicate,
        FindingPredicate::BaselineFailsCandidatePassesV1
    ) && profile.allowed_predicates.contains(&recipe.predicate);
    if !supported {
        return facet(
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Failed,
            "recipe predicate is not allowed by the profile",
        );
    }
    facet(
        FindingFacetKind::RecipeBinding,
        FindingFacetOutcome::Verified,
        "recipe preimage is canonical, digest-bound, and profile-supported",
    )
}

fn evaluate_bond_backing(
    finding: &Finding,
    trust: &FindingVerifierTrustRoots,
    bundle: &FindingEvidenceBundle<'_>,
    profile_envelope_sha256: &str,
) -> (FindingFacetResult, Option<String>) {
    let Some(snapshot) = &bundle.bond_snapshot else {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Unavailable,
                "no fresh collateral snapshot supplied",
            ),
            None,
        );
    };
    // The allocation is evidence only under the externally pinned
    // collateral authority; an unsigned body is a seller claim.
    if let Err(error) = verify_signed_bond_backing(&snapshot.backing, &trust.collateral_authority) {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                format!("backing envelope rejected: {error}"),
            ),
            None,
        );
    }
    let backing = &snapshot.backing.body;
    if backing.profile_envelope_sha256 != profile_envelope_sha256 {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "backing allocation does not bind the evaluated verifier profile",
            ),
            None,
        );
    }
    if let Err(error) = verify_pinned_envelope(
        &snapshot.store_snapshot,
        &trust.collateral_authority,
        "bond_store_snapshot",
    ) {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                format!("collateral store snapshot rejected: {error}"),
            ),
            None,
        );
    }
    let store_snapshot = &snapshot.store_snapshot.body;
    if store_snapshot.schema != FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1 {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "collateral store snapshot has an unsupported schema",
            ),
            None,
        );
    }
    let backing_envelope_sha256 = match signed_envelope_sha256(&snapshot.backing) {
        Ok(digest) => digest,
        Err(error) => {
            return (
                facet(
                    FindingFacetKind::BondBacking,
                    FindingFacetOutcome::Failed,
                    format!("backing envelope digest rejected: {error}"),
                ),
                None,
            );
        }
    };
    if store_snapshot.backing_envelope_sha256 != backing_envelope_sha256
        || store_snapshot.allocation_id != backing.allocation_id
    {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "collateral store snapshot does not bind the backing allocation",
            ),
            None,
        );
    }
    if store_snapshot.finding_id != finding.finding_id {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "collateral store snapshot names a different finding",
            ),
            None,
        );
    }
    if let Err(reason) = verify_bond_requirement(finding, snapshot, trust) {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                reason,
            ),
            None,
        );
    }
    if store_snapshot.observed_at != trust.trusted_time {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "collateral store snapshot is not fresh for this evaluation",
            ),
            None,
        );
    }
    // A live allocation that expires before the claim, audit, and appeal
    // horizons it promises is not backing.
    let horizon_end = backing
        .claim_horizon_secs
        .checked_add(backing.audit_horizon_secs)
        .and_then(|sum| sum.checked_add(backing.appeal_horizon_secs))
        .and_then(|sum| sum.checked_add(backing.settlement_buffer_secs))
        .and_then(|sum| trust.trusted_time.checked_add(sum));
    match horizon_end {
        Some(required) if backing.expires_at >= required => {}
        _ => {
            return (
                facet(
                    FindingFacetKind::BondBacking,
                    FindingFacetOutcome::Failed,
                    "backing expiry does not cover its own liability horizons",
                ),
                None,
            );
        }
    }
    if backing.finding_id != finding.finding_id {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "backing allocation names a different finding",
            ),
            None,
        );
    }
    if backing.issued_at > store_snapshot.accepted_at {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "backing allocation was accepted before its signed issue time",
            ),
            None,
        );
    }
    if store_snapshot.accepted_at >= trust.trusted_time {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Failed,
                "backing allocation was not accepted before report evaluation",
            ),
            None,
        );
    }
    if !store_snapshot.live {
        return (
            facet(
                FindingFacetKind::BondBacking,
                FindingFacetOutcome::Unavailable,
                "allocation is not live in the fresh snapshot",
            ),
            None,
        );
    }
    (
        facet(
            FindingFacetKind::BondBacking,
            FindingFacetOutcome::Verified,
            "live exclusive allocation verified under the pinned collateral authority",
        ),
        Some(backing.allocation_id.clone()),
    )
}

fn evaluate_runtime_assurance(
    finding: &Finding,
    trust: &FindingVerifierTrustRoots,
    bundle: &FindingEvidenceBundle<'_>,
    production_receipts: &[&ChioReceipt],
    receipts_ok: bool,
) -> FindingFacetResult {
    let Some(claimed_tier) = finding.runtime_assurance_tier else {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "finding claims no runtime assurance tier",
        );
    };
    let Some(attestation) = bundle.runtime_attestation.as_ref() else {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "signed runtime-attestation evidence not supplied",
        );
    };
    let Some(appraisal) = bundle.runtime_appraisal.as_ref() else {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "signed runtime-attestation appraisal not supplied",
        );
    };
    let Some(attestation_authority) = trust.runtime_attestation_authority.as_ref() else {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "runtime-attestation authority is not pinned",
        );
    };
    let Some(appraisal_authority) = trust.appraisal_authority.as_ref() else {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "runtime-appraisal authority is not pinned",
        );
    };
    let Some(policy) = trust.attestation_trust_policy.as_ref() else {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "local attestation trust policy is not configured",
        );
    };
    if policy.rules.is_empty() {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            "local attestation trust policy has no rules",
        );
    }
    if let Err(error) =
        verify_pinned_envelope(attestation, attestation_authority, "runtime_attestation")
    {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            format!("runtime-attestation envelope rejected: {error}"),
        );
    }
    if let Err(error) = verify_pinned_envelope(appraisal, appraisal_authority, "runtime_appraisal")
    {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            format!("runtime-appraisal envelope rejected: {error}"),
        );
    }
    if appraisal.body.schema != RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            "runtime-appraisal report schema is unsupported",
        );
    }
    if appraisal.body.generated_at > trust.trusted_time
        || appraisal.body.generated_at < attestation.body.issued_at
        || appraisal.body.generated_at >= attestation.body.expires_at
    {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            "runtime-appraisal time is outside the signed attestation window",
        );
    }
    let verified = match verify_runtime_attestation_record(
        &attestation.body,
        Some(policy),
        trust.trusted_time,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            return facet(
                FindingFacetKind::RuntimeAssuranceBacking,
                FindingFacetOutcome::Failed,
                format!("runtime attestation failed local appraisal: {error}"),
            )
        }
    };
    if !verified.is_locally_accepted() {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            "runtime attestation was not accepted by the local policy",
        );
    }
    if appraisal.body.appraisal != verified.appraisal
        || appraisal.body.policy_outcome != verified.policy_outcome
    {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            "signed appraisal does not equal the locally derived appraisal",
        );
    }
    if claimed_tier != verified.effective_tier() {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Failed,
            "finding runtime-assurance tier does not equal the policy-derived tier",
        );
    }
    if !receipts_ok || production_receipts.is_empty() {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "producing receipts are not available as verified linkage evidence",
        );
    }
    for &receipt in production_receipts {
        if receipt.timestamp < attestation.body.issued_at
            || receipt.timestamp >= attestation.body.expires_at
        {
            return facet(
                FindingFacetKind::RuntimeAssuranceBacking,
                FindingFacetOutcome::Failed,
                format!(
                    "receipt {} falls outside the signed attestation window",
                    receipt.id
                ),
            );
        }
        let Some(governed) = receipt.governed_transaction_metadata() else {
            return facet(
                FindingFacetKind::RuntimeAssuranceBacking,
                FindingFacetOutcome::Failed,
                format!(
                    "receipt {} has no governed-transaction metadata",
                    receipt.id
                ),
            );
        };
        let Some(bound) = governed.runtime_assurance else {
            return facet(
                FindingFacetKind::RuntimeAssuranceBacking,
                FindingFacetOutcome::Failed,
                format!("receipt {} has no runtime-assurance binding", receipt.id),
            );
        };
        if bound.schema != verified.evidence_schema()
            || bound.verifier_family != Some(verified.verifier_family())
            || bound.tier != verified.effective_tier()
            || bound.verifier != verified.canonical_verifier()
            || bound.evidence_sha256 != verified.evidence_sha256()
            || bound.workload_identity.as_ref() != verified.workload_identity()
        {
            return facet(
                FindingFacetKind::RuntimeAssuranceBacking,
                FindingFacetOutcome::Failed,
                format!(
                    "receipt {} runtime-assurance binding does not match the signed evidence",
                    receipt.id
                ),
            );
        }
    }

    let mut result = facet(
        FindingFacetKind::RuntimeAssuranceBacking,
        FindingFacetOutcome::Verified,
        "signed attestation and appraisal match every producing receipt",
    );
    if let Ok(digest) = signed_envelope_sha256(attestation) {
        result.evidence_refs.push(digest);
    }
    if let Ok(digest) = signed_envelope_sha256(appraisal) {
        result.evidence_refs.push(digest);
    }
    result
}

fn evaluate_guarantee_consistency(
    finding: &Finding,
    artifact_ok: bool,
    facets: &[FindingFacetResult],
) -> FindingFacetResult {
    if !artifact_ok {
        return facet(
            FindingFacetKind::GuaranteeConsistency,
            FindingFacetOutcome::Failed,
            "artifact integrity failed",
        );
    }
    let outcome_of = |kind: FindingFacetKind| {
        facets
            .iter()
            .find(|result| result.facet == kind)
            .map(|result| result.outcome)
    };
    // A deterministic-replay guarantee is consistent only when the recipe
    // facet verified; a verified evidence class is consistent only when
    // receipts and membership verified. Weaker claims are consistent by
    // construction; nothing upgrades.
    if finding.guarantee_class == FindingGuaranteeClass::DeterministicReplay
        && outcome_of(FindingFacetKind::RecipeBinding) != Some(FindingFacetOutcome::Verified)
    {
        return facet(
            FindingFacetKind::GuaranteeConsistency,
            FindingFacetOutcome::Failed,
            "deterministic_replay claimed without a verified recipe binding",
        );
    }
    // A metered_attested guarantee asserts that execution and cost were
    // attested by mediated receipts, so it needs the same receipt and
    // membership backing plus a kernel-accounted cost floor. Without
    // this, the strongest non-replay guarantee is the cheapest to claim.
    if finding.guarantee_class == FindingGuaranteeClass::MeteredAttested
        && (outcome_of(FindingFacetKind::ReceiptAuthenticity)
            != Some(FindingFacetOutcome::Verified)
            || outcome_of(FindingFacetKind::CheckpointMembership)
                != Some(FindingFacetOutcome::Verified)
            || outcome_of(FindingFacetKind::MeteredExposureBacking)
                != Some(FindingFacetOutcome::Verified))
    {
        return facet(
            FindingFacetKind::GuaranteeConsistency,
            FindingFacetOutcome::Failed,
            "metered_attested claimed without verified receipts, membership, and metered exposure",
        );
    }
    // Observed and verified evidence classes both assert that the
    // referenced receipts are real and checkpointed; only asserted is
    // free.
    if matches!(
        finding.evidence_class,
        FindingEvidenceClass::Verified | FindingEvidenceClass::Observed
    ) && (outcome_of(FindingFacetKind::ReceiptAuthenticity)
        != Some(FindingFacetOutcome::Verified)
        || outcome_of(FindingFacetKind::CheckpointMembership)
            != Some(FindingFacetOutcome::Verified))
    {
        return facet(
            FindingFacetKind::GuaranteeConsistency,
            FindingFacetOutcome::Failed,
            "evidence class claims receipts that are not verified and checkpoint-bound",
        );
    }
    // A positively failed facet is never consistent, whatever it is.
    if facets
        .iter()
        .any(|result| result.outcome == FindingFacetOutcome::Failed)
    {
        return facet(
            FindingFacetKind::GuaranteeConsistency,
            FindingFacetOutcome::Failed,
            "at least one evaluated facet failed",
        );
    }
    facet(
        FindingFacetKind::GuaranteeConsistency,
        FindingFacetOutcome::Verified,
        "claims are consistent with the evaluated facets",
    )
}

fn bundle_digest(
    bundle: &FindingEvidenceBundle<'_>,
    trust: &FindingVerifierTrustRoots,
) -> Result<String, FindingVerifierError> {
    // Content commitment over the resolved inputs: receipt bytes,
    // checkpoints, recipe preimage, and backing envelope digest inputs,
    // in deterministic order.
    #[derive(serde::Serialize)]
    struct BundleCommitment<'a> {
        receipt_sha256s: Vec<String>,
        execution_nonce_envelope_sha256s: Vec<String>,
        inclusion_proof_sha256s: Vec<String>,
        checkpoint_sha256s: Vec<String>,
        checkpoint_transparency_sha256: String,
        checkpoint_signer_status_sha256s: Vec<String>,
        checkpoint_status_authority: Option<String>,
        checkpoint_status_max_age_secs: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        finding_delivery_execution_nonce_envelope_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        finding_delivery_receipt_sha256: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        finding_delivery_inclusion_proof_sha256: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        finding_delivery_checkpoint_sha256s: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        finding_delivery_checkpoint_transparency_sha256: Option<String>,
        recipe_sha256: Option<String>,
        status_proof_sha256: Option<String>,
        status_operator_authorization_sha256: Option<String>,
        status_freshness_policy_sha256: Option<String>,
        runtime_attestation_sha256: Option<String>,
        runtime_appraisal_sha256: Option<String>,
        runtime_attestation_authority: Option<String>,
        appraisal_authority: Option<String>,
        attestation_trust_policy_sha256: Option<String>,
        backing_allocation_id: Option<&'a str>,
        backing_envelope_sha256: Option<String>,
        fee_schedule_envelope_sha256: Option<String>,
        backing_store_snapshot_envelope_sha256: Option<String>,
    }
    let receipt_sha256s = bundle
        .receipts
        .iter()
        .map(|evidence| sha256_hex(&evidence.canonical_receipt_bytes))
        .collect();
    let mut execution_nonce_envelope_sha256s = Vec::new();
    for evidence in &bundle.receipts {
        if let Some(nonce) = bundle.nonce_resolver.nonce_for(&evidence.receipt) {
            let bytes =
                canonical_json_bytes(nonce).map_err(|_| FindingVerifierError::Canonicalization)?;
            execution_nonce_envelope_sha256s.push(sha256_hex(&bytes));
        }
    }
    let finding_delivery_execution_nonce_envelope_sha256 = bundle
        .finding_delivery
        .as_ref()
        .and_then(|delivery| bundle.nonce_resolver.nonce_for(&delivery.receipt.receipt))
        .map(canonical_json_bytes)
        .transpose()
        .map_err(|_| FindingVerifierError::Canonicalization)?
        .map(|bytes| sha256_hex(&bytes));
    let mut checkpoint_sha256s = Vec::with_capacity(bundle.checkpoints.len());
    for checkpoint in &bundle.checkpoints {
        let bytes =
            canonical_json_bytes(checkpoint).map_err(|_| FindingVerifierError::Canonicalization)?;
        checkpoint_sha256s.push(sha256_hex(&bytes));
    }
    let checkpoint_transparency_bytes = canonical_json_bytes(&bundle.checkpoint_transparency)
        .map_err(|_| FindingVerifierError::Canonicalization)?;
    let mut checkpoint_signer_status_sha256s = trust
        .checkpoint_signer_status
        .as_ref()
        .map(|status_trust| {
            status_trust
                .signed_statuses
                .iter()
                .map(signed_envelope_sha256)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|_| FindingVerifierError::Canonicalization)?
        .unwrap_or_default();
    checkpoint_signer_status_sha256s.sort();
    let mut inclusion_proof_sha256s = Vec::with_capacity(bundle.receipts.len());
    for evidence in &bundle.receipts {
        let bytes = canonical_json_bytes(&evidence.inclusion_proof)
            .map_err(|_| FindingVerifierError::Canonicalization)?;
        inclusion_proof_sha256s.push(sha256_hex(&bytes));
    }
    let (
        finding_delivery_receipt_sha256,
        finding_delivery_inclusion_proof_sha256,
        finding_delivery_checkpoint_sha256s,
        finding_delivery_checkpoint_transparency_sha256,
    ) = match bundle.finding_delivery.as_ref() {
        Some(delivery) => {
            let proof_bytes = canonical_json_bytes(&delivery.receipt.inclusion_proof)
                .map_err(|_| FindingVerifierError::Canonicalization)?;
            let mut checkpoint_digests = Vec::with_capacity(delivery.checkpoints.len());
            for checkpoint in &delivery.checkpoints {
                let bytes = canonical_json_bytes(checkpoint)
                    .map_err(|_| FindingVerifierError::Canonicalization)?;
                checkpoint_digests.push(sha256_hex(&bytes));
            }
            let transparency_bytes = canonical_json_bytes(&delivery.checkpoint_transparency)
                .map_err(|_| FindingVerifierError::Canonicalization)?;
            (
                Some(sha256_hex(&delivery.receipt.canonical_receipt_bytes)),
                Some(sha256_hex(&proof_bytes)),
                checkpoint_digests,
                Some(sha256_hex(&transparency_bytes)),
            )
        }
        None => (None, None, Vec::new(), None),
    };
    let backing_envelope_sha256 = match bundle.bond_snapshot.as_ref() {
        Some(snapshot) => {
            let bytes = canonical_json_bytes(&snapshot.backing)
                .map_err(|_| FindingVerifierError::Canonicalization)?;
            Some(sha256_hex(&bytes))
        }
        None => None,
    };
    let backing_store_snapshot_envelope_sha256 = bundle
        .bond_snapshot
        .as_ref()
        .map(|snapshot| signed_envelope_sha256(&snapshot.store_snapshot))
        .transpose()
        .map_err(|_| FindingVerifierError::Canonicalization)?;
    let fee_schedule_envelope_sha256 = bundle
        .bond_snapshot
        .as_ref()
        .map(|snapshot| signed_envelope_sha256(&snapshot.fee_schedule))
        .transpose()
        .map_err(|_| FindingVerifierError::Canonicalization)?;
    let status_operator_authorization_sha256 = trust
        .status_operator_authorization
        .as_ref()
        .map(canonical_json_bytes)
        .transpose()
        .map_err(|_| FindingVerifierError::Canonicalization)?
        .map(|bytes| sha256_hex(&bytes));
    let status_freshness_policy_sha256 = trust
        .status_freshness_policy
        .map(|policy| {
            canonical_json_bytes(&serde_json::json!({
                "max_epoch_age_secs": policy.max_epoch_age_secs,
                "now": policy.now,
            }))
        })
        .transpose()
        .map_err(|_| FindingVerifierError::Canonicalization)?
        .map(|bytes| sha256_hex(&bytes));
    let commitment = BundleCommitment {
        receipt_sha256s,
        execution_nonce_envelope_sha256s,
        inclusion_proof_sha256s,
        checkpoint_sha256s,
        checkpoint_transparency_sha256: sha256_hex(&checkpoint_transparency_bytes),
        checkpoint_signer_status_sha256s,
        checkpoint_status_authority: trust
            .checkpoint_signer_status
            .as_ref()
            .map(|status| status.status_authority.to_hex()),
        checkpoint_status_max_age_secs: trust
            .checkpoint_signer_status
            .as_ref()
            .map(|status| status.max_age_secs),
        finding_delivery_execution_nonce_envelope_sha256,
        finding_delivery_receipt_sha256,
        finding_delivery_inclusion_proof_sha256,
        finding_delivery_checkpoint_sha256s,
        finding_delivery_checkpoint_transparency_sha256,
        recipe_sha256: bundle.recipe_preimage.map(sha256_hex),
        status_proof_sha256: bundle.status_proof_input.map(sha256_hex),
        status_operator_authorization_sha256,
        status_freshness_policy_sha256,
        runtime_attestation_sha256: bundle
            .runtime_attestation
            .as_ref()
            .map(signed_envelope_sha256)
            .transpose()
            .map_err(|_| FindingVerifierError::Canonicalization)?,
        runtime_appraisal_sha256: bundle
            .runtime_appraisal
            .as_ref()
            .map(signed_envelope_sha256)
            .transpose()
            .map_err(|_| FindingVerifierError::Canonicalization)?,
        runtime_attestation_authority: trust
            .runtime_attestation_authority
            .as_ref()
            .map(PublicKey::to_hex),
        appraisal_authority: trust.appraisal_authority.as_ref().map(PublicKey::to_hex),
        attestation_trust_policy_sha256: trust
            .attestation_trust_policy
            .as_ref()
            .map(canonical_json_bytes)
            .transpose()
            .map_err(|_| FindingVerifierError::Canonicalization)?
            .map(|bytes| sha256_hex(&bytes)),
        backing_allocation_id: bundle
            .bond_snapshot
            .as_ref()
            .map(|snapshot| snapshot.backing.body.allocation_id.as_str()),
        backing_envelope_sha256,
        fee_schedule_envelope_sha256,
        backing_store_snapshot_envelope_sha256,
    };
    let bytes =
        canonical_json_bytes(&commitment).map_err(|_| FindingVerifierError::Canonicalization)?;
    Ok(sha256_hex(&bytes))
}

/// Build and sign the `chio.finding.verifier-report.v1` envelope from a
/// draft. The signing keypair must BE the profile-authorized verifier
/// authority; the body names it and the envelope signer must equal it.
pub fn sign_finding_verifier_report(
    draft: &FindingVerifierDraft,
    trust: &FindingVerifierTrustRoots,
    verifier_implementation_id: &str,
    verifier_keypair: &Keypair,
) -> Result<SignedFindingVerifierReport, FindingVerifierError> {
    let profile = &trust.profile.body;
    let profile_envelope_bytes =
        canonical_json_bytes(&trust.profile).map_err(|_| FindingVerifierError::Canonicalization)?;
    let profile_envelope_sha256 = sha256_hex(&profile_envelope_bytes);
    if profile_envelope_sha256 != draft.verifier_profile_envelope_sha256 {
        return Err(FindingVerifierError::ReportProfileMismatch);
    }
    if verifier_keypair.public_key() != profile.verifier_report_signer.key {
        return Err(FindingVerifierError::ReportSignerMismatch);
    }
    if !policy_covers(&profile.verifier_report_signer, draft.evaluation_time) {
        return Err(FindingVerifierError::ReportSignerInactive);
    }
    let mut report = FindingVerifierReport {
        schema: FINDING_VERIFIER_REPORT_SCHEMA_V1.to_string(),
        report_id: String::new(),
        finding_id: draft.finding.finding_id.clone(),
        finding_artifact_sha256: draft.finding_artifact_sha256.clone(),
        verifier_profile_id: profile.profile_id.clone(),
        verifier_profile_envelope_sha256: profile_envelope_sha256,
        verifier_implementation_id: verifier_implementation_id.to_string(),
        resolved_evidence_bundle_sha256: draft.resolved_evidence_bundle_sha256.clone(),
        replay_recipe_input_sha256: draft.replay_recipe_input_sha256.clone(),
        status_proof_input_sha256: draft.status_proof_input_sha256.clone(),
        finding_delivery_receipt_id: draft.finding_delivery_receipt_id.clone(),
        trust_root_snapshot_sha256: draft.trust_root_snapshot_sha256.clone(),
        resolver_policy_sha256: draft.resolver_policy_sha256.clone(),
        trusted_time_input_sha256: draft.trusted_time_input_sha256.clone(),
        facets: draft.facets.clone(),
        backing_allocation_id: draft.backing_allocation_id.clone(),
        verifier_authority: profile.verifier_report_signer.key.clone(),
        verifier_key_epoch: profile.verifier_report_signer.key_epoch,
        evaluation_time: draft.evaluation_time,
    };
    report.report_id =
        compute_report_id(&report).map_err(|_| FindingVerifierError::Canonicalization)?;
    report
        .validate()
        .map_err(|_| FindingVerifierError::ReportSigning)?;
    SignedExportEnvelope::sign(report, verifier_keypair)
        .map_err(|_| FindingVerifierError::ReportSigning)
}
