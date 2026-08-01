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
use chio_core_types::receipt::body::{chio_receipt_id, ChioReceipt};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_report_id, signed_envelope_sha256, verify_finding, verify_pinned_envelope,
    verify_signed_bond_backing, verify_signed_profile, Finding, FindingChallengeVerifierProfile,
    FindingEvidenceClass, FindingFacetKind, FindingFacetOutcome, FindingFacetResult,
    FindingGuaranteeClass, FindingPredicate, FindingReceiptRole, FindingReplayRecipeInput,
    FindingVerifierReport, SignedFindingBondBacking, SignedFindingChallengeVerifierProfile,
    SignedFindingVerifierReport,
    FINDING_VERIFIER_REPORT_SCHEMA_V1,
};
use chio_kernel::checkpoint::{
    CheckpointTransparencySummary, KernelCheckpoint, ReceiptInclusionProof,
};

use crate::checkpoints::verify_checkpoint_membership;
use crate::cost::FindingNonceResolver;
use crate::cost::{evaluate_metered_exposure, evaluate_settled_spend, CostFacetOutcome};
use crate::receipts::verify_receipt_strict;

/// Size bound on the raw finding submitted to the verifier. Matches the
/// publish surface's route-level cap so both boundaries reject the same
/// inputs.
pub const MAX_RAW_FINDING_BYTES: usize = 256 * 1024;

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
    #[error("no admitted kernel keys configured")]
    NoAdmittedKernelKeys,
    #[error("report body construction failed canonicalization")]
    Canonicalization,
    #[error("report signer does not match the pinned verifier authority")]
    ReportSignerMismatch,
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

/// Fresh authority view of the named collateral allocation, resolved by
/// the caller from the venue collateral store immediately before
/// evaluation. A stale or absent snapshot reports bond backing
/// unavailable, never verified.
pub struct FindingBondSnapshot {
    /// The collateral-authority-signed allocation envelope. The body
    /// alone is a seller-supplied assertion; only the signature under the
    /// pinned authority makes it evidence.
    pub backing: SignedFindingBondBacking,
    /// Store state: live and unconsumed right now.
    pub live: bool,
    /// Venue trusted time when the collateral authority registered the
    /// allocation (the report-before-backing comparison input).
    pub accepted_at: u64,
}

/// The resolved evidence bundle. Resolution happens at the owning
/// surface; absent members degrade the matching facets to unavailable.
pub struct FindingEvidenceBundle<'a> {
    pub receipts: Vec<ResolvedReceiptEvidence>,
    pub checkpoints: Vec<KernelCheckpoint>,
    /// Transparency records resolved with the checkpoint set. These are
    /// re-derived and compared before any checkpoint can back a facet.
    pub checkpoint_transparency: CheckpointTransparencySummary,
    /// Raw replay-recipe preimage bytes, when the finding commits one.
    pub recipe_preimage: Option<&'a [u8]>,
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
    if trust.admitted_kernel_keys.is_empty() {
        return Err(FindingVerifierError::NoAdmittedKernelKeys);
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
    // equality; a set comparison would admit reorderings).
    let receipt_authenticity = if bundle.receipts.is_empty() {
        facet(
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetOutcome::Unavailable,
            "no evidence receipts resolved",
        )
    } else {
        let mut failure: Option<String> = None;
        let mut recomputed_ids = Vec::with_capacity(bundle.receipts.len());
        // The profile pins which kernel keys may sign production
        // evidence. Strict self-verification proves the bytes are
        // internally authentic; only this set makes them trusted.
        let production_signers: Vec<&PublicKey> = profile
            .receipt_signers
            .iter()
            .filter(|signer| signer.role == FindingReceiptRole::Production)
            .map(|signer| &signer.policy.key)
            .collect();
        if bundle.receipts.len() as u64 > profile.resource_caps.max_evidence_receipts {
            failure = Some("evidence receipt count exceeds the profile cap".to_string());
        }
        for evidence in &bundle.receipts {
            if failure.is_some() {
                break;
            }
            if let Err(error) = verify_receipt_strict(&evidence.receipt) {
                failure = Some(format!("receipt {}: {error}", evidence.receipt.id));
                break;
            }
            if !production_signers
                .iter()
                .any(|pinned| **pinned == evidence.receipt.kernel_key)
            {
                failure = Some(format!(
                    "receipt {} is signed by a key the profile does not pin as a production signer",
                    evidence.receipt.id
                ));
                break;
            }
            // The canonical bytes supplied as the leaf must BE the bytes
            // of this receipt, or membership would prove a different
            // projection than the one verified here.
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
        if failure.is_none() && recomputed_ids != finding.evidence_receipt_ids {
            failure = Some(
                "recomputed receipt ids do not equal evidence_receipt_ids in order and cardinality"
                    .to_string(),
            );
        }
        match failure {
            None => facet(
                FindingFacetKind::ReceiptAuthenticity,
                FindingFacetOutcome::Verified,
                "every evidence receipt verified strictly and binds in order",
            ),
            Some(reason) => facet(
                FindingFacetKind::ReceiptAuthenticity,
                FindingFacetOutcome::Failed,
                reason,
            ),
        }
    };
    let receipts_ok = receipt_authenticity.outcome == FindingFacetOutcome::Verified;
    facets.push(receipt_authenticity);

    // Step 3: checkpoint membership with the full wrapper cross-check.
    let checkpoint_membership = if bundle.receipts.is_empty() {
        facet(
            FindingFacetKind::CheckpointMembership,
            FindingFacetOutcome::Unavailable,
            "no evidence receipts resolved",
        )
    } else if !receipts_ok {
        facet(
            FindingFacetKind::CheckpointMembership,
            FindingFacetOutcome::Failed,
            "receipts did not verify; membership not evaluated",
        )
    } else {
        match verify_checkpoint_membership(
            &bundle.receipts,
            &bundle.checkpoints,
            &bundle.checkpoint_transparency,
            profile,
            &finding.evidence_checkpoint_ref,
        ) {
            Ok(()) => facet(
                FindingFacetKind::CheckpointMembership,
                FindingFacetOutcome::Verified,
                "every receipt is a member of a pinned, signature-valid checkpoint",
            ),
            Err(error) => facet(
                FindingFacetKind::CheckpointMembership,
                FindingFacetOutcome::Failed,
                format!("membership failed: {error}"),
            ),
        }
    };
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
    let receipts: Vec<&ChioReceipt> = bundle
        .receipts
        .iter()
        .map(|evidence| &evidence.receipt)
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
        receipts_ok,
    ));

    // Step 7 / facet 11: bond backing against the fresh store snapshot.
    let (bond_backing, backing_allocation_id) = evaluate_bond_backing(&finding, trust, bundle);
    facets.push(bond_backing);

    // Facet 12: status liveness. Callers supply no portable sparse
    // non-inclusion proof; an authenticated online status observation is
    // a venue configuration concern, not evidence this verifier resolves.
    facets.push(facet(
        FindingFacetKind::StatusLiveness,
        FindingFacetOutcome::Unavailable,
        "portable status non-inclusion proof not supplied",
    ));

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
        evaluation_time: trust.trusted_time,
        backing_allocation_id,
    })
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
    if !snapshot.live {
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
    if !receipts_ok || bundle.receipts.is_empty() {
        return facet(
            FindingFacetKind::RuntimeAssuranceBacking,
            FindingFacetOutcome::Unavailable,
            "producing receipts are not available as verified linkage evidence",
        );
    }
    for evidence in &bundle.receipts {
        let receipt = &evidence.receipt;
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
        inclusion_proof_sha256s: Vec<String>,
        checkpoint_sha256s: Vec<String>,
        checkpoint_transparency_sha256: String,
        recipe_sha256: Option<String>,
        runtime_attestation_sha256: Option<String>,
        runtime_appraisal_sha256: Option<String>,
        runtime_attestation_authority: Option<String>,
        appraisal_authority: Option<String>,
        attestation_trust_policy_sha256: Option<String>,
        backing_allocation_id: Option<&'a str>,
        backing_envelope_sha256: Option<String>,
        backing_live: Option<bool>,
        backing_accepted_at: Option<u64>,
    }
    let receipt_sha256s = bundle
        .receipts
        .iter()
        .map(|evidence| sha256_hex(&evidence.canonical_receipt_bytes))
        .collect();
    let mut checkpoint_sha256s = Vec::with_capacity(bundle.checkpoints.len());
    for checkpoint in &bundle.checkpoints {
        let bytes =
            canonical_json_bytes(checkpoint).map_err(|_| FindingVerifierError::Canonicalization)?;
        checkpoint_sha256s.push(sha256_hex(&bytes));
    }
    let checkpoint_transparency_bytes = canonical_json_bytes(&bundle.checkpoint_transparency)
        .map_err(|_| FindingVerifierError::Canonicalization)?;
    let mut inclusion_proof_sha256s = Vec::with_capacity(bundle.receipts.len());
    for evidence in &bundle.receipts {
        let bytes = canonical_json_bytes(&evidence.inclusion_proof)
            .map_err(|_| FindingVerifierError::Canonicalization)?;
        inclusion_proof_sha256s.push(sha256_hex(&bytes));
    }
    let backing_envelope_sha256 = match bundle.bond_snapshot.as_ref() {
        Some(snapshot) => {
            let bytes = canonical_json_bytes(&snapshot.backing)
                .map_err(|_| FindingVerifierError::Canonicalization)?;
            Some(sha256_hex(&bytes))
        }
        None => None,
    };
    let commitment = BundleCommitment {
        receipt_sha256s,
        inclusion_proof_sha256s,
        checkpoint_sha256s,
        checkpoint_transparency_sha256: sha256_hex(&checkpoint_transparency_bytes),
        recipe_sha256: bundle.recipe_preimage.map(sha256_hex),
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
        backing_live: bundle.bond_snapshot.as_ref().map(|snapshot| snapshot.live),
        backing_accepted_at: bundle
            .bond_snapshot
            .as_ref()
            .map(|snapshot| snapshot.accepted_at),
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
    if verifier_keypair.public_key() != profile.verifier_report_signer.key {
        return Err(FindingVerifierError::ReportSignerMismatch);
    }
    let profile_envelope_bytes =
        canonical_json_bytes(&trust.profile).map_err(|_| FindingVerifierError::Canonicalization)?;
    let mut report = FindingVerifierReport {
        schema: FINDING_VERIFIER_REPORT_SCHEMA_V1.to_string(),
        report_id: String::new(),
        finding_id: draft.finding.finding_id.clone(),
        finding_artifact_sha256: draft.finding_artifact_sha256.clone(),
        verifier_profile_id: profile.profile_id.clone(),
        verifier_profile_envelope_sha256: sha256_hex(&profile_envelope_bytes),
        verifier_implementation_id: verifier_implementation_id.to_string(),
        resolved_evidence_bundle_sha256: draft.resolved_evidence_bundle_sha256.clone(),
        trust_root_snapshot_sha256: trust.trust_root_snapshot_sha256.clone(),
        resolver_policy_sha256: trust.resolver_policy_sha256.clone(),
        trusted_time_input_sha256: trust.trusted_time_input_sha256.clone(),
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
