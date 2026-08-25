//! Verified-fix package authoring and reference verification for the local
//! cognition-market operator.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::merkle::MerkleTree;
use chio_core::message::{ExecutionNonce, NonceBinding, SignedExecutionNonce};
use chio_core::receipt::authoritative_spend::BudgetAuthorityReceiptRef;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use chio_core::receipt::kinds::TrustLevel;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    compute_admission_id, compute_allocation_id, compute_authorization_id, compute_finding_id,
    compute_profile_id, compute_terms_id, sign_finding, Finding, FindingAdmission,
    FindingAuthorityKeyPolicy, FindingAuthorityStatus, FindingBackingRequirement,
    FindingBbsIssuerPolicy, FindingBondBacking, FindingBondClass, FindingChallengeBondLimit,
    FindingChallengeVerifierProfile, FindingCheckpointLogPolicy, FindingClaimedVerdict,
    FindingCollateralVault, FindingDescriptor, FindingEvidenceClass, FindingFacetKind,
    FindingFeeEvent, FindingFeeTerminalBinding, FindingGuaranteeClass, FindingMarketTerms,
    FindingOutcomeClass, FindingPayee, FindingPoolBinding, FindingPredicate, FindingReceiptRole,
    FindingReceiptSignerRole, FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind,
    FindingReplayRecipeInput, FindingResourceCaps, FindingSellerAuthorization,
    SignedFindingAdmission, SignedFindingAuthorityStatus, SignedFindingBondBacking,
    SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms,
    SignedFindingSellerAuthorization, FINDING_ADMISSION_SCHEMA_V1,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1, FINDING_BOND_BACKING_SCHEMA_V1,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_MARKET_TERMS_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1,
    FINDING_SELLER_AUTHORIZATION_SCHEMA_V1,
};
use chio_finding_verifier::{
    sign_finding_verifier_report, verify_finding_evidence, FindingBondSnapshot,
    FindingBondStoreSnapshot, FindingCheckpointSignerStatusTrust, FindingEvidenceBundle,
    FindingNonceResolver, FindingVerifierTrustRoots, ResolvedReceiptEvidence,
    SignedFindingBondStoreSnapshot, FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1,
};
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_inclusion_proof, checkpoint_log_id,
    KernelCheckpoint, ReceiptInclusionProof,
};
use chio_open_market::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleIssueRequest,
    SignedOpenMarketFeeSchedule,
};
use chio_open_market::fiscal_adapter::signed_fee_schedule_digest;
use chio_open_market::listing::{
    GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
    GenericListingCompatibilityReference, GenericListingFreshnessState,
    GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
    GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole, Listing,
    ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
    GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
};
use chio_store_sqlite::finding_market_store::finding_fee_idempotency_key;
use serde::{Deserialize, Serialize};

use super::finding_operator_bundle::{FindingOperatorBundle, FINDING_OPERATOR_BUNDLE_SCHEMA};
use super::finding_operator_profile::{
    FindingOperatorAuthoringKeys, FindingOperatorProfile, FindingOperatorSellerProfile,
};
use super::FindingAuthorityPin;

pub const VERIFIED_FIX_DRAFT_SCHEMA: &str = "chio.finding.verified-fix-draft.v1";
pub const FINDING_OPERATOR_PROOF_BUNDLE_SCHEMA: &str = "chio.finding.operator-proof-bundle.v1";
pub const VERIFIED_FIX_PAYLOAD_SCHEMA: &str = "chio.finding.verified-fix-payload.v1";
pub const VERIFIED_FIX_MEDIA_TYPE: &str = "application/vnd.chio.verified-fix+json";

const SERVER_ID: &str = "finding-server.local";
const CURRENCY: &str = "USD";
const PUBLICATION_FEE_UNITS: u64 = 5;
const PARTICIPATION_FEE_UNITS: u64 = 3;
const STAKE_UNITS: u64 = 50;
pub const VERIFIED_FIX_MAXIMUM_SALE_EXPOSURE_UNITS: u64 = 450;
const LOCKED_UNITS: u64 = 500;
const REQUIREMENT_UNITS: u64 = 5_000;
const DISPUTE_BOND_UNITS: u64 = 10;
const ARTIFACT_LIFETIME_SECS: u64 = 180 * 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedFixCommandResult {
    pub command: String,
    pub exit_code: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub duration_millis: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedFixPayload {
    pub schema: String,
    pub repository: String,
    pub base_revision: String,
    pub candidate_revision: String,
    pub patch: String,
    pub baseline: Vec<VerifiedFixCommandResult>,
    pub candidate: Vec<VerifiedFixCommandResult>,
}

#[derive(Clone, Debug)]
pub struct VerifiedFixAuthoringInput {
    pub seller_principal: String,
    pub repository: String,
    pub base_revision: String,
    pub candidate_revision: String,
    pub topic: String,
    pub patch: String,
    pub baseline: Vec<VerifiedFixCommandResult>,
    pub candidate: Vec<VerifiedFixCommandResult>,
    pub runner_manifest: Vec<u8>,
    pub runtime_fingerprint: Vec<u8>,
    pub price_units: u64,
    pub issued_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorRecipeBlob {
    pub sha256: String,
    pub bytes_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorReceiptEvidence {
    pub receipt: ChioReceipt,
    pub canonical_receipt_b64: String,
    pub inclusion_proof: ReceiptInclusionProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingVerifiedFixDraft {
    pub schema: String,
    pub finding: Finding,
    pub listing: Listing,
    pub market_terms: SignedFindingMarketTerms,
    pub seller_authorization: SignedFindingSellerAuthorization,
    pub verifier_profile: SignedFindingChallengeVerifierProfile,
    pub bond_backing: SignedFindingBondBacking,
    pub fee_schedule: SignedOpenMarketFeeSchedule,
    pub payload_b64: String,
    pub replay_recipe_b64: String,
    pub recipe_blobs: Vec<FindingOperatorRecipeBlob>,
    pub evidence_receipts: Vec<FindingOperatorReceiptEvidence>,
    pub evidence_checkpoint: KernelCheckpoint,
    pub execution_nonces: Vec<SignedExecutionNonce>,
    pub trust_root_snapshot_sha256: String,
    pub resolver_policy_sha256: String,
    pub trusted_time_source_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorProofBundle {
    pub schema: String,
    pub bundle: FindingOperatorBundle,
    pub evidence_receipts: Vec<FindingOperatorReceiptEvidence>,
    pub evidence_checkpoint: KernelCheckpoint,
    pub execution_nonces: Vec<SignedExecutionNonce>,
    pub replay_recipe_b64: String,
    pub checkpoint_signer_status: FindingCheckpointSignerStatusTrust,
    pub bond_store_snapshot: SignedFindingBondStoreSnapshot,
    pub trust_root_snapshot_sha256: String,
    pub resolver_policy_sha256: String,
    pub trusted_time_source_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_proof_input_b64: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FindingOperatorFinalization {
    pub bundle: FindingOperatorBundle,
    pub proof: FindingOperatorProofBundle,
}

impl FindingVerifiedFixDraft {
    pub fn author(
        profile: &FindingOperatorProfile,
        input: VerifiedFixAuthoringInput,
    ) -> Result<Self, String> {
        profile.validate()?;
        validate_authoring_input(&input)?;
        let seller = profile.seller(&input.seller_principal)?;
        let keys = profile.authoring_keys()?;
        let expires_at = input
            .issued_at
            .checked_add(ARTIFACT_LIFETIME_SECS)
            .ok_or_else(|| "verified-fix artifact lifetime overflowed".to_owned())?;
        if expires_at >= profile.market.venue.valid_until {
            return Err(
                "operator authority window is too short for a verified-fix package".to_owned(),
            );
        }

        let payload = VerifiedFixPayload {
            schema: VERIFIED_FIX_PAYLOAD_SCHEMA.to_owned(),
            repository: input.repository.clone(),
            base_revision: input.base_revision.clone(),
            candidate_revision: input.candidate_revision.clone(),
            patch: input.patch,
            baseline: input.baseline,
            candidate: input.candidate,
        };
        let payload_bytes = canonical_json_bytes(&payload).map_err(string_error)?;
        let payload_sha256 =
            chio_finding::finding_payload_sha256(VERIFIED_FIX_MEDIA_TYPE, &payload_bytes)
                .map_err(string_error)?;
        let context_bytes = canonical_json_bytes(&serde_json::json!({
            "baseRevision": input.base_revision,
            "candidateRevision": input.candidate_revision,
            "repository": input.repository,
        }))
        .map_err(string_error)?;
        let context_sha256 = sha256_hex(&context_bytes);

        let checkpoint_key = Keypair::generate();
        let dependencies =
            recipe_dependencies(&payload, input.runner_manifest, input.runtime_fingerprint)?;
        let verifier_profile = build_profile(
            profile,
            &keys,
            &checkpoint_key,
            &dependencies.runner_manifest_sha256,
            input.issued_at,
            expires_at,
        )?;
        let profile_sha256 = digest(&verifier_profile)?;
        let recipe = build_recipe(
            &profile_sha256,
            &context_sha256,
            &payload_sha256,
            &dependencies,
        );
        let replay_recipe = canonical_json_bytes(&recipe).map_err(string_error)?;
        let replay_recipe_sha256 = sha256_hex(&replay_recipe);

        let receipts = build_evidence_receipts(&keys.production_kernel, input.issued_at, &payload)?;
        let receipt_bytes = receipts
            .iter()
            .map(|receipt| canonical_json_bytes(receipt).map_err(string_error))
            .collect::<Result<Vec<_>, _>>()?;
        let tree = MerkleTree::from_leaves(&receipt_bytes).map_err(string_error)?;
        let checkpoint = build_checkpoint(
            1,
            1,
            u64::try_from(receipts.len()).map_err(string_error)?,
            &receipt_bytes,
            &checkpoint_key,
        )
        .map_err(string_error)?;
        let checkpoint_ref = format!("{}#1", checkpoint_log_id(&checkpoint));
        let evidence_receipts = receipts
            .iter()
            .zip(receipt_bytes.iter())
            .enumerate()
            .map(|(index, (receipt, bytes))| {
                Ok(FindingOperatorReceiptEvidence {
                    receipt: receipt.clone(),
                    canonical_receipt_b64: STANDARD.encode(bytes),
                    inclusion_proof: build_inclusion_proof(
                        &tree,
                        index,
                        1,
                        u64::try_from(index + 1).map_err(string_error)?,
                    )
                    .map_err(string_error)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let execution_nonces = receipts
            .iter()
            .map(|receipt| signed_nonce(receipt, &keys.production_kernel))
            .collect::<Result<Vec<_>, _>>()?;

        let finding = build_finding(
            seller,
            &context_sha256,
            &payload_sha256,
            &replay_recipe_sha256,
            &receipts,
            &checkpoint_ref,
            &profile.market.status_feed_operator.feed_id,
            &input.topic,
            input.issued_at,
            expires_at,
        )?;
        let finding_sha256 = digest(&finding)?;
        let listing_id = format!("finding-{}", &finding.finding_id[..24]);
        let fee_schedule =
            build_fee_schedule(profile, &keys.fee_schedule_operator, input.issued_at)?;
        let schedule_sha256 = signed_fee_schedule_digest(&fee_schedule).map_err(string_error)?;
        let market_terms = build_terms(
            seller,
            &finding,
            &finding_sha256,
            &listing_id,
            &profile_sha256,
            input.issued_at,
            expires_at,
        )?;
        let terms_sha256 = digest(&market_terms)?;
        let seller_authorization = build_seller_authorization(
            seller,
            &finding,
            &finding_sha256,
            &listing_id,
            input.issued_at,
            expires_at,
        )?;
        let authorization_sha256 = digest(&seller_authorization)?;
        let bond_backing = build_backing(
            seller,
            &keys.collateral,
            &finding,
            &listing_id,
            &fee_schedule,
            &authorization_sha256,
            &terms_sha256,
            &profile_sha256,
            &schedule_sha256,
            input.issued_at,
            expires_at,
        )?;
        let listing = build_listing(
            profile,
            &keys.listing,
            &finding,
            &listing_id,
            input.price_units,
            input.issued_at,
            expires_at,
        )?;
        let trust_root_snapshot_sha256 = digest(&profile.market)?;
        let resolver_policy_sha256 = sha256_hex(b"chio.finding.operator-local-resolver.v1");
        let trusted_time_source_sha256 = sha256_hex(b"chio.finding.operator-system-clock.v1");

        Ok(Self {
            schema: VERIFIED_FIX_DRAFT_SCHEMA.to_owned(),
            finding,
            listing,
            market_terms,
            seller_authorization,
            verifier_profile,
            bond_backing,
            fee_schedule,
            payload_b64: STANDARD.encode(payload_bytes),
            replay_recipe_b64: STANDARD.encode(replay_recipe),
            recipe_blobs: dependencies.blobs,
            evidence_receipts,
            evidence_checkpoint: checkpoint,
            execution_nonces,
            trust_root_snapshot_sha256,
            resolver_policy_sha256,
            trusted_time_source_sha256,
        })
    }

    pub fn verify_static(&self, profile: &FindingOperatorProfile) -> Result<(), String> {
        if self.schema != VERIFIED_FIX_DRAFT_SCHEMA {
            return Err("unsupported verified-fix draft schema".to_owned());
        }
        profile.validate()?;
        chio_finding::verify_finding(&self.finding).map_err(string_error)?;
        let payload = decode_bounded(&self.payload_b64, 16 * 1024 * 1024, "payload")?;
        if chio_finding::finding_payload_sha256(&self.finding.payload_media_type, &payload)
            .map_err(string_error)?
            != self.finding.payload_sha256
        {
            return Err("verified-fix payload does not match the Finding commitment".to_owned());
        }
        let recipe = decode_bounded(&self.replay_recipe_b64, 1024 * 1024, "replay recipe")?;
        if self.finding.replay_recipe_sha256.as_deref() != Some(sha256_hex(&recipe).as_str()) {
            return Err("verified-fix replay recipe does not match the Finding".to_owned());
        }
        for blob in &self.recipe_blobs {
            let bytes = decode_bounded(&blob.bytes_b64, 4 * 1024 * 1024, "recipe blob")?;
            if sha256_hex(&bytes) != blob.sha256 {
                return Err("verified-fix recipe dependency digest mismatch".to_owned());
            }
        }
        self.verifier_profile
            .body
            .validate()
            .map_err(string_error)?;
        let governance = profile.market.governance_root.key().map_err(string_error)?;
        chio_finding::verify_signed_profile(&self.verifier_profile, &governance)
            .map_err(string_error)?;
        let collateral = profile.market.collateral.key().map_err(string_error)?;
        chio_finding::verify_signed_bond_backing(&self.bond_backing, &collateral)
            .map_err(string_error)?;
        chio_finding::verify_signed_market_terms(&self.market_terms).map_err(string_error)?;
        chio_finding::verify_signed_seller_authorization(&self.seller_authorization)
            .map_err(string_error)?;
        verify_listing(&self.listing, profile)?;
        self.validate_evidence_shape()
    }

    pub fn finalize(
        &self,
        profile: &FindingOperatorProfile,
        accepted_at: u64,
        evaluation_time: u64,
    ) -> Result<FindingOperatorFinalization, String> {
        self.verify_static(profile)?;
        if accepted_at >= evaluation_time {
            return Err("report evaluation must follow collateral acceptance".to_owned());
        }
        let keys = profile.authoring_keys()?;
        let (report, checkpoint_signer_status, bond_store_snapshot) =
            self.build_report(profile, &keys, accepted_at, evaluation_time)?;
        let admission = self.build_admission(profile, &keys, &report, evaluation_time)?;
        let bundle = FindingOperatorBundle {
            schema: FINDING_OPERATOR_BUNDLE_SCHEMA.to_owned(),
            finding: self.finding.clone(),
            listing: self.listing.clone(),
            admission,
            market_terms: self.market_terms.clone(),
            seller_authorization: self.seller_authorization.clone(),
            verifier_profile: self.verifier_profile.clone(),
            bond_backing: self.bond_backing.clone(),
            verifier_report: report,
            fee_schedule: self.fee_schedule.clone(),
        };
        bundle
            .verify_at(&profile.market, evaluation_time)
            .map_err(string_error)?;
        let proof = FindingOperatorProofBundle {
            schema: FINDING_OPERATOR_PROOF_BUNDLE_SCHEMA.to_owned(),
            bundle: bundle.clone(),
            evidence_receipts: self.evidence_receipts.clone(),
            evidence_checkpoint: self.evidence_checkpoint.clone(),
            execution_nonces: self.execution_nonces.clone(),
            replay_recipe_b64: self.replay_recipe_b64.clone(),
            checkpoint_signer_status,
            bond_store_snapshot,
            trust_root_snapshot_sha256: self.trust_root_snapshot_sha256.clone(),
            resolver_policy_sha256: self.resolver_policy_sha256.clone(),
            trusted_time_source_sha256: self.trusted_time_source_sha256.clone(),
            status_proof_input_b64: None,
        };
        proof.verify(&profile.market, evaluation_time)?;
        Ok(FindingOperatorFinalization { bundle, proof })
    }

    fn validate_evidence_shape(&self) -> Result<(), String> {
        if self.evidence_receipts.is_empty()
            || self.evidence_receipts.len() != self.finding.evidence_receipt_ids.len()
            || self.execution_nonces.len() != self.evidence_receipts.len()
        {
            return Err("verified-fix evidence cardinality is invalid".to_owned());
        }
        let resolved = self.resolved_receipts()?;
        let ids = resolved
            .iter()
            .map(|evidence| evidence.receipt.id.clone())
            .collect::<Vec<_>>();
        if ids != self.finding.evidence_receipt_ids {
            return Err(
                "verified-fix evidence receipt order does not match the Finding".to_owned(),
            );
        }
        chio_finding_verifier::verify_checkpoint_membership(
            &resolved,
            std::slice::from_ref(&self.evidence_checkpoint),
            &chio_kernel::checkpoint::build_checkpoint_transparency(std::slice::from_ref(
                &self.evidence_checkpoint,
            ))
            .map_err(string_error)?,
            &self.verifier_profile.body,
            &self.finding.evidence_checkpoint_ref,
        )
        .map_err(string_error)
    }

    fn resolved_receipts(&self) -> Result<Vec<ResolvedReceiptEvidence>, String> {
        self.evidence_receipts
            .iter()
            .map(|evidence| {
                let bytes = decode_bounded(
                    &evidence.canonical_receipt_b64,
                    1024 * 1024,
                    "receipt evidence",
                )?;
                if canonical_json_bytes(&evidence.receipt).map_err(string_error)? != bytes {
                    return Err("receipt evidence bytes are not canonical or exact".to_owned());
                }
                Ok(ResolvedReceiptEvidence {
                    receipt: evidence.receipt.clone(),
                    canonical_receipt_bytes: bytes,
                    inclusion_proof: evidence.inclusion_proof.clone(),
                })
            })
            .collect()
    }

    fn build_report(
        &self,
        profile: &FindingOperatorProfile,
        keys: &FindingOperatorAuthoringKeys,
        accepted_at: u64,
        evaluation_time: u64,
    ) -> Result<
        (
            chio_finding::SignedFindingVerifierReport,
            FindingCheckpointSignerStatusTrust,
            SignedFindingBondStoreSnapshot,
        ),
        String,
    > {
        let resolved = self.resolved_receipts()?;
        let nonce_resolver = PackageNonceResolver {
            nonces: self.execution_nonces.clone(),
        };
        let checkpoint_signer_status = signer_status_trust(
            profile,
            &self.verifier_profile,
            &keys.authority_status,
            evaluation_time,
        )?;
        let bond_store_snapshot = SignedExportEnvelope::sign(
            FindingBondStoreSnapshot {
                schema: FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1.to_owned(),
                finding_id: self.finding.finding_id.clone(),
                bond_ref: self.finding.bond_ref.clone(),
                allocation_id: self.bond_backing.body.allocation_id.clone(),
                backing_envelope_sha256: digest(&self.bond_backing)?,
                live: true,
                accepted_at,
                observed_at: evaluation_time,
            },
            &keys.collateral,
        )
        .map_err(string_error)?;
        let recipe = decode_bounded(&self.replay_recipe_b64, 1024 * 1024, "replay recipe")?;
        let trust = verifier_trust(
            &profile.market,
            &self.verifier_profile,
            checkpoint_signer_status.clone(),
            evaluation_time,
            &self.trust_root_snapshot_sha256,
            &self.resolver_policy_sha256,
            &self.trusted_time_source_sha256,
        )?;
        let evidence = FindingEvidenceBundle {
            receipts: resolved,
            checkpoints: vec![self.evidence_checkpoint.clone()],
            checkpoint_transparency: build_checkpoint_transparency(std::slice::from_ref(
                &self.evidence_checkpoint,
            ))
            .map_err(string_error)?,
            finding_delivery: None,
            recipe_preimage: Some(&recipe),
            status_proof_input: None,
            runtime_attestation: None,
            runtime_appraisal: None,
            bond_snapshot: Some(FindingBondSnapshot {
                backing: self.bond_backing.clone(),
                terms: self.market_terms.clone(),
                fee_schedule: self.fee_schedule.clone(),
                store_snapshot: bond_store_snapshot.clone(),
            }),
            nonce_resolver: &nonce_resolver,
        };
        let raw = String::from_utf8(canonical_json_bytes(&self.finding).map_err(string_error)?)
            .map_err(string_error)?;
        let draft = verify_finding_evidence(&raw, &trust, &evidence).map_err(string_error)?;
        if !draft.satisfies_required_facets(&self.verifier_profile.body) {
            return Err(format!(
                "verified-fix evidence does not satisfy the profile: {:?}",
                draft.facets()
            ));
        }
        let report = sign_finding_verifier_report(
            &draft,
            &trust,
            "chio-finding-verifier/0.1",
            &keys.verifier_report,
        )
        .map_err(string_error)?;
        Ok((report, checkpoint_signer_status, bond_store_snapshot))
    }

    fn build_admission(
        &self,
        profile: &FindingOperatorProfile,
        keys: &FindingOperatorAuthoringKeys,
        report: &chio_finding::SignedFindingVerifierReport,
        issued_at: u64,
    ) -> Result<SignedFindingAdmission, String> {
        let expires_at = [
            self.finding.expires_at,
            self.market_terms.body.expires_at,
            self.verifier_profile.body.expires_at,
            self.bond_backing.body.expires_at,
            self.listing.pricing.body.expires_at,
            self.listing
                .listing
                .body
                .expires_at
                .ok_or_else(|| "finding listing has no expiry".to_owned())?,
        ]
        .into_iter()
        .min()
        .ok_or_else(|| "finding admission has no constituent expiry".to_owned())?;
        let schedule_sha256 =
            signed_fee_schedule_digest(&self.fee_schedule).map_err(string_error)?;
        let listing_id = &self.listing.listing.body.listing_id;
        let mut admission = FindingAdmission {
            schema: FINDING_ADMISSION_SCHEMA_V1.to_owned(),
            admission_id: String::new(),
            venue: keys.venue.public_key(),
            venue_id: profile.market.venue_id.clone(),
            finding_id: self.finding.finding_id.clone(),
            finding_artifact_sha256: digest(&self.finding)?,
            seller_authorization_envelope_sha256: digest(&self.seller_authorization)?,
            listing_id: listing_id.clone(),
            listing_envelope_sha256: digest(&self.listing.listing)?,
            server_id: SERVER_ID.to_owned(),
            metadata_url: metadata_url(profile, &self.finding.finding_id),
            pricing_hint_envelope_sha256: digest(&self.listing.pricing)?,
            capability_scope: format!("finding:{}", self.finding.finding_id),
            publisher_operator_id: profile.market.listing.authority_id.clone(),
            payee_destination: match &self.seller_authorization.body.payee {
                FindingPayee::Beneficiary { destination, .. } => destination.clone(),
                FindingPayee::ProviderPayeeMapping { .. } => {
                    return Err("local verified-fix seller must use a direct beneficiary".to_owned())
                }
            },
            fee_schedule_envelope_sha256: schedule_sha256.clone(),
            verifier_report_id: report.body.report_id.clone(),
            verifier_report_envelope_sha256: digest(report)?,
            terms_envelope_sha256: digest(&self.market_terms)?,
            profile_envelope_sha256: digest(&self.verifier_profile)?,
            fee_terminals: vec![
                fee_terminal(
                    profile,
                    &schedule_sha256,
                    FindingFeeEvent::Publication,
                    usd(PUBLICATION_FEE_UNITS),
                    &self.finding.finding_id,
                    listing_id,
                )?,
                fee_terminal(
                    profile,
                    &schedule_sha256,
                    FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                    usd(PARTICIPATION_FEE_UNITS),
                    &self.finding.finding_id,
                    listing_id,
                )?,
            ],
            backing_allocation_id: self.bond_backing.body.allocation_id.clone(),
            backing_envelope_sha256: digest(&self.bond_backing)?,
            audit_pool: pool_binding(&profile.market.audit_pool),
            challenge_administration_pool: pool_binding(
                &profile.market.challenge_administration_pool,
            ),
            community_fund_destination: profile.market.community_fund_destination.clone(),
            status_feed_operator_ref: profile.market.status_feed_operator.feed_id.clone(),
            purchase_authority: pin_policy(&profile.market.purchase)?,
            failed_delivery_authority: pin_policy(&profile.market.failed_delivery)?,
            issued_at,
            expires_at,
        };
        admission.admission_id = compute_admission_id(&admission).map_err(string_error)?;
        SignedExportEnvelope::sign(admission, &keys.venue).map_err(string_error)
    }
}

impl FindingOperatorProofBundle {
    pub fn verify(&self, market: &super::FindingMarketConfig, now: u64) -> Result<(), String> {
        if self.schema != FINDING_OPERATOR_PROOF_BUNDLE_SCHEMA {
            return Err("unsupported finding operator proof-bundle schema".to_owned());
        }
        market.validate().map_err(string_error)?;
        self.bundle.verify_at(market, now).map_err(string_error)?;
        let resolved = self
            .evidence_receipts
            .iter()
            .map(|evidence| {
                let bytes = decode_bounded(
                    &evidence.canonical_receipt_b64,
                    1024 * 1024,
                    "receipt evidence",
                )?;
                if canonical_json_bytes(&evidence.receipt).map_err(string_error)? != bytes {
                    return Err("proof receipt bytes are not exact canonical bytes".to_owned());
                }
                Ok(ResolvedReceiptEvidence {
                    receipt: evidence.receipt.clone(),
                    canonical_receipt_bytes: bytes,
                    inclusion_proof: evidence.inclusion_proof.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let nonce_resolver = PackageNonceResolver {
            nonces: self.execution_nonces.clone(),
        };
        let evaluation_time = self.bundle.verifier_report.body.evaluation_time;
        let trust = verifier_trust(
            market,
            &self.bundle.verifier_profile,
            self.checkpoint_signer_status.clone(),
            evaluation_time,
            &self.trust_root_snapshot_sha256,
            &self.resolver_policy_sha256,
            &self.trusted_time_source_sha256,
        )?;
        let recipe = decode_bounded(&self.replay_recipe_b64, 1024 * 1024, "replay recipe")?;
        let evidence = FindingEvidenceBundle {
            receipts: resolved,
            checkpoints: vec![self.evidence_checkpoint.clone()],
            checkpoint_transparency: build_checkpoint_transparency(std::slice::from_ref(
                &self.evidence_checkpoint,
            ))
            .map_err(string_error)?,
            finding_delivery: None,
            recipe_preimage: Some(&recipe),
            status_proof_input: None,
            runtime_attestation: None,
            runtime_appraisal: None,
            bond_snapshot: Some(FindingBondSnapshot {
                backing: self.bundle.bond_backing.clone(),
                terms: self.bundle.market_terms.clone(),
                fee_schedule: self.bundle.fee_schedule.clone(),
                store_snapshot: self.bond_store_snapshot.clone(),
            }),
            nonce_resolver: &nonce_resolver,
        };
        let raw =
            String::from_utf8(canonical_json_bytes(&self.bundle.finding).map_err(string_error)?)
                .map_err(string_error)?;
        let draft = verify_finding_evidence(&raw, &trust, &evidence).map_err(string_error)?;
        if !draft.satisfies_required_facets(&self.bundle.verifier_profile.body) {
            return Err("proof bundle does not satisfy its required verifier facets".to_owned());
        }
        let report = &self.bundle.verifier_report.body;
        if draft.finding_artifact_sha256() != report.finding_artifact_sha256
            || draft.resolved_evidence_bundle_sha256() != report.resolved_evidence_bundle_sha256
            || draft.replay_recipe_input_sha256() != report.replay_recipe_input_sha256.as_deref()
            || draft.evaluation_time() != report.evaluation_time
            || draft.facets() != report.facets
            || draft.backing_allocation_id() != report.backing_allocation_id.as_deref()
        {
            return Err("proof bundle re-evaluation differs from the signed report".to_owned());
        }
        Ok(())
    }
}

struct RecipeDependencies {
    baseline_input_sha256: String,
    candidate_input_sha256: String,
    parameters_sha256: String,
    pre_run_template_sha256: String,
    runner_manifest_sha256: String,
    runtime_image_sha256: String,
    blobs: Vec<FindingOperatorRecipeBlob>,
}

fn recipe_dependencies(
    payload: &VerifiedFixPayload,
    runner_manifest: Vec<u8>,
    runtime_fingerprint: Vec<u8>,
) -> Result<RecipeDependencies, String> {
    let baseline = canonical_json_bytes(&payload.baseline).map_err(string_error)?;
    let candidate = canonical_json_bytes(&payload.candidate).map_err(string_error)?;
    let parameters = canonical_json_bytes(&serde_json::json!({
        "baseRevision": payload.base_revision,
        "candidateRevision": payload.candidate_revision,
        "commands": payload.candidate.iter().map(|result| result.command.as_str()).collect::<Vec<_>>(),
        "repository": payload.repository,
    }))
    .map_err(string_error)?;
    let pre_run_template = canonical_json_bytes(&serde_json::json!({
        "candidateApplication": "apply_patch_v1",
        "networkPolicy": "deny_all",
        "shell": "sh",
    }))
    .map_err(string_error)?;
    let blobs = vec![
        baseline,
        candidate,
        parameters,
        pre_run_template,
        runner_manifest,
        runtime_fingerprint,
    ];
    let digests = blobs
        .iter()
        .map(|blob| sha256_hex(blob))
        .collect::<Vec<_>>();
    Ok(RecipeDependencies {
        baseline_input_sha256: digests[0].clone(),
        candidate_input_sha256: digests[1].clone(),
        parameters_sha256: digests[2].clone(),
        pre_run_template_sha256: digests[3].clone(),
        runner_manifest_sha256: digests[4].clone(),
        runtime_image_sha256: digests[5].clone(),
        blobs: blobs
            .into_iter()
            .zip(digests)
            .map(|(bytes, sha256)| FindingOperatorRecipeBlob {
                sha256,
                bytes_b64: STANDARD.encode(bytes),
            })
            .collect(),
    })
}

fn build_recipe(
    profile_sha256: &str,
    context_sha256: &str,
    payload_sha256: &str,
    dependencies: &RecipeDependencies,
) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_owned(),
        decision_rule_ref: "decision/baseline-fails-candidate-passes-v1".to_owned(),
        verifier_profile_envelope_sha256: profile_sha256.to_owned(),
        context_sha256: context_sha256.to_owned(),
        payload_sha256: payload_sha256.to_owned(),
        runner_server: SERVER_ID.to_owned(),
        runner_tool: "finding.replay.verified_fix".to_owned(),
        runner_manifest_sha256: dependencies.runner_manifest_sha256.clone(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: dependencies.baseline_input_sha256.clone(),
                payload_application: "not_applied".to_owned(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: dependencies.candidate_input_sha256.clone(),
                payload_application: "apply_patch_v1".to_owned(),
            },
        ],
        parameters_sha256: dependencies.parameters_sha256.clone(),
        environment: FindingRecipeEnvironment {
            runtime_image_sha256: dependencies.runtime_image_sha256.clone(),
            platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            network_policy: "deny_all".to_owned(),
            clock_policy: "host_recorded".to_owned(),
            randomness_policy: "none".to_owned(),
            locale: "C".to_owned(),
            timezone: "UTC".to_owned(),
        },
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: dependencies.pre_run_template_sha256.clone(),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}

fn build_profile(
    profile: &FindingOperatorProfile,
    keys: &FindingOperatorAuthoringKeys,
    checkpoint_key: &Keypair,
    runner_manifest_sha256: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<SignedFindingChallengeVerifierProfile, String> {
    let mut body = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_owned(),
        profile_id: String::new(),
        governance_authority: keys.governance_root.public_key(),
        operator: profile.market.venue_id.clone(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: local_policy(
                    "verified-fix-production",
                    &keys.production_kernel,
                    issued_at,
                    expires_at,
                ),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: local_policy(
                    "verified-fix-delivery",
                    &keys.delivery_receipt,
                    issued_at,
                    expires_at,
                ),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: local_policy(
                    "verified-fix-replay",
                    &keys.replay_receipt,
                    issued_at,
                    expires_at,
                ),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id: chio_finding::finding_checkpoint_log_id(&checkpoint_key.public_key()),
            signer: local_policy(
                "verified-fix-checkpoint",
                checkpoint_key,
                issued_at,
                expires_at,
            ),
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "local-cognition-market-bbs".to_owned(),
            key_hex: keys.production_kernel.public_key().to_hex(),
            registry_ref: "local/cognition-market/bbs".to_owned(),
            key_epoch: 1,
            valid_from: issued_at,
            valid_until: expires_at,
            revocation_status_ref: "local/revocations/bbs".to_owned(),
        },
        allowed_runner_manifests: vec![runner_manifest_sha256.to_owned()],
        required_receipt_semantics: "chio.mediated_spend.v1".to_owned(),
        resolver_policy_ref: "local/verified-fix-resolver-v1".to_owned(),
        retention_policy_ref: "local/m10-pilot-retention-v1".to_owned(),
        resource_caps: resource_caps(),
        predicate_engine: "chio-replay-v1".to_owned(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::RecipeBinding,
            FindingFacetKind::BondBacking,
            FindingFacetKind::GuaranteeConsistency,
        ],
        verifier_report_signer: pin_policy(&profile.market.verifier_report)?,
        purchase_authority: pin_policy(&profile.market.purchase)?,
        failed_delivery_authority: pin_policy(&profile.market.failed_delivery)?,
        issued_at,
        expires_at,
    };
    body.profile_id = compute_profile_id(&body).map_err(string_error)?;
    SignedExportEnvelope::sign(body, &keys.governance_root).map_err(string_error)
}

#[allow(clippy::too_many_arguments)]
fn build_finding(
    seller: &FindingOperatorSellerProfile,
    context_sha256: &str,
    payload_sha256: &str,
    replay_recipe_sha256: &str,
    receipts: &[ChioReceipt],
    checkpoint_ref: &str,
    status_feed_ref: &str,
    topic: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<Finding, String> {
    let seller_key = Keypair::from_seed_hex(&seller.signing_seed).map_err(string_error)?;
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_owned(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: topic.to_owned(),
            context_sha256: context_sha256.to_owned(),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: payload_sha256.to_owned(),
        payload_media_type: VERIFIED_FIX_MEDIA_TYPE.to_owned(),
        evidence_receipt_ids: receipts.iter().map(|receipt| receipt.id.clone()).collect(),
        evidence_checkpoint_ref: checkpoint_ref.to_owned(),
        evidence_cost: usd(u64::try_from(receipts.len()).map_err(string_error)?),
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(replay_recipe_sha256.to_owned()),
        intent_commitment_receipt_id: None,
        bond_ref: "bond:local-cognition-market".to_owned(),
        status_feed_ref: status_feed_ref.to_owned(),
        license_ref: None,
        price_hint_ref: None,
        issuer: seller_key.public_key(),
        issued_at,
        expires_at,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding).map_err(string_error)?;
    sign_finding(finding, &seller_key).map_err(string_error)
}

fn build_fee_schedule(
    profile: &FindingOperatorProfile,
    signer: &Keypair,
    issued_at: u64,
) -> Result<SignedOpenMarketFeeSchedule, String> {
    let namespace = operator_namespace(profile);
    let request = OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: namespace.clone(),
            allowed_listing_operator_ids: vec![profile.market.listing.authority_id.clone()],
            allowed_actor_kinds: Vec::new(),
            allowed_admission_classes: Vec::new(),
            policy_reference: Some("local/cognition-market/m10".to_owned()),
        },
        publication_fee: usd(PUBLICATION_FEE_UNITS),
        dispute_fee: usd(25),
        market_participation_fee: usd(PARTICIPATION_FEE_UNITS),
        bond_requirements: vec![
            OpenMarketBondRequirement {
                bond_class: OpenMarketBondClass::Listing,
                required_amount: usd(REQUIREMENT_UNITS),
                collateral_reference_kind: OpenMarketCollateralReferenceKind::ExternalReference,
                slashable: true,
            },
            OpenMarketBondRequirement {
                bond_class: OpenMarketBondClass::Dispute,
                required_amount: usd(DISPUTE_BOND_UNITS),
                collateral_reference_kind: OpenMarketCollateralReferenceKind::ExternalReference,
                slashable: true,
            },
        ],
        issued_by: profile.market.fee_schedule_operator_keys[0].clone(),
        issued_at: Some(issued_at),
        expires_at: None,
        note: Some("single-operator cognition-market pilot".to_owned()),
    };
    let artifact = build_open_market_fee_schedule_artifact(&namespace, None, &request, issued_at)
        .map_err(string_error)?;
    SignedOpenMarketFeeSchedule::sign(artifact, signer).map_err(string_error)
}

#[allow(clippy::too_many_arguments)]
fn build_terms(
    seller: &FindingOperatorSellerProfile,
    finding: &Finding,
    finding_sha256: &str,
    listing_id: &str,
    profile_sha256: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<SignedFindingMarketTerms, String> {
    let seller_key = Keypair::from_seed_hex(&seller.signing_seed).map_err(string_error)?;
    let mut terms = FindingMarketTerms {
        schema: FINDING_MARKET_TERMS_SCHEMA_V1.to_owned(),
        terms_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: finding_sha256.to_owned(),
        listing_id: listing_id.to_owned(),
        seller: seller_key.public_key(),
        backing_requirement: FindingBackingRequirement {
            base_finding_stake: usd(STAKE_UNITS),
            maximum_sale_exposure: usd(VERIFIED_FIX_MAXIMUM_SALE_EXPOSURE_UNITS),
            collateral_policy: "venue_ledger_exclusive_v1".to_owned(),
        },
        filing_window_secs: 86_400,
        claim_window_secs: 604_800,
        appeal_window_secs: 259_200,
        audit_epoch_length_secs: 86_400,
        audit_eligible: true,
        decision_rule_refs: vec!["decision/baseline-fails-candidate-passes-v1".to_owned()],
        verifier_profile_envelope_sha256: profile_sha256.to_owned(),
        challenge_bond_limits: vec![FindingChallengeBondLimit {
            guarantee_class: FindingGuaranteeClass::DeterministicReplay,
            min_bond: usd(DISPUTE_BOND_UNITS),
            max_bond: usd(100),
        }],
        payout_policy: "pro_rata_capped_v1".to_owned(),
        issued_at,
        expires_at,
    };
    terms.terms_id = compute_terms_id(&terms).map_err(string_error)?;
    SignedExportEnvelope::sign(terms, &seller_key).map_err(string_error)
}

#[allow(clippy::too_many_arguments)]
fn build_seller_authorization(
    seller: &FindingOperatorSellerProfile,
    finding: &Finding,
    finding_sha256: &str,
    listing_id: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<SignedFindingSellerAuthorization, String> {
    let seller_key = Keypair::from_seed_hex(&seller.signing_seed).map_err(string_error)?;
    let mut authorization = FindingSellerAuthorization {
        schema: FINDING_SELLER_AUTHORIZATION_SCHEMA_V1.to_owned(),
        authorization_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: finding_sha256.to_owned(),
        listing_id: listing_id.to_owned(),
        issuer: seller_key.public_key(),
        seller: seller_key.public_key(),
        provider_server_id: SERVER_ID.to_owned(),
        provider_tool: super::finding_reveal_server::READ_FINDING_TOOL.to_owned(),
        payee: FindingPayee::Beneficiary {
            destination: seller.payout_destination.clone(),
            currency: CURRENCY.to_owned(),
        },
        revocation_status_ref: format!("local/revocations/seller/{}", seller.principal_id),
        issued_at,
        expires_at,
    };
    authorization.authorization_id =
        compute_authorization_id(&authorization).map_err(string_error)?;
    SignedExportEnvelope::sign(authorization, &seller_key).map_err(string_error)
}

#[allow(clippy::too_many_arguments)]
fn build_backing(
    seller: &FindingOperatorSellerProfile,
    collateral: &Keypair,
    finding: &Finding,
    listing_id: &str,
    schedule: &SignedOpenMarketFeeSchedule,
    authorization_sha256: &str,
    terms_sha256: &str,
    profile_sha256: &str,
    schedule_sha256: &str,
    issued_at: u64,
    expires_at: u64,
) -> Result<SignedFindingBondBacking, String> {
    let seller_key = Keypair::from_seed_hex(&seller.signing_seed).map_err(string_error)?;
    let requirement = schedule
        .body
        .bond_requirements
        .iter()
        .find(|requirement| requirement.bond_class == OpenMarketBondClass::Listing)
        .ok_or_else(|| "fee schedule has no listing bond requirement".to_owned())?;
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_owned(),
        allocation_id: String::new(),
        collateral_authority: collateral.public_key(),
        seller: seller_key.public_key(),
        authorization_envelope_sha256: authorization_sha256.to_owned(),
        finding_id: finding.finding_id.clone(),
        listing_id: listing_id.to_owned(),
        terms_envelope_sha256: terms_sha256.to_owned(),
        profile_envelope_sha256: profile_sha256.to_owned(),
        fee_requirement_sha256: digest(requirement)?,
        fee_schedule_envelope_sha256: schedule_sha256.to_owned(),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(LOCKED_UNITS),
        maximum_sale_exposure: usd(VERIFIED_FIX_MAXIMUM_SALE_EXPOSURE_UNITS),
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: format!("vault:{}", seller.principal_id),
            operator_epoch: 1,
        },
        issued_at,
        expires_at,
    };
    backing.allocation_id = compute_allocation_id(&backing).map_err(string_error)?;
    SignedExportEnvelope::sign(backing, collateral).map_err(string_error)
}

#[allow(clippy::too_many_arguments)]
fn build_listing(
    profile: &FindingOperatorProfile,
    signer: &Keypair,
    finding: &Finding,
    listing_id: &str,
    price_units: u64,
    issued_at: u64,
    expires_at: u64,
) -> Result<Listing, String> {
    let namespace = operator_namespace(profile);
    let listing = SignedGenericListing::sign(
        GenericListingArtifact {
            schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_owned(),
            listing_id: listing_id.to_owned(),
            namespace: namespace.clone(),
            published_at: issued_at,
            expires_at: Some(expires_at),
            status: GenericListingStatus::Active,
            namespace_ownership: GenericNamespaceOwnership {
                namespace: namespace.clone(),
                owner_id: profile.market.listing.authority_id.clone(),
                owner_name: Some("Local Cognition Market".to_owned()),
                registry_url: namespace.clone(),
                signer_public_key: signer.public_key(),
                registered_at: issued_at,
                transferred_from_owner_id: None,
            },
            subject: GenericListingSubject {
                actor_kind: GenericListingActorKind::ToolServer,
                actor_id: SERVER_ID.to_owned(),
                display_name: Some("Verified fix Finding".to_owned()),
                metadata_url: Some(metadata_url(profile, &finding.finding_id)),
                resolution_url: None,
                homepage_url: None,
            },
            compatibility: GenericListingCompatibilityReference {
                source_schema: FINDING_SCHEMA_V1.to_owned(),
                source_artifact_id: finding.finding_id.clone(),
                source_artifact_sha256: digest(finding)?,
            },
            boundary: GenericListingBoundary::default(),
        },
        signer,
    )
    .map_err(string_error)?;
    let pricing = SignedListingPricingHint::sign(
        ListingPricingHint {
            schema: LISTING_PRICING_HINT_SCHEMA.to_owned(),
            listing_id: listing_id.to_owned(),
            namespace,
            provider_operator_id: profile.market.listing.authority_id.clone(),
            capability_scope: format!("finding:{}", finding.finding_id),
            price_per_call: usd(price_units),
            sla: ListingSla {
                max_latency_ms: 5_000,
                availability_bps: 9_900,
                throughput_rps: 10,
            },
            revocation_rate_bps: 0,
            recent_receipts_volume: 0,
            issued_at,
            expires_at,
        },
        signer,
    )
    .map_err(string_error)?;
    Ok(Listing {
        rank: 1,
        listing,
        pricing,
        publisher: GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: profile.market.listing.authority_id.clone(),
            operator_name: Some("Local Cognition Market".to_owned()),
            registry_url: operator_namespace(profile),
            upstream_registry_urls: Vec::new(),
        },
        freshness: GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 0,
            max_age_secs: 300,
            valid_until: expires_at,
            generated_at: issued_at,
        },
    })
}

fn build_evidence_receipts(
    kernel: &Keypair,
    issued_at: u64,
    payload: &VerifiedFixPayload,
) -> Result<Vec<ChioReceipt>, String> {
    let baseline_sha256 = digest(&payload.baseline)?;
    let candidate_sha256 = digest(&payload.candidate)?;
    [
        ("verified_fix.baseline", baseline_sha256),
        ("verified_fix.candidate", candidate_sha256),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (tool_name, content_hash))| {
        let index = u32::try_from(index).map_err(string_error)?;
        let body = ChioReceiptBody {
            id: String::new(),
            timestamp: issued_at,
            capability_id: format!("verified-fix-evidence-{index}"),
            tool_server: SERVER_ID.to_owned(),
            tool_name: tool_name.to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "phase": tool_name,
                "resultSha256": content_hash,
            }))
            .map_err(string_error)?,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash,
            policy_hash: sha256_hex(b"chio.verified-fix-evidence-policy.v1"),
            evidence: Vec::new(),
            metadata: Some(mediated_spend_metadata(index)),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, kernel).map_err(string_error)
    })
    .collect()
}

fn mediated_spend_metadata(index: u32) -> serde_json::Value {
    serde_json::json!({
        "budget_authority": {
            "authority_profile": "authoritative_hold_event",
            "authorize": {
                "committed_cost_units_after": 1,
                "event_id": format!("verified-fix-{index}:authorize"),
                "exposure_units": 1
            },
            "execution_nonce_id": format!("verified-fix-nonce-{index}"),
            "guarantee_level": "single_node_atomic",
            "hold_id": format!("verified-fix-hold-{index}"),
            "mediated_spend": {"profile": "chio.mediated_spend.v1"},
            "metering_profile": "max_cost_preauthorize_then_reconcile_actual",
            "terminal": {
                "committed_cost_units_after": 1,
                "disposition": "reconciled",
                "event_id": format!("verified-fix-{index}:reconcile"),
                "exposure_units": 1,
                "realized_spend_units": 1
            }
        },
        "financial": {
            "budget_remaining": 99,
            "budget_total": 100,
            "cost_charged": 1,
            "currency": CURRENCY,
            "delegation_depth": 0,
            "grant_index": 0,
            "root_budget_holder": "verified-fix-producer",
            "settlement_status": "settled"
        }
    })
}

fn signed_nonce(receipt: &ChioReceipt, kernel: &Keypair) -> Result<SignedExecutionNonce, String> {
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or_else(|| "receipt budget authority metadata is missing".to_owned())?;
    let nonce = ExecutionNonce {
        schema: "chio.execution_nonce.v1".to_owned(),
        nonce_id: budget
            .execution_nonce_id
            .ok_or_else(|| "receipt execution nonce id is missing".to_owned())?,
        issued_at: i64::try_from(receipt.timestamp.saturating_sub(1)).map_err(string_error)?,
        expires_at: i64::try_from(receipt.timestamp.saturating_add(60)).map_err(string_error)?,
        bound_to: NonceBinding {
            subject_id: "verified-fix-producer".to_owned(),
            request_id: format!("verified-fix-request-{}", receipt.id),
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
        },
        reserved_hold_id: Some(budget.hold_id),
        reserving_request_id: None,
    };
    Ok(SignedExecutionNonce {
        signature: kernel.sign(&canonical_json_bytes(&nonce).map_err(string_error)?),
        nonce,
    })
}

#[derive(Clone)]
struct PackageNonceResolver {
    nonces: Vec<SignedExecutionNonce>,
}

impl FindingNonceResolver for PackageNonceResolver {
    fn nonce_for(&self, receipt: &ChioReceipt) -> Option<&SignedExecutionNonce> {
        let nonce_id = BudgetAuthorityReceiptRef::from_receipt(receipt)?.execution_nonce_id?;
        self.nonces
            .iter()
            .find(|nonce| nonce.nonce.nonce_id == nonce_id)
    }
}

fn signer_status_trust(
    profile: &FindingOperatorProfile,
    verifier_profile: &SignedFindingChallengeVerifierProfile,
    signer: &Keypair,
    observed_at: u64,
) -> Result<FindingCheckpointSignerStatusTrust, String> {
    let mut policies = verifier_profile
        .body
        .receipt_signers
        .iter()
        .map(|role| role.policy.clone())
        .chain(
            verifier_profile
                .body
                .checkpoint_logs
                .iter()
                .map(|log| log.signer.clone()),
        )
        .collect::<Vec<_>>();
    policies.push(pin_policy(&profile.market.governance_root)?);
    policies.push(pin_policy(&profile.market.collateral)?);
    let mut by_key = BTreeMap::new();
    for policy in policies {
        by_key.entry(policy.key.to_hex()).or_insert(policy);
    }
    let signed_statuses = by_key
        .into_values()
        .map(|policy| {
            SignedExportEnvelope::sign(
                FindingAuthorityStatus {
                    schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
                    status_ref: policy.revocation_status_ref,
                    authority_id: policy.authority_id,
                    key: policy.key,
                    key_epoch: policy.key_epoch,
                    revoked_from: None,
                    observed_at,
                },
                signer,
            )
            .map_err(string_error)
        })
        .collect::<Result<Vec<SignedFindingAuthorityStatus>, String>>()?;
    Ok(FindingCheckpointSignerStatusTrust {
        signed_statuses,
        status_authority: pin_policy(&profile.market.authority_status)?,
        max_age_secs: 300,
    })
}

#[allow(clippy::too_many_arguments)]
fn verifier_trust(
    market: &super::FindingMarketConfig,
    verifier_profile: &SignedFindingChallengeVerifierProfile,
    signer_status: FindingCheckpointSignerStatusTrust,
    trusted_time: u64,
    trust_root_snapshot_sha256: &str,
    resolver_policy_sha256: &str,
    trusted_time_source_sha256: &str,
) -> Result<FindingVerifierTrustRoots, String> {
    Ok(FindingVerifierTrustRoots {
        governance_authority: market.governance_root.key().map_err(string_error)?,
        governance_authority_policy: pin_policy(&market.governance_root)?,
        profile: verifier_profile.clone(),
        admitted_kernel_keys: vec![verifier_profile
            .body
            .receipt_signers
            .iter()
            .find(|role| role.role == FindingReceiptRole::Production)
            .ok_or_else(|| "verifier profile has no production signer".to_owned())?
            .policy
            .key
            .clone()],
        collateral_authority: pin_policy(&market.collateral)?,
        fee_schedule_authorities: market.fee_schedule_operators().map_err(string_error)?,
        runtime_attestation_authority: None,
        appraisal_authority: None,
        attestation_trust_policy: None,
        status_operator_authorization: None,
        status_freshness_policy: None,
        checkpoint_signer_status: Some(signer_status),
        trusted_time,
        trust_root_snapshot_sha256: trust_root_snapshot_sha256.to_owned(),
        resolver_policy_sha256: resolver_policy_sha256.to_owned(),
        trusted_time_input_sha256: trusted_time_source_sha256.to_owned(),
    })
}

fn fee_terminal(
    profile: &FindingOperatorProfile,
    schedule_sha256: &str,
    event: FindingFeeEvent,
    amount: MonetaryAmount,
    finding_id: &str,
    listing_id: &str,
) -> Result<FindingFeeTerminalBinding, String> {
    let key = finding_fee_idempotency_key(schedule_sha256, &event, finding_id, listing_id);
    let pool = &profile.market.audit_pool;
    let instruction = super::FindingRailInstruction {
        idempotency_key: key,
        payer: profile.market.listing.authority_id.clone(),
        amount_units: amount.units,
        currency: amount.currency.clone(),
        pool_principal_id: pool.principal_id.clone(),
        rail_destination: pool.rail_destination.clone(),
    };
    let instruction_sha256 = digest(&instruction)?;
    let observation = super::FindingRailObservation {
        instruction_sha256: instruction_sha256.clone(),
        amount_units: amount.units,
        currency: amount.currency.clone(),
        rail_destination: pool.rail_destination.clone(),
        rail: "venue-ledger".to_owned(),
    };
    Ok(FindingFeeTerminalBinding {
        fee_schedule_envelope_sha256: schedule_sha256.to_owned(),
        event,
        payer: profile.market.listing.authority_id.clone(),
        amount,
        pool_principal_id: pool.principal_id.clone(),
        rail_destination: pool.rail_destination.clone(),
        instruction_sha256,
        observation_sha256: digest(&observation)?,
    })
}

fn pin_policy(pin: &FindingAuthorityPin) -> Result<FindingAuthorityKeyPolicy, String> {
    Ok(FindingAuthorityKeyPolicy {
        authority_id: pin.authority_id.clone(),
        key: pin.key().map_err(string_error)?,
        key_epoch: pin.key_epoch,
        valid_from: pin.valid_from,
        valid_until: pin.valid_until,
        rotation_policy_ref: format!("local/rotation/{}", pin.authority_id),
        revocation_status_ref: pin.revocation_status_ref.clone(),
    })
}

fn local_policy(
    authority_id: &str,
    key: &Keypair,
    valid_from: u64,
    valid_until: u64,
) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: authority_id.to_owned(),
        key: key.public_key(),
        key_epoch: 1,
        valid_from,
        valid_until,
        rotation_policy_ref: format!("local/rotation/{authority_id}"),
        revocation_status_ref: format!("local/revocations/{authority_id}"),
    }
}

fn pool_binding(pool: &super::FindingPoolPin) -> FindingPoolBinding {
    FindingPoolBinding {
        principal_id: pool.principal_id.clone(),
        rail_destination: pool.rail_destination.clone(),
        currency: pool.currency.clone(),
        authority_epoch: pool.authority_epoch,
    }
}

fn resource_caps() -> FindingResourceCaps {
    FindingResourceCaps {
        max_recipe_bytes: 1_048_576,
        max_evidence_receipts: 16,
        max_runtime_secs: 3_600,
        max_memory_bytes: 8_589_934_592,
    }
}

fn verify_listing(listing: &Listing, profile: &FindingOperatorProfile) -> Result<(), String> {
    chio_open_market::listing::ensure_generic_listing_signed_by_namespace_owner(
        &listing.listing,
        "verified-fix listing",
    )?;
    if listing.listing.signer_key != profile.market.listing.key().map_err(string_error)?
        || listing.pricing.signer_key != listing.listing.signer_key
        || !listing.pricing.verify_signature().map_err(string_error)?
    {
        return Err("verified-fix listing authority is invalid".to_owned());
    }
    listing.pricing.body.validate()?;
    Ok(())
}

fn validate_authoring_input(input: &VerifiedFixAuthoringInput) -> Result<(), String> {
    for (value, label) in [
        (&input.seller_principal, "seller principal"),
        (&input.repository, "repository"),
        (&input.base_revision, "base revision"),
        (&input.candidate_revision, "candidate revision"),
        (&input.topic, "topic"),
    ] {
        if value.is_empty()
            || value.len() > 512
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(format!("verified-fix {label} is invalid"));
        }
    }
    if input.base_revision == input.candidate_revision {
        return Err("verified-fix base and candidate revisions must differ".to_owned());
    }
    if input.patch.is_empty() || input.patch.len() > 12 * 1024 * 1024 {
        return Err("verified-fix patch is empty or too large".to_owned());
    }
    if input.baseline.is_empty()
        || input.baseline.len() != input.candidate.len()
        || !input.baseline.iter().any(|result| result.exit_code != 0)
        || input.candidate.iter().any(|result| result.exit_code != 0)
    {
        return Err(
            "verified-fix evidence requires a failing baseline and an all-passing candidate"
                .to_owned(),
        );
    }
    if input.price_units == 0 {
        return Err("verified-fix price must be nonzero".to_owned());
    }
    Ok(())
}

fn operator_namespace(profile: &FindingOperatorProfile) -> String {
    format!("http://{}", profile.listen)
}

fn metadata_url(profile: &FindingOperatorProfile, finding_id: &str) -> String {
    format!("http://{}/v1/findings/{finding_id}", profile.listen)
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: CURRENCY.to_owned(),
    }
}

fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(string_error)
}

fn decode_bounded(encoded: &str, max_bytes: usize, label: &'static str) -> Result<Vec<u8>, String> {
    if encoded.len()
        > max_bytes
            .saturating_add(2)
            .saturating_div(3)
            .saturating_mul(4)
    {
        return Err(format!("{label} exceeds its encoded size bound"));
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| format!("{label} is not canonical base64"))?;
    if bytes.len() > max_bytes || STANDARD.encode(&bytes) != encoded {
        return Err(format!("{label} is not canonical bounded base64"));
    }
    Ok(bytes)
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
