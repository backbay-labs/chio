//! Behavioral coverage for the finding evidence verifier: a real signed
//! finding over real kernel-signed receipts committed to a real
//! checkpoint, then adversarial tampering on every wrapper dimension the
//! shipped inclusion-proof verify leaves unchecked.

use std::collections::BTreeMap;
use std::error::Error;

use chio_appraisal::{
    verify_runtime_attestation_record, RuntimeAttestationAppraisalReport,
    SignedRuntimeAttestationAppraisalReport, AZURE_MAA_ATTESTATION_SCHEMA,
    RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA,
};
use chio_core_types::capability::runtime_attestation::{
    RuntimeAssuranceTier, RuntimeAttestationEvidence,
};
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::capability::trust_policy::{AttestationTrustPolicy, AttestationTrustRule};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::governance::{
    GovernedTransactionReceiptMetadata, RuntimeAssuranceReceiptMetadata,
};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::MerkleTree;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    build_status_non_inclusion_proof_input, compute_allocation_id, compute_finding_id,
    compute_profile_id, compute_status_epoch_id, sign_finding, verify_signed_verifier_report,
    Finding, FindingAuthorityKeyPolicy, FindingBbsIssuerPolicy, FindingBondBacking,
    FindingBondClass, FindingChallengeVerifierProfile, FindingCheckpointLogPolicy,
    FindingClaimedVerdict, FindingCollateralVault, FindingDescriptor, FindingEvidenceClass,
    FindingFacetKind, FindingFacetOutcome, FindingGuaranteeClass, FindingOutcomeClass,
    FindingPredicate, FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment,
    FindingRecipePhase, FindingRecipePhaseKind, FindingReplayRecipeInput, FindingResourceCaps,
    FindingStatusEpoch, FindingStatusFreshnessPolicy, FindingStatusOperatorAuthorization,
    FindingStatusOperatorRole, FINDING_BOND_BACKING_SCHEMA_V1,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
    FINDING_SCHEMA_V1, FINDING_STATUS_EPOCH_SCHEMA_V1, FINDING_STATUS_SIGNATURE_DOMAIN,
};
use chio_finding_verifier::{
    sign_finding_verifier_report, verify_checkpoint_membership, verify_finding_evidence,
    CheckpointMembershipError, FindingBondSnapshot, FindingEvidenceBundle, FindingVerifierError,
    FindingVerifierTrustRoots, NoNonceEvidence, ResolvedReceiptEvidence,
};
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_inclusion_proof, checkpoint_log_id,
    CheckpointTransparencySummary, KernelCheckpoint,
};
use chio_revocation_oracle::{
    finding_status_empty_leaf_hash, FindingStatusSparseMap, FINDING_STATUS_BRANCH_DOMAIN,
    FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
};

type TestResult = Result<(), Box<dyn Error>>;

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn receipt(
    kernel: &Keypair,
    index: u32,
    content_hash: &str,
    runtime_assurance: Option<&RuntimeAssuranceReceiptMetadata>,
) -> Result<ChioReceipt, Box<dyn Error>> {
    let metadata = runtime_assurance
        .map(|runtime_assurance| {
            serde_json::to_value(serde_json::json!({
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: format!("intent-evidence-{index}"),
                    intent_hash: HEX64.to_string(),
                    purpose: "produce finding evidence".to_string(),
                    server_id: "finding-server".to_string(),
                    tool_name: "finding.produce".to_string(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    approval: None,
                    runtime_assurance: Some(runtime_assurance.clone()),
                    call_chain: None,
                    autonomy: None,
                    economic_authorization: None,
                }
            }))
        })
        .transpose()?;
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: 1_750_000_000 + u64::from(index),
        capability_id: format!("cap-evidence-{index}"),
        tool_server: "finding-server".to_string(),
        tool_name: "finding.produce".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"step": index}))?,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: content_hash.to_string(),
        policy_hash: "policy-wedge".to_string(),
        evidence: Vec::new(),
        metadata,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    Ok(ChioReceipt::sign(body, kernel)?)
}

struct Fixture {
    issuer: Keypair,
    governance: Keypair,
    verifier: Keypair,
    raw_finding: String,
    receipts: Vec<ResolvedReceiptEvidence>,
    checkpoint: KernelCheckpoint,
    checkpoint_transparency: CheckpointTransparencySummary,
    recipe_bytes: Vec<u8>,
    finding_payload_sha256: String,
    backing: SignedExportEnvelope<FindingBondBacking>,
    profile: SignedExportEnvelope<FindingChallengeVerifierProfile>,
}

fn key_policy(seed: u8, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn resource_caps() -> FindingResourceCaps {
    FindingResourceCaps {
        max_recipe_bytes: 262_144,
        max_evidence_receipts: 64,
        max_runtime_secs: 900,
        max_memory_bytes: 2_147_483_648,
    }
}

fn recipe(
    manifest_sha256: &str,
    payload_sha256: &str,
    profile_envelope_sha256: &str,
    context_sha256: &str,
) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        context_sha256: context_sha256.to_string(),
        payload_sha256: payload_sha256.to_string(),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: manifest_sha256.to_string(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: HEX64.to_string(),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: HEX64.to_string(),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: HEX64.to_string(),
        environment: FindingRecipeEnvironment {
            runtime_image_sha256: HEX64.to_string(),
            platform: "linux/amd64".to_string(),
            network_policy: "deny_all".to_string(),
            clock_policy: "fixed:1700000000".to_string(),
            randomness_policy: "seed:42".to_string(),
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
        },
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: HEX64.to_string(),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}

/// A finding claiming `metered_attested` over the same evidence, used to
/// prove the guarantee-consistency rule for the non-replay class.
fn metered_attested_fixture() -> Result<Fixture, Box<dyn Error>> {
    let mut fx = fixture()?;
    let mut finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    finding.guarantee_class = FindingGuaranteeClass::MeteredAttested;
    finding.replay_recipe_sha256 = None;
    finding.signature = String::new();
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &fx.issuer)?;
    fx.raw_finding = String::from_utf8(canonical_json_bytes(&finding)?)?;
    fx.finding_payload_sha256 = finding.payload_sha256.clone();
    Ok(fx)
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    fixture_with_runtime_assurance(None, None)
}

fn fixture_with_runtime_assurance(
    runtime_assurance_tier: Option<RuntimeAssuranceTier>,
    runtime_assurance: Option<&RuntimeAssuranceReceiptMetadata>,
) -> Result<Fixture, Box<dyn Error>> {
    let issuer = keypair(3);
    let governance = keypair(1);
    let kernel = keypair(21);
    let verifier = keypair(15);
    let collateral = keypair(4);
    let seller = keypair(2);

    // Receipts first: the finding binds their recomputed ids in order.
    let payload_sha256 = HEX64.to_string();
    let first = receipt(&kernel, 0, HEX64, runtime_assurance)?;
    let second = receipt(&kernel, 1, HEX64, runtime_assurance)?;
    let first_bytes = canonical_json_bytes(&first)?;
    let second_bytes = canonical_json_bytes(&second)?;
    let tree = MerkleTree::from_leaves(&[first_bytes.clone(), second_bytes.clone()])?;
    let checkpoint = build_checkpoint(
        1,
        100,
        101,
        &[first_bytes.clone(), second_bytes.clone()],
        &kernel,
    )?;
    let checkpoint_transparency = build_checkpoint_transparency(std::slice::from_ref(&checkpoint))?;
    let log_id = checkpoint_log_id(&checkpoint);
    let evidence_checkpoint_ref = format!("{log_id}#1");

    let mut profile_body = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_string(),
        profile_id: String::new(),
        governance_authority: governance.public_key(),
        operator: "venue-operator".to_string(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: key_policy(21, "production"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: key_policy(12, "delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: key_policy(13, "replay"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id,
            signer: key_policy(21, "checkpoint"),
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "bbs-issuer-fp".to_string(),
            key_hex: HEX64.to_string(),
            registry_ref: "registry/bbs-issuers".to_string(),
            key_epoch: 1,
            valid_from: 1_700_000_000,
            valid_until: 1_900_000_000,
            revocation_status_ref: "revocations/bbs".to_string(),
        },
        allowed_runner_manifests: vec![HEX64.to_string()],
        required_receipt_semantics: "chio.mediated_spend.v1".to_string(),
        resolver_policy_ref: "resolver-policy-v1".to_string(),
        retention_policy_ref: "retention-forever-v1".to_string(),
        resource_caps: resource_caps(),
        predicate_engine: "chio-replay-v1".to_string(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::RecipeBinding,
            FindingFacetKind::BondBacking,
            FindingFacetKind::GuaranteeConsistency,
        ],
        verifier_report_signer: key_policy(15, "verifier-report"),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    profile_body.profile_id = compute_profile_id(&profile_body)?;
    let profile = SignedExportEnvelope::sign(profile_body, &governance)?;
    let profile_envelope_sha256 = sha256_hex(&canonical_json_bytes(&profile)?);

    // The recipe commits the admitted profile; the finding then commits
    // the recipe. Reversing either edge would be a hash cycle.
    let recipe_input = recipe(HEX64, &payload_sha256, &profile_envelope_sha256, HEX64);
    let recipe_bytes = canonical_json_bytes(&recipe_input)?;
    let replay_recipe_sha256 = sha256_hex(&recipe_bytes);

    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "rust/workspace/test-failure".to_string(),
            context_sha256: HEX64.to_string(),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256,
        payload_media_type: "application/json".to_string(),
        evidence_receipt_ids: vec![first.id.clone(), second.id.clone()],
        evidence_checkpoint_ref,
        evidence_cost: MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        runtime_assurance_tier,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(replay_recipe_sha256),
        intent_commitment_receipt_id: None,
        bond_ref: "bond:pending-allocation".to_string(),
        status_feed_ref: "status-feed/venue-wedge".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &issuer)?;
    let raw_finding = String::from_utf8(canonical_json_bytes(&finding)?)?;

    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: collateral.public_key(),
        seller: seller.public_key(),
        authorization_envelope_sha256: HEX64.to_string(),
        finding_id: finding.finding_id.clone(),
        listing_id: "finding-listing-01".to_string(),
        terms_envelope_sha256: HEX64.to_string(),
        profile_envelope_sha256: HEX64.to_string(),
        fee_requirement_sha256: HEX64.to_string(),
        fee_schedule_envelope_sha256: HEX64.to_string(),
        bond_class: FindingBondClass::Listing,
        locked_amount: MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        },
        maximum_sale_exposure: MonetaryAmount {
            units: 450,
            currency: "USD".to_string(),
        },
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: "vault:finding-collateral".to_string(),
            operator_epoch: 1,
        },
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    backing.allocation_id = compute_allocation_id(&backing)?;
    let backing = SignedExportEnvelope::sign(backing, &collateral)?;

    let receipts = vec![
        ResolvedReceiptEvidence {
            receipt: first,
            canonical_receipt_bytes: first_bytes,
            inclusion_proof: build_inclusion_proof(&tree, 0, 1, 100)?,
        },
        ResolvedReceiptEvidence {
            receipt: second,
            canonical_receipt_bytes: second_bytes,
            inclusion_proof: build_inclusion_proof(&tree, 1, 1, 101)?,
        },
    ];

    Ok(Fixture {
        issuer,
        governance,
        verifier,
        raw_finding,
        finding_payload_sha256: finding.payload_sha256.clone(),
        receipts,
        checkpoint,
        checkpoint_transparency,
        recipe_bytes,
        backing,
        profile,
    })
}

struct RuntimeFixture {
    fixture: Fixture,
    attestation_authority: Keypair,
    appraisal_authority: Keypair,
    policy: AttestationTrustPolicy,
    attestation: SignedExportEnvelope<RuntimeAttestationEvidence>,
    appraisal: SignedRuntimeAttestationAppraisalReport,
}

fn runtime_fixture(effective_tier: RuntimeAssuranceTier) -> Result<RuntimeFixture, Box<dyn Error>> {
    let attestation_authority = keypair(31);
    let appraisal_authority = keypair(32);
    let evidence = RuntimeAttestationEvidence {
        schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
        verifier: "https://maa.cognition-market.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: 1_749_000_000,
        expires_at: 1_800_000_000,
        evidence_sha256: HEX64.to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {"attestationType": "sgx"}
        })),
    };
    let policy = AttestationTrustPolicy {
        rules: vec![AttestationTrustRule {
            name: "cognition-market-runtime".to_string(),
            schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://maa.cognition-market.test".to_string(),
            effective_tier,
            verifier_family: Some(
                chio_core_types::runtime_attestation::AttestationVerifierFamily::AzureMaa,
            ),
            max_evidence_age_seconds: Some(10_000_000),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: BTreeMap::new(),
        }],
    };
    let verified = verify_runtime_attestation_record(&evidence, Some(&policy), 1_750_000_000)?;
    let runtime_metadata = RuntimeAssuranceReceiptMetadata {
        schema: verified.evidence_schema().to_string(),
        verifier_family: Some(verified.verifier_family()),
        tier: verified.effective_tier(),
        verifier: verified.canonical_verifier().to_string(),
        evidence_sha256: verified.evidence_sha256().to_string(),
        workload_identity: verified.workload_identity().cloned(),
    };
    let fixture = fixture_with_runtime_assurance(Some(effective_tier), Some(&runtime_metadata))?;
    let attestation = SignedExportEnvelope::sign(evidence, &attestation_authority)?;
    let appraisal = SignedExportEnvelope::sign(
        RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 1_750_000_000,
            appraisal: verified.appraisal,
            policy_outcome: verified.policy_outcome,
        },
        &appraisal_authority,
    )?;
    Ok(RuntimeFixture {
        fixture,
        attestation_authority,
        appraisal_authority,
        policy,
        attestation,
        appraisal,
    })
}

fn runtime_trust_roots(fx: &RuntimeFixture) -> FindingVerifierTrustRoots {
    let mut trust = trust_roots(&fx.fixture);
    trust.runtime_attestation_authority = Some(fx.attestation_authority.public_key());
    trust.appraisal_authority = Some(fx.appraisal_authority.public_key());
    trust.attestation_trust_policy = Some(fx.policy.clone());
    trust
}

fn runtime_bundle(fx: &RuntimeFixture) -> FindingEvidenceBundle<'_> {
    let mut evidence = bundle(&fx.fixture, clone_receipts(&fx.fixture));
    evidence.runtime_attestation = Some(fx.attestation.clone());
    evidence.runtime_appraisal = Some(fx.appraisal.clone());
    evidence
}

fn trust_roots(fx: &Fixture) -> FindingVerifierTrustRoots {
    FindingVerifierTrustRoots {
        governance_authority: fx.governance.public_key(),
        profile: fx.profile.clone(),
        admitted_kernel_keys: vec![keypair(21).public_key()],
        collateral_authority: keypair(4).public_key(),
        runtime_attestation_authority: None,
        appraisal_authority: None,
        attestation_trust_policy: None,
        status_operator_authorization: None,
        status_freshness_policy: None,
        trusted_time: 1_750_000_000,
        trust_root_snapshot_sha256: HEX64.to_string(),
        resolver_policy_sha256: HEX64.to_string(),
        trusted_time_input_sha256: HEX64.to_string(),
    }
}

fn resign_profile(
    mut body: FindingChallengeVerifierProfile,
) -> Result<SignedExportEnvelope<FindingChallengeVerifierProfile>, Box<dyn Error>> {
    body.profile_id = compute_profile_id(&body)?;
    Ok(SignedExportEnvelope::sign(body, &keypair(1))?)
}

fn bundle<'a>(
    fx: &'a Fixture,
    receipts: Vec<ResolvedReceiptEvidence>,
) -> FindingEvidenceBundle<'a> {
    FindingEvidenceBundle {
        receipts,
        checkpoints: vec![fx.checkpoint.clone()],
        checkpoint_transparency: fx.checkpoint_transparency.clone(),
        recipe_preimage: Some(fx.recipe_bytes.as_slice()),
        status_proof_input: None,
        runtime_attestation: None,
        runtime_appraisal: None,
        bond_snapshot: Some(FindingBondSnapshot {
            backing: fx.backing.clone(),
            live: true,
            accepted_at: 1_749_000_000,
        }),
        nonce_resolver: &NoNonceEvidence,
    }
}

fn portable_live_status_proof(
    finding_id: &str,
) -> Result<
    (
        Vec<u8>,
        FindingStatusOperatorAuthorization,
        FindingStatusFreshnessPolicy,
    ),
    Box<dyn Error>,
> {
    let operator = keypair(42);
    let mut map = FindingStatusSparseMap::new();
    let root = map.insert("aa".repeat(32).as_str(), "11".repeat(32).as_str())?;
    let sparse = map.proof(finding_id)?;
    let mut epoch = FindingStatusEpoch {
        schema: FINDING_STATUS_EPOCH_SCHEMA_V1.to_string(),
        status_epoch_id: String::new(),
        signature_domain: FINDING_STATUS_SIGNATURE_DOMAIN.to_string(),
        status_map_version: FINDING_STATUS_MAP_VERSION.to_string(),
        proof_semantics: FINDING_STATUS_PROOF_SEMANTICS.to_string(),
        feed_id: "status-feed/venue-wedge".to_string(),
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        map_epoch: root.map_epoch,
        operator_id: "venue-status-operator".to_string(),
        operator_key: operator.public_key(),
        operator_key_epoch: 1,
        root_hash: hex::encode(root.root_hash),
        tree_depth: FINDING_STATUS_SPARSE_DEPTH as u16,
        hash_algorithm: FINDING_STATUS_HASH_ALGORITHM.to_string(),
        key_hash_domain: FINDING_STATUS_KEY_HASH_DOMAIN.to_string(),
        empty_leaf_domain: FINDING_STATUS_EMPTY_LEAF_DOMAIN.to_string(),
        occupied_leaf_domain: FINDING_STATUS_OCCUPIED_LEAF_DOMAIN.to_string(),
        branch_domain: FINDING_STATUS_BRANCH_DOMAIN.to_string(),
        empty_leaf_hash: hex::encode(finding_status_empty_leaf_hash()),
        anchor_refs: vec!["anchor/status-feed/qualified".to_string()],
        generated_at: 1_750_000_000,
        valid_from: 1_749_999_900,
        valid_until: 1_750_000_300,
    };
    epoch.status_epoch_id = compute_status_epoch_id(&epoch)?;
    let signed = SignedExportEnvelope::sign(epoch, &operator)?;
    let proof =
        build_status_non_inclusion_proof_input(&signed, finding_id, &sparse, 1_750_000_030)?;
    let authorization = FindingStatusOperatorAuthorization {
        role: FindingStatusOperatorRole::FindingStatusOperator,
        feed_id: "status-feed/venue-wedge".to_string(),
        operator: FindingAuthorityKeyPolicy {
            authority_id: "venue-status-operator".to_string(),
            key: operator.public_key(),
            key_epoch: 1,
            valid_from: 1_749_999_900,
            valid_until: 1_750_000_300,
            rotation_policy_ref: "rotation/status-feed-v1".to_string(),
            revocation_status_ref: "revocations/status-feed-v1".to_string(),
        },
        revoked_from: None,
    };
    Ok((
        canonical_json_bytes(&proof)?,
        authorization,
        FindingStatusFreshnessPolicy {
            now: 1_750_000_030,
            max_epoch_age_secs: 60,
        },
    ))
}

fn clone_receipts(fx: &Fixture) -> Vec<ResolvedReceiptEvidence> {
    fx.receipts
        .iter()
        .map(|evidence| ResolvedReceiptEvidence {
            receipt: evidence.receipt.clone(),
            canonical_receipt_bytes: evidence.canonical_receipt_bytes.clone(),
            inclusion_proof: evidence.inclusion_proof.clone(),
        })
        .collect()
}

#[test]
fn full_evidence_bundle_verifies_the_required_facets() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;

    for (kind, expected) in [
        (
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetOutcome::Verified,
        ),
        (
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetOutcome::Verified,
        ),
        (
            FindingFacetKind::CheckpointMembership,
            FindingFacetOutcome::Verified,
        ),
        (
            FindingFacetKind::RecipeBinding,
            FindingFacetOutcome::Verified,
        ),
        (FindingFacetKind::BondBacking, FindingFacetOutcome::Verified),
        (
            FindingFacetKind::GuaranteeConsistency,
            FindingFacetOutcome::Verified,
        ),
        (
            FindingFacetKind::MeteredExposureBacking,
            FindingFacetOutcome::Unavailable,
        ),
        (
            FindingFacetKind::SettledSpendBacking,
            FindingFacetOutcome::Unavailable,
        ),
        (
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Unavailable,
        ),
    ] {
        assert_eq!(draft.facet_outcome(kind), Some(expected), "facet {kind:?}");
    }
    assert!(draft.satisfies_required_facets(&fx.profile.body));
    assert_eq!(
        draft.backing_allocation_id.as_deref(),
        Some(fx.backing.body.allocation_id.as_str())
    );

    // Report round trip under the pinned verifier authority.
    let signed =
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.verifier)?;
    verify_signed_verifier_report(&signed, &fx.verifier.public_key())?;
    Ok(())
}

#[test]
fn portable_status_proof_verifies_and_is_pinned_into_signed_report() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut trust = trust_roots(&fx);
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );
    assert_eq!(
        draft.replay_recipe_input_sha256.as_deref(),
        Some(sha256_hex(&fx.recipe_bytes).as_str())
    );
    assert_eq!(
        draft.status_proof_input_sha256.as_deref(),
        Some(sha256_hex(&status_bytes).as_str())
    );

    let signed =
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.verifier)?;
    verify_signed_verifier_report(&signed, &fx.verifier.public_key())?;
    assert_eq!(
        signed.body.replay_recipe_input_sha256,
        draft.replay_recipe_input_sha256
    );
    assert_eq!(
        signed.body.status_proof_input_sha256,
        draft.status_proof_input_sha256
    );
    Ok(())
}

#[test]
fn failed_optional_facet_denies_the_draft() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Unavailable)
    );
    assert!(!draft
        .required_facets(&fx.profile.body)
        .contains(&FindingFacetKind::StatusLiveness));

    let status = draft
        .facets
        .iter_mut()
        .find(|result| result.facet == FindingFacetKind::StatusLiveness)
        .ok_or("status liveness facet")?;
    status.outcome = FindingFacetOutcome::Failed;
    status.reason = "status proof contradicted the signed snapshot".to_string();

    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn signed_runtime_assurance_can_verify_each_claimed_tier() -> TestResult {
    for tier in [
        RuntimeAssuranceTier::Basic,
        RuntimeAssuranceTier::Attested,
        RuntimeAssuranceTier::Verified,
    ] {
        let fx = runtime_fixture(tier)?;
        let trust = runtime_trust_roots(&fx);
        let evidence = runtime_bundle(&fx);
        let draft = verify_finding_evidence(&fx.fixture.raw_finding, &trust, &evidence)?;
        assert_eq!(
            draft.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
            Some(FindingFacetOutcome::Verified),
            "tier {tier:?}"
        );
        assert!(draft.satisfies_required_facets(&fx.fixture.profile.body));
    }
    Ok(())
}

#[test]
fn resolved_bundle_commitment_includes_assurance_artifacts_pins_and_policy() -> TestResult {
    let fx = runtime_fixture(RuntimeAssuranceTier::Verified)?;
    let trust = runtime_trust_roots(&fx);
    let evidence = runtime_bundle(&fx);
    let baseline = verify_finding_evidence(&fx.fixture.raw_finding, &trust, &evidence)?;

    let alternate_attestation_authority = keypair(33);
    let mut alternate_trust = runtime_trust_roots(&fx);
    alternate_trust.runtime_attestation_authority =
        Some(alternate_attestation_authority.public_key());
    let mut alternate_evidence = runtime_bundle(&fx);
    alternate_evidence.runtime_attestation = Some(SignedExportEnvelope::sign(
        fx.attestation.body.clone(),
        &alternate_attestation_authority,
    )?);
    let alternate = verify_finding_evidence(
        &fx.fixture.raw_finding,
        &alternate_trust,
        &alternate_evidence,
    )?;
    assert_eq!(
        alternate.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256,
        alternate.resolved_evidence_bundle_sha256
    );

    let mut policy_trust = runtime_trust_roots(&fx);
    policy_trust
        .attestation_trust_policy
        .as_mut()
        .ok_or("missing policy")?
        .rules[0]
        .max_evidence_age_seconds = Some(2_000_000);
    let policy_evidence = runtime_bundle(&fx);
    let policy_changed =
        verify_finding_evidence(&fx.fixture.raw_finding, &policy_trust, &policy_evidence)?;
    assert_eq!(
        policy_changed.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256,
        policy_changed.resolved_evidence_bundle_sha256
    );

    let mut appraisal_evidence = runtime_bundle(&fx);
    let mut appraisal_body = fx.appraisal.body.clone();
    appraisal_body.generated_at -= 1;
    appraisal_evidence.runtime_appraisal = Some(SignedExportEnvelope::sign(
        appraisal_body,
        &fx.appraisal_authority,
    )?);
    let appraisal_changed =
        verify_finding_evidence(&fx.fixture.raw_finding, &trust, &appraisal_evidence)?;
    assert_eq!(
        appraisal_changed.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256,
        appraisal_changed.resolved_evidence_bundle_sha256
    );
    Ok(())
}

#[test]
fn runtime_assurance_rejects_empty_policy_and_unrelated_signed_evidence() -> TestResult {
    let fx = runtime_fixture(RuntimeAssuranceTier::Verified)?;

    let mut trust = runtime_trust_roots(&fx);
    trust.attestation_trust_policy = Some(AttestationTrustPolicy { rules: Vec::new() });
    let evidence = runtime_bundle(&fx);
    let draft = verify_finding_evidence(&fx.fixture.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(!draft.satisfies_required_facets(&fx.fixture.profile.body));

    // Both replacement artifacts are validly signed and locally appraised,
    // but they name different attestation evidence than the kernel signed
    // into the producing receipts.
    let mut replacement_evidence = fx.attestation.body.clone();
    replacement_evidence.evidence_sha256 = "1".repeat(64);
    let replacement_record =
        verify_runtime_attestation_record(&replacement_evidence, Some(&fx.policy), 1_750_000_000)?;
    let replacement_attestation =
        SignedExportEnvelope::sign(replacement_evidence, &fx.attestation_authority)?;
    let replacement_appraisal = SignedExportEnvelope::sign(
        RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 1_750_000_000,
            appraisal: replacement_record.appraisal,
            policy_outcome: replacement_record.policy_outcome,
        },
        &fx.appraisal_authority,
    )?;
    let trust = runtime_trust_roots(&fx);
    let mut evidence = runtime_bundle(&fx);
    evidence.runtime_attestation = Some(replacement_attestation);
    evidence.runtime_appraisal = Some(replacement_appraisal);
    let draft = verify_finding_evidence(&fx.fixture.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(!draft.satisfies_required_facets(&fx.fixture.profile.body));
    Ok(())
}

#[test]
fn runtime_assurance_rejects_invalid_or_stale_signed_artifacts() -> TestResult {
    let fx = runtime_fixture(RuntimeAssuranceTier::Verified)?;
    let trust = runtime_trust_roots(&fx);

    let mut invalid = runtime_bundle(&fx);
    invalid
        .runtime_appraisal
        .as_mut()
        .ok_or("missing appraisal")?
        .body
        .generated_at += 1;
    let draft = verify_finding_evidence(&fx.fixture.raw_finding, &trust, &invalid)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Failed)
    );

    let mut stale_trust = runtime_trust_roots(&fx);
    stale_trust.trusted_time = 1_800_000_000;
    let stale = runtime_bundle(&fx);
    let draft = verify_finding_evidence(&fx.fixture.raw_finding, &stale_trust, &stale)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RuntimeAssuranceBacking),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn raw_ingress_rejects_noncanonical_and_oversized_findings() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);

    let duplicate_keys = r#"{"schema":"chio.finding.v1","schema":"chio.finding.v1"}"#;
    assert_eq!(
        verify_finding_evidence(duplicate_keys, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::RawNotCanonical)
    );

    let padded = format!(" {}", fx.raw_finding);
    assert_eq!(
        verify_finding_evidence(&padded, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::RawBytesNotCanonical)
    );

    let oversized = format!(
        "{{\"pad\":\"{}\"}}",
        "a".repeat(chio_finding_verifier::MAX_RAW_FINDING_BYTES)
    );
    assert_eq!(
        verify_finding_evidence(&oversized, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::RawTooLarge)
    );
    Ok(())
}

#[test]
fn wrapper_tampering_fails_membership_on_every_closed_gap() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);

    // Outer leaf index diverges from the inner proof.
    let mut receipts = clone_receipts(&fx);
    receipts[0].inclusion_proof.leaf_index = 1;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, receipts))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );

    // Inner tree size diverges from the signed checkpoint.
    let mut receipts = clone_receipts(&fx);
    receipts[0].inclusion_proof.proof.tree_size = 3;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, receipts))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );

    // Claimed root diverges from the signed root.
    let mut receipts = clone_receipts(&fx);
    receipts[0].inclusion_proof.merkle_root = receipts[0]
        .inclusion_proof
        .proof
        .compute_root_from_hash(chio_core_types::merkle::leaf_hash(b"other"))?;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, receipts))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );

    // Receipt seq outside the batch range.
    let mut receipts = clone_receipts(&fx);
    receipts[0].inclusion_proof.receipt_seq = 999;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, receipts))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn checkpoint_equivocation_fails_before_membership() -> TestResult {
    let fx = fixture()?;
    let mut fork = fx.checkpoint.clone();
    fork.body.issued_at = fork.body.issued_at.saturating_add(1);
    fork.signature = keypair(21).sign(&canonical_json_bytes(&fork.body)?);
    let checkpoints = vec![fx.checkpoint.clone(), fork];
    let transparency = build_checkpoint_transparency(&checkpoints)?;

    assert_eq!(
        verify_checkpoint_membership(
            &fx.receipts,
            &checkpoints,
            &transparency,
            &fx.profile.body,
            &serde_json::from_str::<Finding>(&fx.raw_finding)?.evidence_checkpoint_ref,
        ),
        Err(CheckpointMembershipError::TransparencyInvalid)
    );
    Ok(())
}

#[test]
fn checkpoint_transparency_records_must_match_the_signed_set() -> TestResult {
    let fx = fixture()?;
    let mut transparency = fx.checkpoint_transparency.clone();
    transparency.publications.clear();

    assert_eq!(
        verify_checkpoint_membership(
            &fx.receipts,
            std::slice::from_ref(&fx.checkpoint),
            &transparency,
            &fx.profile.body,
            &serde_json::from_str::<Finding>(&fx.raw_finding)?.evidence_checkpoint_ref,
        ),
        Err(CheckpointMembershipError::TransparencyInvalid)
    );
    Ok(())
}

#[test]
fn reordered_receipts_fail_the_exact_binding() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut receipts = clone_receipts(&fx);
    receipts.swap(0, 1);
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, receipts))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn recipe_digest_mismatch_fails_and_denies_the_deterministic_claim() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut wrong_recipe = recipe(HEX64, HEX64, HEX64, HEX64);
    wrong_recipe.decision_rule_ref = "decision/other".to_string();
    let wrong_bytes = canonical_json_bytes(&wrong_recipe)?;
    let mut evidence_bundle = bundle(&fx, clone_receipts(&fx));
    evidence_bundle.recipe_preimage = Some(wrong_bytes.as_slice());
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence_bundle)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RecipeBinding),
        Some(FindingFacetOutcome::Failed)
    );
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::GuaranteeConsistency),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn missing_bond_snapshot_is_unavailable_and_denies() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence_bundle = bundle(&fx, clone_receipts(&fx));
    evidence_bundle.bond_snapshot = None;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence_bundle)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::BondBacking),
        Some(FindingFacetOutcome::Unavailable)
    );
    assert!(draft.backing_allocation_id.is_none());
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn unpinned_profile_or_empty_kernel_keys_reject_outright() -> TestResult {
    let fx = fixture()?;

    let mut trust = trust_roots(&fx);
    trust.governance_authority = keypair(9).public_key();
    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::ProfileInvalid)
    );

    let mut trust = trust_roots(&fx);
    trust.admitted_kernel_keys.clear();
    assert_eq!(
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
        Some(FindingVerifierError::NoAdmittedKernelKeys)
    );
    Ok(())
}

#[test]
fn report_signing_requires_the_profile_authorized_key() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    let interloper = keypair(9);
    assert_eq!(
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &interloper)
            .err(),
        Some(FindingVerifierError::ReportSignerMismatch)
    );
    // The issuer key is also not the report signer.
    assert!(
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.issuer)
            .is_err()
    );
    Ok(())
}

#[test]
fn receipt_and_checkpoint_signers_must_cover_the_evidence_timestamp() -> TestResult {
    let fx = fixture()?;

    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    let first_receipt_time = fx.receipts[0].receipt.timestamp;
    for signer in &mut profile.receipt_signers {
        if signer.role == FindingReceiptRole::Production {
            signer.policy.valid_until = first_receipt_time;
        }
    }
    trust.profile = resign_profile(profile)?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );

    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    profile.checkpoint_logs[0].signer.valid_until = fx.checkpoint.body.issued_at;
    trust.profile = resign_profile(profile)?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn report_signer_policy_must_cover_the_evaluation_time() -> TestResult {
    let fx = fixture()?;
    let original_trust = trust_roots(&fx);
    let draft = verify_finding_evidence(
        &fx.raw_finding,
        &original_trust,
        &bundle(&fx, clone_receipts(&fx)),
    )?;

    let mut trust = trust_roots(&fx);
    let mut profile = fx.profile.body.clone();
    profile.verifier_report_signer.valid_until = draft.evaluation_time;
    trust.profile = resign_profile(profile)?;
    assert_eq!(
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.verifier,)
            .err(),
        Some(FindingVerifierError::ReportSignerInactive)
    );
    Ok(())
}

#[test]
fn recipe_must_bind_the_finding_it_is_committed_by() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let profile_sha256 = sha256_hex(&canonical_json_bytes(&fx.profile)?);

    // A recipe for a different payload, committed at the right digest,
    // still fails: the digest proves retention, not aboutness.
    let other_payload = "1".repeat(64);
    let foreign = recipe(HEX64, &other_payload, &profile_sha256, HEX64);
    let foreign_bytes = canonical_json_bytes(&foreign)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.recipe_preimage = Some(foreign_bytes.as_slice());
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RecipeBinding),
        Some(FindingFacetOutcome::Failed)
    );

    // A recipe committing an unadmitted profile fails the same way.
    let wrong_profile = recipe(HEX64, &fx.finding_payload_sha256, HEX64, HEX64);
    let wrong_bytes = canonical_json_bytes(&wrong_profile)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.recipe_preimage = Some(wrong_bytes.as_slice());
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::RecipeBinding),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn backing_signed_by_an_unpinned_authority_is_not_bond_evidence() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    trust.collateral_authority = keypair(9).public_key();
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::BondBacking),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(draft.backing_allocation_id.is_none());
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn receipts_signed_by_an_unpinned_kernel_are_not_authentic() -> TestResult {
    let fx = fixture()?;
    let mut trust = trust_roots(&fx);
    // Drop the production signer pin while leaving the receipts and
    // their strict signatures untouched.
    let mut profile_body = fx.profile.body.clone();
    for signer in &mut profile_body.receipt_signers {
        if signer.role == FindingReceiptRole::Production {
            signer.policy.key = keypair(9).public_key();
        }
    }
    profile_body.profile_id = compute_profile_id(&profile_body)?;
    trust.profile = SignedExportEnvelope::sign(profile_body, &keypair(1))?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn guarantee_consistency_denies_an_unbacked_metered_claim() -> TestResult {
    let fx = metered_attested_fixture()?;
    let trust = trust_roots(&fx);
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    // Metered exposure is unavailable without nonce evidence, so the
    // metered_attested claim must not be consistent.
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::MeteredExposureBacking),
        Some(FindingFacetOutcome::Unavailable)
    );
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::GuaranteeConsistency),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}
