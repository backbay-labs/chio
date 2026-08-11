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
use chio_core_types::message::{ExecutionNonce, NonceBinding, SignedExecutionNonce};
use chio_core_types::receipt::authoritative_spend::BudgetAuthorityReceiptRef;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::governance::{
    GovernedTransactionReceiptMetadata, RuntimeAssuranceReceiptMetadata,
};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::metadata::{
    DeliveryContract, DeliveryResult, FindingDelivery, FindingDeliverySettlementMode,
    FindingMediaTypeCheck, FindingTransformProfile, FINDING_DELIVERY_METADATA_KEY,
    FINDING_DELIVERY_SCHEMA,
};
use chio_core_types::MerkleTree;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    build_status_non_inclusion_proof_input, compute_allocation_id, compute_finding_id,
    compute_profile_id, compute_status_epoch_id, sign_finding, verify_signed_verifier_report,
    Finding, FindingAuthorityKeyPolicy, FindingAuthorityStatus, FindingBbsIssuerPolicy,
    FindingBondBacking, FindingBondClass, FindingChallengeVerifierProfile,
    FindingCheckpointLogPolicy, FindingClaimedVerdict, FindingCollateralVault, FindingDescriptor,
    FindingEvidenceClass, FindingFacetKind, FindingFacetOutcome, FindingGuaranteeClass,
    FindingOutcomeClass, FindingPredicate, FindingReceiptRole, FindingReceiptSignerRole,
    FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind, FindingReplayRecipeInput,
    FindingResourceCaps, FindingStatusEpoch, FindingStatusFreshnessPolicy,
    FindingStatusOperatorAuthorization, FindingStatusOperatorRole, SignedFindingAuthorityStatus,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1, FINDING_BOND_BACKING_SCHEMA_V1,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
    FINDING_SCHEMA_V1, FINDING_STATUS_EPOCH_SCHEMA_V1, FINDING_STATUS_SIGNATURE_DOMAIN,
};
use chio_finding_verifier::{
    sign_finding_verifier_report, verify_checkpoint_membership, verify_finding_evidence,
    CheckpointMembershipError, FindingBondSnapshot, FindingBondStoreSnapshot,
    FindingCheckpointSignerStatusTrust, FindingEvidenceBundle, FindingNonceResolver,
    FindingVerifierError, FindingVerifierTrustRoots, NoNonceEvidence,
    ResolvedFindingDeliveryEvidence, ResolvedReceiptEvidence, SignedFindingBondStoreSnapshot,
    FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1,
};
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_transparency, build_checkpoint_with_previous,
    build_inclusion_proof, checkpoint_chain_leaf_hash, checkpoint_log_id,
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

fn checkpoint_at(
    mut checkpoint: KernelCheckpoint,
    issued_at: u64,
    signer: &Keypair,
) -> Result<KernelCheckpoint, Box<dyn Error>> {
    checkpoint.body.issued_at = issued_at;
    checkpoint.signature = signer.sign(&canonical_json_bytes(&checkpoint.body)?);
    Ok(checkpoint)
}

fn receipt(
    kernel: &Keypair,
    index: u32,
    content_hash: &str,
    runtime_assurance: Option<&RuntimeAssuranceReceiptMetadata>,
    delivery_contract: bool,
    finding_delivery: Option<FindingDelivery>,
) -> Result<ChioReceipt, Box<dyn Error>> {
    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "budget_authority".to_owned(),
        serde_json::json!({
            "guarantee_level": "single_node_atomic",
            "authority_profile": "authoritative_hold_event",
            "metering_profile": "max_cost_preauthorize_then_reconcile_actual",
            "hold_id": format!("hold-evidence-{index}"),
            "execution_nonce_id": format!("nonce-evidence-{index}"),
            "mediated_spend": { "profile": "chio.mediated_spend.v1" },
            "authorize": {
                "event_id": format!("hold-evidence-{index}:authorize"),
                "exposure_units": 1,
                "committed_cost_units_after": 1
            },
            "terminal": {
                "disposition": "reconciled",
                "event_id": format!("hold-evidence-{index}:reconcile"),
                "exposure_units": 1,
                "realized_spend_units": 1,
                "committed_cost_units_after": 1
            }
        }),
    );
    metadata.insert(
        "financial".to_owned(),
        serde_json::json!({
            "grant_index": 0,
            "cost_charged": 1,
            "currency": "USD",
            "budget_remaining": 99,
            "budget_total": 100,
            "delegation_depth": 0,
            "root_budget_holder": "finding-producer",
            "settlement_status": "settled"
        }),
    );
    if delivery_contract {
        metadata.insert(
            "delivery_contract".to_owned(),
            serde_json::to_value(DeliveryContract {
                schema: chio_core_types::receipt::metadata::DELIVERY_CONTRACT_SCHEMA.to_owned(),
                expected_digest: content_hash.to_owned(),
                observed_digest: content_hash.to_owned(),
                result: DeliveryResult::Matched,
            })?,
        );
    }
    if let Some(finding_delivery) = finding_delivery {
        metadata.insert(
            FINDING_DELIVERY_METADATA_KEY.to_owned(),
            serde_json::to_value(finding_delivery)?,
        );
    }
    if let Some(runtime_assurance) = runtime_assurance {
        metadata.insert(
            "governed_transaction".to_owned(),
            serde_json::to_value(GovernedTransactionReceiptMetadata {
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
            })?,
        );
    }
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
        metadata: (!metadata.is_empty()).then_some(serde_json::Value::Object(metadata)),
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    Ok(ChioReceipt::sign(body, kernel)?)
}

fn execution_nonce(
    receipt: &ChioReceipt,
    kernel: &Keypair,
) -> Result<SignedExecutionNonce, Box<dyn Error>> {
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or("receipt budget authority missing")?;
    let nonce = ExecutionNonce {
        schema: "chio.execution_nonce.v1".to_string(),
        nonce_id: budget
            .execution_nonce_id
            .ok_or("receipt execution nonce id missing")?,
        issued_at: i64::try_from(receipt.timestamp.saturating_sub(1))?,
        expires_at: i64::try_from(receipt.timestamp.saturating_add(60))?,
        bound_to: NonceBinding {
            subject_id: "finding-producer".to_string(),
            request_id: format!("request-{}", receipt.id),
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
        },
        reserved_hold_id: Some(budget.hold_id),
        reserving_request_id: None,
    };
    let signature = kernel.sign(&canonical_json_bytes(&nonce)?);
    Ok(SignedExecutionNonce { nonce, signature })
}

struct TestNonceResolver {
    nonces: Vec<SignedExecutionNonce>,
}

impl FindingNonceResolver for TestNonceResolver {
    fn nonce_for(&self, receipt: &ChioReceipt) -> Option<&SignedExecutionNonce> {
        let nonce_id = BudgetAuthorityReceiptRef::from_receipt(receipt)?.execution_nonce_id?;
        self.nonces
            .iter()
            .find(|nonce| nonce.nonce_id() == nonce_id)
    }
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
    bond_store_snapshot: SignedFindingBondStoreSnapshot,
    profile: SignedExportEnvelope<FindingChallengeVerifierProfile>,
    nonce_resolver: TestNonceResolver,
    checkpoint_status_authority: Keypair,
    checkpoint_signer_status: SignedFindingAuthorityStatus,
    receipt_signer_statuses: Vec<SignedFindingAuthorityStatus>,
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
    finding.evidence_cost.units = 10;
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
    let first = receipt(
        &kernel,
        0,
        &sha256_hex(b"production-output-0"),
        runtime_assurance,
        false,
        None,
    )?;
    let second = receipt(
        &kernel,
        1,
        &sha256_hex(b"production-output-1"),
        runtime_assurance,
        false,
        None,
    )?;
    let nonce_resolver = TestNonceResolver {
        nonces: vec![
            execution_nonce(&first, &kernel)?,
            execution_nonce(&second, &kernel)?,
        ],
    };
    let first_bytes = canonical_json_bytes(&first)?;
    let second_bytes = canonical_json_bytes(&second)?;
    let leaves = [first_bytes.clone(), second_bytes.clone()];
    let tree = MerkleTree::from_leaves(&leaves)?;
    let checkpoint = checkpoint_at(
        build_checkpoint(1, 1, 2, &leaves, &kernel)?,
        1_750_000_001,
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
            units: 2,
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
        issued_at: 1_750_000_002,
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
        profile_envelope_sha256: profile_envelope_sha256.clone(),
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
    let bond_store_snapshot = SignedExportEnvelope::sign(
        FindingBondStoreSnapshot {
            schema: FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1.to_string(),
            finding_id: finding.finding_id.clone(),
            allocation_id: backing.body.allocation_id.clone(),
            backing_envelope_sha256: sha256_hex(&canonical_json_bytes(&backing)?),
            live: true,
            accepted_at: 1_749_000_000,
            observed_at: 1_750_000_010,
        },
        &collateral,
    )?;

    let receipts = vec![
        ResolvedReceiptEvidence {
            receipt: first,
            canonical_receipt_bytes: first_bytes,
            inclusion_proof: build_inclusion_proof(&tree, 0, 1, 1)?,
        },
        ResolvedReceiptEvidence {
            receipt: second,
            canonical_receipt_bytes: second_bytes,
            inclusion_proof: build_inclusion_proof(&tree, 1, 1, 2)?,
        },
    ];

    let checkpoint_status_authority = keypair(22);
    let checkpoint_signer = profile
        .body
        .checkpoint_logs
        .first()
        .ok_or("fixture checkpoint signer policy is missing")?
        .signer
        .clone();
    let checkpoint_signer_status = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_string(),
            status_ref: checkpoint_signer.revocation_status_ref,
            authority_id: checkpoint_signer.authority_id,
            key: checkpoint_signer.key,
            key_epoch: checkpoint_signer.key_epoch,
            revoked_from: None,
            observed_at: 1_750_000_010,
        },
        &checkpoint_status_authority,
    )?;
    let receipt_signer_statuses = receipt_security_regressions::receipt_signer_statuses(
        &profile,
        &checkpoint_status_authority,
    )?;

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
        bond_store_snapshot,
        profile,
        nonce_resolver,
        checkpoint_status_authority,
        checkpoint_signer_status,
        receipt_signer_statuses,
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
        admitted_kernel_keys: vec![keypair(21).public_key(), keypair(12).public_key()],
        collateral_authority: keypair(4).public_key(),
        runtime_attestation_authority: None,
        appraisal_authority: None,
        attestation_trust_policy: None,
        status_operator_authorization: None,
        status_freshness_policy: None,
        checkpoint_signer_status: Some(FindingCheckpointSignerStatusTrust {
            signed_statuses: std::iter::once(fx.checkpoint_signer_status.clone())
                .chain(fx.receipt_signer_statuses.iter().cloned())
                .collect(),
            status_authority: fx.checkpoint_status_authority.public_key(),
            max_age_secs: 300,
        }),
        trusted_time: 1_750_000_010,
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
        finding_delivery: None,
        recipe_preimage: Some(fx.recipe_bytes.as_slice()),
        status_proof_input: None,
        runtime_attestation: None,
        runtime_appraisal: None,
        bond_snapshot: Some(FindingBondSnapshot {
            backing: fx.backing.clone(),
            store_snapshot: fx.bond_store_snapshot.clone(),
        }),
        nonce_resolver: &fx.nonce_resolver,
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
    portable_live_status_proof_for_feed(finding_id, "status-feed/venue-wedge")
}

fn portable_live_status_proof_for_feed(
    finding_id: &str,
    feed_id: &str,
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
        feed_id: feed_id.to_string(),
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
        feed_id: feed_id.to_string(),
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

fn finding_delivery_overlay(finding_id: &str) -> FindingDelivery {
    FindingDelivery {
        schema: FINDING_DELIVERY_SCHEMA.to_string(),
        finding_id: finding_id.to_string(),
        listing_id: "listing-qualified-1".to_string(),
        transform_profile: FindingTransformProfile::Identity,
        digest_check: DeliveryResult::Matched,
        media_type_check: FindingMediaTypeCheck::Matched,
        settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
        accepted_bid_envelope_sha256: HEX64.to_string(),
        venue_admission_envelope_sha256: HEX64.to_string(),
        reservation_id: "reservation-qualified-1".to_string(),
        purchase_intent_id: "intent-qualified-1".to_string(),
        authoritative_payment_operation_id: "payment-qualified-1".to_string(),
        status_proof: None,
    }
}

fn resolved_delivery(
    fx: &Fixture,
    content_hash: &str,
    overlay: Option<FindingDelivery>,
) -> Result<ResolvedFindingDeliveryEvidence, Box<dyn Error>> {
    resolved_delivery_at(fx, content_hash, overlay, 2, 1_750_000_003)
}

fn resolved_delivery_at(
    fx: &Fixture,
    content_hash: &str,
    overlay: Option<FindingDelivery>,
    receipt_index: u32,
    checkpoint_time: u64,
) -> Result<ResolvedFindingDeliveryEvidence, Box<dyn Error>> {
    resolved_delivery_with_times(
        fx,
        content_hash,
        overlay,
        receipt_index,
        1_750_000_000 + u64::from(receipt_index),
        checkpoint_time,
    )
}

fn resolved_delivery_with_times(
    fx: &Fixture,
    content_hash: &str,
    overlay: Option<FindingDelivery>,
    receipt_index: u32,
    receipt_time: u64,
    checkpoint_time: u64,
) -> Result<ResolvedFindingDeliveryEvidence, Box<dyn Error>> {
    let mut receipt = receipt(
        &keypair(12),
        receipt_index,
        content_hash,
        None,
        true,
        overlay,
    )?;
    if receipt.timestamp != receipt_time {
        let mut body = receipt.body();
        body.timestamp = receipt_time;
        receipt = ChioReceipt::sign(body, &keypair(12))?;
    }
    let receipt_bytes = canonical_json_bytes(&receipt)?;
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&receipt_bytes))?;
    let prior_chain_leaf = checkpoint_chain_leaf_hash(&fx.checkpoint.body)?;
    let checkpoint_signer = keypair(21);
    let checkpoint = checkpoint_at(
        build_checkpoint_with_previous(
            2,
            3,
            3,
            std::slice::from_ref(&receipt_bytes),
            &checkpoint_signer,
            Some(&fx.checkpoint),
            &[prior_chain_leaf],
        )?,
        checkpoint_time,
        &checkpoint_signer,
    )?;
    let checkpoints = vec![fx.checkpoint.clone(), checkpoint];
    let checkpoint_transparency = build_checkpoint_transparency(&checkpoints)?;
    Ok(ResolvedFindingDeliveryEvidence {
        receipt: ResolvedReceiptEvidence {
            receipt,
            canonical_receipt_bytes: receipt_bytes,
            inclusion_proof: build_inclusion_proof(&tree, 0, 2, 3)?,
        },
        checkpoints,
        checkpoint_transparency,
    })
}

fn nonce_resolver_with_delivery(
    fx: &Fixture,
    delivery: &ResolvedFindingDeliveryEvidence,
) -> Result<TestNonceResolver, Box<dyn Error>> {
    let mut nonces = fx.nonce_resolver.nonces.clone();
    nonces.push(execution_nonce(&delivery.receipt.receipt, &keypair(12))?);
    Ok(TestNonceResolver { nonces })
}

#[test]
fn full_evidence_bundle_verifies_the_required_facets() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    assert!(fx
        .receipts
        .iter()
        .all(|evidence| evidence.receipt.delivery_contract().is_none()));
    assert!(fx
        .receipts
        .iter()
        .all(|evidence| evidence.receipt.content_hash != fx.finding_payload_sha256));
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
            FindingFacetOutcome::Verified,
        ),
        (
            FindingFacetKind::SettledSpendBacking,
            FindingFacetOutcome::Verified,
        ),
        (
            FindingFacetKind::StatusLiveness,
            FindingFacetOutcome::Unavailable,
        ),
    ] {
        assert_eq!(draft.facet_outcome(kind), Some(expected), "facet {kind:?}");
    }
    assert!(draft.satisfies_required_facets(&fx.profile.body));
    assert!(draft.finding_delivery_receipt_id.is_none());
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
fn production_receipts_must_satisfy_the_profile_receipt_semantics() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut receipts = clone_receipts(&fx);
    let first = receipts.first_mut().ok_or("production receipt missing")?;
    let mut body = first.receipt.body();
    body.metadata
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|metadata| metadata.get_mut("budget_authority"))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("budget-authority metadata missing")?
        .remove("mediated_spend");
    first.receipt = ChioReceipt::sign(body, &keypair(21))?;
    first.canonical_receipt_bytes = canonical_json_bytes(&first.receipt)?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, receipts))?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(
        authenticity.reason.contains("required receipt semantics"),
        "unexpected reason: {}",
        authenticity.reason
    );
    Ok(())
}

#[test]
fn production_receipt_semantics_require_the_signed_execution_nonce() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let no_nonces = NoNonceEvidence;
    evidence.nonce_resolver = &no_nonces;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity
        .reason
        .contains("execution nonce evidence not supplied"));
    Ok(())
}

#[test]
fn production_receipt_semantics_reject_a_nonce_binding_mismatch() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut nonces = fx.nonce_resolver.nonces.clone();
    nonces
        .first_mut()
        .ok_or("execution nonce missing")?
        .nonce
        .bound_to
        .tool_name = "finding.other".to_string();
    let mismatched = TestNonceResolver { nonces };
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.nonce_resolver = &mismatched;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity.reason.contains("NonceBindingMismatch"));
    Ok(())
}

#[test]
fn post_purchase_delivery_requires_a_finding_specific_overlay() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let delivery = resolved_delivery(&fx, &fx.finding_payload_sha256, None)?;
    let delivery_nonces = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &delivery_nonces;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(
        authenticity.reason.contains("Finding delivery overlay"),
        "unexpected reason: {}",
        authenticity.reason
    );
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn post_purchase_delivery_is_finding_bound_and_checkpointed_in_the_report() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let delivery = resolved_delivery(
        &fx,
        &fx.finding_payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
    )?;
    let expected_receipt_id = delivery.receipt.receipt.id.clone();
    let delivery_nonces = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &delivery_nonces;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let checkpoint_membership = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::CheckpointMembership)
        .ok_or("checkpoint-membership facet missing")?;
    assert_eq!(
        checkpoint_membership.outcome,
        FindingFacetOutcome::Verified,
        "unexpected reason: {}",
        checkpoint_membership.reason
    );
    assert_eq!(
        draft.finding_delivery_receipt_id.as_deref(),
        Some(expected_receipt_id.as_str())
    );
    let report =
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.verifier)?;
    assert_eq!(
        report.body.finding_delivery_receipt_id.as_deref(),
        Some(expected_receipt_id.as_str())
    );
    Ok(())
}

#[test]
fn post_purchase_delivery_requires_the_signed_execution_nonce() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(resolved_delivery(
        &fx,
        &fx.finding_payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
    )?);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity
        .reason
        .contains("execution nonce evidence not supplied"));
    Ok(())
}

#[test]
fn post_purchase_delivery_cannot_predate_the_finding() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let delivery = resolved_delivery_with_times(
        &fx,
        &fx.finding_payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
        20,
        finding.issued_at.saturating_sub(1),
        1_750_000_003,
    )?;
    let delivery_nonces = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &delivery_nonces;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity.reason.contains("predates the Finding"));
    Ok(())
}

#[test]
fn post_purchase_delivery_rejects_a_receipt_after_report_evaluation() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let delivery = resolved_delivery_at(
        &fx,
        &fx.finding_payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
        20,
        1_750_000_003,
    )?;
    let delivery_nonces = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &delivery_nonces;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity.reason.contains("after report evaluation"));
    Ok(())
}

#[test]
fn post_purchase_delivery_rejects_a_checkpoint_after_report_evaluation() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let delivery = resolved_delivery_at(
        &fx,
        &fx.finding_payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
        2,
        1_750_000_020,
    )?;
    let delivery_nonces = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &delivery_nonces;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let membership = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::CheckpointMembership)
        .ok_or("checkpoint-membership facet missing")?;
    assert_eq!(membership.outcome, FindingFacetOutcome::Failed);
    assert!(membership.reason.contains("after report evaluation"));
    Ok(())
}

#[test]
fn production_receipts_cannot_postdate_report_evaluation() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut receipts = clone_receipts(&fx);
    let first = receipts.first_mut().ok_or("production receipt missing")?;
    let mut body = first.receipt.body();
    body.timestamp = trust.trusted_time.saturating_add(1);
    first.receipt = ChioReceipt::sign(body, &keypair(21))?;
    first.canonical_receipt_bytes = canonical_json_bytes(&first.receipt)?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, receipts))?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity.reason.contains("after report evaluation"));
    Ok(())
}

#[test]
fn production_receipts_cannot_postdate_the_finding() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    finding.issued_at = fx.receipts[0].receipt.timestamp.saturating_sub(1);
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &fx.issuer)?;
    let raw_finding = String::from_utf8(canonical_json_bytes(&finding)?)?;

    let draft = verify_finding_evidence(&raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    let authenticity = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::ReceiptAuthenticity)
        .ok_or("receipt-authenticity facet missing")?;
    assert_eq!(authenticity.outcome, FindingFacetOutcome::Failed);
    assert!(authenticity.reason.contains("issued after the Finding"));
    Ok(())
}

#[test]
fn production_checkpoints_cannot_postdate_the_finding() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.checkpoints[0] = checkpoint_at(
        evidence.checkpoints[0].clone(),
        trust.trusted_time.saturating_add(1),
        &keypair(21),
    )?;
    evidence.checkpoint_transparency = build_checkpoint_transparency(&evidence.checkpoints)?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let membership = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::CheckpointMembership)
        .ok_or("checkpoint-membership facet missing")?;
    assert_eq!(membership.outcome, FindingFacetOutcome::Failed);
    assert!(
        membership.reason.contains("after the Finding"),
        "unexpected reason: {}",
        membership.reason
    );
    Ok(())
}

#[test]
fn production_receipts_cannot_postdate_their_checkpoint() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.checkpoints[0] = checkpoint_at(
        evidence.checkpoints[0].clone(),
        fx.receipts[0].receipt.timestamp,
        &keypair(21),
    )?;
    evidence.checkpoint_transparency = build_checkpoint_transparency(&evidence.checkpoints)?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let membership = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::CheckpointMembership)
        .ok_or("checkpoint-membership facet missing")?;
    assert_eq!(membership.outcome, FindingFacetOutcome::Failed);
    assert!(
        membership.reason.contains("issued after checkpoint"),
        "unexpected reason: {}",
        membership.reason
    );
    Ok(())
}

#[test]
fn asserted_finding_can_be_verified_from_checkpointed_delivery_alone() -> TestResult {
    let fx = fixture()?;
    let mut finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    finding.guarantee_class = FindingGuaranteeClass::Asserted;
    finding.evidence_class = FindingEvidenceClass::Asserted;
    finding.evidence_receipt_ids.clear();
    finding.replay_recipe_sha256 = None;
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    let finding = sign_finding(finding, &fx.issuer)?;
    let raw_finding = String::from_utf8(canonical_json_bytes(&finding)?)?;

    let delivery = resolved_delivery(
        &fx,
        &finding.payload_sha256,
        Some(finding_delivery_overlay(&finding.finding_id)),
    )?;
    let expected_receipt_id = delivery.receipt.receipt.id.clone();
    let delivery_nonces = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, Vec::new());
    evidence.finding_delivery = Some(delivery);
    evidence.recipe_preimage = None;
    evidence.bond_snapshot = None;
    evidence.nonce_resolver = &delivery_nonces;

    let mut trust = trust_roots(&fx);
    let mut profile = trust.profile.body.clone();
    profile.required_facets = vec![
        FindingFacetKind::ArtifactIntegrity,
        FindingFacetKind::ReceiptAuthenticity,
        FindingFacetKind::CheckpointMembership,
        FindingFacetKind::GuaranteeConsistency,
    ];
    trust.profile = resign_profile(profile)?;

    let draft = verify_finding_evidence(&raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Verified)
    );
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Verified)
    );
    assert_eq!(
        draft.finding_delivery_receipt_id.as_deref(),
        Some(expected_receipt_id.as_str())
    );
    assert!(draft.satisfies_required_facets(&trust.profile.body));
    Ok(())
}

#[test]
fn post_purchase_delivery_rejects_an_overlay_for_another_finding() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let delivery = resolved_delivery(
        &fx,
        &fx.finding_payload_sha256,
        Some(finding_delivery_overlay(&"ab".repeat(32))),
    )?;
    let delivery_nonces = nonce_resolver_with_delivery(&fx, &delivery)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.finding_delivery = Some(delivery);
    evidence.nonce_resolver = &delivery_nonces;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );
    assert!(draft.finding_delivery_receipt_id.is_none());
    Ok(())
}

#[test]
fn portable_status_proof_verifies_and_is_pinned_into_signed_report() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut trust = trust_roots(&fx);
    trust.trusted_time = freshness.now;
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
fn resolved_bundle_commitment_includes_status_authorization_and_freshness() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let mut baseline_trust = trust_roots(&fx);
    baseline_trust.trusted_time = freshness.now;
    baseline_trust.status_operator_authorization = Some(authorization.clone());
    baseline_trust.status_freshness_policy = Some(freshness);
    let baseline = verify_finding_evidence(&fx.raw_finding, &baseline_trust, &evidence)?;
    assert_eq!(
        baseline.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );

    let mut alternate_authorization = authorization;
    alternate_authorization.operator.rotation_policy_ref =
        "status-rotation-policy/alternate".to_owned();
    let mut authorization_trust = trust_roots(&fx);
    authorization_trust.trusted_time = freshness.now;
    authorization_trust.status_operator_authorization = Some(alternate_authorization);
    authorization_trust.status_freshness_policy = Some(freshness);
    let authorization_changed =
        verify_finding_evidence(&fx.raw_finding, &authorization_trust, &evidence)?;
    assert_eq!(
        authorization_changed.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256,
        authorization_changed.resolved_evidence_bundle_sha256
    );

    let mut freshness_trust = trust_roots(&fx);
    freshness_trust.trusted_time = freshness.now;
    freshness_trust.status_operator_authorization =
        baseline_trust.status_operator_authorization.clone();
    freshness_trust.status_freshness_policy = Some(FindingStatusFreshnessPolicy {
        now: freshness.now,
        max_epoch_age_secs: freshness.max_epoch_age_secs + 1,
    });
    let freshness_changed = verify_finding_evidence(&fx.raw_finding, &freshness_trust, &evidence)?;
    assert_eq!(
        freshness_changed.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256,
        freshness_changed.resolved_evidence_bundle_sha256
    );
    Ok(())
}

#[test]
fn portable_status_proof_rejects_a_clock_different_from_report_evaluation() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut trust = trust_roots(&fx);
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let status = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::StatusLiveness)
        .ok_or("status-liveness facet missing")?;
    assert_eq!(status.outcome, FindingFacetOutcome::Failed);
    assert!(
        status.reason.contains("report evaluation time"),
        "unexpected reason: {}",
        status.reason
    );
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn portable_status_proof_must_bind_the_findings_declared_feed() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) =
        portable_live_status_proof_for_feed(&finding.finding_id, "status-feed/substituted")?;
    let mut trust = trust_roots(&fx);
    trust.trusted_time = freshness.now;
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let status = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::StatusLiveness)
        .ok_or("status-liveness facet missing")?;
    assert_eq!(status.outcome, FindingFacetOutcome::Failed);
    assert!(
        status.reason.contains("Finding status feed"),
        "unexpected reason: {}",
        status.reason
    );
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
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
fn report_evaluation_must_be_inside_the_finding_validity_window() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);

    for (issued_at, expires_at) in [
        (trust.trusted_time.saturating_add(1), 1_900_000_000),
        (1_700_000_000, trust.trusted_time),
    ] {
        let mut finding: Finding = serde_json::from_str(&fx.raw_finding)?;
        finding.issued_at = issued_at;
        finding.expires_at = expires_at;
        finding.signature.clear();
        finding.finding_id = compute_finding_id(&finding)?;
        let finding = sign_finding(finding, &fx.issuer)?;
        let raw_finding = String::from_utf8(canonical_json_bytes(&finding)?)?;
        assert_eq!(
            verify_finding_evidence(&raw_finding, &trust, &bundle(&fx, clone_receipts(&fx))).err(),
            Some(FindingVerifierError::FindingInactive)
        );
    }
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
    receipts[0].inclusion_proof.proof.tree_size = 4;
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
fn unsigned_collateral_store_state_is_not_verified() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence_bundle = bundle(&fx, clone_receipts(&fx));
    evidence_bundle
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?
        .store_snapshot
        .body
        .live = false;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence_bundle)?;
    let backing = draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::BondBacking)
        .ok_or("bond-backing facet missing")?;
    assert_eq!(backing.outcome, FindingFacetOutcome::Failed);
    assert!(backing.reason.contains("store snapshot rejected"));
    assert!(draft.backing_allocation_id.is_none());
    Ok(())
}

#[path = "verifier/authority_regressions.rs"]
mod authority_regressions;
#[path = "verifier/checkpoint_status_regressions.rs"]
mod checkpoint_status_regressions;
#[path = "verifier/receipt_security_regressions.rs"]
mod receipt_security_regressions;
