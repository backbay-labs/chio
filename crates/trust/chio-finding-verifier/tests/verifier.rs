//! Behavioral coverage for the finding evidence verifier: a real signed
//! finding over real kernel-signed receipts committed to a real
//! checkpoint, then adversarial tampering on every wrapper dimension the
//! shipped inclusion-proof verify leaves unchecked.

use std::error::Error;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::MerkleTree;
use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    compute_allocation_id, compute_finding_id, compute_profile_id, sign_finding,
    verify_signed_verifier_report, Finding, FindingAuthorityKeyPolicy, FindingBbsIssuerPolicy,
    FindingBondBacking, FindingBondClass, FindingChallengeVerifierProfile,
    FindingCheckpointLogPolicy, FindingClaimedVerdict, FindingCollateralVault, FindingDescriptor,
    FindingEvidenceClass, FindingFacetKind, FindingFacetOutcome, FindingGuaranteeClass,
    FindingOutcomeClass, FindingPredicate, FindingReceiptRole, FindingReceiptSignerRole,
    FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind, FindingReplayRecipeInput,
    FindingResourceCaps, FINDING_BOND_BACKING_SCHEMA_V1,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
    FINDING_SCHEMA_V1,
};
use chio_finding_verifier::{
    sign_finding_verifier_report, verify_finding_evidence, FindingBondSnapshot,
    FindingEvidenceBundle, FindingVerifierError, FindingVerifierTrustRoots, NoNonceEvidence,
    ResolvedReceiptEvidence,
};
use chio_kernel::checkpoint::{
    build_checkpoint, build_inclusion_proof, checkpoint_log_id, KernelCheckpoint,
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
) -> Result<ChioReceipt, Box<dyn Error>> {
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
        metadata: None,
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
    let issuer = keypair(3);
    let governance = keypair(1);
    let kernel = keypair(21);
    let verifier = keypair(15);
    let collateral = keypair(4);
    let seller = keypair(2);

    // Receipts first: the finding binds their recomputed ids in order.
    let payload_sha256 = HEX64.to_string();
    let first = receipt(&kernel, 0, HEX64)?;
    let second = receipt(&kernel, 1, HEX64)?;
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
        runtime_assurance_tier: None,
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
        recipe_bytes,
        backing,
        profile,
    })
}

fn trust_roots(fx: &Fixture) -> FindingVerifierTrustRoots {
    FindingVerifierTrustRoots {
        governance_authority: fx.governance.public_key(),
        profile: fx.profile.clone(),
        admitted_kernel_keys: vec![keypair(21).public_key()],
        collateral_authority: keypair(4).public_key(),
        trusted_time: 1_750_000_000,
        trust_root_snapshot_sha256: HEX64.to_string(),
        resolver_policy_sha256: HEX64.to_string(),
        trusted_time_input_sha256: HEX64.to_string(),
    }
}

fn bundle<'a>(
    fx: &'a Fixture,
    receipts: Vec<ResolvedReceiptEvidence>,
) -> FindingEvidenceBundle<'a> {
    FindingEvidenceBundle {
        receipts,
        checkpoints: vec![fx.checkpoint.clone()],
        recipe_preimage: Some(fx.recipe_bytes.as_slice()),
        bond_snapshot: Some(FindingBondSnapshot {
            backing: fx.backing.clone(),
            live: true,
            accepted_at: 1_749_000_000,
        }),
        nonce_resolver: &NoNonceEvidence,
    }
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
