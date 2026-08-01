//! Behavioral and schema coverage for the challenge and audit families: the
//! class-gated challenge, its signed outcome and enforcement instruction,
//! the finalized bond snapshot, the audit epoch and report, the unsigned
//! replay observation preimage, and the open-market penalty envelope this
//! lane registers. Cross-artifact adjudication belongs to the evaluator and
//! is covered there.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, canonical_json_string};
use chio_finding::{
    compute_audit_epoch_id, compute_audit_report_id, compute_challenge_id, compute_enforcement_id,
    compute_snapshot_id, derive_audit_seed_commitment, derive_outcome_id,
    ensure_challenge_class_compatibility, signed_envelope_sha256, verdict_for_replay_predicate,
    verify_audit_report_epoch_binding, verify_outcome_challenge_binding, verify_signed_audit_epoch,
    verify_signed_audit_report, verify_signed_challenge, verify_signed_challenge_enforcement,
    verify_signed_challenge_outcome, verify_signed_finalized_bond_snapshot,
    FindingAffectedDelivery, FindingAuditEpoch, FindingAuditReport, FindingBuyerSubmission,
    FindingChallenge, FindingChallengeAuthorization, FindingChallengeAuthorizationKind,
    FindingChallengeEnforcement, FindingChallengeEvidence, FindingChallengeEvidenceKind,
    FindingChallengeFacet, FindingChallengeOutcome, FindingChallengeStanding,
    FindingChallengeVerdict, FindingCheckpointRef, FindingDigestMismatchFacet,
    FindingDisputeBondClass, FindingDisputeFeeEvent, FindingDisputeFeeTerminal,
    FindingDisputeLockRef, FindingEffectIntentBinding, FindingEffectIntentKind,
    FindingEnforcementDestination, FindingError, FindingEvidenceClass, FindingEvidenceInvalidFacet,
    FindingEvidenceInvalidity, FindingFinalizedBondSnapshot, FindingGuaranteeClass,
    FindingMissedAudit, FindingObservedFinality, FindingPenaltyCalculation, FindingPredicate,
    FindingReceiptRef, FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind,
    FindingReplayContradictionFacet, FindingReplayObservation, FindingReplayPredicateResult,
    FindingReplayRecipeInput, FindingReplayReproduction, FindingReplayTerminalResult,
    FindingResourceCaps, FindingVaultReference, FindingVenueAuditAuthorization,
    FINDING_AUDIT_EPOCH_SCHEMA_V1, FINDING_AUDIT_REPORT_SCHEMA_V1,
    FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1, FINDING_CHALLENGE_OUTCOME_SCHEMA_V1,
    FINDING_CHALLENGE_SCHEMA_V1, FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1,
    FINDING_REPLAY_OBSERVATION_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HEX64_ALT: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const HEX64_THIRD: &str = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
const SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// Every artifact family this lane registers. The round-trip coverage
/// assertion is keyed on this list, so a family added to the lane without a
/// value that reaches its registered schema fails here.
const CHALLENGE_LANE_FAMILIES: [&str; 7] = [
    "audit-epoch",
    "audit-report",
    "challenge",
    "challenge-enforcement",
    "challenge-outcome",
    "finalized-bond-snapshot",
    "replay-observation",
];

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn schema_path(family: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1")
        .join(format!("{family}.schema.json"))
}

fn validate_family_schema(
    family: &str,
    value: &Value,
) -> Result<(), chio_spec_validate::ValidateError> {
    let path = schema_path(family);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(&path, &schema, &path, value)
}

fn assert_family_schema_rejects(family: &str, value: &Value, case: &str) -> TestResult {
    match validate_family_schema(family, value) {
        Err(chio_spec_validate::ValidateError::SchemaViolation(_, _, _)) => Ok(()),
        Err(err) => Err(err.into()),
        Ok(()) => Err(std::io::Error::other(format!(
            "{family} schema accepted invalid case: {case}"
        ))
        .into()),
    }
}

/// The exact document a verifier reads: the artifact's canonical bytes,
/// parsed back. Schema conformance is checked over those bytes rather than
/// over an in-memory value that never crossed the wire.
fn canonical_document<T: serde::Serialize>(artifact: &T) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(&canonical_json_bytes(artifact)?)?)
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn recipe_body(profile_envelope_sha256: &str) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        context_sha256: HEX64.to_string(),
        payload_sha256: HEX64.to_string(),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: HEX64.to_string(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: HEX64.to_string(),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: HEX64_ALT.to_string(),
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
        resource_bounds: FindingResourceCaps {
            max_recipe_bytes: 262_144,
            max_evidence_receipts: 64,
            max_runtime_secs: 900,
            max_memory_bytes: 2_147_483_648,
        },
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: HEX64.to_string(),
        claimed_verdict: chio_finding::FindingClaimedVerdict::PredicateHolds,
    }
}

fn observation_body(
    recipe_digest: &str,
    profile_envelope_sha256: &str,
    phase: FindingRecipePhaseKind,
    run_id: &str,
) -> FindingReplayObservation {
    FindingReplayObservation {
        schema: FINDING_REPLAY_OBSERVATION_SCHEMA_V1.to_string(),
        recipe_digest: recipe_digest.to_string(),
        verifier_profile_digest: profile_envelope_sha256.to_string(),
        phase_id: phase,
        runner_manifest_digest: HEX64.to_string(),
        resolved_input_bundle_digest: match phase {
            FindingRecipePhaseKind::Baseline => HEX64.to_string(),
            FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
        },
        environment_digest: HEX64_THIRD.to_string(),
        terminal_result: FindingReplayTerminalResult::Completed,
        exit_code: match phase {
            FindingRecipePhaseKind::Baseline => 1,
            FindingRecipePhaseKind::Candidate => 0,
        },
        report_digest: match phase {
            FindingRecipePhaseKind::Baseline => HEX64.to_string(),
            FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
        },
        replay_run_id: run_id.to_string(),
    }
}

fn affected_delivery() -> FindingAffectedDelivery {
    FindingAffectedDelivery {
        receipt_id: "delivery-receipt-42".to_string(),
        receipt_sha256: HEX64.to_string(),
        checkpoint_ref: "checkpoints/venue-wedge/9001".to_string(),
        checkpoint_sha256: HEX64_ALT.to_string(),
    }
}

fn receipt_ref(receipt_id: &str) -> FindingReceiptRef {
    FindingReceiptRef {
        receipt_id: receipt_id.to_string(),
        receipt_sha256: HEX64.to_string(),
    }
}

fn checkpoint_ref() -> FindingCheckpointRef {
    FindingCheckpointRef {
        checkpoint_ref: "checkpoints/venue-wedge/9001".to_string(),
        checkpoint_sha256: HEX64_ALT.to_string(),
    }
}

fn buyer_authorization(
    challenger: &Keypair,
    standing: FindingChallengeStanding,
) -> FindingChallengeAuthorization {
    FindingChallengeAuthorization::BuyerSubmission(Box::new(FindingBuyerSubmission {
        challenger: challenger.public_key(),
        dispute_fee_terminal: FindingDisputeFeeTerminal {
            fee_schedule_envelope_sha256: HEX64.to_string(),
            event: FindingDisputeFeeEvent::ChallengeFiling,
            payer: challenger.public_key(),
            amount: usd(2_500),
            beneficiary_pool_principal_id: "pool:challenge-administration".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
        },
        dispute_lock_ref: FindingDisputeLockRef {
            lock_id: "dispute-lock-42".to_string(),
            class: FindingDisputeBondClass::Dispute,
            fee_schedule_envelope_sha256: HEX64.to_string(),
            amount: usd(10_000),
            expiry: 1_760_000_000,
        },
        standing,
    }))
}

fn venue_authorization() -> FindingChallengeAuthorization {
    FindingChallengeAuthorization::VenueAudit(FindingVenueAuditAuthorization {
        audit_epoch_envelope_sha256: HEX64.to_string(),
        selection_digest: HEX64_ALT.to_string(),
        authorization_digest: HEX64_THIRD.to_string(),
    })
}

fn digest_mismatch_evidence() -> FindingChallengeEvidence {
    FindingChallengeEvidence::DigestMismatch {
        failed_delivery_envelope_sha256: HEX64_THIRD.to_string(),
        deny_receipt_ref: receipt_ref("deny-receipt-42"),
        deny_checkpoint_ref: checkpoint_ref(),
    }
}

fn evidence_invalid_evidence() -> FindingChallengeEvidence {
    FindingChallengeEvidence::EvidenceInvalid {
        challenged_evidence_receipt_refs: vec![receipt_ref("evidence-receipt-1")],
        challenged_checkpoint_ref: checkpoint_ref(),
        purchase_record_envelope_sha256: HEX64_ALT.to_string(),
    }
}

fn replay_evidence(
    profile_envelope_sha256: &str,
) -> Result<FindingChallengeEvidence, Box<dyn Error>> {
    let recipe = recipe_body(profile_envelope_sha256);
    let recipe_preimage = canonical_json_string(&recipe)?;
    let recipe_digest = recipe.canonical_sha256()?;
    let reproduction = vec![
        FindingReplayReproduction {
            receipt_ref: receipt_ref("replay-receipt-baseline"),
            checkpoint_ref: checkpoint_ref(),
            observation_bytes: canonical_json_string(&observation_body(
                &recipe_digest,
                profile_envelope_sha256,
                FindingRecipePhaseKind::Baseline,
                "replay-run-42",
            ))?,
        },
        FindingReplayReproduction {
            receipt_ref: receipt_ref("replay-receipt-candidate"),
            checkpoint_ref: checkpoint_ref(),
            observation_bytes: canonical_json_string(&observation_body(
                &recipe_digest,
                profile_envelope_sha256,
                FindingRecipePhaseKind::Candidate,
                "replay-run-42",
            ))?,
        },
    ];
    Ok(FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        recipe_preimage,
        purchase_record_envelope_sha256: HEX64_ALT.to_string(),
    })
}

fn challenge_body(
    authorization: FindingChallengeAuthorization,
    evidence: FindingChallengeEvidence,
) -> Result<FindingChallenge, FindingError> {
    let mut challenge = FindingChallenge {
        schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
        challenge_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64_ALT.to_string(),
        listing_id: "finding-listing-01".to_string(),
        terms_envelope_sha256: HEX64.to_string(),
        profile_envelope_sha256: HEX64_THIRD.to_string(),
        venue_admission_envelope_sha256: HEX64.to_string(),
        backing_envelope_sha256: HEX64_ALT.to_string(),
        filed_at: 1_750_000_000,
        affected_deliveries: vec![affected_delivery()],
        authorization,
        evidence,
    };
    challenge.challenge_id = compute_challenge_id(&challenge)?;
    Ok(challenge)
}

fn failed_delivery_standing() -> FindingChallengeStanding {
    FindingChallengeStanding::FailedDelivery {
        failed_delivery_id: HEX64.to_string(),
        failed_delivery_envelope_sha256: HEX64_THIRD.to_string(),
    }
}

fn purchase_standing() -> FindingChallengeStanding {
    FindingChallengeStanding::FinalizedPurchase {
        purchase_key: HEX64.to_string(),
        purchase_record_envelope_sha256: HEX64_ALT.to_string(),
    }
}

fn buyer_digest_mismatch_challenge(challenger: &Keypair) -> Result<FindingChallenge, FindingError> {
    challenge_body(
        buyer_authorization(challenger, failed_delivery_standing()),
        digest_mismatch_evidence(),
    )
}

fn venue_replay_challenge() -> Result<FindingChallenge, Box<dyn Error>> {
    let evidence = replay_evidence(HEX64_THIRD)?;
    Ok(challenge_body(venue_authorization(), evidence)?)
}

fn outcome_body(
    challenge_envelope_sha256: &str,
    verdict: FindingChallengeVerdict,
    facet: FindingChallengeFacet,
) -> Result<FindingChallengeOutcome, FindingError> {
    let evidence_kind = facet.kind();
    let penalty_calculation = match verdict {
        FindingChallengeVerdict::Upheld => Some(FindingPenaltyCalculation {
            base_finding_stake_units: 100_000,
            open_per_sale_encumbrance_units: 20_000,
            computed_exposure_units: 120_000,
            listing_required_amount_units: 150_000,
            live_allocated_collateral_units: 130_000,
            penalty_amount: usd(120_000),
        }),
        _ => None,
    };
    let mut outcome = FindingChallengeOutcome {
        schema: FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_string(),
        outcome_id: String::new(),
        challenge_envelope_sha256: challenge_envelope_sha256.to_string(),
        finding_id: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        backing_allocation_id: HEX64_ALT.to_string(),
        authorization: FindingChallengeAuthorizationKind::BuyerSubmission,
        evidence_kind,
        verifier_profile_envelope_sha256: HEX64_THIRD.to_string(),
        evidence_bundle_digest: HEX64.to_string(),
        verdict,
        facet,
        reason: "committed payload digest does not match the delivered output".to_string(),
        trigger_digest: HEX64_ALT.to_string(),
        retry_deadline: None,
        penalty_calculation,
        evaluator_key_epoch: 7,
        evaluated_at: 1_750_000_500,
    };
    outcome.outcome_id = derive_outcome_id(&outcome)?;
    Ok(outcome)
}

fn upheld_outcome_with_penalty(
    penalty_calculation: FindingPenaltyCalculation,
) -> Result<FindingChallengeOutcome, FindingError> {
    let mut outcome = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    outcome.penalty_calculation = Some(penalty_calculation);
    outcome.outcome_id = derive_outcome_id(&outcome)?;
    Ok(outcome)
}

fn digest_mismatch_facet() -> FindingChallengeFacet {
    FindingChallengeFacet::DigestMismatch(FindingDigestMismatchFacet {
        committed_payload_sha256: HEX64.to_string(),
        delivered_output_sha256: HEX64_ALT.to_string(),
        transform_profile: "identity".to_string(),
        realized_spend_units: 0,
    })
}

fn replay_facet(result: FindingReplayPredicateResult) -> FindingChallengeFacet {
    FindingChallengeFacet::ReplayContradiction(FindingReplayContradictionFacet {
        replay_run_id: "replay-run-42".to_string(),
        recipe_sha256: HEX64.to_string(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        predicate_result: result,
        observation_digests: vec![HEX64.to_string(), HEX64_ALT.to_string()],
    })
}

fn enforcement_body() -> Result<FindingChallengeEnforcement, FindingError> {
    let mut enforcement = FindingChallengeEnforcement {
        schema: FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1.to_string(),
        enforcement_id: String::new(),
        liability_key: HEX64.to_string(),
        finding_id: HEX64_ALT.to_string(),
        listing_id: "finding-listing-01".to_string(),
        outcome_id: HEX64_THIRD.to_string(),
        outcome_envelope_sha256: HEX64.to_string(),
        penalty_envelope_sha256: HEX64_ALT.to_string(),
        bond_snapshot_envelope_sha256: HEX64_THIRD.to_string(),
        purchase_snapshot_digest: HEX64.to_string(),
        deterministic_allocation_digest: HEX64_ALT.to_string(),
        seller_allocation_id: HEX64_THIRD.to_string(),
        vault: FindingVaultReference {
            chain_id: "eip155:8453".to_string(),
            vault_contract: "0x00000000000000000000000000000000000000bd".to_string(),
            vault_id: "vault-42".to_string(),
        },
        amount: usd(120_000),
        destinations: vec![
            FindingEnforcementDestination {
                destination: "rail:venue-ledger:buyer-1".to_string(),
                amount: usd(90_000),
            },
            FindingEnforcementDestination {
                destination: "rail:venue-ledger:community-fund".to_string(),
                amount: usd(30_000),
            },
        ],
        effect_intents: vec![
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::SellerImpair,
                intent_id: HEX64.to_string(),
            },
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::RootIntent,
                intent_id: HEX64_ALT.to_string(),
            },
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::Retraction,
                intent_id: HEX64_THIRD.to_string(),
            },
        ],
        finalized_at: 1_750_100_000,
    };
    enforcement.enforcement_id = compute_enforcement_id(&enforcement)?;
    Ok(enforcement)
}

fn bond_snapshot_body(seller: &Keypair) -> Result<FindingFinalizedBondSnapshot, FindingError> {
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: "eip155:8453".to_string(),
        vault_contract: "0x00000000000000000000000000000000000000bd".to_string(),
        vault_id: "vault-42".to_string(),
        seller: seller.public_key(),
        allocation_id: HEX64.to_string(),
        locked_amount: 500_000,
        held_amount: 120_000,
        slashed_amount: 0,
        currency: "USD".to_string(),
        block_number: 21_000_000,
        block_hash: format!("0x{HEX64}"),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: HEX64_ALT.to_string(),
        operator_key_epoch: 3,
        observed_at: 1_750_090_000,
    };
    snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
    Ok(snapshot)
}

fn audit_epoch_body() -> Result<FindingAuditEpoch, FindingError> {
    let mut epoch = FindingAuditEpoch {
        schema: FINDING_AUDIT_EPOCH_SCHEMA_V1.to_string(),
        audit_epoch_id: String::new(),
        epoch_index: 4,
        eligible_snapshot_digest: HEX64.to_string(),
        eligible_listing_count: 128,
        fee_schedule_envelope_sha256: HEX64_ALT.to_string(),
        seed_commitment: derive_audit_seed_commitment(SEED),
        selection_algorithm_id: "weighted-reservoir-v1".to_string(),
        published_rate_bps: 250,
        available_budget: usd(750_000),
        authorization_digest: HEX64_THIRD.to_string(),
        committed_at: 1_750_000_000,
    };
    epoch.audit_epoch_id = compute_audit_epoch_id(&epoch)?;
    Ok(epoch)
}

fn audit_report_body(epoch_envelope_sha256: &str) -> Result<FindingAuditReport, FindingError> {
    let mut report = FindingAuditReport {
        schema: FINDING_AUDIT_REPORT_SCHEMA_V1.to_string(),
        audit_report_id: String::new(),
        audit_epoch_envelope_sha256: epoch_envelope_sha256.to_string(),
        revealed_seed: SEED.to_string(),
        selected_finding_ids: vec![HEX64.to_string(), HEX64_ALT.to_string()],
        attempt_receipt_ids: vec!["audit-attempt-1".to_string()],
        missed_attempts: vec![FindingMissedAudit {
            finding_id: HEX64_ALT.to_string(),
            reason: "retained replay inputs expired before the attempt".to_string(),
        }],
        outcome_envelope_digests: vec![HEX64_THIRD.to_string()],
        reported_at: 1_750_050_000,
    };
    report.audit_report_id = compute_audit_report_id(&report)?;
    Ok(report)
}

fn market_penalty_envelope() -> Result<Value, Box<dyn Error>> {
    let authority = keypair(31);
    let body = json!({
        "schema": "chio.registry.market-penalty.v1",
        "penaltyId": "market-penalty-42",
        "feeScheduleId": "fee-schedule-1",
        "charterId": "charter-1",
        "caseId": "case-1",
        "governingOperatorId": "venue-operator",
        "namespace": "findings",
        "listingId": "finding-listing-01",
        "abuseClass": "fraudulent_listing",
        "bondClass": "listing",
        "action": "hold_bond",
        "state": "enforced",
        "penaltyAmount": { "units": 120_000, "currency": "USD" },
        "openedAt": 1_750_000_000_u64,
        "updatedAt": 1_750_000_000_u64,
        "evidenceRefs": [
            {
                "kind": "external",
                "referenceId": HEX64,
                "sha256": HEX64_ALT,
            }
        ],
        "issuedBy": "venue-operator",
    });
    let envelope = SignedExportEnvelope::sign(body, &authority)?;
    Ok(serde_json::to_value(&envelope)?)
}

#[test]
fn challenge_content_address_is_stable_and_detects_tampering() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    (challenge.validate())?;
    assert_eq!(compute_challenge_id(&challenge)?, challenge.challenge_id);

    let mut tampered = buyer_digest_mismatch_challenge(&challenger)?;
    tampered.listing_id = "finding-listing-02".to_string();
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("challenge_id"))
    );

    let mut tampered = buyer_digest_mismatch_challenge(&challenger)?;
    tampered.filed_at += 1;
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("challenge_id"))
    );
    Ok(())
}

#[test]
fn challenge_authorization_union_rejects_cross_branch_members() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    let mut value: Value = serde_json::to_value(&challenge)?;
    value["authorization"]["buyer_submission"]["audit_epoch_envelope_sha256"] = json!(HEX64);
    assert!(serde_json::from_value::<FindingChallenge>(value.clone()).is_err());

    let venue = venue_replay_challenge()?;
    let mut value: Value = serde_json::to_value(&venue)?;
    value["authorization"]["venue_audit"]["challenger"] = json!(HEX64);
    assert!(serde_json::from_value::<FindingChallenge>(value).is_err());

    let mut value: Value = serde_json::to_value(&venue)?;
    value["authorization"]["venue_audit"]["dispute_lock_ref"] = json!({
        "lock_id": "dispute-lock-42",
        "class": "dispute",
        "fee_schedule_envelope_sha256": HEX64,
        "amount": { "units": 1, "currency": "USD" },
        "expiry": 1,
    });
    assert!(serde_json::from_value::<FindingChallenge>(value).is_err());

    // Both branches at once is not a union.
    let mut value: Value = serde_json::to_value(&challenge)?;
    value["authorization"]["venue_audit"] = json!({
        "audit_epoch_envelope_sha256": HEX64,
        "selection_digest": HEX64_ALT,
        "authorization_digest": HEX64_THIRD,
    });
    assert!(serde_json::from_value::<FindingChallenge>(value).is_err());
    Ok(())
}

#[test]
fn challenge_evidence_union_rejects_cross_class_members() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    let mut value: Value = serde_json::to_value(&challenge)?;
    value["evidence"]["digest_mismatch"]["purchase_record_envelope_sha256"] = json!(HEX64);
    assert!(serde_json::from_value::<FindingChallenge>(value).is_err());

    let mut value: Value = serde_json::to_value(&challenge)?;
    value["evidence"]["digest_mismatch"]["recipe_preimage"] = json!("{}");
    assert!(serde_json::from_value::<FindingChallenge>(value).is_err());

    let venue = venue_replay_challenge()?;
    let mut value: Value = serde_json::to_value(&venue)?;
    value["evidence"]["replay_contradiction"]["failed_delivery_envelope_sha256"] = json!(HEX64);
    assert!(serde_json::from_value::<FindingChallenge>(value).is_err());

    let mut value: Value = serde_json::to_value(&venue)?;
    value["evidence"]["digest_mismatch"] = json!({
        "failed_delivery_envelope_sha256": HEX64,
        "deny_receipt_ref": { "receipt_id": "deny-receipt-42", "receipt_sha256": HEX64 },
        "deny_checkpoint_ref": {
            "checkpoint_ref": "checkpoints/venue-wedge/9001",
            "checkpoint_sha256": HEX64_ALT,
        },
    });
    assert!(serde_json::from_value::<FindingChallenge>(value).is_err());
    Ok(())
}

#[test]
fn challenge_schema_closes_both_unions() -> TestResult {
    let challenger = keypair(41);
    let signed =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &challenger)?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("challenge", &value)?;

    let mut cross_authorization = value.clone();
    cross_authorization["body"]["authorization"]["buyer_submission"]
        ["audit_epoch_envelope_sha256"] = json!(HEX64);
    assert_family_schema_rejects(
        "challenge",
        &cross_authorization,
        "audit member inside a buyer submission",
    )?;

    let mut both_branches = value.clone();
    both_branches["body"]["authorization"]["venue_audit"] = json!({
        "audit_epoch_envelope_sha256": HEX64,
        "selection_digest": HEX64_ALT,
        "authorization_digest": HEX64_THIRD,
    });
    assert_family_schema_rejects("challenge", &both_branches, "two authorization branches")?;

    let mut cross_evidence = value.clone();
    cross_evidence["body"]["evidence"]["digest_mismatch"]["purchase_record_envelope_sha256"] =
        json!(HEX64);
    assert_family_schema_rejects(
        "challenge",
        &cross_evidence,
        "purchase member inside a digest mismatch",
    )?;

    let mut both_classes = value.clone();
    both_classes["body"]["evidence"]["evidence_invalid"] = json!({
        "challenged_evidence_receipt_refs": [
            { "receipt_id": "evidence-receipt-1", "receipt_sha256": HEX64 }
        ],
        "challenged_checkpoint_ref": {
            "checkpoint_ref": "checkpoints/venue-wedge/9001",
            "checkpoint_sha256": HEX64_ALT,
        },
        "purchase_record_envelope_sha256": HEX64_ALT,
    });
    assert_family_schema_rejects("challenge", &both_classes, "two evidence branches")?;

    let mut unknown = value.clone();
    unknown["body"]["surprise"] = json!(true);
    assert_family_schema_rejects("challenge", &unknown, "unknown body member")?;

    let mut wrong_schema = value;
    wrong_schema["body"]["schema"] = json!("chio.finding.challenge.v9");
    assert_family_schema_rejects("challenge", &wrong_schema, "wrong schema const")?;
    Ok(())
}

#[test]
fn challenge_requires_standing_matching_its_evidence_class() -> TestResult {
    let challenger = keypair(41);

    let mismatched = challenge_body(
        buyer_authorization(&challenger, purchase_standing()),
        digest_mismatch_evidence(),
    )?;
    assert_eq!(
        mismatched.validate(),
        Err(FindingError::InvalidField("standing"))
    );

    let mismatched = challenge_body(
        buyer_authorization(&challenger, failed_delivery_standing()),
        evidence_invalid_evidence(),
    )?;
    assert_eq!(
        mismatched.validate(),
        Err(FindingError::InvalidField("standing"))
    );

    // Right branch, wrong artifact digest.
    let wrong_digest = challenge_body(
        buyer_authorization(
            &challenger,
            FindingChallengeStanding::FinalizedPurchase {
                purchase_key: HEX64.to_string(),
                purchase_record_envelope_sha256: HEX64_THIRD.to_string(),
            },
        ),
        evidence_invalid_evidence(),
    )?;
    assert_eq!(
        wrong_digest.validate(),
        Err(FindingError::InvalidField("standing"))
    );

    let aligned = challenge_body(
        buyer_authorization(&challenger, purchase_standing()),
        evidence_invalid_evidence(),
    )?;
    (aligned.validate())?;

    // A buyer needs at least one affected delivery; a venue audit does not.
    let mut without_standing_receipt = aligned.clone();
    without_standing_receipt.affected_deliveries.clear();
    without_standing_receipt.challenge_id = compute_challenge_id(&without_standing_receipt)?;
    assert_eq!(
        without_standing_receipt.validate(),
        Err(FindingError::MissingEntry("affected_deliveries"))
    );

    let mut audit = venue_replay_challenge()?;
    audit.affected_deliveries.clear();
    audit.challenge_id = compute_challenge_id(&audit)?;
    (audit.validate())?;
    Ok(())
}

#[test]
fn replay_evidence_binds_one_run_and_the_committed_recipe() -> TestResult {
    let challenge = venue_replay_challenge()?;
    (challenge.validate())?;

    // Two runs cannot be spliced into one reproduction set.
    let recipe = recipe_body(HEX64_THIRD);
    let recipe_digest = recipe.canonical_sha256()?;
    let mut spliced = challenge.clone();
    if let FindingChallengeEvidence::ReplayContradiction { reproduction, .. } =
        &mut spliced.evidence
    {
        reproduction[1].observation_bytes = canonical_json_string(&observation_body(
            &recipe_digest,
            HEX64_THIRD,
            FindingRecipePhaseKind::Candidate,
            "replay-run-43",
        ))?;
    }
    spliced.challenge_id = compute_challenge_id(&spliced)?;
    assert_eq!(
        spliced.validate(),
        Err(FindingError::InvalidField(
            "replay_contradiction.reproduction[].observation_bytes"
        ))
    );

    // An observation about another recipe cannot ride along.
    let mut foreign = challenge.clone();
    if let FindingChallengeEvidence::ReplayContradiction { reproduction, .. } =
        &mut foreign.evidence
    {
        reproduction[0].observation_bytes = canonical_json_string(&observation_body(
            HEX64,
            HEX64_THIRD,
            FindingRecipePhaseKind::Baseline,
            "replay-run-42",
        ))?;
    }
    foreign.challenge_id = compute_challenge_id(&foreign)?;
    assert_eq!(
        foreign.validate(),
        Err(FindingError::InvalidField(
            "replay_contradiction.reproduction[].observation_bytes"
        ))
    );

    // A recipe committing another profile cannot ride along.
    let mut foreign_profile = challenge.clone();
    let other_recipe = recipe_body(HEX64);
    if let FindingChallengeEvidence::ReplayContradiction {
        recipe_preimage, ..
    } = &mut foreign_profile.evidence
    {
        *recipe_preimage = canonical_json_string(&other_recipe)?;
    }
    foreign_profile.challenge_id = compute_challenge_id(&foreign_profile)?;
    assert_eq!(
        foreign_profile.validate(),
        Err(FindingError::InvalidField(
            "replay_contradiction.recipe_preimage"
        ))
    );

    // Non-canonical carried bytes reject before anything reads them.
    let mut non_canonical = challenge;
    if let FindingChallengeEvidence::ReplayContradiction {
        recipe_preimage, ..
    } = &mut non_canonical.evidence
    {
        *recipe_preimage = format!(" {recipe_preimage}");
    }
    non_canonical.challenge_id = compute_challenge_id(&non_canonical)?;
    assert_eq!(
        non_canonical.validate(),
        Err(FindingError::NonCanonicalBytes(
            "replay_contradiction.recipe_preimage"
        ))
    );
    Ok(())
}

#[test]
fn compatibility_matrix_admits_exactly_the_closed_pairings() -> TestResult {
    let guarantee_classes = [
        FindingGuaranteeClass::DeterministicReplay,
        FindingGuaranteeClass::MeteredAttested,
        FindingGuaranteeClass::Asserted,
    ];
    let evidence_classes = [
        FindingEvidenceClass::Asserted,
        FindingEvidenceClass::Observed,
        FindingEvidenceClass::Verified,
    ];
    let evidence_kinds = [
        FindingChallengeEvidenceKind::DigestMismatch,
        FindingChallengeEvidenceKind::EvidenceInvalid,
        FindingChallengeEvidenceKind::ReplayContradiction,
    ];

    let mut admitted = 0_usize;
    for kind in evidence_kinds {
        for guarantee_class in guarantee_classes {
            for evidence_class in evidence_classes {
                let expected = match kind {
                    FindingChallengeEvidenceKind::DigestMismatch => true,
                    FindingChallengeEvidenceKind::EvidenceInvalid => {
                        evidence_class != FindingEvidenceClass::Asserted
                    }
                    FindingChallengeEvidenceKind::ReplayContradiction => {
                        guarantee_class == FindingGuaranteeClass::DeterministicReplay
                            && evidence_class == FindingEvidenceClass::Verified
                    }
                };
                let result =
                    ensure_challenge_class_compatibility(kind, guarantee_class, evidence_class);
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "{kind:?} with {guarantee_class:?}/{evidence_class:?}"
                );
                if expected {
                    admitted += 1;
                }
            }
        }
    }
    // Nine digest-mismatch cells, six evidence-invalid cells, one replay cell.
    assert_eq!(admitted, 16);

    assert_eq!(
        ensure_challenge_class_compatibility(
            FindingChallengeEvidenceKind::ReplayContradiction,
            FindingGuaranteeClass::MeteredAttested,
            FindingEvidenceClass::Verified,
        ),
        Err(FindingError::InvalidField(
            "replay_contradiction.guarantee_class"
        ))
    );
    assert_eq!(
        ensure_challenge_class_compatibility(
            FindingChallengeEvidenceKind::EvidenceInvalid,
            FindingGuaranteeClass::MeteredAttested,
            FindingEvidenceClass::Asserted,
        ),
        Err(FindingError::InvalidField(
            "evidence_invalid.evidence_class"
        ))
    );
    Ok(())
}

#[test]
fn challenge_signing_binds_the_challenger_or_the_pinned_audit_authority() -> TestResult {
    let challenger = keypair(41);
    let interloper = keypair(9);
    let audit_authority = keypair(42);

    let signed =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &challenger)?;
    (verify_signed_challenge(&signed, &audit_authority.public_key()))?;

    let forged =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &interloper)?;
    assert_eq!(
        verify_signed_challenge(&forged, &audit_authority.public_key()),
        Err(FindingError::AuthorityMismatch("challenge"))
    );

    let audit = SignedExportEnvelope::sign(venue_replay_challenge()?, &audit_authority)?;
    (verify_signed_challenge(&audit, &audit_authority.public_key()))?;

    let buyer_signed_audit = SignedExportEnvelope::sign(venue_replay_challenge()?, &challenger)?;
    assert_eq!(
        verify_signed_challenge(&buyer_signed_audit, &audit_authority.public_key()),
        Err(FindingError::AuthorityMismatch("challenge"))
    );
    Ok(())
}

#[test]
fn outcome_id_derivation_is_stable_and_domain_separated() -> TestResult {
    let challenger = keypair(41);
    let signed_challenge =
        SignedExportEnvelope::sign(buyer_digest_mismatch_challenge(&challenger)?, &challenger)?;
    let challenge_envelope_sha256 = signed_envelope_sha256(&signed_challenge)?;
    let outcome = outcome_body(
        &challenge_envelope_sha256,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    (outcome.validate())?;
    assert_eq!(derive_outcome_id(&outcome)?, outcome.outcome_id);

    // The derivation is domain-separated: a plain content address over the
    // same body is a different value.
    let mut cleared = outcome.clone();
    cleared.outcome_id = String::new();
    let plain = chio_core_types::crypto::sha256_hex(&canonical_json_bytes(&cleared)?);
    assert_ne!(plain, outcome.outcome_id);

    let mut tampered = outcome.clone();
    tampered.reason = "a different reason".to_string();
    assert_eq!(
        tampered.validate(),
        Err(FindingError::ArtifactIdMismatch("outcome_id"))
    );
    Ok(())
}

#[test]
fn outcome_binds_the_challenge_envelope_not_its_body() -> TestResult {
    let challenger = keypair(41);
    let challenge = buyer_digest_mismatch_challenge(&challenger)?;
    let signed_challenge = SignedExportEnvelope::sign(challenge.clone(), &challenger)?;
    let envelope_digest = signed_envelope_sha256(&signed_challenge)?;
    let body_digest = chio_core_types::crypto::sha256_hex(&canonical_json_bytes(&challenge)?);
    assert_ne!(envelope_digest, body_digest);

    let outcome = outcome_body(
        &envelope_digest,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    (verify_outcome_challenge_binding(&outcome, &signed_challenge))?;

    let body_bound = outcome_body(
        &body_digest,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    assert_eq!(
        verify_outcome_challenge_binding(&body_bound, &signed_challenge),
        Err(FindingError::ArtifactIdMismatch(
            "challenge_envelope_sha256"
        ))
    );
    Ok(())
}

#[test]
fn replay_predicate_maps_onto_every_verdict() -> TestResult {
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::ConfirmedContradiction),
        FindingChallengeVerdict::Upheld
    );
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::Consistent),
        FindingChallengeVerdict::Rejected
    );
    assert_eq!(
        verdict_for_replay_predicate(FindingReplayPredicateResult::Indeterminate),
        FindingChallengeVerdict::Indeterminate
    );

    // Total in both directions: every verdict is reachable exactly once.
    let mut verdicts: Vec<FindingChallengeVerdict> = [
        FindingReplayPredicateResult::ConfirmedContradiction,
        FindingReplayPredicateResult::Consistent,
        FindingReplayPredicateResult::Indeterminate,
    ]
    .into_iter()
    .map(verdict_for_replay_predicate)
    .collect();
    verdicts.dedup();
    assert_eq!(verdicts.len(), 3);

    // The nested result and the top-level verdict must agree in the body.
    let outcome = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::Consistent),
    )?;
    (outcome.validate())?;

    let contradictory = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::ConfirmedContradiction),
    )?;
    assert_eq!(
        contradictory.validate(),
        Err(FindingError::InvalidField("replay_contradiction.verdict"))
    );
    Ok(())
}

#[test]
fn outcome_reserves_the_penalty_calculation_for_upheld_verdicts() -> TestResult {
    let indeterminate = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        replay_facet(FindingReplayPredicateResult::Indeterminate),
    )?;
    (indeterminate.validate())?;
    assert!(indeterminate.penalty_calculation.is_none());

    let mut upheld_without_calculation = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    upheld_without_calculation.penalty_calculation = None;
    upheld_without_calculation.outcome_id = derive_outcome_id(&upheld_without_calculation)?;
    assert_eq!(
        upheld_without_calculation.validate(),
        Err(FindingError::MissingEntry("penalty_calculation"))
    );

    let mut rejected_with_calculation = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::Consistent),
    )?;
    rejected_with_calculation.penalty_calculation = Some(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 1,
        computed_exposure_units: 2,
        listing_required_amount_units: 2,
        live_allocated_collateral_units: 2,
        penalty_amount: usd(2),
    });
    rejected_with_calculation.outcome_id = derive_outcome_id(&rejected_with_calculation)?;
    assert_eq!(
        rejected_with_calculation.validate(),
        Err(FindingError::InvalidField("penalty_calculation"))
    );
    Ok(())
}

#[test]
fn outcome_retry_deadline_is_future_and_indeterminate_only() -> TestResult {
    let mut retryable = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        replay_facet(FindingReplayPredicateResult::Indeterminate),
    )?;
    retryable.retry_deadline = Some(retryable.evaluated_at + 60);
    retryable.outcome_id = derive_outcome_id(&retryable)?;
    (retryable.validate())?;

    let mut terminal = outcome_body(
        HEX64,
        FindingChallengeVerdict::Rejected,
        replay_facet(FindingReplayPredicateResult::Consistent),
    )?;
    terminal.retry_deadline = Some(terminal.evaluated_at + 60);
    terminal.outcome_id = derive_outcome_id(&terminal)?;
    assert_eq!(
        terminal.validate(),
        Err(FindingError::InvalidField("retry_deadline"))
    );

    let mut elapsed = retryable.clone();
    elapsed.retry_deadline = Some(elapsed.evaluated_at);
    elapsed.outcome_id = derive_outcome_id(&elapsed)?;
    assert_eq!(
        elapsed.validate(),
        Err(FindingError::InvalidField("retry_deadline"))
    );

    let mut unsafe_deadline = retryable;
    unsafe_deadline.retry_deadline = Some(1_u64 << 53);
    unsafe_deadline.outcome_id = derive_outcome_id(&unsafe_deadline)?;
    assert_eq!(
        unsafe_deadline.validate(),
        Err(FindingError::IJsonIntegerOutOfRange("retry_deadline"))
    );
    Ok(())
}

#[test]
fn outcome_penalty_calculation_is_checked_against_its_own_formula() -> TestResult {
    let mut wrong_sum = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = wrong_sum.penalty_calculation.as_mut() {
        calculation.computed_exposure_units = 110_000;
    }
    wrong_sum.outcome_id = derive_outcome_id(&wrong_sum)?;
    assert_eq!(
        wrong_sum.validate(),
        Err(FindingError::InvalidField(
            "penalty_calculation.computed_exposure_units"
        ))
    );

    let mut above_ceiling = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = above_ceiling.penalty_calculation.as_mut() {
        calculation.listing_required_amount_units = 100_000;
    }
    above_ceiling.outcome_id = derive_outcome_id(&above_ceiling)?;
    assert_eq!(
        above_ceiling.validate(),
        Err(FindingError::InvalidField(
            "penalty_calculation.listing_required_amount_units"
        ))
    );

    // The penalty is the minimum of live collateral and computed exposure,
    // never the promise alone.
    let mut capped = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = capped.penalty_calculation.as_mut() {
        calculation.live_allocated_collateral_units = 90_000;
        calculation.penalty_amount = usd(90_000);
    }
    capped.outcome_id = derive_outcome_id(&capped)?;
    (capped.validate())?;

    let mut overstated = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let Some(calculation) = overstated.penalty_calculation.as_mut() {
        calculation.live_allocated_collateral_units = 90_000;
    }
    overstated.outcome_id = derive_outcome_id(&overstated)?;
    assert_eq!(
        overstated.validate(),
        Err(FindingError::InvalidField(
            "penalty_calculation.penalty_amount"
        ))
    );
    Ok(())
}

#[test]
fn outcome_rejects_policy_transform_denials_and_facet_substitution() -> TestResult {
    let mut transformed = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let FindingChallengeFacet::DigestMismatch(facet) = &mut transformed.facet {
        facet.transform_profile = "redact_pii_v1".to_string();
    }
    transformed.outcome_id = derive_outcome_id(&transformed)?;
    assert_eq!(
        transformed.validate(),
        Err(FindingError::InvalidField(
            "digest_mismatch.transform_profile"
        ))
    );

    // A digest mismatch that matches is not a mismatch.
    let mut equal_digests = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    if let FindingChallengeFacet::DigestMismatch(facet) = &mut equal_digests.facet {
        facet.delivered_output_sha256 = facet.committed_payload_sha256.clone();
    }
    equal_digests.outcome_id = derive_outcome_id(&equal_digests)?;
    assert_eq!(
        equal_digests.validate(),
        Err(FindingError::InvalidField("digest_mismatch.verdict"))
    );

    // The facet must belong to the class the outcome names.
    let mut substituted = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    substituted.evidence_kind = FindingChallengeEvidenceKind::EvidenceInvalid;
    substituted.outcome_id = derive_outcome_id(&substituted)?;
    assert_eq!(
        substituted.validate(),
        Err(FindingError::InvalidField("facet"))
    );

    // Unavailable inputs are indeterminate, never a rejection of the buyer.
    let unavailable = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        FindingChallengeFacet::EvidenceInvalid(FindingEvidenceInvalidFacet {
            challenged_receipt_ids: vec!["evidence-receipt-1".to_string()],
            invalidity: FindingEvidenceInvalidity::InputsUnavailable,
        }),
    )?;
    (unavailable.validate())?;
    assert_eq!(
        FindingEvidenceInvalidity::InputsUnavailable.verdict(),
        FindingChallengeVerdict::Indeterminate
    );
    assert_eq!(
        FindingEvidenceInvalidity::NoAffirmativeInvalidity.verdict(),
        FindingChallengeVerdict::Rejected
    );
    Ok(())
}

#[test]
fn outcome_signs_and_verifies_under_its_pinned_evaluator() -> TestResult {
    let evaluator = keypair(43);
    let interloper = keypair(9);
    let outcome = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;

    let signed = SignedExportEnvelope::sign(outcome.clone(), &evaluator)?;
    (verify_signed_challenge_outcome(&signed, &evaluator.public_key()))?;
    assert_eq!(
        verify_signed_challenge_outcome(&signed, &interloper.public_key()),
        Err(FindingError::AuthorityMismatch("challenge_outcome"))
    );

    let forged = SignedExportEnvelope::sign(outcome, &interloper)?;
    assert_eq!(
        verify_signed_challenge_outcome(&forged, &evaluator.public_key()),
        Err(FindingError::AuthorityMismatch("challenge_outcome"))
    );
    Ok(())
}

#[test]
fn outcome_conforms_to_its_schema() -> TestResult {
    let evaluator = keypair(43);
    let signed = SignedExportEnvelope::sign(
        outcome_body(
            HEX64,
            FindingChallengeVerdict::Upheld,
            digest_mismatch_facet(),
        )?,
        &evaluator,
    )?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("challenge-outcome", &value)?;

    let rejected = SignedExportEnvelope::sign(
        outcome_body(
            HEX64,
            FindingChallengeVerdict::Rejected,
            replay_facet(FindingReplayPredicateResult::Consistent),
        )?,
        &evaluator,
    )?;
    validate_family_schema("challenge-outcome", &serde_json::to_value(&rejected)?)?;

    let mut retryable = outcome_body(
        HEX64,
        FindingChallengeVerdict::Indeterminate,
        replay_facet(FindingReplayPredicateResult::Indeterminate),
    )?;
    retryable.retry_deadline = Some(retryable.evaluated_at + 60);
    retryable.outcome_id = derive_outcome_id(&retryable)?;
    let signed_retryable = SignedExportEnvelope::sign(retryable, &evaluator)?;
    validate_family_schema(
        "challenge-outcome",
        &serde_json::to_value(&signed_retryable)?,
    )?;

    let mut deadline_on_rejected = serde_json::to_value(&rejected)?;
    deadline_on_rejected["body"]["retry_deadline"] = json!(1_750_000_560_u64);
    assert_family_schema_rejects(
        "challenge-outcome",
        &deadline_on_rejected,
        "retry deadline on a rejected verdict",
    )?;

    let mut unsafe_retry_deadline = serde_json::to_value(&signed_retryable)?;
    unsafe_retry_deadline["body"]["retry_deadline"] = json!(1_u64 << 53);
    assert_family_schema_rejects(
        "challenge-outcome",
        &unsafe_retry_deadline,
        "retry deadline above the I-JSON safe integer",
    )?;

    let mut unknown_verdict = value.clone();
    unknown_verdict["body"]["verdict"] = json!("maybe");
    assert_family_schema_rejects("challenge-outcome", &unknown_verdict, "unknown verdict")?;

    let mut spent = value.clone();
    spent["body"]["facet"]["digest_mismatch"]["realized_spend_units"] = json!(1);
    assert_family_schema_rejects("challenge-outcome", &spent, "nonzero realized spend")?;

    let mut transformed = value.clone();
    transformed["body"]["facet"]["digest_mismatch"]["transform_profile"] = json!("redact_pii_v1");
    assert_family_schema_rejects("challenge-outcome", &transformed, "policy transform")?;

    let mut penalty_without_upheld = serde_json::to_value(&rejected)?;
    penalty_without_upheld["body"]["penalty_calculation"] = json!({
        "base_finding_stake_units": 1,
        "open_per_sale_encumbrance_units": 1,
        "computed_exposure_units": 2,
        "listing_required_amount_units": 2,
        "live_allocated_collateral_units": 2,
        "penalty_amount": { "units": 2, "currency": "USD" },
    });
    assert_family_schema_rejects(
        "challenge-outcome",
        &penalty_without_upheld,
        "penalty calculation on a rejected verdict",
    )?;

    let mut unknown = value;
    unknown["body"]["surprise"] = json!(true);
    assert_family_schema_rejects("challenge-outcome", &unknown, "unknown body member")?;
    Ok(())
}

#[test]
fn enforcement_destinations_sum_exactly_to_the_total() -> TestResult {
    let enforcement = enforcement_body()?;
    (enforcement.validate())?;

    let mut short = enforcement_body()?;
    short.destinations[0].amount = usd(89_999);
    short.enforcement_id = compute_enforcement_id(&short)?;
    assert_eq!(
        short.validate(),
        Err(FindingError::InvalidField("destinations"))
    );

    let mut long = enforcement_body()?;
    long.destinations[1].amount = usd(30_001);
    long.enforcement_id = compute_enforcement_id(&long)?;
    assert_eq!(
        long.validate(),
        Err(FindingError::InvalidField("destinations"))
    );

    let mut mixed_currency = enforcement_body()?;
    mixed_currency.destinations[1].amount = MonetaryAmount {
        units: 30_000,
        currency: "EUR".to_string(),
    };
    mixed_currency.enforcement_id = compute_enforcement_id(&mixed_currency)?;
    assert_eq!(
        mixed_currency.validate(),
        Err(FindingError::CurrencyMismatch("destinations[]"))
    );

    let mut duplicated = enforcement_body()?;
    duplicated.destinations[1].destination = duplicated.destinations[0].destination.clone();
    duplicated.destinations[1].amount = usd(30_000);
    duplicated.enforcement_id = compute_enforcement_id(&duplicated)?;
    assert_eq!(
        duplicated.validate(),
        Err(FindingError::DuplicateEntry("destinations[]"))
    );

    let mut empty = enforcement_body()?;
    empty.destinations.clear();
    empty.enforcement_id = compute_enforcement_id(&empty)?;
    assert_eq!(
        empty.validate(),
        Err(FindingError::MissingEntry("destinations"))
    );
    Ok(())
}

#[test]
fn enforcement_requires_every_pre_dispatch_intent() -> TestResult {
    let mut missing_retraction = enforcement_body()?;
    missing_retraction
        .effect_intents
        .retain(|intent| intent.kind != FindingEffectIntentKind::Retraction);
    missing_retraction.enforcement_id = compute_enforcement_id(&missing_retraction)?;
    assert_eq!(
        missing_retraction.validate(),
        Err(FindingError::MissingEntry("effect_intents[]"))
    );

    let mut duplicated = enforcement_body()?;
    duplicated.effect_intents.push(FindingEffectIntentBinding {
        kind: FindingEffectIntentKind::SellerImpair,
        intent_id: HEX64_THIRD.to_string(),
    });
    duplicated.enforcement_id = compute_enforcement_id(&duplicated)?;
    assert_eq!(
        duplicated.validate(),
        Err(FindingError::DuplicateEntry("effect_intents[]"))
    );

    let mut with_optional = enforcement_body()?;
    with_optional
        .effect_intents
        .push(FindingEffectIntentBinding {
            kind: FindingEffectIntentKind::ChallengeBond,
            intent_id: HEX64_ALT.to_string(),
        });
    with_optional.enforcement_id = compute_enforcement_id(&with_optional)?;
    (with_optional.validate())?;
    Ok(())
}

#[test]
fn enforcement_signs_and_verifies_under_the_finalization_authority() -> TestResult {
    let finalization_authority = keypair(44);
    let evaluator = keypair(43);

    let signed = SignedExportEnvelope::sign(enforcement_body()?, &finalization_authority)?;
    (verify_signed_challenge_enforcement(&signed, &finalization_authority.public_key()))?;

    // Role separation: the evaluator key cannot authorize enforcement.
    let forged = SignedExportEnvelope::sign(enforcement_body()?, &evaluator)?;
    assert_eq!(
        verify_signed_challenge_enforcement(&forged, &finalization_authority.public_key()),
        Err(FindingError::AuthorityMismatch("challenge_enforcement"))
    );
    Ok(())
}

#[test]
fn enforcement_conforms_to_its_schema() -> TestResult {
    let finalization_authority = keypair(44);
    let signed = SignedExportEnvelope::sign(enforcement_body()?, &finalization_authority)?;
    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("challenge-enforcement", &value)?;

    let mut missing_intent = value.clone();
    missing_intent["body"]["effect_intents"] = json!([
        { "kind": "seller_impair", "intent_id": HEX64 },
        { "kind": "root_intent", "intent_id": HEX64_ALT },
        { "kind": "fee", "intent_id": HEX64_THIRD },
    ]);
    assert_family_schema_rejects(
        "challenge-enforcement",
        &missing_intent,
        "missing retraction intent",
    )?;

    let mut publisher_state = value.clone();
    publisher_state["body"]["assigned_sequence"] = json!(7);
    assert_family_schema_rejects(
        "challenge-enforcement",
        &publisher_state,
        "publisher-only sequence member",
    )?;

    let mut zero_destination = value;
    zero_destination["body"]["destinations"][0]["amount"]["units"] = json!(0);
    assert_family_schema_rejects(
        "challenge-enforcement",
        &zero_destination,
        "zero destination amount",
    )?;
    Ok(())
}

#[test]
fn bond_snapshot_arithmetic_is_checked() -> TestResult {
    let seller = keypair(45);
    let snapshot = bond_snapshot_body(&seller)?;
    (snapshot.validate())?;
    assert_eq!(snapshot.live_allocated_collateral()?, 380_000);

    let mut overcommitted = bond_snapshot_body(&seller)?;
    overcommitted.slashed_amount = 400_000;
    overcommitted.snapshot_id = compute_snapshot_id(&overcommitted)?;
    assert_eq!(
        overcommitted.validate(),
        Err(FindingError::InvalidField("held_amount"))
    );

    let mut exactly_full = bond_snapshot_body(&seller)?;
    exactly_full.slashed_amount = 380_000;
    exactly_full.snapshot_id = compute_snapshot_id(&exactly_full)?;
    (exactly_full.validate())?;
    assert_eq!(exactly_full.live_allocated_collateral()?, 0);

    let mut zero_block = bond_snapshot_body(&seller)?;
    zero_block.block_number = 0;
    zero_block.snapshot_id = compute_snapshot_id(&zero_block)?;
    assert_eq!(
        zero_block.validate(),
        Err(FindingError::NonZeroRequired("block_number"))
    );

    let mut malformed_hash = bond_snapshot_body(&seller)?;
    malformed_hash.block_hash = "0xNOTAHASH".to_string();
    malformed_hash.snapshot_id = compute_snapshot_id(&malformed_hash)?;
    assert_eq!(
        malformed_hash.validate(),
        Err(FindingError::MalformedDigest("block_hash"))
    );

    // The prefix is optional, the shape is not.
    let mut bare_hash = bond_snapshot_body(&seller)?;
    bare_hash.block_hash = HEX64.to_string();
    bare_hash.snapshot_id = compute_snapshot_id(&bare_hash)?;
    (bare_hash.validate())?;

    let mut zero_depth = bond_snapshot_body(&seller)?;
    zero_depth.observed_finality = FindingObservedFinality::Confirmations { depth: 0 };
    zero_depth.snapshot_id = compute_snapshot_id(&zero_depth)?;
    assert_eq!(
        zero_depth.validate(),
        Err(FindingError::NonZeroRequired("observed_finality.depth"))
    );
    Ok(())
}

#[test]
fn bond_snapshot_signs_and_conforms_to_its_schema() -> TestResult {
    let seller = keypair(45);
    let observer = keypair(46);
    let interloper = keypair(9);

    let signed = SignedExportEnvelope::sign(bond_snapshot_body(&seller)?, &observer)?;
    (verify_signed_finalized_bond_snapshot(&signed, &observer.public_key()))?;
    assert_eq!(
        verify_signed_finalized_bond_snapshot(&signed, &interloper.public_key()),
        Err(FindingError::AuthorityMismatch("finalized_bond_snapshot"))
    );

    let value: Value = serde_json::to_value(&signed)?;
    validate_family_schema("finalized-bond-snapshot", &value)?;

    let mut finalized = bond_snapshot_body(&seller)?;
    finalized.observed_finality = FindingObservedFinality::Finalized;
    finalized.snapshot_id = compute_snapshot_id(&finalized)?;
    (finalized.validate())?;
    let signed_finalized = SignedExportEnvelope::sign(finalized, &observer)?;
    validate_family_schema(
        "finalized-bond-snapshot",
        &serde_json::to_value(&signed_finalized)?,
    )?;

    let mut zero_locked = value.clone();
    zero_locked["body"]["locked_amount"] = json!(0);
    assert_family_schema_rejects(
        "finalized-bond-snapshot",
        &zero_locked,
        "zero locked amount",
    )?;

    let mut bad_hash = value.clone();
    bad_hash["body"]["block_hash"] = json!("0xzz");
    assert_family_schema_rejects("finalized-bond-snapshot", &bad_hash, "malformed block hash")?;

    let mut unknown_finality = value;
    unknown_finality["body"]["observed_finality"] = json!("probably");
    assert_family_schema_rejects(
        "finalized-bond-snapshot",
        &unknown_finality,
        "unknown finality",
    )?;
    Ok(())
}

#[test]
fn audit_seed_commitment_reproduces_in_both_directions() -> TestResult {
    let commitment = derive_audit_seed_commitment(SEED);
    assert_eq!(commitment.len(), 64);
    assert_eq!(commitment, derive_audit_seed_commitment(SEED));
    assert_ne!(commitment, derive_audit_seed_commitment(HEX64));
    // The commitment is domain-separated from a plain digest of the seed.
    assert_ne!(
        commitment,
        chio_core_types::crypto::sha256_hex(SEED.as_bytes())
    );

    let audit_authority = keypair(42);
    let epoch = audit_epoch_body()?;
    (epoch.validate())?;
    assert_eq!(epoch.seed_commitment, commitment);

    let signed_epoch = SignedExportEnvelope::sign(epoch, &audit_authority)?;
    let epoch_envelope_sha256 = signed_envelope_sha256(&signed_epoch)?;
    let report = audit_report_body(&epoch_envelope_sha256)?;
    (report.validate())?;
    (verify_audit_report_epoch_binding(&report, &signed_epoch))?;

    let mut wrong_seed = audit_report_body(&epoch_envelope_sha256)?;
    wrong_seed.revealed_seed = HEX64.to_string();
    wrong_seed.audit_report_id = compute_audit_report_id(&wrong_seed)?;
    assert_eq!(
        verify_audit_report_epoch_binding(&wrong_seed, &signed_epoch),
        Err(FindingError::ArtifactIdMismatch("revealed_seed"))
    );

    let mut wrong_epoch = audit_report_body(HEX64)?;
    wrong_epoch.audit_report_id = compute_audit_report_id(&wrong_epoch)?;
    assert_eq!(
        verify_audit_report_epoch_binding(&wrong_epoch, &signed_epoch),
        Err(FindingError::ArtifactIdMismatch(
            "audit_epoch_envelope_sha256"
        ))
    );
    Ok(())
}

#[test]
fn audit_report_accounts_for_every_selection() -> TestResult {
    let mut unselected_miss = audit_report_body(HEX64)?;
    unselected_miss.missed_attempts[0].finding_id = HEX64_THIRD.to_string();
    unselected_miss.audit_report_id = compute_audit_report_id(&unselected_miss)?;
    assert_eq!(
        unselected_miss.validate(),
        Err(FindingError::InvalidField("missed_attempts[]"))
    );

    let mut no_attempts = audit_report_body(HEX64)?;
    no_attempts.attempt_receipt_ids.clear();
    no_attempts.audit_report_id = compute_audit_report_id(&no_attempts)?;
    assert_eq!(
        no_attempts.validate(),
        Err(FindingError::MissingEntry("attempt_receipt_ids"))
    );

    // Every selection missed is a complete account with no attempts.
    let mut all_missed = audit_report_body(HEX64)?;
    all_missed.attempt_receipt_ids.clear();
    all_missed.missed_attempts.push(FindingMissedAudit {
        finding_id: HEX64.to_string(),
        reason: "runner unavailable for the whole window".to_string(),
    });
    all_missed.audit_report_id = compute_audit_report_id(&all_missed)?;
    (all_missed.validate())?;

    let mut duplicated = audit_report_body(HEX64)?;
    duplicated.selected_finding_ids.push(HEX64.to_string());
    duplicated.audit_report_id = compute_audit_report_id(&duplicated)?;
    assert_eq!(
        duplicated.validate(),
        Err(FindingError::DuplicateEntry("selected_finding_ids[]"))
    );
    Ok(())
}

#[test]
fn audit_artifacts_sign_and_conform_to_their_schemas() -> TestResult {
    let audit_authority = keypair(42);
    let interloper = keypair(9);

    let signed_epoch = SignedExportEnvelope::sign(audit_epoch_body()?, &audit_authority)?;
    (verify_signed_audit_epoch(&signed_epoch, &audit_authority.public_key()))?;
    assert_eq!(
        verify_signed_audit_epoch(&signed_epoch, &interloper.public_key()),
        Err(FindingError::AuthorityMismatch("audit_epoch"))
    );
    let epoch_value: Value = serde_json::to_value(&signed_epoch)?;
    validate_family_schema("audit-epoch", &epoch_value)?;

    let mut seeded = epoch_value.clone();
    seeded["body"]["revealed_seed"] = json!(SEED);
    assert_family_schema_rejects("audit-epoch", &seeded, "seed inside the precommitment")?;

    let mut over_rate = epoch_value;
    over_rate["body"]["published_rate_bps"] = json!(10_001);
    assert_family_schema_rejects("audit-epoch", &over_rate, "rate above one hundred percent")?;

    let epoch_envelope_sha256 = signed_envelope_sha256(&signed_epoch)?;
    let signed_report =
        SignedExportEnvelope::sign(audit_report_body(&epoch_envelope_sha256)?, &audit_authority)?;
    (verify_signed_audit_report(&signed_report, &audit_authority.public_key()))?;
    let report_value: Value = serde_json::to_value(&signed_report)?;
    validate_family_schema("audit-report", &report_value)?;

    let mut unknown = report_value;
    unknown["body"]["surprise"] = json!(true);
    assert_family_schema_rejects("audit-report", &unknown, "unknown body member")?;
    Ok(())
}

#[test]
fn replay_observation_digest_is_the_receipt_binding() -> TestResult {
    let observation = observation_body(HEX64, HEX64_ALT, FindingRecipePhaseKind::Baseline, "run-1");
    (observation.validate())?;
    let digest = observation.canonical_sha256()?;
    assert_eq!(digest.len(), 64);
    assert_eq!(
        digest,
        chio_core_types::crypto::sha256_hex(&canonical_json_bytes(&observation)?)
    );

    let mut other_phase = observation.clone();
    other_phase.phase_id = FindingRecipePhaseKind::Candidate;
    assert_ne!(other_phase.canonical_sha256()?, digest);

    let mut out_of_range = observation.clone();
    out_of_range.exit_code = 4_096;
    assert_eq!(
        out_of_range.validate(),
        Err(FindingError::InvalidField("exit_code"))
    );

    let mut foreign_schema = observation.clone();
    foreign_schema.schema = "chio.finding.replay-observation.v9".to_string();
    assert!(matches!(
        foreign_schema.validate(),
        Err(FindingError::UnsupportedSchema(_))
    ));

    let value: Value = serde_json::to_value(&observation)?;
    validate_family_schema("replay-observation", &value)?;

    let mut unknown = value.clone();
    unknown["surprise"] = json!(true);
    assert_family_schema_rejects("replay-observation", &unknown, "unknown member")?;

    let mut unknown_terminal = value.clone();
    unknown_terminal["terminal_result"] = json!("mostly_completed");
    assert_family_schema_rejects("replay-observation", &unknown_terminal, "unknown terminal")?;

    let mut unknown_phase = value;
    unknown_phase["phase_id"] = json!("warmup");
    assert_family_schema_rejects("replay-observation", &unknown_phase, "unknown phase")?;
    Ok(())
}

#[test]
fn market_penalty_schema_mirrors_the_frozen_camel_case_shape() -> TestResult {
    let value = market_penalty_envelope()?;
    validate_family_schema("market-penalty", &value)?;

    // The frozen body tolerates unknown members, so its schema must too.
    let mut extended = value.clone();
    extended["body"]["futureMember"] = json!("tolerated");
    validate_family_schema("market-penalty", &extended)?;

    // The envelope itself is strict.
    let mut unknown_envelope_member = value.clone();
    unknown_envelope_member["surprise"] = json!(true);
    assert_family_schema_rejects(
        "market-penalty",
        &unknown_envelope_member,
        "unknown envelope member",
    )?;

    // snake_case member names belong to the finding families, not this one.
    let mut snake_case = value.clone();
    let body = snake_case["body"]
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("penalty body is an object"))?;
    body.remove("penaltyId");
    body.insert("penalty_id".to_string(), json!("market-penalty-42"));
    assert_family_schema_rejects("market-penalty", &snake_case, "snake_case member name")?;

    let mut wrong_schema = value.clone();
    wrong_schema["body"]["schema"] = json!("chio.registry.market-penalty.v9");
    assert_family_schema_rejects("market-penalty", &wrong_schema, "wrong schema const")?;

    let mut unknown_abuse_class = value.clone();
    unknown_abuse_class["body"]["abuseClass"] = json!("mildly_annoying");
    assert_family_schema_rejects(
        "market-penalty",
        &unknown_abuse_class,
        "unknown abuse class",
    )?;

    let mut no_evidence = value;
    no_evidence["body"]["evidenceRefs"] = json!([]);
    assert_family_schema_rejects("market-penalty", &no_evidence, "empty evidence refs")?;
    Ok(())
}

/// Artifact validation and the registered schema are two independent gates
/// over the same bytes, and a signed artifact has to clear both. Anything
/// the validator accepts is round-tripped through its canonical encoding and
/// put to the schema here, so a member the schema constrains more tightly
/// than the validator cannot reach a signature and then strand at the first
/// verifier that reads the registry.
#[test]
fn every_challenge_family_round_trips_its_registered_schema() -> TestResult {
    let challenger = keypair(41);
    let audit_authority = keypair(42);
    let evaluator = keypair(43);
    let finalization_authority = keypair(44);
    let seller = keypair(45);
    let observer = keypair(46);
    let mut documents: Vec<(&'static str, Value)> = Vec::new();

    let buyer_challenge = buyer_digest_mismatch_challenge(&challenger)?;
    (buyer_challenge.validate())?;
    documents.push((
        "challenge",
        canonical_document(&SignedExportEnvelope::sign(buyer_challenge, &challenger)?)?,
    ));

    let venue_challenge = venue_replay_challenge()?;
    (venue_challenge.validate())?;
    documents.push((
        "challenge",
        canonical_document(&SignedExportEnvelope::sign(
            venue_challenge,
            &audit_authority,
        )?)?,
    ));

    for (verdict, facet) in [
        (FindingChallengeVerdict::Upheld, digest_mismatch_facet()),
        (
            FindingChallengeVerdict::Rejected,
            replay_facet(FindingReplayPredicateResult::Consistent),
        ),
        (
            FindingChallengeVerdict::Indeterminate,
            replay_facet(FindingReplayPredicateResult::Indeterminate),
        ),
    ] {
        let outcome = outcome_body(HEX64, verdict, facet)?;
        (outcome.validate())?;
        documents.push((
            "challenge-outcome",
            canonical_document(&SignedExportEnvelope::sign(outcome, &evaluator)?)?,
        ));
    }

    // The smallest calculation the formula admits: one unit of exposure fully
    // covered by one unit of live collateral.
    let minimal_penalty = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 1,
        listing_required_amount_units: 1,
        live_allocated_collateral_units: 1,
        penalty_amount: usd(1),
    })?;
    (minimal_penalty.validate())?;
    documents.push((
        "challenge-outcome",
        canonical_document(&SignedExportEnvelope::sign(minimal_penalty, &evaluator)?)?,
    ));

    let enforcement = enforcement_body()?;
    (enforcement.validate())?;
    documents.push((
        "challenge-enforcement",
        canonical_document(&SignedExportEnvelope::sign(
            enforcement,
            &finalization_authority,
        )?)?,
    ));

    for finality in [
        FindingObservedFinality::Finalized,
        FindingObservedFinality::Confirmations { depth: 96 },
    ] {
        let mut snapshot = bond_snapshot_body(&seller)?;
        snapshot.observed_finality = finality;
        snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
        (snapshot.validate())?;
        documents.push((
            "finalized-bond-snapshot",
            canonical_document(&SignedExportEnvelope::sign(snapshot, &observer)?)?,
        ));
    }

    let epoch = audit_epoch_body()?;
    (epoch.validate())?;
    let signed_epoch = SignedExportEnvelope::sign(epoch, &audit_authority)?;
    documents.push(("audit-epoch", canonical_document(&signed_epoch)?));

    let report = audit_report_body(&signed_envelope_sha256(&signed_epoch)?)?;
    (report.validate())?;
    documents.push((
        "audit-report",
        canonical_document(&SignedExportEnvelope::sign(report, &audit_authority)?)?,
    ));

    for phase in [
        FindingRecipePhaseKind::Baseline,
        FindingRecipePhaseKind::Candidate,
    ] {
        let observation = observation_body(HEX64, HEX64_ALT, phase, "replay-run-42");
        (observation.validate())?;
        documents.push(("replay-observation", canonical_document(&observation)?));
    }

    let mut covered = BTreeSet::new();
    for (family, document) in &documents {
        validate_family_schema(family, document)?;
        covered.insert(*family);
    }
    assert_eq!(
        covered,
        CHALLENGE_LANE_FAMILIES.into_iter().collect::<BTreeSet<_>>()
    );
    Ok(())
}

/// The penalty calculation is the one place where the outcome carries raw
/// unit members rather than a monetary amount alone, so its bounds are
/// pinned against the registered schema in both directions.
#[test]
fn penalty_calculation_bounds_match_the_registered_schema() -> TestResult {
    let evaluator = keypair(43);

    // Live collateral exhausted by an earlier hold: the formula yields zero,
    // which authorizes no sanction and which no monetary member may carry.
    let exhausted_collateral = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 50,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 50,
        listing_required_amount_units: 5_000,
        live_allocated_collateral_units: 0,
        penalty_amount: usd(0),
    })?;
    assert_eq!(
        exhausted_collateral.validate(),
        Err(FindingError::NonZeroRequired(
            "penalty_calculation.penalty_amount"
        ))
    );
    let signed = SignedExportEnvelope::sign(exhausted_collateral, &evaluator)?;
    assert_family_schema_rejects(
        "challenge-outcome",
        &canonical_document(&signed)?,
        "zero penalty amount",
    )?;

    // A unit member above the I-JSON safe integer would round in any
    // consumer that parses the canonical bytes as a double.
    let unsafe_requirement = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 1,
        listing_required_amount_units: u64::MAX,
        live_allocated_collateral_units: 1,
        penalty_amount: usd(1),
    })?;
    assert_eq!(
        unsafe_requirement.validate(),
        Err(FindingError::IJsonIntegerOutOfRange(
            "penalty_calculation.listing_required_amount_units"
        ))
    );
    let signed = SignedExportEnvelope::sign(unsafe_requirement, &evaluator)?;
    assert_family_schema_rejects(
        "challenge-outcome",
        &canonical_document(&signed)?,
        "listing requirement above the I-JSON safe integer",
    )?;

    let unsafe_collateral = upheld_outcome_with_penalty(FindingPenaltyCalculation {
        base_finding_stake_units: 1,
        open_per_sale_encumbrance_units: 0,
        computed_exposure_units: 1,
        listing_required_amount_units: 1,
        live_allocated_collateral_units: u64::MAX,
        penalty_amount: usd(1),
    })?;
    assert_eq!(
        unsafe_collateral.validate(),
        Err(FindingError::IJsonIntegerOutOfRange(
            "penalty_calculation.live_allocated_collateral_units"
        ))
    );
    Ok(())
}
