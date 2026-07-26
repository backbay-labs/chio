mod support;

use chio_runtime_core::{
    bilateral_dsse_consistency_model, bounded_treaty_constitution_refines_on,
    bounded_treaty_receipt_view_from_verified_artifacts, compute_ladder_intersection,
    evaluate_bounded_treaty_constitution, evaluate_bounded_treaty_predicate,
    evaluate_bounded_treaty_predicate_json, evaluate_cross_boundary_admission, ladder_co_sign_mode,
    treaty_scope_sha256, validate_cross_boundary_admission_report,
    validate_governance_ladder_manifest, validate_ladder_intersection, BilateralInvocation,
    BoundedAdmissionDecision, BoundedEvidenceDigest, BoundedTreatyConstitution,
    BoundedTreatyPredicate, BoundedTreatyPredicateAtom, BoundedTreatyReceiptView,
    CrossBoundaryAdmissionInput, CrossBoundaryAdmissionReport, CrossBoundaryEvidenceRef,
    CrossKernelContinuation, GovernanceLadderQuorum, CHIO_BOUNDED_TREATY_PREDICATE_SCHEMA,
    CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA, CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA,
};
use std::io;
use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

#[test]
fn bilateral_dsse_consistency_models_use_wire_vocabulary() {
    for (runtime, wire) in [
        ("crdt_commutative", "crdt-commutative"),
        ("totally_ordered", "totally-ordered"),
        ("single_kernel", "single-kernel"),
        ("quorum_required", "quorum-required"),
        ("crdt-commutative", "crdt-commutative"),
        ("totally-ordered", "totally-ordered"),
        ("single-kernel", "single-kernel"),
        ("quorum-required", "quorum-required"),
    ] {
        let actual = match bilateral_dsse_consistency_model(runtime) {
            Ok(actual) => actual,
            Err(error) => panic!("{runtime} failed to map to DSSE: {error}"),
        };
        assert_eq!(actual, wire);
    }
    assert!(bilateral_dsse_consistency_model("unsupported").is_err());
}

#[test]
fn ladder_co_sign_modes_use_wire_vocabulary() {
    for (runtime, wire) in [
        ("none", "none"),
        ("bilateral_if_cross_org", "bilateral_if_cross_org"),
        ("bilateral_required", "bilateral_required"),
        ("n_of_m", "n_of_m"),
        ("quorum_required", "n_of_m"),
    ] {
        let actual = match ladder_co_sign_mode(runtime) {
            Ok(actual) => actual,
            Err(error) => panic!("{runtime} failed to map to a co-sign mode: {error}"),
        };
        assert_eq!(actual, wire);
    }
    assert!(ladder_co_sign_mode("unsupported").is_err());
}

#[test]
fn governance_ladder_manifest_round_trips_n_of_m_quorum() -> Result<(), Box<dyn std::error::Error>>
{
    let mut action = treaty_action_class(
        "receipt_backed",
        true,
        "totally-ordered",
        vec!["governance_receipt", "quorum_signature"],
    );
    action.co_sign = "n_of_m".to_string();
    action.co_sign_quorum = Some(GovernanceLadderQuorum {
        n: 2,
        m: 3,
        scope: "treaty".to_string(),
    });
    let manifest = treaty_manifest("kernel.buyer", action);
    validate_governance_ladder_manifest(&manifest)?;

    let encoded = serde_json::to_string(&manifest)?;
    assert!(encoded.contains("\"coSignQuorum\""));
    let decoded = chio_runtime_core::governance_ladder_manifest_from_json(&encoded)?;
    assert_eq!(decoded, manifest);

    let mut without_quorum = manifest.clone();
    without_quorum.action_classes[0].co_sign_quorum = None;
    assert!(validate_governance_ladder_manifest(&without_quorum).is_err());

    let mut misdeclared = manifest;
    misdeclared.action_classes[0].co_sign_quorum = Some(GovernanceLadderQuorum {
        n: 4,
        m: 3,
        scope: "treaty".to_string(),
    });
    assert!(validate_governance_ladder_manifest(&misdeclared).is_err());
    Ok(())
}

fn accepted_admission_report() -> CrossBoundaryAdmissionReport {
    CrossBoundaryAdmissionReport {
        schema: chio_runtime_core::CHIO_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        accepted: true,
        failure_code: None,
        mode: "receipt_backed".to_string(),
        consistency_model: "totally_ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        co_sign_quorum: None,
        required_evidence: vec!["governance_receipt".to_string()],
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_invocation".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
        ],
        treaty_scope_sha256: "a".repeat(64),
        ladder_intersection_sha256: "b".repeat(64),
        expected_ladder_intersection_sha256: Some("b".repeat(64)),
        checks: vec!["chio_treaty.cross_boundary_admission".to_string()],
    }
}

fn bounded_view() -> BoundedTreatyReceiptView {
    BoundedTreatyReceiptView {
        receipt_id: "receipt-1".to_string(),
        receipt_hash: "a".repeat(64),
        action_class: "workflow.destructive.vendor_call".to_string(),
        participant_kernel_ids: vec!["kernel-a".to_string(), "kernel-b".to_string()],
        ladder_mode_rank: 2,
        live_continuation_ids: vec!["continuation-1".to_string()],
        decision: BoundedAdmissionDecision::Allow,
        failure_code: None,
        evidence_digests: vec![BoundedEvidenceDigest {
            evidence_class: "bilateral_dsse".to_string(),
            digest: "b".repeat(64),
        }],
    }
}

fn atom(atom: BoundedTreatyPredicateAtom) -> BoundedTreatyPredicate {
    BoundedTreatyPredicate::Atom { atom }
}

#[test]
fn bounded_treaty_predicate_covers_every_lean_atom() {
    let receipt = bounded_view();
    for predicate in [
        atom(BoundedTreatyPredicateAtom::ScopeContains {
            target: receipt.receipt_id.clone(),
        }),
        atom(BoundedTreatyPredicateAtom::ParticipantKernelIdEquals {
            kernel_id: "kernel-b".to_string(),
        }),
        atom(BoundedTreatyPredicateAtom::ActionClassIn {
            class: receipt.action_class.clone(),
        }),
        atom(BoundedTreatyPredicateAtom::LadderModeAtLeastRank { rank: 2 }),
        atom(BoundedTreatyPredicateAtom::ReceiptHashEquals {
            hash: receipt.receipt_hash.clone(),
        }),
        atom(BoundedTreatyPredicateAtom::ContinuationLive {
            continuation_id: "continuation-1".to_string(),
        }),
        atom(BoundedTreatyPredicateAtom::DecisionEquals {
            decision: BoundedAdmissionDecision::Allow,
        }),
        BoundedTreatyPredicate::Neg {
            predicate: Box::new(atom(BoundedTreatyPredicateAtom::FailureCodeEquals {
                code: "denied".to_string(),
            })),
        },
        atom(BoundedTreatyPredicateAtom::EvidenceDigestEquals {
            evidence_class: "bilateral_dsse".to_string(),
            digest: "b".repeat(64),
        }),
    ] {
        assert!(evaluate_bounded_treaty_predicate(&predicate, &receipt));
    }

    let boundary = atom(BoundedTreatyPredicateAtom::LadderModeAtLeastRank { rank: 3 });
    assert!(!evaluate_bounded_treaty_predicate(&boundary, &receipt));
}

#[test]
fn bounded_treaty_predicate_serialization_denies_unknown_or_unsupported_input(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = bounded_view();
    let valid = serde_json::json!({
        "schema": CHIO_BOUNDED_TREATY_PREDICATE_SCHEMA,
        "predicate": {
            "op": "atom",
            "atom": {
                "tag": "decision_equals",
                "decision": "allow"
            }
        }
    });
    assert!(evaluate_bounded_treaty_predicate_json(
        &serde_json::to_string(&valid)?,
        &receipt
    ));

    let unknown_tag = serde_json::json!({
        "schema": CHIO_BOUNDED_TREATY_PREDICATE_SCHEMA,
        "predicate": {
            "op": "atom",
            "atom": {
                "tag": "request_override",
                "value": true
            }
        }
    });
    assert!(!evaluate_bounded_treaty_predicate_json(
        &serde_json::to_string(&unknown_tag)?,
        &receipt
    ));

    let unknown_field = serde_json::json!({
        "schema": CHIO_BOUNDED_TREATY_PREDICATE_SCHEMA,
        "predicate": {
            "op": "top",
            "requestOverride": true
        }
    });
    assert!(!evaluate_bounded_treaty_predicate_json(
        &serde_json::to_string(&unknown_field)?,
        &receipt
    ));

    let unsupported_version = serde_json::json!({
        "schema": "chio.federation.bounded-treaty-predicate.v2",
        "predicate": { "op": "top" }
    });
    assert!(!evaluate_bounded_treaty_predicate_json(
        &serde_json::to_string(&unsupported_version)?,
        &receipt
    ));
    Ok(())
}

#[test]
fn bounded_treaty_constitution_matches_finite_domain_refinement() {
    let receipt = bounded_view();
    let old = BoundedTreatyConstitution {
        predicates: vec![BoundedTreatyPredicate::Top],
    };
    let new = BoundedTreatyConstitution {
        predicates: vec![atom(BoundedTreatyPredicateAtom::ActionClassIn {
            class: receipt.action_class.clone(),
        })],
    };
    assert!(evaluate_bounded_treaty_constitution(&new, &receipt));
    assert!(bounded_treaty_constitution_refines_on(
        &new,
        &old,
        std::slice::from_ref(&receipt)
    ));
    assert!(!bounded_treaty_constitution_refines_on(
        &old,
        &new,
        &[BoundedTreatyReceiptView {
            action_class: "workflow.read_only".to_string(),
            ..receipt
        }]
    ));
}

#[test]
fn bounded_treaty_view_binds_runtime_artifacts_and_rejects_wrong_treaty(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};

    let scope = treaty_scope();
    let continuation = CrossKernelContinuation {
        schema: CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continuation:bounded:001".to_string(),
        source_kernel_id: scope.participant_kernel_ids[0].clone(),
        target_kernel_id: scope.participant_kernel_ids[1].clone(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "capability:bounded:001".to_string(),
        action_class_id: scope.allowed_action_classes[0].clone(),
        audience_tool: "vendor.lookup".to_string(),
        nonce: "nonce-bounded-001".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_000_060_000,
    };
    let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);
    let mut report = accepted_admission_report();
    report.treaty_scope_sha256 = treaty_scope_sha256(&scope)?;
    report.ladder_intersection_sha256 = "3".repeat(64);
    report.expected_ladder_intersection_sha256 = Some("3".repeat(64));
    let invocation = BilateralInvocation {
        schema: CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "bilateral:bounded:001".to_string(),
        treaty_id: scope.treaty_id.clone(),
        ladder_intersection_sha256: report.ladder_intersection_sha256.clone(),
        continuation_sha256,
        lineage_statement_sha256: "4".repeat(64),
        action_class_id: report.action_class_id.clone(),
        consistency_model: report.consistency_model.clone(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: "5".repeat(64),
        outcome_sha256: "6".repeat(64),
        local_receipt_sha256: "7".repeat(64),
        remote_receipt_sha256: "8".repeat(64),
        signer_kernel_ids: scope.participant_kernel_ids.clone(),
    };

    let view = bounded_treaty_receipt_view_from_verified_artifacts(
        &scope,
        &report,
        &invocation,
        &continuation,
        1_800_000_010_000,
    )?;
    assert_eq!(view.receipt_hash, invocation.local_receipt_sha256);
    assert_eq!(view.action_class, report.action_class_id);
    assert_eq!(view.ladder_mode_rank, 2);
    assert_eq!(
        view.live_continuation_ids,
        vec![continuation.continuation_id.clone()]
    );
    assert_eq!(view.decision, BoundedAdmissionDecision::Allow);
    assert_eq!(view.evidence_digests.len(), 2);

    let mut mismatched = invocation.clone();
    mismatched.action_class_id = "workflow.read_only".to_string();
    assert!(bounded_treaty_receipt_view_from_verified_artifacts(
        &scope,
        &report,
        &mismatched,
        &continuation,
        1_800_000_010_000,
    )
    .is_err());

    let mut wrong_treaty = invocation;
    wrong_treaty.treaty_id = "treaty-attacker".to_string();
    let err = bounded_treaty_receipt_view_from_verified_artifacts(
        &scope,
        &report,
        &wrong_treaty,
        &continuation,
        1_800_000_010_000,
    )
    .expect_err("a signed invocation for another treaty must be rejected");
    assert_eq!(err.code(), "chio_treaty_scope_hash_mismatch");
    Ok(())
}

#[test]
fn bounded_treaty_predicate_denies_excessive_nesting() {
    let receipt = bounded_view();
    let mut predicate = BoundedTreatyPredicate::Top;
    for _ in 0..34 {
        predicate = BoundedTreatyPredicate::Neg {
            predicate: Box::new(predicate),
        };
    }
    assert!(!evaluate_bounded_treaty_predicate(&predicate, &receipt));
}

#[test]
fn treaty_ladder_intersection_rejects_destructive_observation(
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = treaty_manifest(
        "kernel.buyer",
        treaty_action_class("observation", true, "totally_ordered", vec!["tool_receipt"]),
    );

    let err = match validate_governance_ladder_manifest(&manifest) {
        Ok(()) => {
            return Err(Box::new(io::Error::other(
                "destructive observation manifest unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chio_ladder_destructive_below_floor");
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_requires_intersection_and_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec![
                "governance_receipt",
                "bilateral_invocation",
                "receipt_lineage",
            ],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_invocation"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;

    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256.clone()),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec!["governance_receipt".to_string()],
        verified_evidence: Vec::new(),
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_treaty_missing_required_evidence")
    );

    let accepted = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_invocation".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: "f".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(accepted.accepted);
    assert_eq!(accepted.mode, "receipt_backed");
    assert_eq!(accepted.consistency_model, "totally-ordered");
    Ok(())
}

#[test]
fn chio_federation_treaty_schema_is_accepted_and_emitted() -> Result<(), Box<dyn std::error::Error>>
{
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.schema = "chio.federation.treaty-scope.v1".to_string();
    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];

    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    assert_eq!(
        intersection.schema,
        "chio.federation.ladder-intersection.v1"
    );
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;
    let admission = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_invocation".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(admission.accepted);
    assert_eq!(
        admission.schema,
        "chio.federation.cross-boundary-admission-report.v1"
    );
    validate_cross_boundary_admission_report(&admission)?;
    Ok(())
}

#[test]
fn treaty_loaded_ladder_intersection_rejects_destructive_crdt_commutative(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let mut intersection =
        compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    intersection.action_classes[0].destructive = true;
    intersection.action_classes[0].consistency_model = "crdt_commutative".to_string();

    let err = match validate_ladder_intersection(&intersection) {
        Ok(()) => {
            return Err(Box::new(io::Error::other(
                "destructive crdt_commutative ladder intersection unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chio_ladder_destructive_crdt_not_allowed");
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_rejects_accepted_failure_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let report = CrossBoundaryAdmissionReport {
        schema: chio_runtime_core::CHIO_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        accepted: true,
        failure_code: Some("chio_treaty_forged_failure".to_string()),
        mode: "receipt_backed".to_string(),
        consistency_model: "totally_ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        co_sign_quorum: None,
        required_evidence: vec!["governance_receipt".to_string()],
        present_evidence: vec!["governance_receipt".to_string()],
        verified_evidence: vec![CrossBoundaryEvidenceRef {
            evidence_class: "governance_receipt".to_string(),
            artifact_sha256: "d".repeat(64),
            verified: true,
        }],
        treaty_scope_sha256: "a".repeat(64),
        ladder_intersection_sha256: "b".repeat(64),
        expected_ladder_intersection_sha256: Some("b".repeat(64)),
        checks: vec!["chio_treaty.cross_boundary_admission".to_string()],
    };

    let error = match validate_cross_boundary_admission_report(&report) {
        Ok(()) => {
            return Err(
                io::Error::other("accepted treaty report with failure code was accepted").into(),
            );
        }
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        "cross_boundary_admission_unexpected_failure_code"
    );
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_rejects_accepted_missing_required_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = accepted_admission_report();
    report
        .required_evidence
        .push("quorum_signature".to_string());

    let error = match validate_cross_boundary_admission_report(&report) {
        Ok(()) => {
            return Err(io::Error::other(
                "accepted treaty report without required evidence was accepted",
            )
            .into());
        }
        Err(error) => error,
    };
    assert_eq!(error.code(), "chio_treaty_missing_required_evidence");
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_rejects_accepted_unverified_required_evidence(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = accepted_admission_report();
    report
        .required_evidence
        .push("quorum_signature".to_string());
    report.present_evidence.push("quorum_signature".to_string());
    report.verified_evidence.push(CrossBoundaryEvidenceRef {
        evidence_class: "quorum_signature".to_string(),
        artifact_sha256: "e".repeat(64),
        verified: false,
    });

    let error = match validate_cross_boundary_admission_report(&report) {
        Ok(()) => {
            return Err(io::Error::other(
                "accepted treaty report with unverified required evidence was accepted",
            )
            .into());
        }
        Err(error) => error,
    };
    assert_eq!(error.code(), "chio_treaty_unverified_required_evidence");
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_rejects_stale_treaty_or_future_intersection(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_invocation", "receipt_lineage"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["bilateral_invocation", "receipt_lineage"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let mut intersection =
        compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_020_000)?;
    intersection.generated_at_unix_ms = 1_800_000_020_000;
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;

    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "bilateral_invocation".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: "f".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;

    assert!(!denied.accepted);
    assert_eq!(denied.failure_code.as_deref(), Some("chio_treaty_stale"));

    let mut stale_treaty = treaty;
    stale_treaty.expires_at_unix_ms = 1_800_000_010_000;
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;
    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &stale_treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "bilateral_invocation".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: "f".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(!denied.accepted);
    assert_eq!(denied.failure_code.as_deref(), Some("chio_treaty_stale"));
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_injects_bilateral_requirement_for_cosign(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;

    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec!["governance_receipt".to_string()],
        verified_evidence: vec![CrossBoundaryEvidenceRef {
            evidence_class: "governance_receipt".to_string(),
            artifact_sha256: "d".repeat(64),
            verified: true,
        }],
        now_unix_ms: 1_800_000_010_000,
    })?;

    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_treaty_missing_required_evidence")
    );
    assert!(denied
        .required_evidence
        .contains(&"bilateral_invocation".to_string()));
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_requires_quorum_evidence_for_quorum_cosign(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buyer_action = treaty_action_class(
        "receipt_backed",
        true,
        "quorum_required",
        vec!["governance_receipt"],
    );
    buyer_action.co_sign = "quorum_required".to_string();
    buyer_action.co_sign_quorum = Some(GovernanceLadderQuorum {
        n: 2,
        m: 3,
        scope: "treaty".to_string(),
    });
    let mut vendor_action = treaty_action_class(
        "receipt_backed",
        true,
        "quorum_required",
        vec!["governance_receipt"],
    );
    vendor_action.co_sign = "quorum_required".to_string();
    vendor_action.co_sign_quorum = Some(GovernanceLadderQuorum {
        n: 2,
        m: 3,
        scope: "treaty".to_string(),
    });
    let buyer = treaty_manifest("kernel.buyer", buyer_action);
    let vendor = treaty_manifest("kernel.vendor-b", vendor_action);
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    assert_eq!(intersection.action_classes[0].co_sign, "n_of_m");
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;

    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec!["governance_receipt".to_string()],
        verified_evidence: vec![CrossBoundaryEvidenceRef {
            evidence_class: "governance_receipt".to_string(),
            artifact_sha256: "d".repeat(64),
            verified: true,
        }],
        now_unix_ms: 1_800_000_010_000,
    })?;

    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_treaty_missing_required_evidence")
    );
    assert!(denied
        .required_evidence
        .contains(&"quorum_signature".to_string()));
    Ok(())
}

#[test]
fn treaty_cross_boundary_admission_rejects_unverified_or_forged_intersection(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec![
                "governance_receipt",
                "bilateral_invocation",
                "receipt_lineage",
            ],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_invocation"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let mut intersection =
        compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;
    intersection.action_classes[0]
        .evidence_required
        .retain(|evidence| evidence != "receipt_lineage");

    let forged = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_invocation".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(!forged.accepted);
    assert_eq!(
        forged.failure_code.as_deref(),
        Some("chio_treaty_intersection_mismatch")
    );

    let intersection = compute_ladder_intersection(
        &treaty,
        &[
            treaty_manifest(
                "kernel.buyer",
                treaty_action_class(
                    "receipt_backed",
                    true,
                    "totally_ordered",
                    vec![
                        "governance_receipt",
                        "bilateral_invocation",
                        "receipt_lineage",
                    ],
                ),
            ),
            treaty_manifest(
                "kernel.vendor-b",
                treaty_action_class(
                    "receipt_backed",
                    true,
                    "totally_ordered",
                    vec!["governance_receipt", "bilateral_invocation"],
                ),
            ),
        ],
        1_800_000_010_000,
    )?;
    let expected_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&intersection)?;
    let denied = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: vec![
            "governance_receipt".to_string(),
            "bilateral_invocation".to_string(),
            "receipt_lineage".to_string(),
        ],
        verified_evidence: vec![
            CrossBoundaryEvidenceRef {
                evidence_class: "governance_receipt".to_string(),
                artifact_sha256: "d".repeat(64),
                verified: true,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_invocation".to_string(),
                artifact_sha256: "e".repeat(64),
                verified: false,
            },
            CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: "f".repeat(64),
                verified: true,
            },
        ],
        now_unix_ms: 1_800_000_010_000,
    })?;
    assert!(!denied.accepted);
    assert_eq!(
        denied.failure_code.as_deref(),
        Some("chio_treaty_unverified_required_evidence")
    );
    Ok(())
}

#[test]
fn treaty_intersection_rejects_manifest_hash_mismatch_and_unknown_class(
) -> Result<(), Box<dyn std::error::Error>> {
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_invocation"],
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            vec!["governance_receipt", "bilateral_invocation"],
        ),
    );
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec!["0".repeat(64), "1".repeat(64)];
    let err = match compute_ladder_intersection(
        &treaty,
        &[buyer.clone(), vendor.clone()],
        1_800_000_010_000,
    ) {
        Ok(_) => {
            return Err(Box::new(io::Error::other(
                "manifest hash mismatch unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chio_ladder_manifest_hash_mismatch");

    treaty.ladder_manifest_sha256s = vec![
        chio_runtime_core::governance_ladder_manifest_sha256(&buyer)?,
        chio_runtime_core::governance_ladder_manifest_sha256(&vendor)?,
    ];
    treaty.allowed_action_classes = vec!["workflow.unknown".to_string()];
    let err = match compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000) {
        Ok(_) => {
            return Err(Box::new(io::Error::other(
                "unknown action class unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chio_treaty_action_class_not_allowed");
    Ok(())
}
