mod support;

use chio_runtime_core::{
    bilateral_dsse_consistency_model, compute_ladder_intersection,
    evaluate_cross_boundary_admission, ladder_co_sign_mode,
    validate_cross_boundary_admission_report, validate_governance_ladder_manifest,
    validate_ladder_intersection, CrossBoundaryAdmissionInput, CrossBoundaryAdmissionReport,
    CrossBoundaryEvidenceRef, GovernanceLadderQuorum,
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
fn treaty_cross_boundary_admission_rejects_future_ladder_intersection(
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
