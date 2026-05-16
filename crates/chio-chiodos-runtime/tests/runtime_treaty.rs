mod support;

use chio_chiodos_runtime::{
    compute_ladder_intersection, evaluate_cross_boundary_admission,
    validate_governance_ladder_manifest, CrossBoundaryAdmissionInput, CrossBoundaryEvidenceRef,
};
use std::io;
use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

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
    assert_eq!(err.code(), "chiodos_ladder_destructive_below_floor");
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
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;

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
        Some("chiodos_treaty_missing_required_evidence")
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
    assert_eq!(accepted.consistency_model, "totally_ordered");
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
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let mut intersection =
        compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_020_000)?;
    intersection.generated_at_unix_ms = 1_800_000_020_000;
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;

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
    assert_eq!(denied.failure_code.as_deref(), Some("chiodos_treaty_stale"));
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
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;

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
        Some("chiodos_treaty_missing_required_evidence")
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
    let mut vendor_action = treaty_action_class(
        "receipt_backed",
        true,
        "quorum_required",
        vec!["governance_receipt"],
    );
    vendor_action.co_sign = "quorum_required".to_string();
    let buyer = treaty_manifest("kernel.buyer", buyer_action);
    let vendor = treaty_manifest("kernel.vendor-b", vendor_action);
    let mut treaty = treaty_scope();
    treaty.ladder_manifest_sha256s = vec![
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let intersection = compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    assert_eq!(intersection.action_classes[0].co_sign, "quorum_required");
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;

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
        Some("chiodos_treaty_missing_required_evidence")
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
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
    ];
    let mut intersection =
        compute_ladder_intersection(&treaty, &[buyer, vendor], 1_800_000_010_000)?;
    let expected_intersection_sha256 =
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;
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
        Some("chiodos_treaty_intersection_mismatch")
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
        chio_chiodos_runtime::ladder_intersection_sha256(&intersection)?;
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
        Some("chiodos_treaty_unverified_required_evidence")
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
    assert_eq!(err.code(), "chiodos_ladder_manifest_hash_mismatch");

    treaty.ladder_manifest_sha256s = vec![
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&buyer)?,
        chio_chiodos_runtime::governance_ladder_manifest_sha256(&vendor)?,
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
    assert_eq!(err.code(), "chiodos_treaty_action_class_not_allowed");
    Ok(())
}
