//! Receiver-owned cross-boundary admission over a verified treaty intersection.

#[path = "fixtures/treaty_admission_fixture.rs"]
mod treaty_admission_fixture;

use chio_core_types::crypto::Keypair;
use chio_runtime_core::{
    compute_ladder_intersection, evaluate_cross_boundary_admission,
    governance_ladder_manifest_sha256, ladder_intersection_sha256, CrossBoundaryAdmissionInput,
    CrossBoundaryEvidenceRef, GovernanceLadderActionClass, GovernanceLadderManifest, TreatyScope,
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA, CHIO_TREATY_SCOPE_SCHEMA,
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use treaty_admission_fixture::TreatyPredispatchDenyFixture;

fn action() -> GovernanceLadderActionClass {
    GovernanceLadderActionClass {
        action_class_id: "workflow.cross_kernel.read_refund_case".to_string(),
        mode: "receipt_backed".to_string(),
        destructive: false,
        consistency_model: "totally-ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        co_sign_quorum: None,
        evidence_required: vec![
            "receipt_lineage".to_string(),
            "bilateral_invocation".to_string(),
        ],
        aliases: Vec::new(),
    }
}

fn manifest(kernel_id: &str) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder-{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: kernel_id.to_string(),
        key_id: format!("key-{kernel_id}"),
        issued_at_unix_ms: 1_766_000_000_000,
        expires_at_unix_ms: 1_900_000_000_000,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![action()],
    }
}

pub fn bench(c: &mut Criterion) {
    let treaty_deny_fixture = match TreatyPredispatchDenyFixture::new() {
        Ok(fixture) => fixture,
        Err(error) => panic!("failed to build real treaty admission hook fixture: {error}"),
    };
    c.bench_function("treaty_predispatch_deny", |b| {
        b.iter_batched(
            || match treaty_deny_fixture.prepare_request() {
                Ok(request) => request,
                Err(error) => {
                    panic!("failed to prepare treaty admission benchmark request: {error}")
                }
            },
            |request| {
                assert!(
                    black_box(treaty_deny_fixture.evaluate_once(&request)),
                    "real treaty admission hook did not return the expected policy denial"
                );
            },
            BatchSize::SmallInput,
        );
    });

    let manifests = vec![
        manifest("did:chio:buyer-kernel"),
        manifest("did:chio:vendor-a"),
    ];
    let manifest_hashes = manifests
        .iter()
        .map(
            |manifest| match governance_ladder_manifest_sha256(manifest) {
                Ok(hash) => hash,
                Err(error) => panic!("failed to hash admission benchmark manifest: {error}"),
            },
        )
        .collect::<Vec<_>>();
    let scope = TreatyScope {
        schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        participant_kernel_ids: vec![
            "did:chio:buyer-kernel".to_string(),
            "did:chio:vendor-a".to_string(),
        ],
        participant_public_keys: vec![
            Keypair::from_seed(&[11_u8; 32]).public_key(),
            Keypair::from_seed(&[12_u8; 32]).public_key(),
        ],
        ladder_manifest_sha256s: manifest_hashes,
        allowed_action_classes: vec!["workflow.cross_kernel.read_refund_case".to_string()],
        issued_at_unix_ms: 1_766_000_000_000,
        expires_at_unix_ms: 1_900_000_000_000,
        revocation_epoch_sha256: "c".repeat(64),
        trust_bundle_sha256: "b".repeat(64),
    };
    let intersection = match compute_ladder_intersection(&scope, &manifests, 1_766_000_001_000) {
        Ok(intersection) => intersection,
        Err(error) => panic!("failed to build admission benchmark intersection: {error}"),
    };
    let intersection_sha256 = match ladder_intersection_sha256(&intersection) {
        Ok(hash) => hash,
        Err(error) => panic!("failed to hash admission benchmark intersection: {error}"),
    };
    let evidence = vec![
        CrossBoundaryEvidenceRef {
            evidence_class: "receipt_lineage".to_string(),
            artifact_sha256: "d".repeat(64),
            verified: true,
        },
        CrossBoundaryEvidenceRef {
            evidence_class: "bilateral_invocation".to_string(),
            artifact_sha256: "e".repeat(64),
            verified: true,
        },
    ];

    c.bench_function("cross_boundary_admission_allow", |b| {
        b.iter(|| {
            let report = match evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
                treaty_scope: black_box(&scope),
                ladder_intersection: black_box(&intersection),
                expected_ladder_intersection_sha256: Some(intersection_sha256.clone()),
                action_class_id: "workflow.cross_kernel.read_refund_case",
                present_evidence: vec![
                    "receipt_lineage".to_string(),
                    "bilateral_invocation".to_string(),
                ],
                verified_evidence: evidence.clone(),
                now_unix_ms: 1_766_000_001_000,
            }) {
                Ok(report) => report,
                Err(error) => panic!("cross-boundary admission benchmark failed: {error}"),
            };
            assert!(
                black_box(report.accepted),
                "cross-boundary admission benchmark rejected its fixture"
            );
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
