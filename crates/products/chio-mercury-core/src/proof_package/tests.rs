use chio_core::crypto::Keypair;
use chio_core::merkle::MerkleTree;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, checkpoint::CheckpointPublicationIdentity,
    checkpoint::CheckpointPublicationIdentityKind,
    checkpoint::CheckpointPublicationTrustAnchorBinding, checkpoint::CheckpointTrustAnchorIdentity,
    checkpoint::CheckpointTrustAnchorIdentityKind, decision::Decision, decision::ToolCallAction,
    lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody,
};
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_kernel::checkpoint::{
    build_checkpoint, build_checkpoint_with_previous, build_inclusion_proof,
    build_trust_anchored_checkpoint_publication, checkpoint_chain_leaf_hash,
    validate_checkpoint_transparency, CheckpointTransparencySummary,
};
use chio_kernel::evidence_export::{
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportQuery,
    EvidenceRetentionMetadata, EvidenceToolReceiptRecord, EvidenceUncheckpointedReceipt,
};

use crate::fixtures::{sample_mercury_bundle_manifest, sample_mercury_receipt_metadata};
use crate::MercuryApprovalStatus;

use super::*;

#[path = "tests/completeness.rs"]
mod completeness;

struct SampleReceiptContext {
    mercury_metadata: MercuryReceiptMetadata,
    tenant_id: Option<String>,
}

impl SampleReceiptContext {
    fn unscoped(mercury_metadata: MercuryReceiptMetadata) -> Self {
        Self {
            mercury_metadata,
            tenant_id: None,
        }
    }

    fn tenant(mercury_metadata: MercuryReceiptMetadata, tenant_id: &str) -> Self {
        Self {
            mercury_metadata,
            tenant_id: Some(tenant_id.to_string()),
        }
    }
}

fn sample_receipt(sequence: u64) -> ChioReceipt {
    let keypair = Keypair::generate();
    sample_receipt_with_key(sequence, &keypair)
}

fn sample_receipt_with_key(sequence: u64, keypair: &Keypair) -> ChioReceipt {
    let mercury_metadata = sample_mercury_receipt_metadata();
    sample_receipt_with_metadata(sequence, keypair, mercury_metadata)
}

fn sample_receipt_with_metadata(
    sequence: u64,
    keypair: &Keypair,
    mercury_metadata: MercuryReceiptMetadata,
) -> ChioReceipt {
    let action_parameters = mercury_action_parameters(&mercury_metadata);
    let action = ToolCallAction::from_parameters(action_parameters).expect("action");
    signed_sample_receipt_with_action_and_metadata(
        sequence,
        keypair,
        Some(Decision::Allow),
        "mercury",
        "release_control",
        action,
        SampleReceiptContext::unscoped(mercury_metadata),
    )
}

fn mercury_action_parameters(metadata: &MercuryReceiptMetadata) -> serde_json::Value {
    serde_json::json!({
        "workflowId": metadata.business_ids.workflow_id,
        "eventId": metadata.chronology.event_id,
        "decisionType": metadata.decision_context.decision_type.as_str(),
        "stage": metadata.chronology.stage,
        "toolName": "release_control",
    })
}

fn signed_sample_receipt(
    sequence: u64,
    keypair: &Keypair,
    decision: Option<Decision>,
    tool_server: &str,
    action_parameters: serde_json::Value,
) -> ChioReceipt {
    let action = ToolCallAction::from_parameters(action_parameters).expect("action");
    signed_sample_receipt_with_action(
        sequence,
        keypair,
        decision,
        tool_server,
        "release_control",
        action,
    )
}

fn signed_sample_receipt_with_action(
    sequence: u64,
    keypair: &Keypair,
    decision: Option<Decision>,
    tool_server: &str,
    tool_name: &str,
    action: ToolCallAction,
) -> ChioReceipt {
    let mercury_metadata = sample_mercury_receipt_metadata();
    signed_sample_receipt_with_action_and_metadata(
        sequence,
        keypair,
        decision,
        tool_server,
        tool_name,
        action,
        SampleReceiptContext::unscoped(mercury_metadata),
    )
}

fn signed_sample_receipt_with_action_and_metadata(
    sequence: u64,
    keypair: &Keypair,
    decision: Option<Decision>,
    tool_server: &str,
    tool_name: &str,
    action: ToolCallAction,
    context: SampleReceiptContext,
) -> ChioReceipt {
    let metadata = context
        .mercury_metadata
        .into_receipt_metadata_value()
        .expect("metadata value");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("receipt-proof-{sequence}"),
            timestamp: 1_775_137_625 + sequence,
            capability_id: format!("cap-proof-{sequence}"),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action,
            decision,
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-proof-{sequence}"),
            policy_hash: format!("policy-proof-{sequence}"),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: context.tenant_id,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .expect("sign receipt")
}

fn sample_bundle() -> EvidenceExportBundle {
    sample_bundle_with_receipt(sample_receipt(1))
}

fn sample_bundle_with_receipt(receipt: ChioReceipt) -> EvidenceExportBundle {
    let checkpoint_keypair = Keypair::generate();
    sample_bundle_with_records(
        vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
        Vec::new(),
        &checkpoint_keypair,
    )
}

fn sample_bundle_with_records(
    tool_receipts: Vec<EvidenceToolReceiptRecord>,
    child_receipts: Vec<EvidenceChildReceiptRecord>,
    checkpoint_keypair: &Keypair,
) -> EvidenceExportBundle {
    let canonical = tool_receipts
        .iter()
        .map(|record| canonical_json_bytes(&record.receipt).expect("canonical receipt"))
        .collect::<Vec<_>>();
    let batch_start_seq = tool_receipts
        .iter()
        .map(|record| record.seq)
        .min()
        .expect("tool receipts");
    let batch_end_seq = tool_receipts
        .iter()
        .map(|record| record.seq)
        .max()
        .expect("tool receipts");
    let checkpoint = build_checkpoint(
        1,
        batch_start_seq,
        batch_end_seq,
        &canonical,
        checkpoint_keypair,
    )
    .expect("checkpoint");
    let tree = MerkleTree::from_leaves(&canonical).expect("merkle tree");
    let inclusion_proofs = tool_receipts
        .iter()
        .enumerate()
        .map(|(index, record)| {
            build_inclusion_proof(&tree, index, checkpoint.body.checkpoint_seq, record.seq)
                .expect("proof")
        })
        .collect();
    EvidenceExportBundle {
        query: EvidenceExportQuery::admin_all(),
        tool_receipts,
        child_receipt_scope: if child_receipts.is_empty() {
            EvidenceChildReceiptScope::OmittedNoJoinPath
        } else {
            EvidenceChildReceiptScope::FullQueryWindow
        },
        child_receipts,
        checkpoints: vec![checkpoint],
        capability_lineage: Vec::new(),
        inclusion_proofs,
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(1_024),
            oldest_live_receipt_timestamp: Some(1_775_137_626),
        },
    }
}

fn sample_child_receipt(sequence: u64, keypair: &Keypair) -> ChildRequestReceipt {
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: format!("child-receipt-{sequence}"),
            timestamp: 1_775_137_650 + sequence,
            session_id: SessionId::new(format!("session-{sequence}")),
            parent_request_id: RequestId::new(format!("parent-request-{sequence}")),
            request_id: RequestId::new(format!("child-request-{sequence}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: format!("outcome-{sequence}"),
            policy_hash: format!("policy-child-{sequence}"),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        keypair,
    )
    .expect("child receipt")
}

fn metadata_with_bundle_refs(bundle_refs: Vec<MercuryBundleReference>) -> MercuryReceiptMetadata {
    let mut metadata = sample_mercury_receipt_metadata();
    metadata.bundle_refs = bundle_refs;
    metadata
}

fn trusted_authority_keys(bundle: &EvidenceExportBundle) -> BTreeSet<String> {
    bundle
        .tool_receipts
        .iter()
        .map(|record| record.receipt.kernel_key.to_hex())
        .chain(
            bundle
                .child_receipts
                .iter()
                .map(|record| record.receipt.kernel_key.to_hex()),
        )
        .chain(
            bundle
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.body.kernel_key.to_hex()),
        )
        .collect()
}

fn build_sample_proof_package(
    bundle: EvidenceExportBundle,
) -> Result<MercuryProofPackage, MercuryContractError> {
    MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![sample_mercury_bundle_manifest()],
    )
}

fn build_partial_checkpoint_sample_package() -> MercuryProofPackage {
    let mut bundle = sample_bundle();
    let receipt_id = bundle.tool_receipts[0].receipt.id.clone();
    bundle.checkpoints.clear();
    bundle.inclusion_proofs.clear();
    bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt { seq: 1, receipt_id }];
    let mut profile = MercuryPublicationProfile::pilot_default();
    profile.checkpoint_continuity = CHECKPOINT_CONTINUITY_AUDIT_ONLY.to_string();
    profile.checkpoint_signatures_required = false;
    profile.inclusion_proofs_required = false;
    MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        profile,
        None,
        vec![sample_mercury_bundle_manifest()],
    )
    .expect("partial checkpoint proof package")
}

fn proof_package_with_signed_refs(
    bundle_refs: Vec<MercuryBundleReference>,
    manifests: Vec<MercuryBundleManifest>,
) -> MercuryProofPackage {
    let receipt_keypair = Keypair::generate();
    let receipt =
        sample_receipt_with_metadata(1, &receipt_keypair, metadata_with_bundle_refs(bundle_refs));
    MercuryProofPackage::build(
        sample_bundle_with_receipt(receipt),
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        manifests,
    )
    .expect("proof package")
}

fn full_trusted_sample_package() -> MercuryProofPackage {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let receipt_keypair = Keypair::generate();
    let child_keypair = Keypair::generate();
    let checkpoint_keypair = Keypair::generate();
    let receipt = sample_receipt_with_metadata(
        1,
        &receipt_keypair,
        metadata_with_bundle_refs(vec![bundle_ref]),
    );
    let child_receipt = sample_child_receipt(1, &child_keypair);
    let bundle = sample_bundle_with_records(
        vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
        vec![EvidenceChildReceiptRecord {
            seq: 1,
            receipt: child_receipt,
        }],
        &checkpoint_keypair,
    );
    MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![manifest],
    )
    .expect("full trusted proof package")
}

fn inquiry_package_with_metadata(
    mut metadata: MercuryReceiptMetadata,
    audience: &str,
    redaction_profile: Option<&str>,
    verifier_equivalent: bool,
) -> MercuryInquiryPackage {
    let manifest = sample_mercury_bundle_manifest();
    metadata.bundle_refs =
        vec![MercuryBundleReference::from_manifest(&manifest).expect("bundle ref")];
    let receipt_keypair = Keypair::generate();
    let receipt = sample_receipt_with_metadata(1, &receipt_keypair, metadata);
    let proof_package = MercuryProofPackage::build(
        sample_bundle_with_receipt(receipt),
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![manifest],
    )
    .expect("proof package");
    MercuryInquiryPackage::build(
        proof_package,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_901,
            audience: audience.to_string(),
            redaction_profile: redaction_profile.map(ToOwned::to_owned),
            verifier_equivalent,
        },
    )
    .expect("inquiry package")
}

fn sample_bundle_with_publication_records() -> (EvidenceExportBundle, CheckpointTransparencySummary)
{
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let first_keypair = Keypair::generate();
    let first_receipt = sample_receipt_with_metadata(
        1,
        &first_keypair,
        metadata_with_bundle_refs(vec![bundle_ref]),
    );
    let second_receipt = sample_receipt(2);
    let first_canonical = canonical_json_bytes(&first_receipt).expect("first canonical");
    let second_canonical = canonical_json_bytes(&second_receipt).expect("second canonical");
    let checkpoint_keypair = Keypair::generate();
    let first_checkpoint = build_checkpoint(
        1,
        1,
        1,
        std::slice::from_ref(&first_canonical),
        &checkpoint_keypair,
    )
    .expect("first checkpoint");
    let first_chain_leaf =
        checkpoint_chain_leaf_hash(&first_checkpoint.body).expect("first checkpoint chain leaf");
    let second_checkpoint = build_checkpoint_with_previous(
        2,
        2,
        2,
        std::slice::from_ref(&second_canonical),
        &checkpoint_keypair,
        Some(&first_checkpoint),
        &[first_chain_leaf],
    )
    .expect("second checkpoint");
    let first_tree =
        MerkleTree::from_leaves(std::slice::from_ref(&first_canonical)).expect("first tree");
    let second_tree =
        MerkleTree::from_leaves(std::slice::from_ref(&second_canonical)).expect("second tree");
    let first_proof =
        build_inclusion_proof(&first_tree, 0, first_checkpoint.body.checkpoint_seq, 1)
            .expect("first proof");
    let second_proof =
        build_inclusion_proof(&second_tree, 0, second_checkpoint.body.checkpoint_seq, 2)
            .expect("second proof");
    let bundle = EvidenceExportBundle {
        query: EvidenceExportQuery::admin_all(),
        tool_receipts: vec![
            EvidenceToolReceiptRecord {
                seq: 1,
                receipt: first_receipt,
            },
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: second_receipt,
            },
        ],
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: vec![first_checkpoint.clone(), second_checkpoint.clone()],
        capability_lineage: Vec::new(),
        inclusion_proofs: vec![first_proof, second_proof],
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(2_048),
            oldest_live_receipt_timestamp: Some(1_775_137_626),
        },
    };
    let mut transparency =
        validate_checkpoint_transparency(&[first_checkpoint.clone(), second_checkpoint.clone()])
            .expect("transparency");
    let binding = CheckpointPublicationTrustAnchorBinding {
        publication_identity: CheckpointPublicationIdentity::new(
            CheckpointPublicationIdentityKind::LocalLog,
            transparency.publications[0].log_id.clone(),
        ),
        trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
            CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "root-set-1",
        ),
        trust_anchor_ref: "anchor-root-1".to_string(),
        signer_cert_ref: "cert-chain-1".to_string(),
        publication_profile_version: "phase4-pilot".to_string(),
    };
    transparency.publications = vec![
        build_trust_anchored_checkpoint_publication(&first_checkpoint, binding.clone())
            .expect("first anchored publication"),
        build_trust_anchored_checkpoint_publication(&second_checkpoint, binding)
            .expect("second anchored publication"),
    ];
    (bundle, transparency)
}

#[test]
fn proof_package_build_and_verify_passes() {
    let package = MercuryProofPackage::build(
        sample_bundle(),
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![sample_mercury_bundle_manifest()],
    )
    .expect("proof package");
    assert_eq!(package.schema, "chio.mercury.proof_package.v2");
    let claim_boundary = package
        .publication_claim_boundary
        .as_ref()
        .expect("publication claim boundary");
    assert_eq!(
        claim_boundary.publication_state.as_str(),
        "transparency_preview"
    );
    assert!(claim_boundary.trust_anchor.is_none());

    let report = package.verify(1_775_137_900).expect("verification report");
    assert_eq!(report.package_kind, MercuryPackageKind::Proof);
    assert_eq!(report.workflow_id, "workflow-release-control");
    assert_eq!(report.receipt_count, 1);
    assert!(!report.verifier_equivalent);
}

#[test]
fn proof_package_rejects_partial_checkpoint_bundle_claiming_full_coverage() {
    let mut package = build_partial_checkpoint_sample_package();
    assert_eq!(
        package.publication_profile.completeness_mode,
        COMPLETENESS_BEST_EFFORT
    );
    package.publication_profile.completeness_mode =
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE.to_string();
    package.refresh_package_id().expect("refresh package id");

    let error = package
        .validate()
        .expect_err("partial checkpoint coverage cannot claim full coverage");

    assert!(
        error
            .to_string()
            .contains("completeness_mode must be best_effort"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_full_coverage_when_inclusion_proof_is_missing() {
    let mut incomplete_bundle = sample_bundle();
    incomplete_bundle.inclusion_proofs.clear();
    assert!(incomplete_bundle.uncheckpointed_receipts.is_empty());
    assert_eq!(
        derived_completeness_mode(&incomplete_bundle),
        COMPLETENESS_BEST_EFFORT
    );

    let mut package =
        build_sample_proof_package(incomplete_bundle).expect("best-effort proof package");
    assert_eq!(
        package.publication_profile.completeness_mode,
        COMPLETENESS_BEST_EFFORT
    );
    package.publication_profile.inclusion_proofs_required = false;
    package.refresh_package_id().expect("refresh package id");

    let error = package
        .verify(1_775_137_923)
        .expect_err("verification must derive the missing checkpoint coverage");
    assert!(
        error
            .to_string()
            .contains("declared uncheckpointed receipts do not match derived checkpoint coverage"),
        "unexpected error: {error}"
    );

    package.publication_profile.completeness_mode =
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE.to_string();
    package.refresh_package_id().expect("refresh package id");

    let error = package
        .validate()
        .expect_err("validation cannot trust an empty uncheckpointed declaration");
    assert!(
        error
            .to_string()
            .contains("completeness_mode must be best_effort"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_mismatched_outer_and_embedded_leaf_indexes() {
    let mut bundle = sample_bundle();
    let embedded_leaf_index = bundle.inclusion_proofs[0].proof.leaf_index;
    bundle.inclusion_proofs[0].leaf_index = embedded_leaf_index.saturating_add(1);

    assert_eq!(derived_completeness_mode(&bundle), COMPLETENESS_BEST_EFFORT);
    let error = match validate_checkpoint_receipt_sequence_bindings(&bundle) {
        Ok(()) => panic!("outer and embedded proof indexes must match"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("does not match embedded leaf index"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_uncheckpointed_receipt_id_mismatch() {
    let mut package = build_partial_checkpoint_sample_package();
    package.chio_bundle.uncheckpointed_receipts[0].receipt_id =
        "receipt-sha256-attacker".to_string();
    package.refresh_package_id().expect("refresh package id");

    let error = package
        .verify(1_775_137_923)
        .expect_err("uncheckpointed receipt id must bind to its tool receipt");
    assert!(
        error.to_string().contains("uncheckpointed receipt id"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_false_or_unknown_full_coverage_labels() {
    let package = build_sample_proof_package(sample_bundle()).expect("proof package");
    assert_eq!(
        package.publication_profile.completeness_mode,
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE
    );

    let mut best_effort = package.clone();
    best_effort.publication_profile.completeness_mode = COMPLETENESS_BEST_EFFORT.to_string();
    best_effort
        .refresh_package_id()
        .expect("refresh package id");
    let error = best_effort
        .validate()
        .expect_err("full checkpoint coverage cannot claim best effort");
    assert!(
        error
            .to_string()
            .contains("completeness_mode must be full_checkpoint_coverage"),
        "unexpected error: {error}"
    );

    let mut arbitrary = package;
    arbitrary.publication_profile.completeness_mode = "arbitrary".to_string();
    arbitrary.refresh_package_id().expect("refresh package id");
    let error = arbitrary
        .validate()
        .expect_err("full checkpoint coverage cannot use an unknown label");
    assert!(
        error
            .to_string()
            .contains("unsupported publication_profile.completeness_mode: arbitrary"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_package_id_tampering() {
    let mut package = build_sample_proof_package(sample_bundle()).expect("proof package");
    package.package_id = "proof-attacker-selected".to_string();

    let error = package.validate().expect_err("tampered package id");

    assert!(
        error
            .to_string()
            .contains("does not match the deterministic proof-package identity"),
        "unexpected error: {error}"
    );
}

#[test]
fn legacy_v1_package_identity_still_verifies_and_builds_an_inquiry() {
    let mut package = build_sample_proof_package(sample_bundle()).expect("proof package");
    package.schema = "chio.mercury.proof_package.v1".to_string();
    package.package_id = build_hash_id(
        "proof",
        &serde_json::json!({
            "createdAt": package.created_at,
            "evidenceExportManifestHash": package.evidence_export_manifest_hash,
            "workflowId": package.workflow_id,
            "receiptIds": ordered_receipt_ids(&package),
        }),
    )
    .expect("legacy package identity");
    let encoded = serde_json::to_vec(&package).expect("serialize legacy package");
    let restored: MercuryProofPackage =
        serde_json::from_slice(&encoded).expect("deserialize legacy package");

    restored
        .verify(1_775_137_901)
        .expect("legacy package remains verifiable");
    MercuryInquiryPackage::build(
        restored,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_902,
            audience: "legacy-reviewer".to_string(),
            redaction_profile: None,
            verifier_equivalent: false,
        },
    )
    .expect("legacy package can still seed an inquiry");
}

#[test]
fn proof_package_rejects_mixed_signed_receipt_workflows() {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let first_keypair = Keypair::generate();
    let second_keypair = Keypair::generate();
    let checkpoint_keypair = Keypair::generate();
    let first_receipt = sample_receipt_with_metadata(
        1,
        &first_keypair,
        metadata_with_bundle_refs(vec![bundle_ref]),
    );
    let second_receipt = sample_receipt_with_key(2, &second_keypair);
    let initial_bundle = sample_bundle_with_records(
        vec![
            EvidenceToolReceiptRecord {
                seq: 1,
                receipt: first_receipt,
            },
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: second_receipt,
            },
        ],
        Vec::new(),
        &checkpoint_keypair,
    );
    let mut package = MercuryProofPackage::build(
        initial_bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![manifest],
    )
    .expect("initial proof package");

    let mut second_metadata = sample_mercury_receipt_metadata();
    second_metadata.business_ids.workflow_id = "workflow-other".to_string();
    let mixed_receipt = sample_receipt_with_metadata(2, &second_keypair, second_metadata.clone());
    package.chio_bundle = sample_bundle_with_records(
        vec![
            package.chio_bundle.tool_receipts[0].clone(),
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: mixed_receipt.clone(),
            },
        ],
        Vec::new(),
        &checkpoint_keypair,
    );
    package.receipt_records[1] = MercuryProofReceiptRecord {
        receipt_id: mixed_receipt.id.clone(),
        seq: 2,
        metadata: second_metadata,
    };
    let (checkpoint_transparency, publication_claim_boundary) =
        derive_publication_materials_with_summary(
            &package.chio_bundle,
            &package.publication_profile,
            None,
        )
        .expect("publication materials");
    package.checkpoint_transparency = checkpoint_transparency;
    package.publication_claim_boundary = Some(publication_claim_boundary);
    package.package_id = derive_proof_package_id(&package).expect("package id");

    let error = package
        .validate()
        .expect_err("mixed signed receipt workflows");

    assert!(
        error
            .to_string()
            .contains("workflow_id does not match proof-package workflow_id"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_optional_business_id_tampering_after_identity_recomputation() {
    let mut account_package = build_sample_proof_package(sample_bundle()).expect("account package");
    account_package.account_id = Some("account-attacker".to_string());
    account_package.package_id =
        derive_proof_package_id(&account_package).expect("account package id");
    let error = account_package.validate().expect_err("tampered account id");
    assert!(
        error
            .to_string()
            .contains("account_id does not match the signed receipt metadata summary"),
        "unexpected error: {error}"
    );

    let mut desk_package = build_sample_proof_package(sample_bundle()).expect("desk package");
    desk_package.desk_id = Some("desk-attacker".to_string());
    desk_package.package_id = derive_proof_package_id(&desk_package).expect("desk package id");
    let error = desk_package.validate().expect_err("tampered desk id");
    assert!(
        error
            .to_string()
            .contains("desk_id does not match the signed receipt metadata summary"),
        "unexpected error: {error}"
    );

    let mut strategy_package =
        build_sample_proof_package(sample_bundle()).expect("strategy package");
    strategy_package.strategy_id = Some("strategy-attacker".to_string());
    strategy_package.package_id =
        derive_proof_package_id(&strategy_package).expect("strategy package id");
    let error = strategy_package
        .validate()
        .expect_err("tampered strategy id");
    assert!(
        error
            .to_string()
            .contains("strategy_id does not match the signed receipt metadata summary"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_export_descriptor_tampering_without_identity_recomputation() {
    let package = build_sample_proof_package(sample_bundle()).expect("proof package");

    let mut hash_tamper = package.clone();
    hash_tamper.evidence_export_manifest_hash = "manifest-attacker".to_string();
    let error = hash_tamper
        .validate()
        .expect_err("tampered export manifest hash");
    assert!(
        error
            .to_string()
            .contains("does not match the deterministic proof-package identity"),
        "unexpected error: {error}"
    );

    let mut schema_tamper = package.clone();
    schema_tamper.evidence_export_schema = "attacker.schema.v1".to_string();
    let error = schema_tamper
        .validate()
        .expect_err("tampered export schema");
    assert!(
        error
            .to_string()
            .contains("does not match the deterministic proof-package identity"),
        "unexpected error: {error}"
    );

    let mut timestamp_tamper = package;
    timestamp_tamper.evidence_exported_at += 1;
    let error = timestamp_tamper
        .validate()
        .expect_err("tampered export timestamp");
    assert!(
        error
            .to_string()
            .contains("does not match the deterministic proof-package identity"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_signed_deny_receipt() {
    let keypair = Keypair::generate();
    let metadata = sample_mercury_receipt_metadata();
    let receipt = signed_sample_receipt(
        1,
        &keypair,
        Some(Decision::Deny {
            reason: "approval missing".to_string(),
            guard: "approval".to_string(),
        }),
        "mercury",
        mercury_action_parameters(&metadata),
    );

    let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
        .expect_err("signed deny receipt");

    assert!(
        error.to_string().contains("must carry an allow decision"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_signed_observation_as_mercury_authorization() {
    use chio_core::receipt::kinds::{BoundaryClass, ObservationOutcome};

    let keypair = Keypair::generate();
    let mut body = sample_receipt_with_key(1, &keypair).body();
    body.decision = None;
    body.receipt_kind = ReceiptKind::TraceObservation;
    body.boundary_class = BoundaryClass::DetectOnly;
    body.observation_outcome = Some(ObservationOutcome::Observed);
    body.trust_level = TrustLevel::Verified;
    let observation = ChioReceipt::sign(body, &keypair).expect("signed observation receipt");
    assert!(observation.verify_signature().expect("verify observation"));

    let error = build_sample_proof_package(sample_bundle_with_receipt(observation))
        .expect_err("observation receipt cannot authorize Mercury action");

    assert!(
        error
            .to_string()
            .contains("must be a kernel-mediated decision receipt"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_wrong_tool_server() {
    let keypair = Keypair::generate();
    let metadata = sample_mercury_receipt_metadata();
    let receipt = signed_sample_receipt(
        1,
        &keypair,
        Some(Decision::Allow),
        "other-server",
        mercury_action_parameters(&metadata),
    );

    let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
        .expect_err("wrong tool server");

    assert!(
        error
            .to_string()
            .contains("must target the mercury tool server"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_tool_action_metadata_mismatches() {
    for field in ["workflowId", "eventId", "decisionType", "stage"] {
        let keypair = Keypair::generate();
        let metadata = sample_mercury_receipt_metadata();
        let mut action_parameters = mercury_action_parameters(&metadata);
        action_parameters[field] = serde_json::Value::String("wrong-binding".to_string());
        let receipt = signed_sample_receipt(
            1,
            &keypair,
            Some(Decision::Allow),
            "mercury",
            action_parameters,
        );

        let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
            .expect_err("action metadata mismatch");

        assert!(
            error.to_string().contains(field),
            "unexpected error for {field}: {error}"
        );
    }
}

#[test]
fn proof_package_rejects_unverified_tool_action() {
    let keypair = Keypair::generate();
    let metadata = sample_mercury_receipt_metadata();
    let mut action =
        ToolCallAction::from_parameters(mercury_action_parameters(&metadata)).expect("action");
    action.parameter_hash = "invalid-action-hash".to_string();
    let receipt = signed_sample_receipt_with_action(
        1,
        &keypair,
        Some(Decision::Allow),
        "mercury",
        "release_control",
        action,
    );

    let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
        .expect_err("unverified tool action");

    assert!(
        error
            .to_string()
            .contains("action hash verification failed"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_tool_name_action_mismatch() {
    let keypair = Keypair::generate();
    let metadata = sample_mercury_receipt_metadata();
    let action =
        ToolCallAction::from_parameters(mercury_action_parameters(&metadata)).expect("action");
    let receipt = signed_sample_receipt_with_action(
        1,
        &keypair,
        Some(Decision::Allow),
        "mercury",
        "rollback_control",
        action,
    );

    let error = build_sample_proof_package(sample_bundle_with_receipt(receipt))
        .expect_err("tool name action mismatch");

    assert!(
        error.to_string().contains("toolName"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_requires_explicitly_trusted_mercury_signers() {
    let mercury_keypair = Keypair::generate();
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let receipt = sample_receipt_with_metadata(
        1,
        &mercury_keypair,
        metadata_with_bundle_refs(vec![bundle_ref]),
    );
    let bundle = sample_bundle_with_receipt(receipt);
    let trusted_keys = trusted_authority_keys(&bundle);
    let package = MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![manifest],
    )
    .expect("proof package");

    let structural_report = package.verify(1_775_137_900).expect("structural report");
    assert!(!structural_report.verifier_equivalent);

    let untrusted_keypair = Keypair::generate();
    let untrusted_keys = BTreeSet::from([untrusted_keypair.public_key().to_hex()]);
    let error = package
        .verify_with_trusted_kernel_keys(1_775_137_901, &untrusted_keys)
        .expect_err("self-signed untrusted receipt");
    assert!(
        error.to_string().contains("untrusted Mercury kernel key"),
        "unexpected error: {error}"
    );

    let trusted_report = package
        .verify_with_trusted_kernel_keys(1_775_137_902, &trusted_keys)
        .expect("trusted verification report");
    assert!(!trusted_report.verifier_equivalent);
}

#[test]
fn trusted_proof_verification_requires_exact_signed_manifest_coverage() {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");

    let duplicate_ref_package = proof_package_with_signed_refs(
        vec![bundle_ref.clone(), bundle_ref.clone()],
        vec![manifest.clone()],
    );
    let trusted_keys = trusted_authority_keys(&duplicate_ref_package.chio_bundle);
    duplicate_ref_package
        .verify_with_trusted_kernel_keys(1_775_137_910, &trusted_keys)
        .expect("identical signed refs are deduplicated across receipts");

    let mut conflicting_ref = bundle_ref.clone();
    conflicting_ref.artifact_count = conflicting_ref.artifact_count.saturating_add(1);
    let conflicting_ref_package = proof_package_with_signed_refs(
        vec![bundle_ref.clone(), conflicting_ref],
        vec![manifest.clone()],
    );
    let trusted_keys = trusted_authority_keys(&conflicting_ref_package.chio_bundle);
    let error = conflicting_ref_package
        .verify_with_trusted_kernel_keys(1_775_137_910, &trusted_keys)
        .expect_err("conflicting signed refs");
    assert!(
        error
            .to_string()
            .contains("conflicting signed Mercury bundle reference"),
        "unexpected error: {error}"
    );

    let mut missing_ref = bundle_ref.clone();
    missing_ref.bundle_id = "bundle-missing".to_string();
    let missing_manifest_package =
        proof_package_with_signed_refs(vec![missing_ref], vec![manifest.clone()]);
    let trusted_keys = trusted_authority_keys(&missing_manifest_package.chio_bundle);
    let error = missing_manifest_package
        .verify_with_trusted_kernel_keys(1_775_137_911, &trusted_keys)
        .expect_err("missing packaged manifest");
    assert!(
        error.to_string().contains("has no packaged manifest"),
        "unexpected error: {error}"
    );

    let mut unreferenced_manifest = manifest.clone();
    unreferenced_manifest.bundle_id = "bundle-unreferenced".to_string();
    let unreferenced_manifest_package = proof_package_with_signed_refs(
        vec![bundle_ref.clone()],
        vec![manifest.clone(), unreferenced_manifest],
    );
    let trusted_keys = trusted_authority_keys(&unreferenced_manifest_package.chio_bundle);
    let error = unreferenced_manifest_package
        .verify_with_trusted_kernel_keys(1_775_137_912, &trusted_keys)
        .expect_err("unreferenced packaged manifest");
    assert!(
        error
            .to_string()
            .contains("has no signed receipt reference"),
        "unexpected error: {error}"
    );

    let duplicate_manifest_package =
        proof_package_with_signed_refs(vec![bundle_ref], vec![manifest.clone(), manifest]);
    let trusted_keys = trusted_authority_keys(&duplicate_manifest_package.chio_bundle);
    let error = duplicate_manifest_package
        .verify_with_trusted_kernel_keys(1_775_137_913, &trusted_keys)
        .expect_err("duplicate packaged manifests");
    assert!(
        error
            .to_string()
            .contains("duplicate Mercury bundle manifest id"),
        "unexpected error: {error}"
    );
}

#[test]
fn trusted_proof_verification_binds_manifest_hash_artifact_count_and_retention_class() {
    let mutations: [fn(&mut MercuryBundleReference); 3] = [
        |bundle_ref: &mut MercuryBundleReference| {
            bundle_ref.manifest_sha256 = "wrong-manifest-hash".to_string();
        },
        |bundle_ref: &mut MercuryBundleReference| {
            bundle_ref.artifact_count += 1;
        },
        |bundle_ref: &mut MercuryBundleReference| {
            bundle_ref.retention_class = Some("wrong-retention-class".to_string());
        },
    ];
    for mutate in mutations {
        let manifest = sample_mercury_bundle_manifest();
        let mut bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
        mutate(&mut bundle_ref);
        let package = proof_package_with_signed_refs(vec![bundle_ref], vec![manifest]);
        let trusted_keys = trusted_authority_keys(&package.chio_bundle);
        let error = package
            .verify_with_trusted_kernel_keys(1_775_137_914, &trusted_keys)
            .expect_err("manifest reference mismatch");
        assert!(
            error.to_string().contains(
                "does not match packaged manifest id/hash/artifact_count/retention_class"
            ),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn trusted_proof_verification_reports_bundled_prefix_without_source_equivalence() {
    let package = full_trusted_sample_package();
    let trusted_keys = trusted_authority_keys(&package.chio_bundle);

    let report = package
        .verify_with_trusted_kernel_keys(1_775_137_920, &trusted_keys)
        .expect("full trusted authority scope");

    assert!(!report.verifier_equivalent);
    let coverage_detail = report
        .steps
        .iter()
        .find(|step| step.name == "chio_bundle_integrity")
        .map(|step| step.detail.as_str())
        .expect("coverage detail");
    assert!(coverage_detail.contains("bundled checkpoint prefix"));
    assert!(coverage_detail.contains("does not establish the current source log tip"));
    assert!(coverage_detail.contains("later uncheckpointed suffix"));
}

#[test]
fn trusted_proof_verification_rejects_selectively_omitted_checkpoint_leaf() {
    let checkpoint_keypair = Keypair::generate();
    let mut bundle = sample_bundle_with_records(
        vec![
            EvidenceToolReceiptRecord {
                seq: 1,
                receipt: sample_receipt(1),
            },
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: sample_receipt(2),
            },
        ],
        Vec::new(),
        &checkpoint_keypair,
    );
    assert_eq!(bundle.checkpoints[0].body.tree_size, 2);

    bundle.tool_receipts.pop();
    bundle.inclusion_proofs.pop();
    assert!(bundle.uncheckpointed_receipts.is_empty());

    let mut package = build_sample_proof_package(bundle).expect("best-effort selective package");
    assert_eq!(
        package.publication_profile.completeness_mode,
        COMPLETENESS_BEST_EFFORT
    );
    package
        .verify(1_775_137_920)
        .expect("selective package remains structurally verifiable");

    let trusted_keys = trusted_authority_keys(&package.chio_bundle);
    let error = package
        .verify_with_trusted_kernel_keys(1_775_137_921, &trusted_keys)
        .expect_err("selective checkpoint package cannot be verifier-equivalent");
    assert!(
        error.to_string().contains(
            "unfiltered admin-all coverage of every leaf in the bundled checkpoint prefix"
        ),
        "unexpected error: {error}"
    );

    package.publication_profile.completeness_mode =
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE.to_string();
    package.refresh_package_id().expect("refresh package id");
    let error = package
        .validate()
        .expect_err("selective checkpoint package cannot claim full coverage");
    assert!(
        error
            .to_string()
            .contains("completeness_mode must be best_effort"),
        "unexpected error: {error}"
    );
}

#[test]
fn trusted_proof_verification_rejects_untrusted_child_signer() {
    let package = full_trusted_sample_package();
    let child_key = package.chio_bundle.child_receipts[0]
        .receipt
        .kernel_key
        .to_hex();
    let mut trusted_keys = trusted_authority_keys(&package.chio_bundle);
    trusted_keys.remove(&child_key);

    let error = package
        .verify_with_trusted_kernel_keys(1_775_137_921, &trusted_keys)
        .expect_err("untrusted child signer");

    assert!(
        error
            .to_string()
            .contains("child receipt child-receipt-1 was signed by an untrusted"),
        "unexpected error: {error}"
    );
}

#[test]
fn trusted_proof_verification_rejects_untrusted_checkpoint_signer() {
    let package = full_trusted_sample_package();
    let checkpoint_key = package.chio_bundle.checkpoints[0].body.kernel_key.to_hex();
    let mut trusted_keys = trusted_authority_keys(&package.chio_bundle);
    trusted_keys.remove(&checkpoint_key);

    let error = package
        .verify_with_trusted_kernel_keys(1_775_137_922, &trusted_keys)
        .expect_err("untrusted checkpoint signer");

    assert!(
        error
            .to_string()
            .contains("checkpoint 1 was signed by an untrusted"),
        "unexpected error: {error}"
    );
}

#[test]
fn trusted_proof_verification_rejects_invalid_checkpoint_when_profile_flag_is_false() {
    let mut package = full_trusted_sample_package();
    package.publication_profile.checkpoint_signatures_required = false;
    package.chio_bundle.checkpoints[0].signature = Keypair::generate().sign(b"invalid");
    let trusted_keys = trusted_authority_keys(&package.chio_bundle);

    let error = package
        .verify_with_trusted_kernel_keys(1_775_137_923, &trusted_keys)
        .expect_err("invalid checkpoint signature");

    assert!(
        error
            .to_string()
            .contains("checkpoint transparency verification failed"),
        "unexpected error: {error}"
    );
}

#[test]
fn trusted_proof_verification_rejects_checkpoint_free_audit_only_package() {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let receipt_keypair = Keypair::generate();
    let receipt = sample_receipt_with_metadata(
        1,
        &receipt_keypair,
        metadata_with_bundle_refs(vec![bundle_ref]),
    );
    let receipt_id = receipt.id.clone();
    let mut bundle = sample_bundle_with_receipt(receipt);
    bundle.checkpoints.clear();
    bundle.inclusion_proofs.clear();
    bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt { seq: 1, receipt_id }];
    let trusted_keys = trusted_authority_keys(&bundle);
    let mut profile = MercuryPublicationProfile::pilot_default();
    profile.checkpoint_continuity = CHECKPOINT_CONTINUITY_AUDIT_ONLY.to_string();
    profile.checkpoint_signatures_required = false;
    profile.inclusion_proofs_required = false;
    let package = MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        profile,
        None,
        vec![manifest],
    )
    .expect("checkpoint-free audit package");
    let structural_report = package.verify(1_775_137_923).expect("structural report");
    assert!(!structural_report.verifier_equivalent);

    let error = package
        .verify_with_trusted_kernel_keys(1_775_137_924, &trusted_keys)
        .expect_err("checkpoint-free trusted verification");

    assert!(
        error
            .to_string()
            .contains("trusted Mercury verification requires at least one checkpoint"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_rejects_padded_package_id() {
    let mut package = MercuryProofPackage::build(
        sample_bundle(),
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![sample_mercury_bundle_manifest()],
    )
    .expect("proof package");
    package.package_id = format!(" {} ", package.package_id);

    let error = package.validate().expect_err("padded package id");

    assert!(matches!(
        error,
        MercuryContractError::PaddedField("package_id")
    ));
}

#[test]
fn mercury_proof_package_requires_trust_anchor_for_append_only_claim() {
    let mut profile = MercuryPublicationProfile::pilot_default();
    profile.checkpoint_continuity = "append_only".to_string();

    let error = MercuryProofPackage::build(
        sample_bundle(),
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        profile,
        None,
        vec![sample_mercury_bundle_manifest()],
    )
    .expect_err("append_only profile without trust anchor should fail");

    assert!(
        error
            .to_string()
            .contains("requires publication_profile.trust_anchor"),
        "unexpected error: {error}"
    );
}

#[test]
fn mercury_preview_profile_rejects_trust_anchor_material() {
    let mut profile = MercuryPublicationProfile::pilot_default();
    profile.trust_anchor = Some("anchor-root-1".to_string());

    let error = profile
        .validate()
        .expect_err("preview profiles should not carry trust anchors");

    assert!(
        error
            .to_string()
            .contains("only valid when publication_profile.checkpoint_continuity=append_only"),
        "unexpected error: {error}"
    );
}

#[test]
fn append_only_proof_package_fails_closed_without_publication_records() {
    let mut profile = MercuryPublicationProfile::pilot_default();
    profile.checkpoint_continuity = "append_only".to_string();
    profile.trust_anchor = Some("anchor-root-1".to_string());

    let error = MercuryProofPackage::build(
        sample_bundle(),
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        profile,
        None,
        vec![sample_mercury_bundle_manifest()],
    )
    .expect_err("append_only proof package without packaged publication records should fail");

    assert!(
        error
            .to_string()
            .contains("must carry checkpoint_transparency publication records"),
        "unexpected error: {error}"
    );
}

#[test]
fn proof_package_carries_publication_record_and_optional_consistency_chain() {
    let (bundle, transparency) = sample_bundle_with_publication_records();
    let mut profile = MercuryPublicationProfile::pilot_default();
    profile.checkpoint_continuity = "append_only".to_string();
    profile.trust_anchor = Some("anchor-root-1".to_string());

    let package = MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        profile,
        Some(transparency),
        vec![sample_mercury_bundle_manifest()],
    )
    .expect("proof package with publication records");

    let packaged = package
        .checkpoint_transparency
        .as_ref()
        .expect("checkpoint transparency");
    assert_eq!(packaged.publications.len(), 2);
    assert_eq!(packaged.consistency_proofs.len(), 1);
    assert_eq!(
        packaged.publications[0]
            .trust_anchor_binding
            .as_ref()
            .expect("binding")
            .trust_anchor_ref,
        "anchor-root-1"
    );
    assert_eq!(
        package
            .publication_claim_boundary
            .as_ref()
            .expect("claim boundary")
            .trust_anchor
            .as_deref(),
        Some("anchor-root-1")
    );

    package.verify(1_775_137_900).expect("verification report");

    let first_signer_only = BTreeSet::from([package.chio_bundle.tool_receipts[0]
        .receipt
        .kernel_key
        .to_hex()]);
    package
        .verify_with_trusted_kernel_keys(1_775_137_901, &first_signer_only)
        .expect_err("every Mercury receipt signer must be trusted");

    let all_signers = trusted_authority_keys(&package.chio_bundle);
    let trusted_report = package
        .verify_with_trusted_kernel_keys(1_775_137_902, &all_signers)
        .expect("all Mercury receipt signers are trusted");
    assert!(!trusted_report.verifier_equivalent);
}

#[test]
fn inquiry_package_build_and_verify_passes() {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let receipt_keypair = Keypair::generate();
    let receipt = sample_receipt_with_metadata(
        1,
        &receipt_keypair,
        metadata_with_bundle_refs(vec![bundle_ref]),
    );
    let bundle = sample_bundle_with_receipt(receipt);
    let trusted_keys = trusted_authority_keys(&bundle);
    let proof_package = MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![manifest],
    )
    .expect("proof package");
    let inquiry = MercuryInquiryPackage::build(
        proof_package,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_901,
            audience: "compliance".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            verifier_equivalent: true,
        },
    )
    .expect("inquiry package");

    let report = inquiry.verify(1_775_137_902).expect("verification report");
    assert_eq!(report.package_kind, MercuryPackageKind::Inquiry);
    assert!(!report.verifier_equivalent);

    let trusted_report = inquiry
        .verify_with_trusted_kernel_keys(1_775_137_903, &trusted_keys)
        .expect("trusted inquiry verification report");
    assert!(!trusted_report.verifier_equivalent);
}

#[test]
fn inquiry_rejects_arbitrary_rendered_export_even_with_matching_self_hash() {
    let mut inquiry = inquiry_package_with_metadata(
        sample_mercury_receipt_metadata(),
        "compliance",
        Some("internal-default"),
        true,
    );
    inquiry.rendered_export = serde_json::json!({"attackerControlled": true});
    inquiry.rendered_export_sha256 = sha256_hex(
        &canonical_json(&inquiry.rendered_export, "rendered_export").expect("canonical export"),
    );

    let error = inquiry
        .validate()
        .expect_err("arbitrary export with self-consistent hash");

    assert!(
        error
            .to_string()
            .contains("not the exact deterministic inquiry projection"),
        "unexpected error: {error}"
    );
}

#[test]
fn inquiry_uses_unique_max_sequence_receipt_when_signed_receipts_are_reordered() {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let older_keypair = Keypair::generate();
    let newer_keypair = Keypair::generate();
    let checkpoint_keypair = Keypair::generate();
    let older = sample_receipt_with_metadata(
        1,
        &older_keypair,
        metadata_with_bundle_refs(vec![bundle_ref]),
    );
    let older_receipt_id = older.id.clone();
    let mut newer_metadata = sample_mercury_receipt_metadata();
    newer_metadata.approval_state.state = MercuryApprovalStatus::Denied;
    let newer = sample_receipt_with_metadata(2, &newer_keypair, newer_metadata.clone());
    let newer_receipt_id = newer.id.clone();
    let mut bundle = sample_bundle_with_records(
        vec![
            EvidenceToolReceiptRecord {
                seq: 1,
                receipt: older,
            },
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: newer,
            },
        ],
        Vec::new(),
        &checkpoint_keypair,
    );
    bundle.tool_receipts.swap(0, 1);
    let trusted_keys = trusted_authority_keys(&bundle);
    let proof_package = MercuryProofPackage::build(
        bundle,
        "manifest-sha256-proof",
        "chio.evidence_export_manifest.v1",
        1_775_137_700,
        1_775_137_800,
        MercuryPublicationProfile::pilot_default(),
        None,
        vec![manifest],
    )
    .expect("reordered proof package");
    let inquiry = MercuryInquiryPackage::build(
        proof_package,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_901,
            audience: "compliance".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            verifier_equivalent: true,
        },
    )
    .expect("reordered inquiry package");

    assert_eq!(inquiry.approval_state, newer_metadata.approval_state);
    assert!(!inquiry.verifier_equivalent);
    assert_eq!(
        inquiry.rendered_export["authoritativeReceiptId"],
        newer_receipt_id
    );
    assert_eq!(
        inquiry.rendered_export["receiptIds"],
        serde_json::json!([older_receipt_id, newer_receipt_id])
    );
    let report = inquiry
        .verify_with_trusted_kernel_keys(1_775_137_902, &trusted_keys)
        .expect("trusted reordered inquiry");
    assert!(!report.verifier_equivalent);
}

#[test]
fn inquiry_rejects_stale_receipt_sequence_manipulation() {
    let checkpoint_keypair = Keypair::generate();
    let older = sample_receipt(1);
    let newer = sample_receipt(2);
    let bundle = sample_bundle_with_records(
        vec![
            EvidenceToolReceiptRecord {
                seq: 1,
                receipt: older,
            },
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: newer,
            },
        ],
        Vec::new(),
        &checkpoint_keypair,
    );
    let mut proof_package = build_sample_proof_package(bundle).expect("proof package");
    proof_package.receipt_records.swap(0, 1);
    proof_package.chio_bundle.tool_receipts.swap(0, 1);
    proof_package.receipt_records[0].seq = 1;
    proof_package.receipt_records[1].seq = 2;
    proof_package.chio_bundle.tool_receipts[0].seq = 1;
    proof_package.chio_bundle.tool_receipts[1].seq = 2;
    proof_package.chio_bundle.inclusion_proofs[0].receipt_seq = 2;
    proof_package.chio_bundle.inclusion_proofs[1].receipt_seq = 1;
    proof_package.publication_profile.completeness_mode = COMPLETENESS_BEST_EFFORT.to_string();

    let error = MercuryInquiryPackage::build(
        proof_package,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_901,
            audience: "compliance".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            verifier_equivalent: true,
        },
    )
    .expect_err("stale receipt sequence manipulation");

    assert!(
        error
            .to_string()
            .contains("does not match checkpoint leaf sequence"),
        "unexpected error: {error}"
    );
}

#[test]
fn inquiry_rejects_duplicate_max_sequence_authority() {
    let checkpoint_keypair = Keypair::generate();
    let bundle = sample_bundle_with_records(
        vec![
            EvidenceToolReceiptRecord {
                seq: 1,
                receipt: sample_receipt(1),
            },
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: sample_receipt(2),
            },
        ],
        Vec::new(),
        &checkpoint_keypair,
    );
    let mut proof_package = build_sample_proof_package(bundle).expect("proof package");
    proof_package.receipt_records[0].seq = 2;
    proof_package.chio_bundle.tool_receipts[0].seq = 2;
    proof_package.publication_profile.completeness_mode = COMPLETENESS_BEST_EFFORT.to_string();
    proof_package.package_id =
        derive_proof_package_id(&proof_package).expect("recomputed package id");

    let error = MercuryInquiryPackage::build(
        proof_package,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_901,
            audience: "compliance".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            verifier_equivalent: true,
        },
    )
    .expect_err("duplicate max sequence");

    assert!(
        error
            .to_string()
            .contains("authoritative receipt sequence 2 is not unique"),
        "unexpected error: {error}"
    );
}

#[test]
fn inquiry_rejects_uncheckpointed_max_sequence_authority() {
    let checkpoint_keypair = Keypair::generate();
    let older = sample_receipt(1);
    let newer = sample_receipt(2);
    let newer_receipt_id = newer.id.clone();
    let mut bundle = sample_bundle_with_records(
        vec![
            EvidenceToolReceiptRecord {
                seq: 1,
                receipt: older,
            },
            EvidenceToolReceiptRecord {
                seq: 2,
                receipt: newer,
            },
        ],
        Vec::new(),
        &checkpoint_keypair,
    );
    bundle
        .inclusion_proofs
        .retain(|proof| proof.receipt_seq == 1);
    bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt {
        seq: 2,
        receipt_id: newer_receipt_id,
    }];
    let proof_package = build_sample_proof_package(bundle).expect("proof package");

    let error = MercuryInquiryPackage::build(
        proof_package,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_901,
            audience: "compliance".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            verifier_equivalent: true,
        },
    )
    .expect_err("uncheckpointed maximum sequence");

    assert!(
        error
            .to_string()
            .contains("authoritative receipt sequence 2 is not checkpoint-authenticated"),
        "unexpected error: {error}"
    );
}

#[test]
fn inquiry_rejects_approval_disclosure_and_equivalence_elevation() {
    let mut signed_metadata = sample_mercury_receipt_metadata();
    signed_metadata.approval_state.state = MercuryApprovalStatus::Denied;
    signed_metadata.disclosure.verifier_equivalent = false;
    signed_metadata.disclosure.reviewed_export_approved = false;
    let inquiry = inquiry_package_with_metadata(
        signed_metadata,
        "compliance",
        Some("internal-default"),
        true,
    );
    assert!(!inquiry.verifier_equivalent);

    let mut approval_elevation = inquiry.clone();
    approval_elevation.approval_state.state = MercuryApprovalStatus::Approved;
    let error = approval_elevation
        .validate()
        .expect_err("approval elevation");
    assert!(
        error
            .to_string()
            .contains("approval_state does not match the authoritative signed receipt"),
        "unexpected error: {error}"
    );

    let mut disclosure_elevation = inquiry.clone();
    disclosure_elevation.disclosure.verifier_equivalent = true;
    disclosure_elevation.disclosure.reviewed_export_approved = true;
    let error = disclosure_elevation
        .validate()
        .expect_err("disclosure elevation");
    assert!(
        error
            .to_string()
            .contains("disclosure does not match the authoritative signed receipt"),
        "unexpected error: {error}"
    );

    let mut equivalence_elevation = inquiry;
    equivalence_elevation.verifier_equivalent = true;
    let error = equivalence_elevation
        .validate()
        .expect_err("equivalence elevation");
    assert!(
        error
            .to_string()
            .contains(
                "portable inquiry cannot claim verifier equivalence without authenticated export provenance"
            ),
        "unexpected error: {error}"
    );
}

#[test]
fn inquiry_equivalence_requires_matching_signed_audience_and_redaction() {
    let audience_mismatch = inquiry_package_with_metadata(
        sample_mercury_receipt_metadata(),
        "external-review",
        Some("internal-default"),
        true,
    );
    assert!(!audience_mismatch.verifier_equivalent);

    let redaction_mismatch = inquiry_package_with_metadata(
        sample_mercury_receipt_metadata(),
        "compliance",
        Some("external-default"),
        true,
    );
    assert!(!redaction_mismatch.verifier_equivalent);

    let explicit_downgrade = inquiry_package_with_metadata(
        sample_mercury_receipt_metadata(),
        "compliance",
        Some("internal-default"),
        false,
    );
    assert!(!explicit_downgrade.verifier_equivalent);
}
