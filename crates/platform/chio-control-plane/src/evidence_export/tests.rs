use super::verification::*;
use super::*;

use chio_core::crypto::Keypair;
#[cfg(feature = "pq")]
use chio_core::crypto::{Ed25519Backend, HybridBackend, MlDsa65Backend, SigningBackend};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
#[cfg(feature = "pq")]
use chio_core::receipt::{lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody};
#[cfg(feature = "pq")]
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_kernel::{build_checkpoint, build_checkpoint_with_previous};
use chio_kernel::{
    CapabilitySnapshotProvenance, EvidenceChildReceiptScope, EvidenceExportBundle,
    EvidenceExportQuery, EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
};

use chio_test_support::prelude::*;

fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
    match err {
        CliError::Chio(chio) => {
            assert_eq!(chio.code().as_str(), expected_code);
            assert_eq!(chio.domain().as_str(), expected_domain);
        }
        other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
    }
}

fn unique_test_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "chio-evidence-{name}-{}-{stamp}",
        std::process::id()
    ))
}

#[test]
fn output_path_file_uses_cli_domain() {
    let temp = unique_test_dir("file-output");
    std::fs::create_dir_all(&temp).test_unwrap();
    let output = temp.join("evidence-output");
    std::fs::write(&output, b"not a directory").test_unwrap();

    let error = ensure_clean_output_dir(&output).test_unwrap_err();

    assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn output_path_nonempty_directory_uses_cli_domain() {
    let temp = unique_test_dir("nonempty-output");
    std::fs::create_dir_all(&temp).test_unwrap();
    let output = temp.join("evidence-output");
    std::fs::create_dir_all(&output).test_unwrap();
    std::fs::write(output.join("existing.json"), b"{}").test_unwrap();

    let error = ensure_clean_output_dir(&output).test_unwrap_err();

    assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
    let _ = std::fs::remove_dir_all(&temp);
}

fn sample_receipt() -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-export-1".to_string(),
            timestamp: 1_775_137_626,
            capability_id: "cap-export-1".to_string(),
            tool_server: "export".to_string(),
            tool_name: "publish".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"release":"candidate-1"}))
                .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-export-1".to_string(),
            policy_hash: "policy-export-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_unwrap()
}

#[cfg(feature = "pq")]
fn hybrid_backend(seed: [u8; 32]) -> HybridBackend {
    let keypair = Keypair::generate();
    let pq = MlDsa65Backend::from_seed(&seed);
    HybridBackend::new(Box::new(Ed25519Backend::new(keypair)), pq).test_unwrap()
}

#[cfg(feature = "pq")]
fn sample_hybrid_receipt() -> ChioReceipt {
    let backend = hybrid_backend([9u8; 32]);
    ChioReceipt::sign_with_backend(
        ChioReceiptBody {
            id: "receipt-export-hybrid-1".to_string(),
            timestamp: 1_775_137_627,
            capability_id: "cap-export-hybrid-1".to_string(),
            tool_server: "export".to_string(),
            tool_name: "publish".to_string(),
            action: ToolCallAction::from_parameters(
                serde_json::json!({"release":"candidate-hybrid"}),
            )
            .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-export-hybrid-1".to_string(),
            policy_hash: "policy-export-hybrid-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: backend.public_key(),
            bbs_projection_version: None,
        },
        &backend,
    )
    .test_unwrap()
}

#[cfg(feature = "pq")]
fn sample_hybrid_child_receipt() -> ChildRequestReceipt {
    let backend = hybrid_backend([10u8; 32]);
    ChildRequestReceipt::sign_with_backend(
        ChildRequestReceiptBody {
            id: "child-receipt-export-hybrid-1".to_string(),
            timestamp: 1_775_137_628,
            session_id: SessionId::new("sess-export-hybrid-1"),
            parent_request_id: RequestId::new("parent-export-hybrid-1"),
            request_id: RequestId::new("child-export-hybrid-1"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-export-hybrid-1".to_string(),
            policy_hash: "policy-export-hybrid-1".to_string(),
            metadata: None,
            kernel_key: backend.public_key(),
        },
        &backend,
    )
    .test_unwrap()
}

fn sample_bundle() -> EvidenceExportBundle {
    let receipt = sample_receipt();
    let canonical = canonical_json_bytes(&receipt).test_unwrap();
    let checkpoint_keypair = Keypair::generate();
    let checkpoint = build_checkpoint(
        1,
        1,
        1,
        std::slice::from_ref(&canonical),
        &checkpoint_keypair,
    )
    .test_unwrap();
    let tree = chio_core::merkle::MerkleTree::from_leaves(&[canonical]).test_unwrap();
    let proof = chio_kernel::build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1)
        .test_unwrap();
    EvidenceExportBundle {
        query: EvidenceExportQuery::default(),
        tool_receipts: vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: vec![checkpoint],
        capability_lineage: Vec::new(),
        inclusion_proofs: vec![proof],
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(512),
            oldest_live_receipt_timestamp: Some(1_775_137_626),
        },
    }
}

fn manifest_for_bundle(bundle: &EvidenceExportBundle) -> EvidenceExportManifest {
    let counts = EvidenceExportCounts {
        tool_receipts: bundle.tool_receipts.len() as u64,
        child_receipts: bundle.child_receipts.len() as u64,
        checkpoints: bundle.checkpoints.len() as u64,
        capability_lineage: bundle.capability_lineage.len() as u64,
        inclusion_proofs: bundle.inclusion_proofs.len() as u64,
        uncheckpointed_receipts: bundle.uncheckpointed_receipts.len() as u64,
    };
    let disclosure_notice = maybe_build_disclosure_notice(&bundle.query);
    EvidenceExportManifest {
        schema: EVIDENCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        exported_at: unix_now(),
        query: bundle.query.clone(),
        proof_coverage: EvidenceProofCoverage {
            checkpointed_receipts: counts
                .tool_receipts
                .saturating_sub(counts.uncheckpointed_receipts),
            uncheckpointed_receipts: counts.uncheckpointed_receipts,
        },
        receipt_semantics: evidence_receipt_semantic_summary(&bundle.tool_receipts),
        counts,
        child_receipt_scope: bundle.child_receipt_scope,
        claim_boundary: None,
        files: Vec::new(),
        policy: None,
        federation_policy: None,
        disclosure_notice,
    }
}

#[cfg(feature = "pq")]
#[test]
fn evidence_export_verification_accepts_hybrid_receipts_without_policy_floor() {
    let tool_receipts = vec![EvidenceToolReceiptRecord {
        seq: 1,
        receipt: sample_hybrid_receipt(),
    }];
    let child_receipts = vec![EvidenceChildReceiptRecord {
        seq: 2,
        receipt: sample_hybrid_child_receipt(),
    }];

    let verified = verify_tool_receipts(&tool_receipts).test_unwrap();
    verify_child_receipts(&child_receipts).test_unwrap();
    let semantics = evidence_receipt_semantic_summary(&tool_receipts);

    assert_eq!(verified.len(), 1);
    assert_eq!(semantics.authorized, 1);
}

#[test]
fn manifest_count_verification_rejects_semantic_drift() {
    let bundle = sample_bundle();
    let mut manifest = manifest_for_bundle(&bundle);
    manifest.receipt_semantics.authorized = 0;

    let error = verify_manifest_counts(
        &manifest,
        &bundle.tool_receipts,
        &bundle.child_receipts,
        &bundle.checkpoints,
        &bundle.capability_lineage,
        &bundle.inclusion_proofs,
    )
    .test_unwrap_err();

    assert!(
        error.to_string().contains("semantic summary"),
        "unexpected error: {error}"
    );
}

#[test]
fn evidence_verification_rejects_legacy_lineage_projection() {
    let snapshot = CapabilitySnapshot {
        capability_id: "legacy-evidence-capability".to_string(),
        subject_key: "legacy-subject".to_string(),
        issuer_key: "legacy-issuer".to_string(),
        issued_at: 1,
        expires_at: 2,
        grants_json: "{}".to_string(),
        delegation_depth: 0,
        parent_capability_id: None,
        federated_parent_capability_id: None,
        provenance: CapabilitySnapshotProvenance::LegacyProjection,
        signed_capability: None,
    };

    let error = verify_lineage(&[snapshot]).test_unwrap_err();
    assert!(error.to_string().contains("legacy projection provenance"));
}

#[test]
fn query_scope_rejects_tenant_scoped_package_with_mixed_receipt_tenant() {
    let mut receipt = sample_receipt();
    receipt.tenant_id = Some("tenant-b".to_string());
    let tool_receipts = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
    let error = verify_query_scope(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
        },
        &tool_receipts,
        &[],
        EvidenceChildReceiptScope::OmittedNoJoinPath,
        &BTreeMap::new(),
    )
    .test_unwrap_err();

    assert!(
        error.to_string().contains("outside tenant scope tenant-a"),
        "unexpected error: {error}"
    );
}

#[test]
fn query_scope_rejects_admin_tenant_filtered_package_with_mixed_receipt_tenant() {
    let mut receipt = sample_receipt();
    receipt.tenant_id = Some("tenant-b".to_string());
    let tool_receipts = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
    let error = verify_query_scope(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
        &tool_receipts,
        &[],
        EvidenceChildReceiptScope::OmittedNoJoinPath,
        &BTreeMap::new(),
    )
    .test_unwrap_err();

    assert!(
        error.to_string().contains("outside tenant scope tenant-a"),
        "unexpected error: {error}"
    );
}

#[test]
fn merge_export_query_preserves_policy_tenant_scope() {
    let merged = merge_export_query(
        &EvidenceExportQuery {
            capability_id: Some("cap-1".to_string()),
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: Some("agent-1".to_string()),
            since: None,
            until: None,
            tenant: None,
            read_boundary: None,
        },
    )
    .test_unwrap();

    assert_eq!(merged.capability_id.as_deref(), Some("cap-1"));
    assert_eq!(merged.agent_subject.as_deref(), Some("agent-1"));
    assert_eq!(merged.tenant.as_deref(), Some("tenant-a"));
}

#[test]
fn merge_export_query_rejects_tenant_scope_expansion() {
    let error = merge_export_query(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-b".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-b")),
        },
    )
    .test_unwrap_err();

    assert!(error.to_string().contains("tenant"));
}

#[test]
fn merge_export_query_allows_admin_policy_to_narrow_to_tenant_filter() {
    let merged = merge_export_query(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: None,
        },
    )
    .test_unwrap();

    assert_eq!(merged.tenant.as_deref(), Some("tenant-a"));
    assert_eq!(merged.read_boundary, Some(ReceiptReadBoundary::AdminAll));
}

#[test]
fn merge_export_query_rejects_request_chosen_boundary_without_policy_binding() {
    let error = merge_export_query(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: None,
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
    )
    .test_unwrap_err();

    assert!(
        error.to_string().contains("read boundary"),
        "unexpected error: {error}"
    );
}

#[test]
fn ensure_query_within_federation_policy_rejects_tenant_scope_expansion() {
    let error = ensure_query_within_federation_policy(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-b".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-b")),
        },
    )
    .test_unwrap_err();

    assert!(error.to_string().contains("tenant scope"));
}

#[test]
fn ensure_query_within_federation_policy_rejects_admin_all_under_tenant_scope() {
    let error = ensure_query_within_federation_policy(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
    )
    .test_unwrap_err();

    assert!(error.to_string().contains("admin-all"));
}

#[test]
fn ensure_query_within_federation_policy_allows_admin_policy_tenant_narrowing() {
    ensure_query_within_federation_policy(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
    )
    .test_unwrap();
}

#[test]
fn signed_federation_policy_rejects_unbound_read_boundary() {
    let keypair = Keypair::generate();
    let body = FederationPolicyBody {
        schema: FEDERATION_POLICY_SCHEMA.to_string(),
        issuer: "issuer-a".to_string(),
        partner: "partner-b".to_string(),
        signer_public_key: keypair.public_key(),
        created_at: 10,
        expires_at: 20,
        query: EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: None,
        },
        require_proofs: false,
        purpose: None,
    };
    let (signature, _) = keypair.sign_canonical(&body).test_unwrap();
    let policy = FederationPolicyDocument { body, signature };

    let error = verify_federation_policy(&policy).test_unwrap_err();

    assert!(
        error.to_string().contains("read boundary"),
        "unexpected error: {error}"
    );
}

#[test]
fn import_package_requires_explicit_read_boundary() {
    let bundle = sample_bundle();
    let manifest = manifest_for_bundle(&bundle);
    let package = EvidenceImportPackage {
        manifest,
        bundle,
        transparency: None,
        federation_policy: None,
    };
    let error = validate_import_package_data(&package).test_unwrap_err();

    assert!(error.to_string().contains("read boundary"));
}

#[test]
fn checkpoint_transparency_records_match_derived_chain() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).test_unwrap();
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&first),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();
    let checkpoints = vec![first, second];

    let summary = validate_checkpoint_transparency_summary(&checkpoints).test_unwrap();
    verify_checkpoint_transparency_records(
        &checkpoints,
        &summary.publications,
        &summary.witnesses,
        &summary.consistency_proofs,
        &summary.equivocations,
    )
    .test_unwrap();
}

#[test]
fn checkpoint_transparency_verification_fails_closed_on_duplicate_checkpoint_fork() {
    let kp = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).test_unwrap();
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &kp,
        Some(&first),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();
    let fork = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"five".to_vec(), b"six".to_vec()],
        &kp,
        Some(&first),
        &[chio_kernel::checkpoint::checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();

    let error = validate_checkpoint_transparency_summary(&[first, second, fork]).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("duplicate checkpoint sequence 2"),
        "unexpected error: {error}"
    );
}

#[test]
fn anchored_transparency_claims_fail_closed_during_export_verification() {
    let bundle = sample_bundle();
    let transparency = validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
    let anchored_claims = EvidenceTransparencyClaims {
        schema: chio_kernel::evidence_export::EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA.to_string(),
        publication_state: chio_kernel::evidence_export::EvidencePublicationState::TrustAnchored,
        trust_anchor: Some("anchor-root-1".to_string()),
        audit: chio_kernel::evidence_export::EvidenceAuditClaims {
            checkpoint_logs: transparency
                .publications
                .iter()
                .map(|publication| publication.log_id.clone())
                .collect(),
            signed_checkpoints: bundle.checkpoints.len() as u64,
            checkpoint_publications: transparency.publications.len() as u64,
            checkpoint_witnesses: transparency.witnesses.len() as u64,
            checkpoint_consistency_proofs: transparency.consistency_proofs.len() as u64,
            inclusion_proofs: bundle.inclusion_proofs.len() as u64,
            capability_lineage_records: bundle.capability_lineage.len() as u64,
        },
        transparency_preview: Vec::new(),
    };

    let error = verify_transparency_claim_boundary(Some(&anchored_claims), &bundle, &transparency)
        .test_unwrap_err();

    assert!(
        error.to_string().contains("claim boundary does not match"),
        "unexpected error: {error}"
    );
}

#[test]
fn transparency_claim_boundary_validation_uses_attest_domain() {
    let bundle = sample_bundle();
    let transparency = match validate_checkpoint_transparency_summary(&bundle.checkpoints) {
        Ok(summary) => summary,
        Err(error) => panic!("failed to build transparency summary: {error}"),
    };
    let mut claims = build_evidence_transparency_claims(&bundle, &transparency, None);
    claims.schema = "invalid-schema".to_string();

    let error = match verify_transparency_claim_boundary(Some(&claims), &bundle, &transparency) {
        Ok(()) => panic!("invalid transparency claims should fail closed"),
        Err(error) => error,
    };

    assert_registry_error(&error, "urn:chio:error:attest:provenance-missing", "attest");
}

#[test]
fn anchored_transparency_claims_verify_when_publications_carry_valid_bindings() {
    let bundle = sample_bundle();
    let checkpoint = bundle.checkpoints.first().cloned().test_unwrap();
    let mut transparency =
        validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
    let binding = chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding {
        publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
            chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
            transparency.publications[0].log_id.clone(),
        ),
        trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
            chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "root-set-1",
        ),
        trust_anchor_ref: "anchor-root-1".to_string(),
        signer_cert_ref: "cert-chain-1".to_string(),
        publication_profile_version: "phase4-pilot".to_string(),
    };
    transparency.publications = vec![
        chio_kernel::checkpoint::build_trust_anchored_checkpoint_publication(&checkpoint, binding)
            .test_unwrap(),
    ];
    let anchored_claims =
        build_evidence_transparency_claims(&bundle, &transparency, Some("anchor-root-1"));

    verify_checkpoint_transparency_records(
        &bundle.checkpoints,
        &transparency.publications,
        &transparency.witnesses,
        &transparency.consistency_proofs,
        &transparency.equivocations,
    )
    .test_unwrap();
    verify_transparency_claim_boundary(Some(&anchored_claims), &bundle, &transparency)
        .test_unwrap();
}

#[test]
fn evidence_export_fails_closed_on_stale_or_missing_publication() {
    let bundle = sample_bundle();
    let checkpoint = bundle.checkpoints.first().cloned().test_unwrap();
    let mut transparency =
        validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
    let binding = chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding {
        publication_identity: chio_core::receipt::checkpoint::CheckpointPublicationIdentity::new(
            chio_core::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
            transparency.publications[0].log_id.clone(),
        ),
        trust_anchor_identity: chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
            chio_core::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "root-set-1",
        ),
        trust_anchor_ref: "anchor-root-1".to_string(),
        signer_cert_ref: "cert-chain-1".to_string(),
        publication_profile_version: "phase4-pilot".to_string(),
    };
    transparency.publications = vec![
        chio_kernel::checkpoint::build_trust_anchored_checkpoint_publication(&checkpoint, binding)
            .test_unwrap(),
    ];
    let anchored_claims =
        build_evidence_transparency_claims(&bundle, &transparency, Some("anchor-root-1"));

    let missing_publication =
        validate_checkpoint_transparency_summary(&bundle.checkpoints).test_unwrap();
    let missing_error =
        verify_transparency_claim_boundary(Some(&anchored_claims), &bundle, &missing_publication)
            .test_unwrap_err();
    assert!(
        missing_error
            .to_string()
            .contains("claim boundary does not match"),
        "unexpected missing-publication error: {missing_error}"
    );

    let mut stale_publications = transparency.publications.clone();
    stale_publications[0].log_tree_size += 1;
    let stale_error = verify_checkpoint_transparency_records(
        &bundle.checkpoints,
        &stale_publications,
        &transparency.witnesses,
        &transparency.consistency_proofs,
        &transparency.equivocations,
    )
    .test_unwrap_err();
    assert!(
        stale_error
            .to_string()
            .contains("checkpoint transparency verification failed"),
        "unexpected stale-publication error: {stale_error}"
    );
}

#[test]
fn tenant_scoped_disclosure_notice_is_built_for_tenant_read_boundary() {
    let query = EvidenceExportQuery::tenant_scoped("tenant-a");
    let notice = maybe_build_disclosure_notice(&query).test_unwrap();
    assert_eq!(notice.schema, EVIDENCE_DISCLOSURE_NOTICE_SCHEMA);
    for required in [
        "batch_start_seq",
        "batch_end_seq",
        "tree_size",
        "merkle_root",
    ] {
        assert!(
            notice
                .disclosed_checkpoint_body_fields
                .iter()
                .any(|field| field == required),
            "{required} must appear in disclosed checkpoint body fields: {:?}",
            notice.disclosed_checkpoint_body_fields,
        );
    }
    for required in ["entry_start_seq", "entry_end_seq", "log_tree_size"] {
        assert!(
            notice
                .disclosed_publication_fields
                .iter()
                .any(|field| field == required),
            "{required} must appear in disclosed publication fields: {:?}",
            notice.disclosed_publication_fields,
        );
    }
    assert!(
        !notice.narrowed_metadata.is_empty(),
        "narrowed metadata list must enumerate the tenant-scoped narrowings",
    );
}

#[test]
fn admin_all_export_carries_no_tenant_disclosure_notice() {
    let query = EvidenceExportQuery::admin_all();
    assert!(maybe_build_disclosure_notice(&query).is_none());
}

#[test]
fn verify_disclosure_notice_rejects_stripped_tenant_notice() {
    let bundle = EvidenceExportBundle {
        query: EvidenceExportQuery::tenant_scoped("tenant-a"),
        tool_receipts: Vec::new(),
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: Vec::new(),
        capability_lineage: Vec::new(),
        inclusion_proofs: Vec::new(),
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: None,
            oldest_live_receipt_timestamp: None,
        },
    };
    let mut manifest = manifest_for_bundle(&bundle);
    assert!(manifest.disclosure_notice.is_some());
    manifest.disclosure_notice = None;

    let error = verify_disclosure_notice(&manifest).test_unwrap_err();
    assert!(
        error.to_string().contains("disclosure notice"),
        "unexpected error: {error}",
    );
}

#[test]
fn verify_disclosure_notice_rejects_admin_all_with_spurious_notice() {
    let bundle = EvidenceExportBundle {
        query: EvidenceExportQuery::admin_all(),
        tool_receipts: Vec::new(),
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: Vec::new(),
        capability_lineage: Vec::new(),
        inclusion_proofs: Vec::new(),
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(0),
            oldest_live_receipt_timestamp: None,
        },
    };
    let mut manifest = manifest_for_bundle(&bundle);
    manifest.disclosure_notice = Some(tenant_scoped_disclosure_notice());

    let error = verify_disclosure_notice(&manifest).test_unwrap_err();
    assert!(
        error.to_string().contains("admin-all"),
        "unexpected error: {error}",
    );
}

#[test]
fn verify_disclosure_notice_rejects_tampered_notice() {
    let bundle = EvidenceExportBundle {
        query: EvidenceExportQuery::tenant_scoped("tenant-a"),
        tool_receipts: Vec::new(),
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: Vec::new(),
        capability_lineage: Vec::new(),
        inclusion_proofs: Vec::new(),
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: None,
            oldest_live_receipt_timestamp: None,
        },
    };
    let mut manifest = manifest_for_bundle(&bundle);
    if let Some(notice) = manifest.disclosure_notice.as_mut() {
        notice.disclosed_checkpoint_body_fields.clear();
    }

    let error = verify_disclosure_notice(&manifest).test_unwrap_err();
    assert!(
        error.to_string().contains("disclosure notice"),
        "unexpected error: {error}",
    );
}
