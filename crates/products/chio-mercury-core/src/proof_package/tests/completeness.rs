use super::*;

fn selected_context_package() -> MercuryProofPackage {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let selected_keypair = Keypair::generate();
    let checkpoint_keypair = Keypair::generate();
    let context_receipt = sample_receipt(1);
    let selected_metadata = metadata_with_bundle_refs(vec![bundle_ref]);
    let selected_action =
        ToolCallAction::from_parameters(mercury_action_parameters(&selected_metadata))
            .expect("selected action");
    let selected_receipt = signed_sample_receipt_with_action_and_metadata(
        2,
        &selected_keypair,
        Some(Decision::Allow),
        "mercury",
        "release_control",
        selected_action,
        SampleReceiptContext::tenant(selected_metadata, "tenant-a"),
    );
    let context_canonical =
        canonical_json_bytes(&context_receipt).expect("context canonical receipt");
    let selected_canonical =
        canonical_json_bytes(&selected_receipt).expect("selected canonical receipt");
    let context_checkpoint = build_checkpoint(
        1,
        1,
        1,
        std::slice::from_ref(&context_canonical),
        &checkpoint_keypair,
    )
    .expect("context checkpoint");
    let context_chain_leaf = checkpoint_chain_leaf_hash(&context_checkpoint.body)
        .expect("context checkpoint chain leaf");
    let selected_checkpoint = build_checkpoint_with_previous(
        2,
        2,
        2,
        std::slice::from_ref(&selected_canonical),
        &checkpoint_keypair,
        Some(&context_checkpoint),
        &[context_chain_leaf],
    )
    .expect("selected checkpoint");
    let selected_tree =
        MerkleTree::from_leaves(std::slice::from_ref(&selected_canonical)).expect("selected tree");
    let selected_proof = build_inclusion_proof(
        &selected_tree,
        0,
        selected_checkpoint.body.checkpoint_seq,
        2,
    )
    .expect("selected proof");
    let mut query = EvidenceExportQuery::tenant_scoped("tenant-a");
    query.since = Some(1_775_137_627);
    query.until = Some(1_775_137_627);
    let bundle = EvidenceExportBundle {
        query,
        tool_receipts: vec![EvidenceToolReceiptRecord {
            seq: 2,
            receipt: selected_receipt,
        }],
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: vec![context_checkpoint, selected_checkpoint],
        capability_lineage: Vec::new(),
        inclusion_proofs: vec![selected_proof],
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: None,
            oldest_live_receipt_timestamp: Some(1_775_137_627),
        },
    };

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
    .expect("selected proof package")
}

fn rebuild_with_query(
    package: &MercuryProofPackage,
    query: EvidenceExportQuery,
    evidence_export_manifest_hash: &str,
) -> MercuryProofPackage {
    let mut bundle = package.chio_bundle.clone();
    bundle.query = query;
    MercuryProofPackage::build(
        bundle,
        evidence_export_manifest_hash,
        package.evidence_export_schema.clone(),
        package.evidence_exported_at,
        package.created_at,
        package.publication_profile.clone(),
        package.checkpoint_transparency.clone(),
        package.bundle_manifests.clone(),
    )
    .expect("rebuilt proof package")
}

#[test]
fn tenant_time_scoped_context_uses_selected_receipt_coverage() {
    let package = selected_context_package();
    assert_eq!(
        package.publication_profile.completeness_mode,
        COMPLETENESS_SELECTED_RECEIPT_COVERAGE
    );
    assert_eq!(package.chio_bundle.checkpoints.len(), 2);
    assert!(package
        .chio_bundle
        .inclusion_proofs
        .iter()
        .all(|proof| proof.checkpoint_seq == 2));

    let structural_report = package.verify(1_775_137_920).expect("structural report");
    assert!(!structural_report.verifier_equivalent);
    let trusted_keys = trusted_authority_keys(&package.chio_bundle);
    let trusted_report = package
        .verify_with_trusted_kernel_keys(1_775_137_921, &trusted_keys)
        .expect("trusted selected receipt verification");
    assert!(!trusted_report.verifier_equivalent);
    assert!(trusted_report.steps.iter().any(|step| {
        step.name == "chio_bundle_integrity"
            && step
                .detail
                .contains("zero-proof checkpoint-prefix context is permitted")
    }));

    let mut inquiry = MercuryInquiryPackage::build(
        package,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_922,
            audience: "compliance".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            verifier_equivalent: true,
        },
    )
    .expect("selected inquiry package");
    assert!(!inquiry.verifier_equivalent);
    inquiry.verifier_equivalent = true;
    let error = inquiry
        .validate()
        .expect_err("selected inquiry cannot force verifier equivalence");
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
fn unsigned_query_mutation_cannot_elevate_selected_coverage() {
    let mut package = selected_context_package();
    let selected_package_id = package.package_id.clone();
    package.chio_bundle.query = EvidenceExportQuery::admin_all();
    assert_eq!(
        derived_completeness_mode(&package.chio_bundle),
        COMPLETENESS_BEST_EFFORT
    );
    package.publication_profile.completeness_mode = COMPLETENESS_BEST_EFFORT.to_string();
    package.refresh_package_id().expect("refresh package id");
    assert_ne!(package.package_id, selected_package_id);
    package
        .verify(1_775_137_922)
        .expect("mutated descriptor remains structurally checkable");

    let trusted_keys = trusted_authority_keys(&package.chio_bundle);
    let error = package
        .verify_with_trusted_kernel_keys(1_775_137_923, &trusted_keys)
        .expect_err("unsigned query mutation cannot gain verifier equivalence");
    assert!(
        error.to_string().contains(
            "unfiltered admin-all coverage of every leaf in the bundled checkpoint prefix"
        ),
        "unexpected error: {error}"
    );

    package.publication_profile.completeness_mode =
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE.to_string();
    package
        .refresh_package_id()
        .expect("refresh forced package id");
    let error = package
        .validate()
        .expect_err("forced full coverage cannot hide the omitted context leaf");
    assert!(
        error
            .to_string()
            .contains("completeness_mode must be best_effort"),
        "unexpected error: {error}"
    );
}

#[test]
fn content_addressed_query_rebuild_cannot_elevate_full_batch_selection() {
    let manifest = sample_mercury_bundle_manifest();
    let bundle_ref = MercuryBundleReference::from_manifest(&manifest).expect("bundle ref");
    let full_package = proof_package_with_signed_refs(vec![bundle_ref], vec![manifest]);
    let mut selected_query = EvidenceExportQuery::admin_all();
    selected_query.capability_id = Some(
        full_package.chio_bundle.tool_receipts[0]
            .receipt
            .capability_id
            .clone(),
    );
    let selected_package = rebuild_with_query(
        &full_package,
        selected_query,
        &full_package.evidence_export_manifest_hash,
    );
    assert_eq!(
        selected_package.publication_profile.completeness_mode,
        COMPLETENESS_SELECTED_RECEIPT_COVERAGE
    );
    let selected_keys = trusted_authority_keys(&selected_package.chio_bundle);
    let selected_report = selected_package
        .verify_with_trusted_kernel_keys(1_775_137_924, &selected_keys)
        .expect("trusted selected full-batch verification");
    assert!(!selected_report.verifier_equivalent);

    let repackaged = rebuild_with_query(
        &selected_package,
        EvidenceExportQuery::admin_all(),
        "attacker-selected-manifest-sha256",
    );
    assert_ne!(repackaged.package_id, selected_package.package_id);
    assert_ne!(
        repackaged.evidence_export_manifest_hash,
        selected_package.evidence_export_manifest_hash
    );
    assert_eq!(
        repackaged.publication_profile.completeness_mode,
        COMPLETENESS_FULL_CHECKPOINT_COVERAGE
    );
    let repackaged_keys = trusted_authority_keys(&repackaged.chio_bundle);
    let repackaged_report = repackaged
        .verify_with_trusted_kernel_keys(1_775_137_925, &repackaged_keys)
        .expect("trusted repackaged full-batch verification");
    assert!(!repackaged_report.verifier_equivalent);
    assert!(repackaged_report.steps.iter().any(|step| {
        step.name == "portable_export_boundary"
            && step.detail.contains("not signed by a trusted exporter")
    }));

    let inquiry = MercuryInquiryPackage::build(
        repackaged,
        MercuryInquiryPackageArgs {
            created_at: 1_775_137_926,
            audience: "compliance".to_string(),
            redaction_profile: Some("internal-default".to_string()),
            verifier_equivalent: true,
        },
    )
    .expect("repackaged full-batch inquiry");
    assert!(!inquiry.verifier_equivalent);
    assert_eq!(
        inquiry
            .rendered_export
            .get("verifierEquivalent")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let inquiry_report = inquiry
        .verify_with_trusted_kernel_keys(1_775_137_927, &repackaged_keys)
        .expect("trusted repackaged full-batch inquiry verification");
    assert!(!inquiry_report.verifier_equivalent);
}

#[test]
fn selected_coverage_rejects_missing_extra_duplicate_and_misbound_proofs() {
    let base = selected_context_package().chio_bundle;

    let mut missing = base.clone();
    missing.inclusion_proofs.clear();

    let mut extra = base.clone();
    let mut extra_proof = extra.inclusion_proofs[0].clone();
    extra_proof.receipt_seq = 1;
    extra.inclusion_proofs.push(extra_proof);

    let mut duplicate = base.clone();
    duplicate
        .inclusion_proofs
        .push(duplicate.inclusion_proofs[0].clone());

    let mut misbound = base;
    misbound.inclusion_proofs[0].leaf_index += 1;

    for (case, bundle) in [
        ("missing", missing),
        ("extra", extra),
        ("duplicate", duplicate),
        ("misbound", misbound),
    ] {
        assert_eq!(
            derived_completeness_mode(&bundle),
            COMPLETENESS_BEST_EFFORT,
            "{case} proof must not qualify for selected coverage"
        );
    }
}
