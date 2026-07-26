use chio_core_types::crypto::Keypair;
use chio_federation::{
    treaty::compute_ladder_intersection, treaty::evaluate_cross_boundary_admission,
    treaty::governance_ladder_manifest_sha256, treaty::ladder_intersection_sha256,
    treaty::CrossBoundaryAdmissionInput, treaty::CrossBoundaryEvidenceRef,
    treaty::GovernanceLadderActionClass, treaty::GovernanceLadderManifest,
    treaty::GovernanceLadderQuorum, treaty::TreatyScope,
    treaty::CHIO_FEDERATION_GOVERNANCE_LADDER_MANIFEST_SCHEMA,
    treaty::CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA,
    treaty::CHIO_FEDERATION_TREATY_SCOPE_SCHEMA,
};

#[test]
fn chio_treaty_intersection_emits_chio_schema() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_a = treaty_manifest("kernel.buyer", treaty_action("receipt_backed", false));
    let manifest_b = treaty_manifest("kernel.vendor", treaty_action("receipt_backed", false));
    let scope = treaty_scope(&manifest_a, &manifest_b)?;

    let intersection =
        compute_ladder_intersection(&scope, &[manifest_a, manifest_b], 1_800_000_001_000)?;

    assert_eq!(
        intersection.schema,
        CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA
    );
    assert_eq!(intersection.treaty_id, scope.treaty_id);
    assert_eq!(intersection.action_classes.len(), 1);
    assert_eq!(intersection.action_classes[0].mode, "receipt_backed");
    Ok(())
}

#[test]
fn chio_treaty_intersection_rejects_destructive_crdt() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_a = treaty_manifest("kernel.buyer", treaty_action("receipt_backed", true));
    let manifest_b = treaty_manifest("kernel.vendor", treaty_action("receipt_backed", true));
    let scope = treaty_scope(&manifest_a, &manifest_b)?;
    let mut manifest_b = manifest_b;
    manifest_b.action_classes[0].consistency_model = "crdt-commutative".to_string();

    let error =
        match compute_ladder_intersection(&scope, &[manifest_a, manifest_b], 1_800_000_001_000) {
            Ok(_) => panic!("destructive CRDT action class must fail closed"),
            Err(error) => error,
        };

    assert_eq!(
        error.code(),
        "chio_federation_ladder_destructive_crdt_not_allowed"
    );
    Ok(())
}

#[test]
fn chio_treaty_manifest_rejects_alias_shadowing_later_canonical_action(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias_action = treaty_action("receipt_backed", false);
    alias_action.action_class_id = "workflow.alias.source".to_string();
    alias_action.aliases = vec!["workflow.destructive.vendor_call".to_string()];
    let canonical_action = treaty_action("receipt_backed", true);
    let manifest = treaty_manifest("kernel.buyer", alias_action);
    let mut manifest = manifest;
    manifest.action_classes.push(canonical_action);

    let error = match governance_ladder_manifest_sha256(&manifest) {
        Ok(_) => panic!("ladder aliases must not shadow later canonical action classes"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "chio_federation_ladder_alias_conflict");
    Ok(())
}

#[test]
fn chio_treaty_uses_canonical_n_of_m_vocabulary_and_quorum_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut canonical = treaty_action("receipt_backed", true);
    canonical.co_sign = "n_of_m".to_string();
    canonical.consistency_model = "quorum-required".to_string();
    canonical.co_sign_quorum = Some(GovernanceLadderQuorum {
        n: 2,
        m: 3,
        scope: "treaty".to_string(),
    });
    let manifest = treaty_manifest("kernel.quorum", canonical);
    governance_ladder_manifest_sha256(&manifest)?;

    let mut legacy = manifest;
    legacy.action_classes[0].co_sign = "quorum_required".to_string();
    let error = match governance_ladder_manifest_sha256(&legacy) {
        Ok(_) => panic!("legacy quorum_required co-sign vocabulary must reject"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "chio_federation_ladder_invalid_cosign_mode");
    Ok(())
}

#[test]
fn chio_cross_boundary_admission_report_uses_chio_codes_and_checks(
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_a = treaty_manifest("kernel.buyer", treaty_action("receipt_backed", false));
    let manifest_b = treaty_manifest("kernel.vendor", treaty_action("receipt_backed", false));
    let scope = treaty_scope(&manifest_a, &manifest_b)?;
    let intersection = compute_ladder_intersection(
        &scope,
        &[manifest_a.clone(), manifest_b.clone()],
        1_800_000_001_000,
    )?;
    let expected_ladder_intersection_sha256 = ladder_intersection_sha256(&intersection)?;

    let report = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &scope,
        ladder_intersection: &intersection,
        expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256),
        action_class_id: "workflow.destructive.vendor_call",
        present_evidence: Vec::new(),
        verified_evidence: Vec::<CrossBoundaryEvidenceRef>::new(),
        now_unix_ms: 1_800_000_002_000,
    })?;

    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_federation_treaty_missing_required_evidence")
    );
    assert!(
        report
            .checks
            .iter()
            .all(|check| !check.contains("chio_treaty")),
        "Chio federation admission checks must not expose Chio names: {:#?}",
        report.checks
    );
    Ok(())
}

fn treaty_action(mode: &str, destructive: bool) -> GovernanceLadderActionClass {
    GovernanceLadderActionClass {
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        mode: mode.to_string(),
        destructive,
        consistency_model: "totally-ordered".to_string(),
        co_sign: "bilateral_required".to_string(),
        co_sign_quorum: None,
        evidence_required: vec!["receipt_lineage".to_string()],
        aliases: Vec::new(),
    }
}

fn treaty_manifest(
    kernel_id: &str,
    action: GovernanceLadderActionClass,
) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_FEDERATION_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder-{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: format!("did:chio:{kernel_id}"),
        key_id: "ladder-key-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![action],
    }
}

fn treaty_scope(
    manifest_a: &GovernanceLadderManifest,
    manifest_b: &GovernanceLadderManifest,
) -> Result<TreatyScope, Box<dyn std::error::Error>> {
    let buyer_key = Keypair::generate();
    let vendor_key = Keypair::generate();
    Ok(TreatyScope {
        schema: CHIO_FEDERATION_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: "treaty-buyer-vendor".to_string(),
        participant_kernel_ids: vec![manifest_a.kernel_id.clone(), manifest_b.kernel_id.clone()],
        participant_public_keys: vec![buyer_key.public_key(), vendor_key.public_key()],
        ladder_manifest_sha256s: vec![
            governance_ladder_manifest_sha256(manifest_a)?,
            governance_ladder_manifest_sha256(manifest_b)?,
        ],
        allowed_action_classes: vec!["workflow.destructive.vendor_call".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        revocation_epoch_sha256: "c".repeat(64),
        trust_bundle_sha256: "b".repeat(64),
    })
}
