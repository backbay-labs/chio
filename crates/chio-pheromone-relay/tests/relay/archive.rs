use super::*;

#[test]
fn relay_alert_assurance_archive_verifies_before_closeout_review() {
    let (bundle, exporter) =
        relay_alert_assurance_export_bundle(93, "relay-alert-assurance-export-archive-001");
    let candidate = RelayAlertAssuranceArchiveBundleCandidate {
        bundle_path: "exports/relay-alert-assurance-export-archive-001".to_string(),
        bundle: Some(bundle),
        error_code: None,
        error_detail: None,
    };
    let trusted = trusted_exporters(exporter.public_key());
    let archive = generate_relay_alert_assurance_archive_report(RelayAlertAssuranceArchiveInput {
        bundles: std::slice::from_ref(&candidate),
        trusted_exporters: &trusted,
        archive_profile: &archive_profile_for_export(),
        retention_profile: &retention_profile_for_export(),
        now_unix_ms: NOW + 100_000,
    })
    .unwrap();

    assert_eq!(
        archive.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA
    );
    assert!(archive.accepted);
    assert_eq!(archive.archive_ready_count, 1);
    assert_eq!(archive.quarantine_count, 0);
    assert_eq!(archive.legal_hold_count, 1);
    assert_eq!(archive.reviews[0].state, "archive_ready");
    assert!(archive.reviews[0].trusted_exporter_verified);
    assert!(archive.reviews[0].replay_matched);
    assert!(archive.reviews[0].recovery_drill_accepted);

    let closeout =
        generate_relay_alert_assurance_closeout_report(RelayAlertAssuranceCloseoutInput {
            bundles: &[candidate],
            trusted_exporters: &trusted,
            closeout_profile: &closeout_profile_for_export(),
            retention_profile: &retention_profile_for_export(),
            now_unix_ms: NOW + 100_000,
        })
        .unwrap();
    assert_eq!(
        closeout.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA
    );
    assert!(!closeout.accepted);
    assert_eq!(closeout.closeout_blocked_count, 1);
    assert_eq!(closeout.reviews[0].state, "closeout_blocked");
    assert_eq!(closeout.reviews[0].code, "legal_hold_blocked");
}

#[test]
fn relay_alert_assurance_archive_quarantines_bad_bundle_without_aborting_batch() {
    let (bundle, _exporter) =
        relay_alert_assurance_export_bundle(94, "relay-alert-assurance-export-archive-002");
    let candidate = RelayAlertAssuranceArchiveBundleCandidate {
        bundle_path: "exports/relay-alert-assurance-export-archive-002".to_string(),
        bundle: Some(bundle),
        error_code: None,
        error_detail: None,
    };
    let untrusted = trusted_exporters(key(95).public_key());

    let archive = generate_relay_alert_assurance_archive_report(RelayAlertAssuranceArchiveInput {
        bundles: &[candidate],
        trusted_exporters: &untrusted,
        archive_profile: &archive_profile_for_export(),
        retention_profile: &retention_profile_for_export(),
        now_unix_ms: NOW + 100_000,
    })
    .unwrap();

    assert!(!archive.accepted);
    assert_eq!(archive.archive_ready_count, 0);
    assert_eq!(archive.quarantine_count, 1);
    assert_eq!(archive.reviews[0].state, "quarantine");
    assert_eq!(archive.reviews[0].code, "signature_invalid");
    assert!(!archive.reviews[0].trusted_exporter_verified);
}

#[test]
fn relay_alert_assurance_export_signs_verifies_replays_and_plans_retention() {
    let chain = generated_assurance_chain();
    let exporter = key(91);
    let bundle = sign_relay_alert_assurance_export_bundle(RelayAlertAssuranceExportBuildInput {
        bundle_id: "relay-alert-assurance-export-001",
        exporter_id: "relay-exporter",
        exporter_key_id: "relay-export-key-1",
        signing_key: &exporter,
        retention_profile: &retention_profile_for_export(),
        alert_report: &chain.alert_report,
        trend_report: &chain.trend_report,
        handoff_report: &chain.handoff_report,
        normalization_report: &chain.normalization_report,
        delivery_report: &chain.delivery_report,
        acknowledgement_report: &chain.acknowledgement_report,
        drift_report: &chain.drift_report,
        review_packet: &chain.review_packet,
        assurance_package: &chain.assurance_package,
        normalized_delivery_evidence: &chain.normalization_report.evidence,
        exported_at_unix_ms: NOW + 100_000,
    })
    .unwrap();

    assert_eq!(
        bundle.manifest.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA
    );
    assert_eq!(
        bundle.report.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA
    );
    assert!(bundle.report.accepted);
    assert!(bundle
        .manifest
        .body
        .artifacts
        .iter()
        .any(|artifact| artifact.role == "assurance_package"));
    assert!(bundle
        .manifest
        .body
        .artifacts
        .iter()
        .all(|artifact| !artifact.path.starts_with('/')));

    let trusted = trusted_exporters(exporter.public_key());
    let verify =
        verify_relay_alert_assurance_export_bundle(&bundle, &trusted, NOW + 100_000).unwrap();
    assert!(verify.accepted);

    let replay = generate_relay_alert_assurance_replay_report(RelayAlertAssuranceReplayInput {
        bundle: &bundle,
        trusted_exporters: &trusted,
        now_unix_ms: NOW + 100_000,
    })
    .unwrap();
    assert_eq!(
        replay.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_REPLAY_REPORT_SCHEMA
    );
    assert!(replay.accepted);
    assert_eq!(replay.replayed_package_sha256, replay.source_package_sha256);

    let retention =
        generate_relay_alert_assurance_retention_report(RelayAlertAssuranceRetentionInput {
            bundles: std::slice::from_ref(&bundle),
            retention_profile: &retention_profile_for_export(),
            now_unix_ms: NOW + 100_000,
        })
        .unwrap();
    assert_eq!(
        retention.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_REPORT_SCHEMA
    );
    assert!(retention.accepted);
    assert!(retention
        .entries
        .iter()
        .any(|entry| entry.state == "blocked" && entry.artifact_role == "assurance_package"));

    let drill = generate_relay_alert_assurance_recovery_drill_report(
        RelayAlertAssuranceRecoveryDrillInput {
            bundle: &bundle,
            trusted_exporters: &trusted,
            case_id: "all",
            now_unix_ms: NOW + 100_000,
        },
    )
    .unwrap();
    assert_eq!(
        drill.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA
    );
    assert!(drill.accepted);
    assert!(drill
        .drills
        .iter()
        .any(|entry| entry.case_id == "bad_export_signature"));
}

#[test]
fn relay_alert_assurance_export_rejects_unsafe_or_untrusted_bundles() {
    let chain = generated_assurance_chain();
    let exporter = key(92);
    let bundle = sign_relay_alert_assurance_export_bundle(RelayAlertAssuranceExportBuildInput {
        bundle_id: "relay-alert-assurance-export-002",
        exporter_id: "relay-exporter",
        exporter_key_id: "relay-export-key-1",
        signing_key: &exporter,
        retention_profile: &retention_profile_for_export(),
        alert_report: &chain.alert_report,
        trend_report: &chain.trend_report,
        handoff_report: &chain.handoff_report,
        normalization_report: &chain.normalization_report,
        delivery_report: &chain.delivery_report,
        acknowledgement_report: &chain.acknowledgement_report,
        drift_report: &chain.drift_report,
        review_packet: &chain.review_packet,
        assurance_package: &chain.assurance_package,
        normalized_delivery_evidence: &chain.normalization_report.evidence,
        exported_at_unix_ms: NOW + 100_000,
    })
    .unwrap();

    let unknown = trusted_exporters(key(99).public_key());
    let err =
        verify_relay_alert_assurance_export_bundle(&bundle, &unknown, NOW + 100_000).unwrap_err();
    assert_eq!(err.code(), "signature_invalid");

    let mut tampered = bundle.clone();
    tampered.files[0].bytes.push(b'\n');
    let err = verify_relay_alert_assurance_export_bundle(
        &tampered,
        &trusted_exporters(exporter.public_key()),
        NOW + 100_000,
    )
    .unwrap_err();
    assert_eq!(err.code(), "body_hash_mismatch");

    let mut unsafe_path = bundle.clone();
    unsafe_path.files[0].path = "../escape.json".to_string();
    let err = verify_relay_alert_assurance_export_bundle(
        &unsafe_path,
        &trusted_exporters(exporter.public_key()),
        NOW + 100_000,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");
}
