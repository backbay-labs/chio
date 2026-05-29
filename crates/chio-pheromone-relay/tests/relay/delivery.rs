use super::common::{
    canonical_hash, delivery_evidence, delivery_evidence_set, delivery_negative_code,
    delivery_profile, evaluate_relay_alert_acknowledgement, evaluate_relay_alert_delivery, fs,
    generate_relay_alert_assurance_package, generate_relay_alert_delivery_drift_report,
    generate_relay_alert_handoff_drift_report, generate_relay_alert_route_review_packet,
    generated_alert_trend_handoff, generated_handoff_report, json, normalization_profile,
    normalize_relay_alert_delivery_evidence, relay_alert_delivery_evidence_from_json,
    relay_alert_delivery_profile_from_json, route_owner_profile, NegativeCorpus,
    RelayAlertAcknowledgementInput, RelayAlertAssuranceInput, RelayAlertDeliveryDriftInput,
    RelayAlertDeliveryInput, RelayAlertDeliveryStatus, RelayAlertHandoffDriftInput,
    RelayAlertNormalizationInput, RelayAlertRouteReviewInput, RelayAlertSeverity, NOW,
    PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA, PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA,
};

#[test]
fn relay_alert_delivery_import_binds_downstream_evidence_to_handoff() {
    let handoff_report = generated_handoff_report();
    let handoff_hash = canonical_hash(&handoff_report);
    let profile = relay_alert_delivery_profile_from_json(
        &serde_json::to_string(&delivery_profile()).unwrap(),
        NOW + 60_000,
    )
    .unwrap();
    let pager = &profile.receivers[0];
    let digest = &profile.receivers[1];
    let evidence = vec![
        delivery_evidence(
            &handoff_hash,
            pager,
            "dead_letters_present",
            RelayAlertSeverity::Critical,
            RelayAlertDeliveryStatus::Delivered,
        ),
        delivery_evidence(
            &handoff_hash,
            pager,
            "endpoint_denied",
            RelayAlertSeverity::Critical,
            RelayAlertDeliveryStatus::Accepted,
        ),
        delivery_evidence(
            &handoff_hash,
            digest,
            "retries_pending",
            RelayAlertSeverity::Info,
            RelayAlertDeliveryStatus::Duplicate,
        ),
    ];

    let report = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &handoff_report,
        delivery_profile: &profile,
        evidence: &evidence,
        now_unix_ms: NOW + 70_000,
    })
    .unwrap();

    assert_eq!(report.schema, PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA);
    assert!(report.accepted);
    assert_eq!(report.code, "accepted");
    assert_eq!(report.source_handoff_report_sha256, handoff_hash);
    assert_eq!(report.delivered_count, 3);
    assert_eq!(report.failed_count, 0);
    assert_eq!(report.results.len(), 3);
    assert!(report
        .results
        .iter()
        .all(|result| result.downstream_evidence_sha256.len() == 64));
}

#[test]
fn relay_alert_delivery_rejects_secrets_unbounded_labels_and_mismatches() {
    let mut bad_profile = delivery_profile();
    bad_profile.receivers[0].target_ref = "alertmanager:bearer-prod".to_string();
    let err =
        relay_alert_delivery_profile_from_json(&serde_json::to_string(&bad_profile).unwrap(), NOW)
            .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");

    let handoff_report = generated_handoff_report();
    let handoff_hash = canonical_hash(&handoff_report);
    let profile = relay_alert_delivery_profile_from_json(
        &serde_json::to_string(&delivery_profile()).unwrap(),
        NOW + 60_000,
    )
    .unwrap();
    let mut evidence = delivery_evidence(
        &handoff_hash,
        &profile.receivers[0],
        "dead_letters_present",
        RelayAlertSeverity::Critical,
        RelayAlertDeliveryStatus::Delivered,
    );

    evidence.receiver_id = "alertmanager-unknown".to_string();
    let err = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &handoff_report,
        delivery_profile: &profile,
        evidence: std::slice::from_ref(&evidence),
        now_unix_ms: NOW + 70_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");

    evidence.receiver_id = profile.receivers[0].receiver_id.clone();
    evidence
        .labels
        .insert("peer_id".to_string(), "did:chio:vendor-a".to_string());
    let err = relay_alert_delivery_evidence_from_json(&serde_json::to_string(&evidence).unwrap())
        .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");

    let mut missing = vec![delivery_evidence(
        &handoff_hash,
        &profile.receivers[0],
        "dead_letters_present",
        RelayAlertSeverity::Critical,
        RelayAlertDeliveryStatus::Delivered,
    )];
    missing.push(missing[0].clone());
    let err = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &handoff_report,
        delivery_profile: &profile,
        evidence: &missing,
        now_unix_ms: NOW + 70_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");

    let mut stale_handoff = handoff_report.clone();
    stale_handoff.generated_at_unix_ms = NOW - 600_000;
    let err = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &stale_handoff,
        delivery_profile: &profile,
        evidence: &[],
        now_unix_ms: NOW + 70_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");
}

#[test]
fn relay_alert_delivery_acknowledgement_and_drift_reports_are_bounded() {
    let handoff_report = generated_handoff_report();
    let handoff_hash = canonical_hash(&handoff_report);
    let profile = relay_alert_delivery_profile_from_json(
        &serde_json::to_string(&delivery_profile()).unwrap(),
        NOW + 60_000,
    )
    .unwrap();
    let evidence = vec![
        delivery_evidence(
            &handoff_hash,
            &profile.receivers[0],
            "dead_letters_present",
            RelayAlertSeverity::Critical,
            RelayAlertDeliveryStatus::Delivered,
        ),
        delivery_evidence(
            &handoff_hash,
            &profile.receivers[0],
            "endpoint_denied",
            RelayAlertSeverity::Critical,
            RelayAlertDeliveryStatus::Accepted,
        ),
        delivery_evidence(
            &handoff_hash,
            &profile.receivers[1],
            "retries_pending",
            RelayAlertSeverity::Info,
            RelayAlertDeliveryStatus::Delivered,
        ),
    ];
    let delivery_report = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &handoff_report,
        delivery_profile: &profile,
        evidence: &evidence,
        now_unix_ms: NOW + 70_000,
    })
    .unwrap();

    let acknowledgement = evaluate_relay_alert_acknowledgement(RelayAlertAcknowledgementInput {
        handoff_report: &handoff_report,
        delivery_report: &delivery_report,
        delivery_profile: &profile,
        now_unix_ms: NOW + 80_000,
    })
    .unwrap();
    assert_eq!(
        acknowledgement.schema,
        PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA
    );
    assert!(acknowledgement.accepted);
    assert_eq!(acknowledgement.acknowledged_count, 3);
    assert_eq!(acknowledgement.pending_count, 0);

    let drift = generate_relay_alert_handoff_drift_report(RelayAlertHandoffDriftInput {
        handoff_reports: std::slice::from_ref(&handoff_report),
        delivery_reports: std::slice::from_ref(&delivery_report),
        delivery_profile: &profile,
        since_unix_ms: NOW,
        until_unix_ms: NOW + 90_000,
    })
    .unwrap();
    assert_eq!(
        drift.schema,
        PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA
    );
    assert!(drift.accepted);
    assert_eq!(drift.drift_count, 0);

    let mut incomplete_delivery = delivery_report.clone();
    incomplete_delivery
        .results
        .retain(|result| result.alert_code != "endpoint_denied");
    let drift = generate_relay_alert_handoff_drift_report(RelayAlertHandoffDriftInput {
        handoff_reports: &[handoff_report],
        delivery_reports: &[incomplete_delivery],
        delivery_profile: &profile,
        since_unix_ms: NOW,
        until_unix_ms: NOW + 90_000,
    })
    .unwrap();
    assert!(!drift.accepted);
    assert_eq!(drift.code, "handoff_drift_detected");
    assert!(drift
        .drifts
        .iter()
        .any(|entry| entry.code == "missing_delivery_result"));
}

#[test]
fn relay_alert_delivery_negative_corpus_cases_are_executable() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/chio-3vendor/fixtures/pheromone/relay/",
        "relay-alert-delivery-negative-cases.json"
    );
    let corpus: NegativeCorpus = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for case in &corpus.cases {
        assert!(seen.insert(case.id.as_str()), "duplicate case {}", case.id);
        if case.id == "wrong-expected-code" {
            let observed = delivery_negative_code("source-hash-mismatch");
            assert_ne!(observed, "unsupported_schema");
            assert_eq!(case.expected_code, "negative_expectation_mismatch");
            continue;
        }
        let observed = delivery_negative_code(&case.id);
        assert_eq!(
            observed, case.expected_code,
            "negative case {} expected {} but observed {}",
            case.id, case.expected_code, observed
        );
    }
    for required in [
        "live-url",
        "inline-token",
        "unbounded-label",
        "unknown-receiver",
        "route-mismatch",
        "dedupe-missing",
        "stale-handoff",
        "source-hash-mismatch",
        "duplicate-result",
        "missing-critical-delivery",
        "severity-weakened",
        "runbook-drift",
        "wrong-expected-code",
    ] {
        assert!(seen.contains(required), "missing negative case {required}");
    }
}

#[test]
fn relay_alert_assurance_normalizes_downstream_evidence() {
    let handoff_report = generated_handoff_report();
    let handoff_hash = canonical_hash(&handoff_report);
    let profile = normalization_profile();
    let sources = vec![
        json!({
            "schema": "downstream.alertmanager.drop.v1",
            "receiverId": "alertmanager-pagerduty-primary",
            "alertCode": "dead_letters_present",
            "dedupeKey": "chio-relay:did:chio:buyer-kernel:dead_letters_present:delivery",
            "status": "delivered",
            "severity": "critical",
            "runbook": "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage",
            "observedAtUnixMs": NOW + 61_000,
            "sourceHandoffReportSha256": handoff_hash,
            "labels": {
                "notification_route": "pagerduty-primary",
                "opsgenie": "relay-oncall",
                "service": "chio-pheromone-relay",
                "severity": "critical",
                "status": "delivered",
                "receiver": "alertmanager-pagerduty-primary"
            }
        }),
        json!({
            "schema": "downstream.alertmanager.drop.v1",
            "receiverId": "alertmanager-pagerduty-primary",
            "alertCode": "endpoint_denied",
            "dedupeKey": "chio-relay:did:chio:buyer-kernel:endpoint_denied:delivery",
            "status": "accepted",
            "severity": "critical",
            "runbook": "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage",
            "observedAtUnixMs": NOW + 61_000,
            "sourceHandoffReportSha256": handoff_hash,
            "labels": {
                "notification_route": "pagerduty-primary",
                "opsgenie": "relay-oncall",
                "service": "chio-pheromone-relay",
                "severity": "critical",
                "status": "accepted",
                "receiver": "alertmanager-pagerduty-primary"
            }
        }),
        json!({
            "schema": "downstream.siem.drop.v1",
            "receiver_id": "alertmanager-slack-digest",
            "alert_code": "retries_pending",
            "dedupe_key": "chio-relay:did:chio:buyer-kernel:retries_pending:delivery",
            "outcome": "delivered",
            "severity": "info",
            "runbook_ref": "docs/release/CHIO_PHEROMONE_RELAY_RUNBOOK.md#stuck-outbox",
            "observed_at_unix_ms": NOW + 61_000,
            "source_handoff_report_sha256": handoff_hash,
            "labels": {
                "notification_route": "slack-ops-digest",
                "opsgenie": "relay-oncall",
                "service": "chio-pheromone-relay",
                "severity": "info",
                "status": "delivered",
                "receiver": "alertmanager-slack-digest"
            }
        }),
    ];

    let report = normalize_relay_alert_delivery_evidence(RelayAlertNormalizationInput {
        profile: &profile,
        sources: &sources,
        now_unix_ms: NOW + 70_000,
    })
    .unwrap();

    assert_eq!(
        report.schema,
        PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA
    );
    assert!(report.accepted);
    assert_eq!(report.normalized_count, 3);
    assert_eq!(report.evidence.len(), 3);
    assert!(report
        .evidence
        .iter()
        .all(|item| item.schema == PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA));

    let delivery = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &handoff_report,
        delivery_profile: &delivery_profile(),
        evidence: &report.evidence,
        now_unix_ms: NOW + 70_000,
    })
    .unwrap();
    assert!(delivery.accepted);
}

#[test]
fn relay_alert_assurance_rejects_bad_normalization_inputs() {
    let mut duplicate_profile = normalization_profile();
    duplicate_profile
        .receivers
        .push(duplicate_profile.receivers[0].clone());
    let err = normalize_relay_alert_delivery_evidence(RelayAlertNormalizationInput {
        profile: &duplicate_profile,
        sources: &[],
        now_unix_ms: NOW + 70_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");

    let profile = normalization_profile();
    let err = normalize_relay_alert_delivery_evidence(RelayAlertNormalizationInput {
        profile: &profile,
        sources: &[json!({
            "schema": "downstream.alertmanager.drop.v1",
            "receiverId": "alertmanager-pagerduty-primary",
            "alertCode": "dead_letters_present",
            "status": "delivered",
            "severity": "critical",
            "observedAtUnixMs": NOW + 61_000,
            "sourceHandoffReportSha256": "a".repeat(64),
            "url": "https://alerts.example.test/api"
        })],
        now_unix_ms: NOW + 70_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_delivery_invalid");
}

#[test]
fn relay_alert_assurance_source_bound_drift_rejects_cross_handoff_masking() {
    let old_handoff = generated_handoff_report();
    let old_handoff_hash = canonical_hash(&old_handoff);
    let mut newer_handoff = old_handoff.clone();
    newer_handoff.generated_at_unix_ms = NOW + 80_000;
    let newer_handoff_hash = canonical_hash(&newer_handoff);
    let profile = relay_alert_delivery_profile_from_json(
        &serde_json::to_string(&delivery_profile()).unwrap(),
        NOW + 120_000,
    )
    .unwrap();
    let newer_evidence = delivery_evidence_set(&newer_handoff_hash, &profile);
    let newer_delivery = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &newer_handoff,
        delivery_profile: &profile,
        evidence: &newer_evidence,
        now_unix_ms: NOW + 90_000,
    })
    .unwrap();

    let drift = generate_relay_alert_delivery_drift_report(RelayAlertDeliveryDriftInput {
        handoff_reports: &[old_handoff, newer_handoff],
        delivery_reports: &[newer_delivery],
        delivery_profile: &profile,
        since_unix_ms: NOW,
        until_unix_ms: NOW + 120_000,
    })
    .unwrap();

    assert_eq!(
        drift.schema,
        PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA
    );
    assert!(!drift.accepted);
    assert!(drift
        .drifts
        .iter()
        .any(|entry| entry.code == "missing_delivery_result"
            && entry.source_handoff_report_sha256 == old_handoff_hash));
}

#[test]
fn relay_alert_assurance_package_binds_full_operator_chain() {
    let (alert_report, trend_report, handoff_report) = generated_alert_trend_handoff();
    let handoff_hash = canonical_hash(&handoff_report);
    let delivery_profile = relay_alert_delivery_profile_from_json(
        &serde_json::to_string(&delivery_profile()).unwrap(),
        NOW + 90_000,
    )
    .unwrap();
    let normalization = normalize_relay_alert_delivery_evidence(RelayAlertNormalizationInput {
        profile: &normalization_profile(),
        sources: &delivery_evidence_set(&handoff_hash, &delivery_profile)
            .into_iter()
            .map(|evidence| serde_json::to_value(evidence).unwrap())
            .collect::<Vec<_>>(),
        now_unix_ms: NOW + 70_000,
    })
    .unwrap();
    let delivery_report = evaluate_relay_alert_delivery(RelayAlertDeliveryInput {
        handoff_report: &handoff_report,
        delivery_profile: &delivery_profile,
        evidence: &normalization.evidence,
        now_unix_ms: NOW + 70_000,
    })
    .unwrap();
    let acknowledgement = evaluate_relay_alert_acknowledgement(RelayAlertAcknowledgementInput {
        handoff_report: &handoff_report,
        delivery_report: &delivery_report,
        delivery_profile: &delivery_profile,
        now_unix_ms: NOW + 80_000,
    })
    .unwrap();
    let drift = generate_relay_alert_delivery_drift_report(RelayAlertDeliveryDriftInput {
        handoff_reports: std::slice::from_ref(&handoff_report),
        delivery_reports: std::slice::from_ref(&delivery_report),
        delivery_profile: &delivery_profile,
        since_unix_ms: NOW,
        until_unix_ms: NOW + 90_000,
    })
    .unwrap();
    let review = generate_relay_alert_route_review_packet(RelayAlertRouteReviewInput {
        handoff_report: &handoff_report,
        delivery_report: &delivery_report,
        acknowledgement_report: &acknowledgement,
        drift_report: &drift,
        route_owner_profile: &route_owner_profile(),
        now_unix_ms: NOW + 90_000,
    })
    .unwrap();
    assert_eq!(
        review.schema,
        PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA
    );
    assert!(review.accepted);

    let assurance = generate_relay_alert_assurance_package(RelayAlertAssuranceInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        handoff_report: &handoff_report,
        normalization_report: &normalization,
        delivery_report: &delivery_report,
        acknowledgement_report: &acknowledgement,
        drift_report: &drift,
        review_packet: &review,
        now_unix_ms: NOW + 90_000,
    })
    .unwrap();

    assert_eq!(
        assurance.schema,
        PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA
    );
    assert!(!assurance.accepted);
    assert_eq!(assurance.code, "assurance_attention_required");
    assert_eq!(assurance.source_handoff_report_sha256, handoff_hash);
    assert!(assurance
        .operator_action_codes
        .iter()
        .any(|code| code == "active_alerts_present"));
}
