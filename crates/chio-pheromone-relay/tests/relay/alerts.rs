use super::common::{
    alert_event, alert_profile, degraded_observability_report, evaluate_relay_alert_handoff,
    evaluate_relay_alerts, generate_relay_trend_report, handoff_profile,
    relay_alert_handoff_profile_from_json, relay_alert_routing_profile_from_json,
    relay_alert_suppression_state_from_json, RelayAlertEvaluationInput, RelayAlertHandoffInput,
    RelayAlertHandoffSinkKind, RelayAlertSeverity, RelayAlertSuppressionEntry,
    RelayAlertSuppressionStateDocument, RelayEventReport, RelayTrendInput, NOW,
    PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_REPORT_SCHEMA,
    PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA,
};

#[test]
fn relay_alert_evaluation_routes_degraded_observability_with_bounded_evidence() {
    let observability = degraded_observability_report();
    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let event = RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: "dead_letters_present".to_string(),
        detail: "dead-lettered relay batch".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW - 30_000,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: Some("dead_letters_present".to_string()),
    };
    let report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[event],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();

    assert_eq!(report.schema, PHEROMONE_RELAY_ALERT_REPORT_SCHEMA);
    assert!(!report.accepted);
    assert_eq!(report.alerts.len(), 3);
    let critical = report
        .alerts
        .iter()
        .find(|alert| alert.code == "dead_letters_present")
        .unwrap();
    assert_eq!(critical.state, "firing");
    assert_eq!(critical.severity, "critical");
    assert_eq!(critical.notification_route, "pagerduty-primary");
    assert_eq!(critical.opsgenie, "relay-oncall");
    assert_eq!(critical.event_evidence_sha256.len(), 1);
    assert!(critical.labels.keys().all(|key| {
        matches!(
            key.as_str(),
            "notification_route" | "opsgenie" | "service" | "severity"
        )
    }));
}

#[test]
fn relay_alert_evaluation_rejects_secrets_dynamic_urls_and_bad_suppression() {
    let mut profile = alert_profile();
    profile.routes[0].target_ref = "https://hooks.example.test/secret-token".to_string();
    let err = relay_alert_routing_profile_from_json(&serde_json::to_string(&profile).unwrap(), NOW)
        .unwrap_err();
    assert_eq!(err.code(), "alert_routing_invalid");

    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let suppression = RelayAlertSuppressionStateDocument {
        schema: PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        entries: vec![RelayAlertSuppressionEntry {
            alert_code: "dead_letters_present".to_string(),
            route_id: "pagerduty-primary".to_string(),
            reason: "operator_acknowledged".to_string(),
            starts_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 120_000,
        }],
    };
    let suppression = relay_alert_suppression_state_from_json(
        &serde_json::to_string(&suppression).unwrap(),
        &profile,
    )
    .unwrap();
    let observability = degraded_observability_report();
    let event = RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: "dead_letters_present".to_string(),
        detail: "dead-lettered relay batch".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: Some("dead_letters_present".to_string()),
    };
    let report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: Some(&suppression),
        event_reports: &[event],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();
    let critical = report
        .alerts
        .iter()
        .find(|alert| alert.code == "dead_letters_present")
        .unwrap();
    assert_eq!(critical.state, "firing");
    assert_eq!(critical.suppressed_until_unix_ms, None);

    let overlong = RelayAlertSuppressionStateDocument {
        schema: PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        entries: vec![RelayAlertSuppressionEntry {
            alert_code: "retries_pending".to_string(),
            route_id: "ops-digest".to_string(),
            reason: "maintenance".to_string(),
            starts_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 3_600_001,
        }],
    };
    let err = relay_alert_suppression_state_from_json(
        &serde_json::to_string(&overlong).unwrap(),
        &profile,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_routing_invalid");

    let mut false_clear = degraded_observability_report();
    false_clear.recommendations.clear();
    let err = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &false_clear,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let err = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let err = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: Some("0"),
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");
}

#[test]
fn relay_alert_handoff_dry_run_proves_routeable_artifacts_without_delivery() {
    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let events = vec![alert_event("dead_letters_present")];
    let alert_report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &degraded_observability_report(),
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &events,
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();
    let trend_report = generate_relay_trend_report(RelayTrendInput {
        local_kernel_id: "did:chio:buyer-kernel",
        observability_reports: &[degraded_observability_report()],
        event_reports: &events,
        routing_profile: &profile,
        since_unix_ms: NOW - 60_000,
        until_unix_ms: NOW + 60_000,
    })
    .unwrap();
    let handoff = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&handoff_profile()).unwrap(),
        NOW,
    )
    .unwrap();

    let report = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap();

    assert_eq!(report.schema, PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA);
    assert!(report.accepted);
    assert_eq!(report.code, "accepted");
    assert_eq!(report.firing_alert_count, 3);
    assert_eq!(report.critical_firing_count, 2);
    assert_eq!(report.source_alert_report_sha256.len(), 64);
    assert_eq!(report.source_trend_report_sha256.len(), 64);
    assert!(report.routes.iter().any(|route| {
        route.target_ref == "alertmanager:pagerduty-primary"
            && route.highest_severity == RelayAlertSeverity::Critical
            && route
                .alert_codes
                .contains(&"dead_letters_present".to_string())
    }));
}

#[test]
fn relay_alert_handoff_rejects_secret_dynamic_and_uncovered_targets() {
    let mut bad_profile = handoff_profile();
    bad_profile.receivers[0].target_ref = "https://hooks.example.test/secret-token".to_string();
    let err =
        relay_alert_handoff_profile_from_json(&serde_json::to_string(&bad_profile).unwrap(), NOW)
            .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut bearer_profile = handoff_profile();
    bearer_profile.receivers[0].target_ref = "alertmanager:bearer-prod".to_string();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&bearer_profile).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let events = vec![alert_event("dead_letters_present")];
    let alert_report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &degraded_observability_report(),
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &events,
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();
    let trend_report = generate_relay_trend_report(RelayTrendInput {
        local_kernel_id: "did:chio:buyer-kernel",
        observability_reports: &[degraded_observability_report()],
        event_reports: &events,
        routing_profile: &profile,
        since_unix_ms: NOW - 60_000,
        until_unix_ms: NOW + 60_000,
    })
    .unwrap();

    let mut missing_receiver = handoff_profile();
    missing_receiver
        .receivers
        .retain(|receiver| receiver.target_ref != "alertmanager:pagerduty-primary");
    let missing_receiver = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&missing_receiver).unwrap(),
        NOW,
    )
    .unwrap();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &missing_receiver,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut stale_alert = alert_report.clone();
    stale_alert.generated_at_unix_ms = NOW - 600_000;
    let handoff = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&handoff_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &stale_alert,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut stale_trend = trend_report.clone();
    stale_trend.until_unix_ms = NOW - 1_000_000;
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &stale_trend,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut mismatched_source = alert_report.clone();
    mismatched_source.alerts[0].source_report_sha256 = "c".repeat(64);
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &mismatched_source,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut invalid_source_hash = alert_report.clone();
    invalid_source_hash.source_report_sha256 = "not-a-hash".to_string();
    for alert in &mut invalid_source_hash.alerts {
        alert.source_report_sha256 = "not-a-hash".to_string();
    }
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &invalid_source_hash,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut hidden_critical = alert_report.clone();
    hidden_critical.alerts[0].state = "suppressed".to_string();
    hidden_critical.alerts[0].suppressed_until_unix_ms = Some(NOW + 120_000);
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &hidden_critical,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut missing_event = alert_report.clone();
    missing_event.alerts[0].event_evidence_sha256.clear();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &missing_event,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut bad_runbook = alert_report.clone();
    bad_runbook.alerts[0].runbook = "docs/release/other-runbook.md".to_string();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &bad_runbook,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut unknown_alert_code = alert_report.clone();
    unknown_alert_code.alerts[0].code = "bounded_unknown".to_string();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &unknown_alert_code,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut missing_trend_code = trend_report.clone();
    missing_trend_code
        .points
        .retain(|point| point.code != alert_report.alerts[0].code);
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &missing_trend_code,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut unbounded_label = alert_report.clone();
    unbounded_label.alerts[0]
        .labels
        .insert("peer_id".to_string(), "did:chio:vendor-a".to_string());
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &unbounded_label,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut unknown_sink = handoff_profile();
    unknown_sink.receivers[0].kind = RelayAlertHandoffSinkKind::Unknown;
    let err =
        relay_alert_handoff_profile_from_json(&serde_json::to_string(&unknown_sink).unwrap(), NOW)
            .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut weak_escalation = handoff_profile();
    weak_escalation.receivers[0].escalation_ref = "relay-digest".to_string();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&weak_escalation).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut duplicate_route = handoff_profile();
    duplicate_route.receivers[1].target_ref = "alertmanager:secondary".to_string();
    duplicate_route.receivers[1].notification_route =
        duplicate_route.receivers[0].notification_route.clone();
    duplicate_route.receivers[1].opsgenie = duplicate_route.receivers[0].opsgenie.clone();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&duplicate_route).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut missing_runbook = handoff_profile();
    missing_runbook.receivers[0].runbook.clear();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&missing_runbook).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut route_collision = alert_profile();
    let mut duplicate = route_collision.routes[0].clone();
    duplicate.route_id = "pagerduty-primary-copy".to_string();
    route_collision.routes.push(duplicate);
    let err = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&route_collision).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_routing_invalid");
}
