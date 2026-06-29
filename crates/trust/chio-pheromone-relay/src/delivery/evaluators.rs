use super::*;

pub fn relay_alert_routing_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertRoutingProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertRoutingProfileDocument = serde_json::from_str(json)?;
    validate_alert_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_suppression_state_from_json(
    json: &str,
    profile: &RelayAlertRoutingProfileDocument,
) -> Result<RelayAlertSuppressionStateDocument, PheromoneRelayError> {
    let state: RelayAlertSuppressionStateDocument = serde_json::from_str(json)?;
    validate_suppression_state(&state, profile)?;
    Ok(state)
}

pub fn relay_alert_handoff_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertHandoffProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertHandoffProfileDocument = serde_json::from_str(json)?;
    validate_handoff_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_delivery_profile_from_json(
    json: &str,
    now_unix_ms: u64,
) -> Result<RelayAlertDeliveryProfileDocument, PheromoneRelayError> {
    let profile: RelayAlertDeliveryProfileDocument = serde_json::from_str(json)?;
    validate_delivery_profile(&profile, now_unix_ms)?;
    Ok(profile)
}

pub fn relay_alert_delivery_evidence_from_json(
    json: &str,
) -> Result<RelayAlertDeliveryEvidence, PheromoneRelayError> {
    let evidence: RelayAlertDeliveryEvidence = serde_json::from_str(json)?;
    validate_delivery_evidence_shape(&evidence)?;
    Ok(evidence)
}

pub fn evaluate_relay_alert_delivery(
    input: RelayAlertDeliveryInput<'_>,
) -> Result<RelayAlertDeliveryReport, PheromoneRelayError> {
    validate_delivery_profile(input.delivery_profile, input.now_unix_ms)?;
    validate_delivery_handoff_report(
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    let source_handoff_report_sha256 = canonical_sha256(input.handoff_report)?;
    let receiver_map = delivery_receiver_map(input.delivery_profile)?;
    let route_map = handoff_route_map(input.handoff_report)?;
    let mut seen_results = BTreeSet::new();
    let mut seen_alerts = BTreeSet::new();
    let mut results = Vec::new();
    let mut delayed_count = 0u64;
    let mut failed_count = 0u64;
    let mut unknown_count = 0u64;

    for evidence in input.evidence {
        validate_delivery_evidence_shape(evidence)?;
        if evidence.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence local kernel id mismatch".to_string(),
            ));
        }
        if evidence.observed_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence timestamp is in the future".to_string(),
            ));
        }
        if input
            .now_unix_ms
            .saturating_sub(evidence.observed_at_unix_ms)
            > input.delivery_profile.max_evidence_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence is stale".to_string(),
            ));
        }
        if evidence.source_handoff_report_sha256 != source_handoff_report_sha256 {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery evidence is not bound to the handoff report".to_string(),
            ));
        }
        if !seen_results.insert(evidence.result_id.as_str()) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery result {}",
                evidence.result_id
            )));
        }
        let receiver = receiver_map
            .get(evidence.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "delivery evidence references unknown receiver {}",
                    evidence.receiver_id
                ))
            })?;
        let route = route_map
            .get(evidence.receiver_id.as_str())
            .ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "handoff report has no route for receiver {}",
                    evidence.receiver_id
                ))
            })?;
        if evidence.kind != receiver.kind
            || evidence.kind != route.kind
            || evidence.target_ref != receiver.target_ref
            || evidence.target_ref != route.target_ref
            || evidence.notification_route != receiver.notification_route
            || evidence.notification_route != route.notification_route
            || evidence.opsgenie != receiver.opsgenie
            || evidence.opsgenie != route.opsgenie
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence route does not match receiver {}",
                evidence.receiver_id
            )));
        }
        if evidence.runbook != receiver.runbook {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence runbook does not match receiver {}",
                evidence.receiver_id
            )));
        }
        if evidence.severity < receiver.severity_floor || evidence.severity < route.highest_severity
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence weakens alert severity for {}",
                evidence.alert_code
            )));
        }
        if !route.alert_codes.contains(&evidence.alert_code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "delivery evidence alert {} is not in handoff route",
                evidence.alert_code
            )));
        }
        if !seen_alerts.insert((evidence.receiver_id.as_str(), evidence.alert_code.as_str())) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate delivery evidence for alert {}",
                evidence.alert_code
            )));
        }
        if evidence.status == RelayAlertDeliveryStatus::Delayed {
            delayed_count = delayed_count.saturating_add(1);
        } else if evidence.status == RelayAlertDeliveryStatus::Failed {
            failed_count = failed_count.saturating_add(1);
        } else if evidence.status == RelayAlertDeliveryStatus::Unknown {
            unknown_count = unknown_count.saturating_add(1);
        }
        results.push(RelayAlertDeliveryResult {
            result_id: evidence.result_id.clone(),
            receiver_id: evidence.receiver_id.clone(),
            kind: evidence.kind,
            target_ref: evidence.target_ref.clone(),
            notification_route: evidence.notification_route.clone(),
            opsgenie: evidence.opsgenie.clone(),
            alert_code: evidence.alert_code.clone(),
            dedupe_key: evidence.dedupe_key.clone(),
            severity: evidence.severity,
            runbook: evidence.runbook.clone(),
            status: evidence.status,
            observed_at_unix_ms: evidence.observed_at_unix_ms,
            downstream_evidence_sha256: evidence.downstream_evidence_sha256.clone(),
        });
    }

    let mut missing = Vec::new();
    for route in input
        .handoff_report
        .routes
        .iter()
        .filter(|route| route.ready)
    {
        for alert_code in &route.alert_codes {
            if !seen_alerts.contains(&(route.receiver_id.as_str(), alert_code.as_str())) {
                missing.push((route.receiver_id.clone(), alert_code.clone()));
            }
        }
    }
    if !missing.is_empty() {
        let rendered = missing
            .iter()
            .map(|(receiver, alert)| format!("{receiver}:{alert}"))
            .collect::<Vec<_>>()
            .join(",");
        return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "missing delivery evidence for {rendered}"
        )));
    }

    results.sort_by(|left, right| {
        left.receiver_id
            .cmp(&right.receiver_id)
            .then_with(|| left.alert_code.cmp(&right.alert_code))
            .then_with(|| left.result_id.cmp(&right.result_id))
    });
    let delivered_count = results
        .iter()
        .filter(|result| {
            matches!(
                result.status,
                RelayAlertDeliveryStatus::Delivered
                    | RelayAlertDeliveryStatus::Accepted
                    | RelayAlertDeliveryStatus::Duplicate
                    | RelayAlertDeliveryStatus::OperatorAcknowledged
            )
        })
        .count() as u64;
    let accepted = delayed_count == 0 && failed_count == 0 && unknown_count == 0;
    Ok(RelayAlertDeliveryReport {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "delivery_attention_required"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256,
        source_alert_report_sha256: input.handoff_report.source_alert_report_sha256.clone(),
        source_trend_report_sha256: input.handoff_report.source_trend_report_sha256.clone(),
        critical_firing_count: input.handoff_report.critical_firing_count,
        delivered_count,
        delayed_count,
        failed_count,
        unknown_count,
        results,
        checks: vec![
            RelayAlertCheck {
                code: "handoff_report".to_string(),
                accepted: true,
                detail: "handoff report is fresh and hash-bound".to_string(),
            },
            RelayAlertCheck {
                code: "delivery_evidence".to_string(),
                accepted,
                detail: "downstream delivery evidence covers every handoff alert".to_string(),
            },
        ],
    })
}

pub fn evaluate_relay_alert_acknowledgement(
    input: RelayAlertAcknowledgementInput<'_>,
) -> Result<RelayAlertAcknowledgementReport, PheromoneRelayError> {
    validate_delivery_profile(input.delivery_profile, input.now_unix_ms)?;
    validate_delivery_handoff_report(
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    validate_delivery_report(
        input.delivery_report,
        input.handoff_report,
        input.delivery_profile,
        input.now_unix_ms,
    )?;
    let source_delivery_report_sha256 = canonical_sha256(input.delivery_report)?;
    let mut acknowledgements = Vec::new();
    let mut acknowledged_count = 0u64;
    let mut pending_count = 0u64;
    let mut failed_count = 0u64;
    for result in &input.delivery_report.results {
        if result.observed_at_unix_ms > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery result timestamp is in the future".to_string(),
            ));
        }
        if input.now_unix_ms.saturating_sub(result.observed_at_unix_ms)
            > input.delivery_profile.max_acknowledgement_age_ms
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery result is stale for acknowledgement".to_string(),
            ));
        }
        if result.status == RelayAlertDeliveryStatus::Failed {
            failed_count = failed_count.saturating_add(1);
        } else if result.status.requires_attention() {
            pending_count = pending_count.saturating_add(1);
        } else {
            acknowledged_count = acknowledged_count.saturating_add(1);
        }
        acknowledgements.push(RelayAlertAcknowledgement {
            result_id: result.result_id.clone(),
            receiver_id: result.receiver_id.clone(),
            alert_code: result.alert_code.clone(),
            dedupe_key: result.dedupe_key.clone(),
            status: result.status,
            acknowledged_at_unix_ms: input.now_unix_ms,
            downstream_evidence_sha256: result.downstream_evidence_sha256.clone(),
        });
    }
    let accepted = pending_count == 0 && failed_count == 0;
    Ok(RelayAlertAcknowledgementReport {
        schema: PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "acknowledgement_attention_required"
        }
        .to_string(),
        local_kernel_id: input.delivery_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256: input.delivery_report.source_handoff_report_sha256.clone(),
        source_delivery_report_sha256,
        acknowledged_count,
        pending_count,
        failed_count,
        acknowledgements,
        checks: vec![RelayAlertCheck {
            code: "delivery_report".to_string(),
            accepted,
            detail: "delivery outcomes are summarized without notifying downstream systems"
                .to_string(),
        }],
    })
}

pub fn generate_relay_alert_handoff_drift_report(
    input: RelayAlertHandoffDriftInput<'_>,
) -> Result<RelayAlertHandoffDriftReport, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "drift lower bound is after upper bound".to_string(),
        ));
    }
    validate_delivery_profile(input.delivery_profile, input.until_unix_ms)?;
    let mut drifts = Vec::new();
    let mut delivery_index = BTreeMap::<(String, String), &RelayAlertDeliveryResult>::new();
    let mut delivery_report_count = 0u64;
    for report in input.delivery_reports {
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        if report.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report local kernel id mismatch".to_string(),
            ));
        }
        delivery_report_count = delivery_report_count.saturating_add(1);
        for result in &report.results {
            delivery_index.insert(
                (result.receiver_id.clone(), result.alert_code.clone()),
                result,
            );
        }
    }

    let mut handoff_report_count = 0u64;
    for handoff in input.handoff_reports {
        if handoff.generated_at_unix_ms < input.since_unix_ms
            || handoff.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        validate_delivery_handoff_report(handoff, input.delivery_profile, input.until_unix_ms)?;
        handoff_report_count = handoff_report_count.saturating_add(1);
        for route in &handoff.routes {
            for alert_code in &route.alert_codes {
                let key = (route.receiver_id.clone(), alert_code.clone());
                match delivery_index.get(&key) {
                    Some(result) => {
                        if result.severity < route.highest_severity {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "severity_weakening".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery evidence weakens handoff severity".to_string(),
                            });
                        }
                        if result.target_ref != route.target_ref
                            || result.notification_route != route.notification_route
                            || result.opsgenie != route.opsgenie
                        {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "route_alias_drift".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery route aliases differ from handoff route"
                                    .to_string(),
                            });
                        }
                        if result.status.requires_attention() {
                            drifts.push(RelayAlertHandoffDrift {
                                code: "delivery_attention_required".to_string(),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery status requires operator attention".to_string(),
                            });
                        }
                    }
                    None => drifts.push(RelayAlertHandoffDrift {
                        code: "missing_delivery_result".to_string(),
                        receiver_id: route.receiver_id.clone(),
                        alert_code: alert_code.clone(),
                        detail: "handoff alert has no downstream delivery evidence".to_string(),
                    }),
                }
            }
        }
    }
    for drift in &drifts {
        if !is_bounded_code(&drift.code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "drift code is not bounded".to_string(),
            ));
        }
    }
    let accepted = drifts.is_empty();
    Ok(RelayAlertHandoffDriftReport {
        schema: PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "handoff_drift_detected"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.until_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        handoff_report_count,
        delivery_report_count,
        drift_count: drifts.len() as u64,
        drifts,
        checks: vec![RelayAlertCheck {
            code: "handoff_delivery_intersection".to_string(),
            accepted,
            detail: "handoff and downstream delivery reports intersect by bounded route aliases"
                .to_string(),
        }],
    })
}

pub fn normalize_relay_alert_delivery_evidence(
    input: RelayAlertNormalizationInput<'_>,
) -> Result<RelayAlertNormalizationReport, PheromoneRelayError> {
    validate_normalization_profile(input.profile, input.now_unix_ms)?;
    if input.sources.is_empty() {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization input has no downstream sources".to_string(),
        ));
    }
    let receivers = normalization_receiver_map(input.profile)?;
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    for source in input.sources {
        reject_downstream_source_secrets(source)?;
        let normalized =
            normalize_downstream_source(source, &receivers, input.profile, input.now_unix_ms)?;
        let key = (
            normalized.source_handoff_report_sha256.clone(),
            normalized.receiver_id.clone(),
            normalized.alert_code.clone(),
        );
        if !seen.insert(key) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "normalization source mapping is ambiguous".to_string(),
            ));
        }
        evidence.push(normalized);
    }
    evidence.sort_by(|left, right| {
        left.receiver_id
            .cmp(&right.receiver_id)
            .then_with(|| left.alert_code.cmp(&right.alert_code))
            .then_with(|| left.result_id.cmp(&right.result_id))
    });
    let evidence_hashes = evidence
        .iter()
        .map(canonical_sha256)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RelayAlertNormalizationReport {
        schema: PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA.to_string(),
        accepted: true,
        code: "accepted".to_string(),
        local_kernel_id: input.profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_count: input.sources.len() as u64,
        normalized_count: evidence.len() as u64,
        evidence_hashes,
        evidence,
        checks: vec![RelayAlertCheck {
            code: "normalization".to_string(),
            accepted: true,
            detail: "local downstream exports normalized into Chio delivery evidence".to_string(),
        }],
    })
}

pub fn generate_relay_alert_delivery_drift_report(
    input: RelayAlertDeliveryDriftInput<'_>,
) -> Result<RelayAlertDeliveryDriftReport, PheromoneRelayError> {
    if input.since_unix_ms > input.until_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "drift lower bound is after upper bound".to_string(),
        ));
    }
    validate_delivery_profile(input.delivery_profile, input.until_unix_ms)?;

    let mut handoffs_by_hash = BTreeMap::new();
    let mut ordered_handoffs = Vec::new();
    for handoff in input.handoff_reports {
        if handoff.generated_at_unix_ms < input.since_unix_ms
            || handoff.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        validate_delivery_handoff_report(
            handoff,
            input.delivery_profile,
            handoff.generated_at_unix_ms,
        )?;
        let hash = canonical_sha256(handoff)?;
        if handoffs_by_hash.insert(hash.clone(), handoff).is_some() {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "duplicate handoff report hash in drift window".to_string(),
            ));
        }
        ordered_handoffs.push((hash, handoff));
    }

    let mut drifts = Vec::new();
    let mut delivery_index =
        BTreeMap::<(String, String, String), (&RelayAlertDeliveryResult, String)>::new();
    let mut delivery_report_count = 0u64;
    for report in input.delivery_reports {
        if report.generated_at_unix_ms < input.since_unix_ms
            || report.generated_at_unix_ms > input.until_unix_ms
        {
            continue;
        }
        if report.schema != PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA {
            return Err(PheromoneRelayError::UnsupportedSchema(
                report.schema.clone(),
            ));
        }
        if report.local_kernel_id != input.delivery_profile.local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "delivery report local kernel id mismatch".to_string(),
            ));
        }
        let report_hash = canonical_sha256(report)?;
        delivery_report_count = delivery_report_count.saturating_add(1);
        if !handoffs_by_hash.contains_key(&report.source_handoff_report_sha256) {
            drifts.push(RelayAlertDeliveryDrift {
                code: "unbound_delivery_report".to_string(),
                source_handoff_report_sha256: report.source_handoff_report_sha256.clone(),
                matched_delivery_report_sha256: Some(report_hash.clone()),
                receiver_id: "unknown".to_string(),
                alert_code: "unknown".to_string(),
                detail: "delivery report source handoff hash is outside the review window"
                    .to_string(),
            });
        }
        for result in &report.results {
            validate_delivery_result(result)?;
            let key = (
                report.source_handoff_report_sha256.clone(),
                result.receiver_id.clone(),
                result.alert_code.clone(),
            );
            if delivery_index
                .insert(key, (result, report_hash.clone()))
                .is_some()
            {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "duplicate delivery result across drift reports".to_string(),
                ));
            }
        }
    }

    if ordered_handoffs.is_empty() && delivery_report_count == 0 {
        drifts.push(RelayAlertDeliveryDrift {
            code: "no_window_evidence".to_string(),
            source_handoff_report_sha256: "0".repeat(64),
            matched_delivery_report_sha256: None,
            receiver_id: "unknown".to_string(),
            alert_code: "unknown".to_string(),
            detail: "no handoff or delivery reports were present in the requested window"
                .to_string(),
        });
    }

    for (handoff_hash, handoff) in &ordered_handoffs {
        for route in handoff.routes.iter().filter(|route| route.ready) {
            for alert_code in &route.alert_codes {
                let key = (
                    handoff_hash.clone(),
                    route.receiver_id.clone(),
                    alert_code.clone(),
                );
                match delivery_index.get(&key) {
                    Some((result, report_hash)) => {
                        if result.severity < route.highest_severity {
                            drifts.push(RelayAlertDeliveryDrift {
                                code: "severity_weakening".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery evidence weakens handoff severity".to_string(),
                            });
                        }
                        if result.target_ref != route.target_ref
                            || result.notification_route != route.notification_route
                            || result.opsgenie != route.opsgenie
                        {
                            drifts.push(RelayAlertDeliveryDrift {
                                code: "route_alias_drift".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery route aliases differ from handoff route"
                                    .to_string(),
                            });
                        }
                        if result.status.requires_attention() {
                            drifts.push(RelayAlertDeliveryDrift {
                                code: "delivery_attention_required".to_string(),
                                source_handoff_report_sha256: handoff_hash.clone(),
                                matched_delivery_report_sha256: Some(report_hash.clone()),
                                receiver_id: route.receiver_id.clone(),
                                alert_code: alert_code.clone(),
                                detail: "delivery status requires operator attention".to_string(),
                            });
                        }
                    }
                    None => drifts.push(RelayAlertDeliveryDrift {
                        code: "missing_delivery_result".to_string(),
                        source_handoff_report_sha256: handoff_hash.clone(),
                        matched_delivery_report_sha256: None,
                        receiver_id: route.receiver_id.clone(),
                        alert_code: alert_code.clone(),
                        detail: "handoff alert has no source-bound downstream delivery evidence"
                            .to_string(),
                    }),
                }
            }
        }
    }
    for drift in &drifts {
        if !is_bounded_code(&drift.code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "drift code is not bounded".to_string(),
            ));
        }
    }
    let accepted = drifts.is_empty();
    Ok(RelayAlertDeliveryDriftReport {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "delivery_drift_detected"
        }
        .to_string(),
        local_kernel_id: input.delivery_profile.local_kernel_id.clone(),
        generated_at_unix_ms: input.until_unix_ms,
        since_unix_ms: input.since_unix_ms,
        until_unix_ms: input.until_unix_ms,
        handoff_report_count: ordered_handoffs.len() as u64,
        delivery_report_count,
        drift_count: drifts.len() as u64,
        drifts,
        checks: vec![RelayAlertCheck {
            code: "source_bound_delivery_intersection".to_string(),
            accepted,
            detail: "handoff and delivery reports intersect by source handoff hash".to_string(),
        }],
    })
}

pub fn generate_relay_alert_route_review_packet(
    input: RelayAlertRouteReviewInput<'_>,
) -> Result<RelayAlertRouteReviewPacket, PheromoneRelayError> {
    validate_route_owner_profile(input.route_owner_profile, input.now_unix_ms)?;
    validate_review_source_chain(&input)?;
    let source_handoff_report_sha256 = canonical_sha256(input.handoff_report)?;
    let source_delivery_report_sha256 = canonical_sha256(input.delivery_report)?;
    let source_acknowledgement_report_sha256 = canonical_sha256(input.acknowledgement_report)?;
    let source_drift_report_sha256 = canonical_sha256(input.drift_report)?;
    let owner_map = route_owner_map(input.route_owner_profile)?;
    let drift_keys = input
        .drift_report
        .drifts
        .iter()
        .map(|drift| (drift.receiver_id.as_str(), drift.alert_code.as_str()))
        .collect::<BTreeSet<_>>();
    let delivery_status = input
        .delivery_report
        .results
        .iter()
        .map(|result| {
            (
                (result.receiver_id.as_str(), result.alert_code.as_str()),
                result.status,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reviews = Vec::new();
    for route in input
        .handoff_report
        .routes
        .iter()
        .filter(|route| route.ready)
    {
        let owner = owner_map.get(route.receiver_id.as_str()).ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "route owner missing for receiver {}",
                route.receiver_id
            ))
        })?;
        let mut status = "ready";
        for alert_code in &route.alert_codes {
            if drift_keys.contains(&(route.receiver_id.as_str(), alert_code.as_str())) {
                status = "attention_required";
            }
            if delivery_status
                .get(&(route.receiver_id.as_str(), alert_code.as_str()))
                .is_some_and(|delivery_status| delivery_status.requires_attention())
            {
                status = "attention_required";
            }
        }
        reviews.push(RelayAlertRouteReview {
            owner_alias: owner.owner_alias.clone(),
            receiver_id: route.receiver_id.clone(),
            notification_route: route.notification_route.clone(),
            alert_codes: route.alert_codes.clone(),
            status: status.to_string(),
            runbook: owner.runbook.clone(),
        });
    }
    reviews.sort_by(|left, right| {
        left.owner_alias
            .cmp(&right.owner_alias)
            .then_with(|| left.receiver_id.cmp(&right.receiver_id))
    });
    let accepted = input.delivery_report.accepted
        && input.acknowledgement_report.accepted
        && input.drift_report.accepted
        && reviews.iter().all(|review| review.status == "ready");
    Ok(RelayAlertRouteReviewPacket {
        schema: PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "route_review_attention_required"
        }
        .to_string(),
        local_kernel_id: input.handoff_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_handoff_report_sha256,
        source_delivery_report_sha256,
        source_acknowledgement_report_sha256,
        source_drift_report_sha256,
        ready_route_count: input
            .handoff_report
            .routes
            .iter()
            .filter(|route| route.ready)
            .count() as u64,
        owner_review_count: reviews.len() as u64,
        reviews,
        checks: vec![RelayAlertCheck {
            code: "route_owner_review".to_string(),
            accepted,
            detail: "route owners are bound to handoff and delivery evidence".to_string(),
        }],
    })
}
