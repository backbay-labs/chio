use super::*;

pub fn generate_relay_alert_assurance_package(
    input: RelayAlertAssuranceInput<'_>,
) -> Result<RelayAlertAssurancePackage, PheromoneRelayError> {
    validate_assurance_source_chain(&input)?;
    let delivery_attention_count = input.delivery_report.delayed_count
        + input.delivery_report.failed_count
        + input.delivery_report.unknown_count;
    let acknowledgement_pending_count =
        input.acknowledgement_report.pending_count + input.acknowledgement_report.failed_count;
    let accepted = input.alert_report.accepted
        && input.normalization_report.accepted
        && input.delivery_report.accepted
        && input.acknowledgement_report.accepted
        && input.drift_report.accepted
        && input.review_packet.accepted
        && delivery_attention_count == 0
        && acknowledgement_pending_count == 0;
    let mut operator_action_codes = Vec::new();
    if accepted {
        operator_action_codes.push("ready".to_string());
    } else {
        if !input.alert_report.accepted {
            operator_action_codes.push("active_alerts_present".to_string());
        }
        if !input.normalization_report.accepted {
            operator_action_codes.push("normalization_attention_required".to_string());
        }
        if delivery_attention_count > 0 {
            operator_action_codes.push("delivery_attention_required".to_string());
        }
        if acknowledgement_pending_count > 0 {
            operator_action_codes.push("acknowledgement_attention_required".to_string());
        }
        if input.drift_report.drift_count > 0 || !input.drift_report.accepted {
            operator_action_codes.push("delivery_drift_detected".to_string());
        }
        if !input.review_packet.accepted {
            operator_action_codes.push("route_review_attention_required".to_string());
        }
        if operator_action_codes.is_empty() {
            operator_action_codes.push("assurance_attention_required".to_string());
        }
    }
    for code in &operator_action_codes {
        if !is_bounded_code(code) {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "assurance action code is not bounded".to_string(),
            ));
        }
    }
    Ok(RelayAlertAssurancePackage {
        schema: PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA.to_string(),
        accepted,
        code: if accepted {
            "accepted"
        } else {
            "assurance_attention_required"
        }
        .to_string(),
        local_kernel_id: input.alert_report.local_kernel_id.clone(),
        generated_at_unix_ms: input.now_unix_ms,
        source_alert_report_sha256: canonical_sha256(input.alert_report)?,
        source_trend_report_sha256: canonical_sha256(input.trend_report)?,
        source_handoff_report_sha256: canonical_sha256(input.handoff_report)?,
        source_normalization_report_sha256: canonical_sha256(input.normalization_report)?,
        source_delivery_report_sha256: canonical_sha256(input.delivery_report)?,
        source_acknowledgement_report_sha256: canonical_sha256(input.acknowledgement_report)?,
        source_drift_report_sha256: canonical_sha256(input.drift_report)?,
        source_review_packet_sha256: canonical_sha256(input.review_packet)?,
        firing_alert_count: input.handoff_report.firing_alert_count,
        critical_firing_alert_count: input.handoff_report.critical_firing_count,
        normalized_count: input.normalization_report.normalized_count,
        ready_route_count: input.review_packet.ready_route_count,
        delivery_attention_count,
        acknowledgement_pending_count,
        drift_count: input.drift_report.drift_count,
        operator_action_codes,
        checks: vec![RelayAlertCheck {
            code: "alert_assurance_chain".to_string(),
            accepted,
            detail: "alert, handoff, normalized delivery, acknowledgement, drift, and review reports are hash-bound".to_string(),
        }],
    })
}

pub(crate) fn validate_assurance_source_chain(
    input: &RelayAlertAssuranceInput<'_>,
) -> Result<(), PheromoneRelayError> {
    let local_kernel_id = input.alert_report.local_kernel_id.as_str();
    for (name, candidate) in [
        ("handoff", input.handoff_report.local_kernel_id.as_str()),
        (
            "normalization",
            input.normalization_report.local_kernel_id.as_str(),
        ),
        ("delivery", input.delivery_report.local_kernel_id.as_str()),
        (
            "acknowledgement",
            input.acknowledgement_report.local_kernel_id.as_str(),
        ),
        ("drift", input.drift_report.local_kernel_id.as_str()),
        ("review", input.review_packet.local_kernel_id.as_str()),
    ] {
        if candidate != local_kernel_id {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "assurance {name} local kernel id mismatch"
            )));
        }
    }
    if input.trend_report.local_kernel_id != local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance trend local kernel id mismatch".to_string(),
        ));
    }
    if input.handoff_report.source_alert_report_sha256 != canonical_sha256(input.alert_report)?
        || input.handoff_report.source_trend_report_sha256 != canonical_sha256(input.trend_report)?
        || input.delivery_report.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.acknowledgement_report.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
        || input.review_packet.source_handoff_report_sha256
            != canonical_sha256(input.handoff_report)?
        || input.review_packet.source_delivery_report_sha256
            != canonical_sha256(input.delivery_report)?
        || input.review_packet.source_acknowledgement_report_sha256
            != canonical_sha256(input.acknowledgement_report)?
        || input.review_packet.source_drift_report_sha256 != canonical_sha256(input.drift_report)?
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance source hash mismatch".to_string(),
        ));
    }
    for (name, generated_at) in [
        ("alert report", input.alert_report.generated_at_unix_ms),
        ("handoff report", input.handoff_report.generated_at_unix_ms),
        (
            "normalization report",
            input.normalization_report.generated_at_unix_ms,
        ),
        (
            "delivery report",
            input.delivery_report.generated_at_unix_ms,
        ),
        (
            "acknowledgement report",
            input.acknowledgement_report.generated_at_unix_ms,
        ),
        ("drift report", input.drift_report.generated_at_unix_ms),
        ("review packet", input.review_packet.generated_at_unix_ms),
    ] {
        if generated_at > input.now_unix_ms {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "assurance {name} timestamp is in the future"
            )));
        }
    }
    if input.trend_report.until_unix_ms > input.now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "assurance trend report timestamp is in the future".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_assurance_package_sources(
    input: &RelayAlertAssuranceExportBuildInput<'_>,
) -> Result<(), PheromoneRelayError> {
    if input.assurance_package.schema != PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA {
        return Err(PheromoneRelayError::UnsupportedSchema(
            input.assurance_package.schema.clone(),
        ));
    }
    let expected = [
        (
            input.assurance_package.source_alert_report_sha256.as_str(),
            canonical_sha256(input.alert_report)?,
        ),
        (
            input.assurance_package.source_trend_report_sha256.as_str(),
            canonical_sha256(input.trend_report)?,
        ),
        (
            input
                .assurance_package
                .source_handoff_report_sha256
                .as_str(),
            canonical_sha256(input.handoff_report)?,
        ),
        (
            input
                .assurance_package
                .source_normalization_report_sha256
                .as_str(),
            canonical_sha256(input.normalization_report)?,
        ),
        (
            input
                .assurance_package
                .source_delivery_report_sha256
                .as_str(),
            canonical_sha256(input.delivery_report)?,
        ),
        (
            input
                .assurance_package
                .source_acknowledgement_report_sha256
                .as_str(),
            canonical_sha256(input.acknowledgement_report)?,
        ),
        (
            input.assurance_package.source_drift_report_sha256.as_str(),
            canonical_sha256(input.drift_report)?,
        ),
        (
            input.assurance_package.source_review_packet_sha256.as_str(),
            canonical_sha256(input.review_packet)?,
        ),
    ];
    for (actual, expected) in expected {
        if actual != expected {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "assurance package source hash mismatch".to_string(),
            ));
        }
    }
    for evidence in input.normalized_delivery_evidence {
        validate_delivery_evidence_shape(evidence)?;
        if !input
            .normalization_report
            .evidence_hashes
            .contains(&canonical_sha256(evidence)?)
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(
                "normalized delivery evidence is not bound to normalization report".to_string(),
            ));
        }
    }
    Ok(())
}
