use super::*;

pub(crate) fn normalization_receiver_map(
    profile: &RelayAlertNormalizationProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertDeliveryReceiver>, PheromoneRelayError> {
    let mut receivers = BTreeMap::new();
    for receiver in &profile.receivers {
        if receivers
            .insert(receiver.receiver_id.as_str(), receiver)
            .is_some()
        {
            return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                "duplicate normalization receiver {}",
                receiver.receiver_id
            )));
        }
    }
    Ok(receivers)
}
pub(crate) fn normalize_downstream_source(
    source: &Value,
    receivers: &BTreeMap<&str, &RelayAlertDeliveryReceiver>,
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<RelayAlertDeliveryEvidence, PheromoneRelayError> {
    if source
        .get("schema")
        .and_then(Value::as_str)
        .is_some_and(|schema| schema == PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA)
    {
        let evidence: RelayAlertDeliveryEvidence = serde_json::from_value(source.clone())?;
        validate_delivery_evidence_shape(&evidence)?;
        validate_normalized_evidence(&evidence, receivers, profile, now_unix_ms)?;
        return Ok(evidence);
    }

    let receiver_id = json_string(source, &["receiverId", "receiver_id", "receiver"])?;
    let receiver = receivers.get(receiver_id.as_str()).ok_or_else(|| {
        PheromoneRelayError::AlertDeliveryInvalid(format!(
            "normalization receiver {receiver_id} is unknown"
        ))
    })?;
    let alert_code = json_string(source, &["alertCode", "alert_code", "alertname"])?;
    if !is_bounded_code(&alert_code) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized alert code is not bounded".to_string(),
        ));
    }
    let observed_at_unix_ms = json_u64(source, &["observedAtUnixMs", "observed_at_unix_ms"])?;
    if observed_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(observed_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source is stale".to_string(),
        ));
    }
    let status = relay_alert_delivery_status_from_str(
        json_string(source, &["status", "outcome"])?.as_str(),
    )?;
    let severity = relay_alert_severity_from_str(json_string(source, &["severity"])?.as_str())
        .map_err(|error| PheromoneRelayError::AlertDeliveryInvalid(error.to_string()))?;
    let source_handoff_report_sha256 = json_string(
        source,
        &["sourceHandoffReportSha256", "source_handoff_report_sha256"],
    )?;
    if !is_sha256_hex(&source_handoff_report_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization source handoff hash is invalid".to_string(),
        ));
    }
    let dedupe_key = json_string(source, &["dedupeKey", "dedupe_key", "fingerprint"])?;
    if !is_bounded_route_token(&dedupe_key) || contains_secret_marker(&dedupe_key) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization dedupe key is not bounded".to_string(),
        ));
    }
    let runbook = json_string(source, &["runbook", "runbook_ref"])
        .unwrap_or_else(|_| receiver.runbook.clone());
    if runbook.trim().is_empty() || runbook.contains("://") || contains_secret_marker(&runbook) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization runbook must be a local non-secret reference".to_string(),
        ));
    }
    let downstream_evidence_sha256 = json_string(
        source,
        &["downstreamEvidenceSha256", "downstream_evidence_sha256"],
    )
    .unwrap_or(canonical_sha256(source)?);
    if !is_sha256_hex(&downstream_evidence_sha256) {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalization downstream evidence hash is invalid".to_string(),
        ));
    }
    let result_id = json_string(source, &["resultId", "result_id"])
        .unwrap_or_else(|_| format!("normalized:{receiver_id}:{alert_code}"));
    validate_delivery_token("result_id", &result_id)?;
    let mut labels = json_labels(source)?;
    labels
        .entry("notification_route".to_string())
        .or_insert_with(|| receiver.notification_route.clone());
    labels
        .entry("opsgenie".to_string())
        .or_insert_with(|| receiver.opsgenie.clone());
    labels
        .entry("service".to_string())
        .or_insert_with(|| PHEROMONE_RELAY_SERVICE_LABEL.to_string());
    labels
        .entry("severity".to_string())
        .or_insert_with(|| severity.as_str().to_string());
    labels
        .entry("status".to_string())
        .or_insert_with(|| status.as_str().to_string());
    labels
        .entry("receiver".to_string())
        .or_insert_with(|| receiver.receiver_id.clone());

    let evidence = RelayAlertDeliveryEvidence {
        schema: PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA.to_string(),
        local_kernel_id: profile.local_kernel_id.clone(),
        observed_at_unix_ms,
        result_id,
        receiver_id: receiver.receiver_id.clone(),
        kind: receiver.kind,
        target_ref: receiver.target_ref.clone(),
        notification_route: receiver.notification_route.clone(),
        opsgenie: receiver.opsgenie.clone(),
        alert_code,
        dedupe_key,
        severity,
        runbook,
        status,
        source_handoff_report_sha256,
        downstream_evidence_sha256,
        labels,
    };
    validate_normalized_evidence(&evidence, receivers, profile, now_unix_ms)?;
    Ok(evidence)
}
pub(crate) fn validate_normalized_evidence(
    evidence: &RelayAlertDeliveryEvidence,
    receivers: &BTreeMap<&str, &RelayAlertDeliveryReceiver>,
    profile: &RelayAlertNormalizationProfileDocument,
    now_unix_ms: u64,
) -> Result<(), PheromoneRelayError> {
    validate_delivery_evidence_shape(evidence)?;
    if evidence.local_kernel_id != profile.local_kernel_id {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence local kernel id mismatch".to_string(),
        ));
    }
    if evidence.observed_at_unix_ms > now_unix_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence timestamp is in the future".to_string(),
        ));
    }
    if now_unix_ms.saturating_sub(evidence.observed_at_unix_ms) > profile.max_source_age_ms {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence is stale".to_string(),
        ));
    }
    let receiver = receivers
        .get(evidence.receiver_id.as_str())
        .ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(format!(
                "normalization receiver {} is unknown",
                evidence.receiver_id
            ))
        })?;
    validate_evidence_matches_receiver(evidence, receiver)
}
pub(crate) fn validate_evidence_matches_receiver(
    evidence: &RelayAlertDeliveryEvidence,
    receiver: &RelayAlertDeliveryReceiver,
) -> Result<(), PheromoneRelayError> {
    if evidence.kind != receiver.kind
        || evidence.target_ref != receiver.target_ref
        || evidence.notification_route != receiver.notification_route
        || evidence.opsgenie != receiver.opsgenie
        || evidence.severity < receiver.severity_floor
        || evidence.runbook != receiver.runbook
    {
        return Err(PheromoneRelayError::AlertDeliveryInvalid(
            "normalized evidence does not match receiver contract".to_string(),
        ));
    }
    Ok(())
}
pub(crate) fn relay_alert_delivery_status_from_str(
    value: &str,
) -> Result<RelayAlertDeliveryStatus, PheromoneRelayError> {
    match value {
        "delivered" => Ok(RelayAlertDeliveryStatus::Delivered),
        "accepted" => Ok(RelayAlertDeliveryStatus::Accepted),
        "failed" => Ok(RelayAlertDeliveryStatus::Failed),
        "delayed" => Ok(RelayAlertDeliveryStatus::Delayed),
        "duplicate" => Ok(RelayAlertDeliveryStatus::Duplicate),
        "unknown" => Ok(RelayAlertDeliveryStatus::Unknown),
        "operator_acknowledged" => Ok(RelayAlertDeliveryStatus::OperatorAcknowledged),
        _ => Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
            "delivery status {value} is not supported"
        ))),
    }
}
pub(crate) fn json_string(value: &Value, names: &[&str]) -> Result<String, PheromoneRelayError> {
    for name in names {
        if let Some(text) = value.get(*name).and_then(Value::as_str) {
            if text.trim().is_empty() {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "field {name} is empty"
                )));
            }
            return Ok(text.to_string());
        }
    }
    Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
        "missing field {}",
        names.join("/")
    )))
}
pub(crate) fn json_u64(value: &Value, names: &[&str]) -> Result<u64, PheromoneRelayError> {
    for name in names {
        if let Some(number) = value.get(*name).and_then(Value::as_u64) {
            return Ok(number);
        }
    }
    Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
        "missing numeric field {}",
        names.join("/")
    )))
}
pub(crate) fn json_labels(value: &Value) -> Result<BTreeMap<String, String>, PheromoneRelayError> {
    let mut labels = BTreeMap::new();
    if let Some(raw_labels) = value.get("labels") {
        let object = raw_labels.as_object().ok_or_else(|| {
            PheromoneRelayError::AlertDeliveryInvalid(
                "normalization labels must be an object".to_string(),
            )
        })?;
        for (name, value) in object {
            let text = value.as_str().ok_or_else(|| {
                PheromoneRelayError::AlertDeliveryInvalid(
                    "normalization label value must be a string".to_string(),
                )
            })?;
            labels.insert(name.clone(), text.to_string());
        }
    }
    Ok(labels)
}
pub(crate) fn reject_downstream_source_secrets(value: &Value) -> Result<(), PheromoneRelayError> {
    match value {
        Value::String(text) => {
            if text.contains("://") || contains_secret_marker(text) {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(
                    "downstream source contains secret material or a dynamic URL".to_string(),
                ));
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_downstream_source_secrets(item)?;
            }
        }
        Value::Object(object) => {
            for (name, item) in object {
                if contains_secret_marker(name) || name.to_ascii_lowercase().contains("url") {
                    return Err(PheromoneRelayError::AlertDeliveryInvalid(
                        "downstream source contains secret material or a dynamic URL".to_string(),
                    ));
                }
                reject_downstream_source_secrets(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}
pub(crate) fn route_owner_map(
    profile: &RelayAlertRouteOwnerProfileDocument,
) -> Result<BTreeMap<&str, &RelayAlertRouteOwner>, PheromoneRelayError> {
    let mut owners = BTreeMap::new();
    for owner in &profile.owners {
        for receiver_id in &owner.receiver_ids {
            if owners.insert(receiver_id.as_str(), owner).is_some() {
                return Err(PheromoneRelayError::AlertDeliveryInvalid(format!(
                    "duplicate route owner receiver {receiver_id}"
                )));
            }
        }
    }
    Ok(owners)
}
