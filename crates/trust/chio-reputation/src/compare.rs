fn compute_history_depth(
    receipts: &[&ChioReceipt],
    config: &ReputationConfig,
) -> HistoryDepthMetrics {
    if receipts.is_empty() {
        return HistoryDepthMetrics {
            score: MetricValue::Unknown,
            receipt_count: 0,
            active_days: 0,
            first_seen: None,
            last_seen: None,
            span_days: 0,
            activity_ratio: MetricValue::Unknown,
        };
    }

    let first_seen = receipts.iter().map(|receipt| receipt.timestamp).min();
    let last_seen = receipts.iter().map(|receipt| receipt.timestamp).max();
    let active_days: BTreeSet<u64> = receipts
        .iter()
        .map(|receipt| receipt.timestamp / SECONDS_PER_DAY)
        .collect();
    let span_days = match (first_seen, last_seen) {
        (Some(first), Some(last)) => {
            let first_day = first / SECONDS_PER_DAY;
            let last_day = last / SECONDS_PER_DAY;
            last_day.saturating_sub(first_day) + 1
        }
        _ => 0,
    };
    let activity_ratio = if span_days > 0 {
        active_days.len() as f64 / span_days as f64
    } else {
        0.0
    };
    let receipt_score =
        (receipts.len() as f64 / config.history_receipt_target.max(1) as f64).min(1.0);
    let day_score = (span_days as f64 / config.history_day_target.max(1) as f64).min(1.0);
    let normalized = (receipt_score + day_score + activity_ratio) / 3.0;

    HistoryDepthMetrics {
        score: MetricValue::known(normalized),
        receipt_count: receipts.len(),
        active_days: active_days.len(),
        first_seen,
        last_seen,
        span_days,
        activity_ratio: MetricValue::known(activity_ratio),
    }
}

fn compute_specialization(
    receipts: &[&ChioReceipt],
    now: u64,
    config: &ReputationConfig,
) -> SpecializationMetrics {
    if receipts.is_empty() {
        return SpecializationMetrics {
            score: MetricValue::Unknown,
            distinct_tools: 0,
        };
    }

    let mut weights_by_tool: BTreeMap<(&str, &str), f64> = BTreeMap::new();
    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        *weights_by_tool
            .entry((receipt.tool_server.as_str(), receipt.tool_name.as_str()))
            .or_default() += weight;
    }

    let total_weight = weights_by_tool.values().sum::<f64>();
    let entropy = weights_by_tool
        .values()
        .map(|count| {
            let p = count / total_weight;
            -p * p.log2()
        })
        .sum::<f64>();
    let max_entropy = if weights_by_tool.len() > 1 {
        (weights_by_tool.len() as f64).log2()
    } else {
        0.0
    };
    let score = if max_entropy > 0.0 {
        entropy / max_entropy
    } else {
        0.0
    };

    SpecializationMetrics {
        score: MetricValue::known(score),
        distinct_tools: weights_by_tool.len(),
    }
}

fn compute_delegation_hygiene(
    delegations: &[&CapabilityLineageRecord],
    capability_map: &BTreeMap<&str, &CapabilityLineageRecord>,
    now: u64,
    config: &ReputationConfig,
) -> DelegationHygieneMetrics {
    if delegations.is_empty() {
        return DelegationHygieneMetrics {
            score: MetricValue::Unknown,
            delegations_observed: 0,
            scope_reduction_rate: MetricValue::Unknown,
            ttl_reduction_rate: MetricValue::Unknown,
            budget_reduction_rate: MetricValue::Unknown,
        };
    }

    let mut scope_signals = Vec::new();
    let mut ttl_signals = Vec::new();
    let mut budget_signals = Vec::new();

    for child in delegations {
        let Some(parent_id) = child.parent_capability_id.as_deref() else {
            continue;
        };
        let Some(parent) = capability_map.get(parent_id) else {
            continue;
        };

        let weight = decay_weight(now, child.issued_at, config.temporal_decay_half_life_days);
        scope_signals.push((
            bool_to_score(scope_reduced(&parent.scope, &child.scope)),
            weight,
        ));
        ttl_signals.push((bool_to_score(child.expires_at < parent.expires_at), weight));
        budget_signals.push((
            bool_to_score(budget_reduced(&parent.scope, &child.scope)),
            weight,
        ));
    }

    if scope_signals.is_empty() {
        return DelegationHygieneMetrics {
            score: MetricValue::Unknown,
            delegations_observed: 0,
            scope_reduction_rate: MetricValue::Unknown,
            ttl_reduction_rate: MetricValue::Unknown,
            budget_reduction_rate: MetricValue::Unknown,
        };
    }

    let scope_rate = weighted_average(&scope_signals);
    let ttl_rate = weighted_average(&ttl_signals);
    let budget_rate = weighted_average(&budget_signals);

    DelegationHygieneMetrics {
        score: MetricValue::known((scope_rate + ttl_rate + budget_rate) / 3.0),
        delegations_observed: scope_signals.len(),
        scope_reduction_rate: MetricValue::known(scope_rate),
        ttl_reduction_rate: MetricValue::known(ttl_rate),
        budget_reduction_rate: MetricValue::known(budget_rate),
    }
}

fn compute_reliability(
    receipts: &[&ChioReceipt],
    now: u64,
    config: &ReputationConfig,
) -> ReliabilityMetrics {
    let mut allow_weight = 0.0;
    let mut cancelled_weight = 0.0;
    let mut incomplete_weight = 0.0;
    let mut observed = 0usize;

    for receipt in receipts {
        let weight = decay_weight(now, receipt.timestamp, config.temporal_decay_half_life_days);
        match &receipt.decision {
            Some(Decision::Allow) if receipt_authority_valid(receipt, config) => {
                allow_weight += weight;
                observed += 1;
            }
            Some(Decision::Allow) => {}
            Some(Decision::Cancelled { .. }) => {
                cancelled_weight += weight;
                observed += 1;
            }
            Some(Decision::Incomplete { .. }) => {
                incomplete_weight += weight;
                observed += 1;
            }
            Some(Decision::Deny { .. }) | None => {}
        }
    }

    let total = allow_weight + cancelled_weight + incomplete_weight;
    if total == 0.0 {
        return ReliabilityMetrics {
            score: MetricValue::Unknown,
            completion_rate: MetricValue::Unknown,
            cancellation_rate: MetricValue::Unknown,
            incompletion_rate: MetricValue::Unknown,
            receipts_observed: observed,
        };
    }

    let completion_rate = allow_weight / total;
    let cancellation_rate = cancelled_weight / total;
    let incompletion_rate = incomplete_weight / total;

    ReliabilityMetrics {
        score: MetricValue::known(completion_rate),
        completion_rate: MetricValue::known(completion_rate),
        cancellation_rate: MetricValue::known(cancellation_rate),
        incompletion_rate: MetricValue::known(incompletion_rate),
        receipts_observed: observed,
    }
}

fn compute_incident_correlation(
    _subject_key: &str,
    now: u64,
    corpus: &LocalReputationCorpus,
    config: &ReputationConfig,
) -> IncidentCorrelationMetrics {
    let Some(incidents) = corpus.incident_reports.as_ref() else {
        return IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        };
    };

    let weighted_incidents = incidents
        .iter()
        .map(|incident| {
            decay_weight(
                now,
                incident.timestamp,
                config.temporal_decay_half_life_days,
            )
        })
        .sum::<f64>();
    let score = 1.0 - config.incident_penalty.max(0.0) * weighted_incidents;

    IncidentCorrelationMetrics {
        score: MetricValue::known(score),
        incidents_observed: Some(incidents.len()),
    }
}

#[must_use]
pub fn build_imported_reputation_signal(
    subject_key: &str,
    provenance: ImportedReputationProvenance,
    corpus: &LocalReputationCorpus,
    now: u64,
    config: &ReputationConfig,
    policy: &ImportedTrustPolicy,
) -> ImportedReputationSignal {
    let scorecard = compute_local_scorecard(subject_key, now, corpus, config);
    let issuer_identity = ImportedIssuerIdentity {
        issuer: provenance.issuer.trim().to_string(),
        signer_public_key: provenance.signer_public_key.trim().to_string(),
    };
    let trust_mode = ImportedTrustMode::BilateralEvidenceShare;
    let mut accepted = true;
    let mut reasons = Vec::new();

    if !validate_imported_identity_field("share id", &provenance.share_id, true, &mut reasons) {
        accepted = false;
    }
    if !validate_imported_identity_field("issuer identity", &provenance.issuer, true, &mut reasons)
    {
        accepted = false;
    }
    if !validate_imported_identity_field(
        "partner boundary identity",
        &provenance.partner,
        true,
        &mut reasons,
    ) {
        accepted = false;
    }
    if !validate_imported_identity_field(
        "signer identity",
        &provenance.signer_public_key,
        policy.require_signer_identity,
        &mut reasons,
    ) {
        accepted = false;
    }
    if policy.require_proofs && !provenance.require_proofs {
        accepted = false;
        reasons.push("imported evidence share did not require proofs".to_string());
    }
    if !policy.allowed_issuers.is_empty()
        && !policy
            .allowed_issuers
            .iter()
            .any(|issuer| issuer == &issuer_identity.issuer)
    {
        accepted = false;
        reasons.push(format!(
            "issuer `{}` falls outside the imported-trust allowlist",
            issuer_identity.issuer
        ));
    }
    if !policy.allowed_signer_public_keys.is_empty()
        && !policy
            .allowed_signer_public_keys
            .iter()
            .any(|signer| signer == &issuer_identity.signer_public_key)
    {
        accepted = false;
        reasons.push(format!(
            "signer `{}` falls outside the imported-trust signer allowlist",
            issuer_identity.signer_public_key
        ));
    }
    if let Some(max_age_days) = policy.max_signal_age_days {
        let max_age_secs = max_age_days as u64 * SECONDS_PER_DAY;
        if now.saturating_sub(provenance.exported_at) > max_age_secs {
            accepted = false;
            reasons.push(format!(
                "imported signal is older than {} day(s)",
                max_age_days
            ));
        }
    }
    if provenance.imported_at < provenance.exported_at {
        accepted = false;
        reasons.push("imported evidence share timestamps are not monotonic".to_string());
    }
    if !trust_mode.satisfies(policy.required_trust_mode) {
        accepted = false;
        reasons.push(format!(
            "imported trust mode `{}` does not satisfy required mode `{}`",
            imported_trust_mode_label(trust_mode),
            imported_trust_mode_label(policy.required_trust_mode)
        ));
    }

    let attenuation_factor = clamp01(policy.attenuation_factor);
    let attenuated_composite_score = scorecard
        .composite_score
        .as_option()
        .filter(|_| accepted)
        .map(|value| clamp01(value * attenuation_factor));

    ImportedReputationSignal {
        provenance,
        issuer_identity,
        policy: policy.clone(),
        trust_mode,
        accepted,
        reasons,
        scorecard,
        attenuated_composite_score,
    }
}

fn validate_imported_identity_field(
    label: &str,
    value: &str,
    required: bool,
    reasons: &mut Vec<String>,
) -> bool {
    if value.trim().is_empty() {
        if required {
            reasons.push(format!("imported evidence share is missing {label}"));
            return false;
        }
        return true;
    }
    if value.trim() != value {
        reasons.push(format!(
            "imported evidence share {label} must not contain surrounding whitespace"
        ));
        return false;
    }
    if value.chars().any(char::is_control) {
        reasons.push(format!(
            "imported evidence share {label} must not contain control characters"
        ));
        return false;
    }
    true
}

fn imported_trust_mode_label(mode: ImportedTrustMode) -> &'static str {
    match mode {
        ImportedTrustMode::BilateralEvidenceShare => "bilateral_evidence_share",
        ImportedTrustMode::NetworkCleared => "network_cleared",
    }
}

#[cfg(test)]
mod imported_trust_tests {
    use super::*;

    fn sample_provenance() -> ImportedReputationProvenance {
        ImportedReputationProvenance {
            share_id: "share-1".to_string(),
            issuer: "operator-alpha".to_string(),
            partner: "operator-beta".to_string(),
            signer_public_key: "ed25519:issuer-alpha".to_string(),
            imported_at: 200,
            exported_at: 100,
            require_proofs: true,
            tool_receipts: 2,
            capability_lineage: 1,
        }
    }

    #[test]
    fn imported_signal_exposes_first_class_identity_and_mode() {
        let signal = build_imported_reputation_signal(
            "subject-1",
            sample_provenance(),
            &LocalReputationCorpus::default(),
            300,
            &ReputationConfig::default(),
            &ImportedTrustPolicy::default(),
        );

        assert!(signal.accepted);
        assert_eq!(signal.issuer_identity.issuer, "operator-alpha");
        assert_eq!(
            signal.issuer_identity.signer_public_key,
            "ed25519:issuer-alpha"
        );
        assert_eq!(signal.trust_mode, ImportedTrustMode::BilateralEvidenceShare);
    }

    #[test]
    fn imported_signal_rejects_disallowed_signer_identity() {
        let policy = ImportedTrustPolicy {
            allowed_signer_public_keys: vec!["ed25519:other-signer".to_string()],
            ..ImportedTrustPolicy::default()
        };

        let signal = build_imported_reputation_signal(
            "subject-1",
            sample_provenance(),
            &LocalReputationCorpus::default(),
            300,
            &ReputationConfig::default(),
            &policy,
        );

        assert!(!signal.accepted);
        assert!(signal
            .reasons
            .iter()
            .any(|reason| reason.contains("signer")));
    }

    #[test]
    fn imported_signal_rejects_ambiguous_identity_material() {
        let mut provenance = sample_provenance();
        provenance.share_id = " ".to_string();
        provenance.issuer = " operator-alpha".to_string();
        provenance.partner = "operator-beta ".to_string();
        provenance.signer_public_key = " ed25519:issuer-alpha".to_string();

        let signal = build_imported_reputation_signal(
            "subject-1",
            provenance,
            &LocalReputationCorpus::default(),
            300,
            &ReputationConfig::default(),
            &ImportedTrustPolicy::default(),
        );

        assert!(!signal.accepted);
        assert!(signal
            .reasons
            .iter()
            .any(|reason| reason.contains("share id")));
        assert!(signal
            .reasons
            .iter()
            .any(|reason| reason.contains("issuer identity")));
        assert!(signal
            .reasons
            .iter()
            .any(|reason| reason.contains("partner boundary identity")));
        assert!(signal
            .reasons
            .iter()
            .any(|reason| reason.contains("signer identity")));
    }

    #[test]
    fn imported_signal_rejects_network_cleared_requirement_for_bilateral_share() {
        let policy = ImportedTrustPolicy {
            required_trust_mode: ImportedTrustMode::NetworkCleared,
            ..ImportedTrustPolicy::default()
        };

        let signal = build_imported_reputation_signal(
            "subject-1",
            sample_provenance(),
            &LocalReputationCorpus::default(),
            300,
            &ReputationConfig::default(),
            &policy,
        );

        assert!(!signal.accepted);
        assert!(signal
            .reasons
            .iter()
            .any(|reason| reason.contains("network_cleared")));
    }

    #[test]
    fn imported_signal_rejects_non_monotonic_import_timestamps() {
        let mut provenance = sample_provenance();
        provenance.imported_at = provenance.exported_at.saturating_sub(1);

        let signal = build_imported_reputation_signal(
            "subject-1",
            provenance,
            &LocalReputationCorpus::default(),
            300,
            &ReputationConfig::default(),
            &ImportedTrustPolicy::default(),
        );

        assert!(!signal.accepted);
        assert!(signal
            .reasons
            .iter()
            .any(|reason| reason.contains("not monotonic")));
    }
}
