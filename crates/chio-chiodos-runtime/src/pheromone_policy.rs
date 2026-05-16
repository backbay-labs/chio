use crate::admission::passed;
use crate::hash::{runtime_peer_weights_sha256, runtime_pheromone_policy_sha256};
use crate::schema::*;
use crate::serde_io::runtime_pheromone_advisory_from_query_report_value;
use crate::types::*;
use chio_core_types::PublicKey;
use std::collections::BTreeSet;

pub(crate) struct RuntimePolicyEvaluationInput<'a, 'b> {
    pub(crate) policy: Option<&'a SignedRuntimePheromonePolicy>,
    pub(crate) peer_weights: Option<&'a SignedRuntimePeerWeights>,
    pub(crate) query_report: Option<&'a SignedRuntimePheromoneQueryReport>,
    pub(crate) runtime_trust_input: Option<&'a SignedRuntimeVerifierTrustBundle>,
    pub(crate) trusted_verifier_keys: &'a [RuntimeTrustedVerifierKey],
    pub(crate) bundle: &'a RuntimeAdmissionBundle,
    pub(crate) action_class_id: Option<&'a str>,
    pub(crate) now_unix_ms: u64,
    pub(crate) checks: &'b mut Vec<RuntimeAdmissionCheck>,
}

pub(crate) fn evaluate_runtime_pheromone_policy(
    input: RuntimePolicyEvaluationInput<'_, '_>,
) -> Result<
    (
        Option<RuntimePheromonePolicyDecision>,
        Option<RuntimePheromoneAdvisory>,
    ),
    &'static str,
> {
    if input.bundle.destructive
        && (input.policy.is_none() || input.peer_weights.is_none() || input.query_report.is_none())
    {
        return Err("runtime_pheromone_required_for_destructive");
    }
    match (input.policy, input.peer_weights) {
        (None, None) => return Ok((None, None)),
        (Some(_), None) => return Err("missing_runtime_peer_weights"),
        (None, Some(_)) => return Err("missing_runtime_pheromone_policy"),
        (Some(_), Some(_)) => {}
    }
    let Some(runtime_trust_input) = input.runtime_trust_input else {
        return Err("missing_runtime_trust_input");
    };
    let Some(query_report) = input.query_report else {
        return Err("missing_runtime_pheromone_advisory");
    };

    let policy = input.policy.ok_or("missing_runtime_pheromone_policy")?;
    let peer_weights = input.peer_weights.ok_or("missing_runtime_peer_weights")?;
    validate_signed_verifier_material(
        &policy.body.verifier_id,
        &policy.body.key_id,
        &policy.signer_key,
        || policy.verify_signature(),
        input.trusted_verifier_keys,
        input.now_unix_ms,
    )
    .map_err(|_| "runtime_pheromone_policy_untrusted")?;
    input.checks.push(passed("runtime_policy.signature"));
    if query_report.signer_key != policy.signer_key {
        return Err("runtime_pheromone_policy_query_report_signer_mismatch");
    }
    if !query_report
        .verify_signature()
        .map_err(|_| "runtime_pheromone_query_report_signature_invalid")?
    {
        return Err("runtime_pheromone_query_report_signature_invalid");
    }
    input
        .checks
        .push(passed("runtime_pheromone_query_report.signature"));
    let advisory = runtime_pheromone_advisory_from_query_report_value(&query_report.body)
        .map_err(|_| "invalid_pheromone_query_report")?;
    if !advisory.observe_only {
        return Err("runtime_pheromone_advisory_not_observe_only");
    }
    if !advisory.accepted {
        return Err("runtime_pheromone_advisory_rejected");
    }
    if advisory.evaluated_at_unix_ms > input.now_unix_ms {
        return Err("runtime_pheromone_advisory_future_dated");
    }
    validate_signed_verifier_material(
        &peer_weights.body.verifier_id,
        &peer_weights.body.key_id,
        &peer_weights.signer_key,
        || peer_weights.verify_signature(),
        input.trusted_verifier_keys,
        input.now_unix_ms,
    )
    .map_err(|_| "runtime_peer_weights_untrusted")?;
    input.checks.push(passed("runtime_peer_weights.signature"));

    let policy_body = &policy.body;
    let weights_body = &peer_weights.body;
    if policy_body.schema != CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA {
        return Err("unsupported_runtime_pheromone_policy_schema");
    }
    if weights_body.schema != CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA {
        return Err("unsupported_runtime_peer_weights_schema");
    }
    if policy_body.mode != "observe" && policy_body.mode != "enforce" {
        return Err("runtime_pheromone_policy_mode_unsupported");
    }
    if input.now_unix_ms < policy_body.issued_at_unix_ms
        || input.now_unix_ms >= policy_body.expires_at_unix_ms
    {
        return Err("runtime_pheromone_policy_stale");
    }
    if input.now_unix_ms < weights_body.issued_at_unix_ms
        || input.now_unix_ms >= weights_body.expires_at_unix_ms
    {
        return Err("runtime_peer_weights_stale");
    }
    if policy_body.verifier_id != runtime_trust_input.body.verifier_id {
        return Err("runtime_pheromone_policy_verifier_mismatch");
    }
    if policy_body.runtime_trust_bundle_sha256 != runtime_trust_input.body.trust_bundle_sha256 {
        return Err("runtime_pheromone_policy_trust_mismatch");
    }
    let weights_hash = runtime_peer_weights_sha256(weights_body)
        .map_err(|_| "runtime_peer_weights_hash_failed")?;
    if policy_body.peer_weights_sha256 != weights_hash {
        return Err("runtime_peer_weights_hash_mismatch");
    }
    if weights_body.reputation_epoch != advisory.reputation_epoch
        || !policy_body
            .allowed_reputation_epochs
            .contains(&advisory.reputation_epoch)
    {
        return Err("runtime_reputation_epoch_mismatch");
    }
    if input
        .now_unix_ms
        .saturating_sub(advisory.evaluated_at_unix_ms)
        > policy_body.max_query_report_age_ms
    {
        return Err("runtime_pheromone_advisory_stale");
    }
    if advisory.distinct_origin_pairs < policy_body.min_distinct_origin_pairs {
        return Err("runtime_pheromone_distinct_origin_floor");
    }
    validate_peer_weights(weights_body)?;
    input.checks.push(passed("runtime_policy.bindings"));

    let policy_hash =
        runtime_pheromone_policy_sha256(policy_body).map_err(|_| "runtime_policy_hash_failed")?;
    let mut decision = RuntimePheromonePolicyDecision {
        schema: CHIODOS_RUNTIME_PHEROMONE_POLICY_DECISION_SCHEMA.to_string(),
        enforced: policy_body.mode == "enforce",
        decision: "allow".to_string(),
        policy_id: policy_body.policy_id.clone(),
        policy_sha256: policy_hash,
        query_report_sha256: advisory.source_report_sha256.clone(),
        peer_weights_sha256: weights_hash,
        reputation_epoch: advisory.reputation_epoch,
        matched_rule_id: None,
        reason_code: "runtime_pheromone_policy_allow".to_string(),
    };

    let action_class_id = input
        .action_class_id
        .unwrap_or(&input.bundle.binding.tool_name);
    for rule in &policy_body.rules {
        if rule.subject_class != advisory.subject_class
            || rule.subject_class_namespace != advisory.subject_class_namespace
        {
            continue;
        }
        if rule.action_class_id != action_class_id && rule.action_class_id != "*" {
            continue;
        }
        let matched = match rule.direction.as_str() {
            "deny_if_at_or_above" => advisory.total_strength >= rule.threshold_total_strength,
            "require_at_or_above" => advisory.total_strength < rule.threshold_total_strength,
            _ => return Err("runtime_pheromone_policy_direction_unsupported"),
        };
        if !matched {
            continue;
        }
        decision.matched_rule_id = Some(rule.rule_id.clone());
        decision.reason_code = format!("runtime_pheromone_policy_{}", rule.effect);
        if policy_body.mode == "enforce" {
            decision.decision = match rule.effect.as_str() {
                "deny" => "deny".to_string(),
                "require_review" => "escalate".to_string(),
                "receipt_tag" => "allow".to_string(),
                _ => return Err("runtime_pheromone_policy_effect_unsupported"),
            };
        }
        break;
    }
    Ok((Some(decision), Some(advisory)))
}

fn validate_peer_weights(weights: &RuntimePeerWeights) -> Result<(), &'static str> {
    let mut peers = BTreeSet::new();
    for weight in &weights.weights {
        if weight.peer_kernel_id.trim().is_empty() {
            return Err("runtime_peer_weights_invalid");
        }
        if !peers.insert(weight.peer_kernel_id.as_str()) {
            return Err("runtime_peer_weights_duplicate_peer");
        }
        if !weight.weight.is_finite() || weight.weight < 0.0 {
            return Err("runtime_peer_weights_invalid");
        }
    }
    Ok(())
}

fn validate_signed_verifier_material<F>(
    verifier_id: &str,
    key_id: &str,
    signer_key: &PublicKey,
    verify_signature: F,
    trusted_verifier_keys: &[RuntimeTrustedVerifierKey],
    now_unix_ms: u64,
) -> Result<(), &'static str>
where
    F: FnOnce() -> Result<bool, chio_core_types::Error>,
{
    if !verify_signature().map_err(|_| "signature_invalid")? {
        return Err("signature_invalid");
    }
    let Some(trusted_key) = trusted_verifier_keys.iter().find(|trusted| {
        trusted.verifier_id == verifier_id
            && trusted.key_id == key_id
            && trusted.public_key == *signer_key
    }) else {
        return Err("signer_untrusted");
    };
    if trusted_key.status != "active" {
        return Err("signer_inactive");
    }
    if now_unix_ms < trusted_key.valid_from_unix_ms
        || now_unix_ms >= trusted_key.valid_until_unix_ms
    {
        return Err("signer_stale");
    }
    Ok(())
}
