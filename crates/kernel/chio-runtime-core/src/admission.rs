use crate::error::ChioRuntimeError;
use crate::hash::runtime_verifier_trust_bundle_sha256;
use crate::pheromone_policy::{evaluate_runtime_pheromone_policy, RuntimePolicyEvaluationInput};
use crate::schema::*;
use crate::store::RuntimeAdmissionStore;
use crate::types::*;

pub struct RuntimeAdmissionInput<'a> {
    pub profile: &'a RuntimeAdmissionProfile,
    pub store: &'a dyn RuntimeAdmissionStore,
    pub admission_id: &'a str,
    pub request: &'a RuntimeRequestBinding,
    pub action_class_id: Option<&'a str>,
    pub runtime_trust_input: Option<&'a SignedRuntimeVerifierTrustBundle>,
    pub trusted_verifier_keys: &'a [RuntimeTrustedVerifierKey],
    pub pheromone_query_report: Option<&'a SignedRuntimePheromoneQueryReport>,
    pub runtime_pheromone_policy: Option<&'a SignedRuntimePheromonePolicy>,
    pub runtime_peer_weights: Option<&'a SignedRuntimePeerWeights>,
    pub now_unix_ms: u64,
}

pub fn evaluate_runtime_admission(
    input: RuntimeAdmissionInput<'_>,
) -> Result<RuntimeAdmissionReport, ChioRuntimeError> {
    evaluate_runtime_admission_tracked(input, None)
}

#[derive(Default)]
pub(crate) struct RuntimeAdmissionReservationTracker {
    destructive_lease_id: std::cell::RefCell<Option<String>>,
}

impl RuntimeAdmissionReservationTracker {
    pub(crate) fn destructive_lease_id(&self) -> Option<String> {
        self.destructive_lease_id.borrow().clone()
    }

    fn mark_destructive_lease_consumed(&self, lease_id: String) {
        self.destructive_lease_id.replace(Some(lease_id));
    }

    fn clear_destructive_lease(&self) {
        self.destructive_lease_id.replace(None);
    }
}

pub(crate) fn evaluate_runtime_admission_tracked(
    input: RuntimeAdmissionInput<'_>,
    reservation_tracker: Option<&RuntimeAdmissionReservationTracker>,
) -> Result<RuntimeAdmissionReport, ChioRuntimeError> {
    let mut checks = Vec::new();
    let report_schema = runtime_admission_report_schema(&input.profile.schema);
    if !is_runtime_admission_profile_schema(&input.profile.schema) {
        return Ok(rejected_report(
            report_schema,
            input.admission_id,
            "unsupported_profile_schema",
            checks,
        ));
    }
    checks.push(passed("profile.schema"));
    if input.now_unix_ms < input.profile.issued_at_unix_ms
        || input.now_unix_ms >= input.profile.expires_at_unix_ms
    {
        return Ok(rejected_report(
            report_schema,
            input.admission_id,
            "stale_profile",
            checks,
        ));
    }
    checks.push(passed("profile.freshness"));

    let bundle = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        input.store.bundle(input.admission_id)
    })) {
        Ok(Ok(Some(bundle))) => bundle,
        Ok(Ok(None)) => {
            return Ok(rejected_report(
                report_schema,
                input.admission_id,
                "missing_admission_bundle",
                checks,
            ));
        }
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Ok(rejected_report(
                report_schema,
                input.admission_id,
                "admission_bundle_store_error",
                checks,
            ));
        }
    };
    if !is_runtime_admission_bundle_schema(&bundle.schema) {
        return Ok(rejected_report(
            report_schema,
            input.admission_id,
            "unsupported_bundle_schema",
            checks,
        ));
    }
    checks.push(passed("bundle.schema"));

    let mut trust_floor_update = None;
    if let Some(runtime_trust_input) = input.runtime_trust_input {
        if runtime_trust_input.body.verifier_id != input.profile.verifier_id {
            return Ok(rejected_report(
                report_schema,
                input.admission_id,
                "runtime_trust_input_verifier_mismatch",
                checks,
            ));
        }
        checks.push(passed("runtime_trust.profile_verifier"));
        match validate_runtime_trust_input(
            runtime_trust_input,
            input.trusted_verifier_keys,
            &bundle,
            input.now_unix_ms,
            &mut checks,
        ) {
            Ok(entry) => {
                trust_floor_update = Some((
                    entry,
                    runtime_trust_input.body.previous_hash_sha256.as_deref(),
                ));
            }
            Err(code) => {
                return Ok(rejected_report(
                    report_schema,
                    input.admission_id,
                    code,
                    checks,
                ))
            }
        }
    } else if !input.trusted_verifier_keys.is_empty() {
        return Ok(rejected_report(
            report_schema,
            input.admission_id,
            "missing_runtime_trust_input",
            checks,
        ));
    }

    if bundle.binding.host_kernel_id != input.profile.local_kernel_id {
        return Ok(rejected_report(
            report_schema,
            input.admission_id,
            "host_kernel_mismatch",
            checks,
        ));
    }
    checks.push(passed("bundle.host_kernel"));

    if &bundle.binding != input.request {
        return Ok(rejected_report(
            report_schema,
            input.admission_id,
            "request_binding_mismatch",
            checks,
        ));
    }
    checks.push(passed("request.binding"));

    if input.pheromone_query_report.is_some() {
        checks.push(passed("pheromone.query_report_signed"));
    }
    let (policy_decision, pheromone_advisory) =
        match evaluate_runtime_pheromone_policy(RuntimePolicyEvaluationInput {
            policy: input.runtime_pheromone_policy,
            peer_weights: input.runtime_peer_weights,
            query_report: input.pheromone_query_report,
            runtime_trust_input: input.runtime_trust_input,
            trusted_verifier_keys: input.trusted_verifier_keys,
            bundle: &bundle,
            action_class_id: input.action_class_id,
            now_unix_ms: input.now_unix_ms,
            checks: &mut checks,
        }) {
            Ok(result) => result,
            Err(code) => {
                return Ok(rejected_report_with_policy(
                    report_schema,
                    input.admission_id,
                    code,
                    checks,
                    None,
                ));
            }
        };
    if pheromone_advisory.is_some() {
        checks.push(passed("pheromone.observe_only"));
    }
    if let Some(decision) = policy_decision.as_ref() {
        if decision.decision == "deny" {
            return Ok(rejected_report_with_policy(
                report_schema,
                input.admission_id,
                "runtime_pheromone_policy_deny",
                checks,
                Some(decision.clone()),
            ));
        }
        if decision.decision == "escalate" {
            return Ok(rejected_report_with_policy(
                report_schema,
                input.admission_id,
                "runtime_pheromone_policy_escalate",
                checks,
                Some(decision.clone()),
            ));
        }
    }

    let mut consumed_destructive_lease_id = None;
    if bundle.destructive {
        let Some(lease_id) = bundle.lease_id.as_deref() else {
            return Ok(rejected_report(
                report_schema,
                input.admission_id,
                "missing_destructive_lease",
                checks,
            ));
        };
        if bundle.governance_receipt_id.is_none() {
            return Ok(rejected_report(
                report_schema,
                input.admission_id,
                "missing_governance_receipt",
                checks,
            ));
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            input
                .store
                .consume_destructive_lease(lease_id, input.admission_id)
        })) {
            Err(_) => {
                return Ok(rejected_report_with_ambiguous_destructive_consumption(
                    report_schema,
                    input.admission_id,
                    checks,
                    lease_id,
                    "destructive lease consume callback panicked",
                ));
            }
            Ok(Ok(())) => {
                consumed_destructive_lease_id = Some(lease_id.to_string());
                if let (Some(tracker), Some(consumed_lease_id)) =
                    (reservation_tracker, consumed_destructive_lease_id.as_ref())
                {
                    tracker.mark_destructive_lease_consumed(consumed_lease_id.clone());
                }
                checks.push(passed("destructive.lease_reserved"));
            }
            Ok(Err(ChioRuntimeError::Rejected { code, .. })) => {
                return Ok(rejected_report(
                    report_schema,
                    input.admission_id,
                    code,
                    checks,
                ));
            }
            Ok(Err(error)) => {
                return Ok(rejected_report_with_ambiguous_destructive_consumption(
                    report_schema,
                    input.admission_id,
                    checks,
                    lease_id,
                    &error.to_string(),
                ));
            }
        }
    }
    if let Some((entry, previous_hash_sha256)) = trust_floor_update {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            input
                .store
                .validate_and_record_runtime_trust_floor(entry, previous_hash_sha256)
        })) {
            Err(_) => {
                let failure_code = "runtime_trust_floor_error";
                if let Some(lease_id) = consumed_destructive_lease_id.as_deref() {
                    if let Err(reason) = release_destructive_lease_best_effort(
                        input.store,
                        lease_id,
                        input.admission_id,
                    ) {
                        return Ok(rejected_report_with_destructive_release_failure(
                            report_schema,
                            input.admission_id,
                            failure_code,
                            checks,
                            lease_id,
                            &format!("runtime trust floor callback panicked; {reason}"),
                        ));
                    }
                    if let Some(tracker) = reservation_tracker {
                        tracker.clear_destructive_lease();
                    }
                }
                return Ok(rejected_report(
                    report_schema,
                    input.admission_id,
                    failure_code,
                    checks,
                ));
            }
            Ok(Ok(())) => checks.push(passed("runtime_trust.floor")),
            Ok(Err(ChioRuntimeError::Rejected { code, .. })) => {
                if let Some(lease_id) = consumed_destructive_lease_id.as_deref() {
                    if let Err(reason) = release_destructive_lease_best_effort(
                        input.store,
                        lease_id,
                        input.admission_id,
                    ) {
                        return Ok(rejected_report_with_destructive_release_failure(
                            report_schema,
                            input.admission_id,
                            code,
                            checks,
                            lease_id,
                            &reason,
                        ));
                    }
                    if let Some(tracker) = reservation_tracker {
                        tracker.clear_destructive_lease();
                    }
                }
                return Ok(rejected_report(
                    report_schema,
                    input.admission_id,
                    code,
                    checks,
                ));
            }
            Ok(Err(error)) => {
                if let Some(lease_id) = consumed_destructive_lease_id.as_deref() {
                    if let Err(reason) = release_destructive_lease_best_effort(
                        input.store,
                        lease_id,
                        input.admission_id,
                    ) {
                        return Ok(rejected_report_with_destructive_release_failure(
                            report_schema,
                            input.admission_id,
                            "runtime_trust_floor_error",
                            checks,
                            lease_id,
                            &format!("{error}; {reason}"),
                        ));
                    }
                    if let Some(tracker) = reservation_tracker {
                        tracker.clear_destructive_lease();
                    }
                }
                return Err(error);
            }
        }
    }

    Ok(RuntimeAdmissionReport {
        schema: report_schema.to_string(),
        admission_id: input.admission_id.to_string(),
        accepted: true,
        failure_code: None,
        checks,
        pheromone_advisory: pheromone_advisory.clone(),
        pheromone_policy_decision: policy_decision.clone(),
        receipt_metadata: receipt_metadata(
            report_schema,
            &bundle,
            true,
            None,
            consumed_destructive_lease_id.as_deref(),
            pheromone_advisory.as_ref(),
            policy_decision.as_ref(),
        ),
    })
}

fn release_destructive_lease_best_effort(
    store: &dyn RuntimeAdmissionStore,
    lease_id: &str,
    admission_id: &str,
) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.release_destructive_lease(lease_id, admission_id)
    })) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("destructive lease release callback panicked".to_string()),
    }
}

fn is_runtime_admission_profile_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA)
}

fn is_runtime_admission_bundle_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA)
}

fn runtime_admission_report_schema(_profile_schema: &str) -> &'static str {
    CHIO_RUNTIME_ADMISSION_REPORT_SCHEMA
}

pub(crate) fn passed(code: &str) -> RuntimeAdmissionCheck {
    RuntimeAdmissionCheck {
        code: code.to_string(),
        passed: true,
    }
}

pub(crate) fn validate_runtime_trust_input(
    envelope: &SignedRuntimeVerifierTrustBundle,
    trusted_verifier_keys: &[RuntimeTrustedVerifierKey],
    bundle: &RuntimeAdmissionBundle,
    now_unix_ms: u64,
    checks: &mut Vec<RuntimeAdmissionCheck>,
) -> Result<RuntimeTrustFloorEntry, &'static str> {
    let body = &envelope.body;
    if !is_runtime_verifier_trust_bundle_schema(&body.schema) {
        return Err("unsupported_runtime_trust_schema");
    }
    checks.push(passed("runtime_trust.schema"));

    let signature_valid = envelope
        .verify_signature()
        .map_err(|_| "runtime_trust_signature_invalid")?;
    if !signature_valid {
        return Err("runtime_trust_signature_invalid");
    }
    checks.push(passed("runtime_trust.signature"));

    let Some(trusted_key) = trusted_verifier_keys.iter().find(|trusted| {
        trusted.verifier_id == body.verifier_id
            && trusted.key_id == body.key_id
            && trusted.public_key == envelope.signer_key
    }) else {
        return Err("runtime_trust_signer_untrusted");
    };
    if trusted_key.status != "active" {
        return Err("runtime_trust_signer_inactive");
    }
    if now_unix_ms < trusted_key.valid_from_unix_ms
        || now_unix_ms >= trusted_key.valid_until_unix_ms
    {
        return Err("runtime_trust_signer_stale");
    }
    checks.push(passed("runtime_trust.signer"));

    if now_unix_ms < body.issued_at_unix_ms || now_unix_ms >= body.expires_at_unix_ms {
        return Err("runtime_trust_stale");
    }
    checks.push(passed("runtime_trust.freshness"));

    if body.version == 0 {
        return Err("runtime_trust_version_zero");
    }
    if body.version > 1 && body.previous_hash_sha256.is_none() {
        return Err("runtime_trust_previous_hash_missing");
    }
    checks.push(passed("runtime_trust.version"));

    let body_hash =
        runtime_verifier_trust_bundle_sha256(body).map_err(|_| "runtime_trust_hash_failed")?;

    if body.revocation_authority_roots.is_empty() {
        return Err("runtime_trust_revocation_roots_missing");
    }
    checks.push(passed("runtime_trust.revocation_roots"));

    if body.trust_bundle_sha256 != bundle.trust_bundle_sha256 {
        return Err("runtime_trust_bundle_hash_mismatch");
    }
    if body.verification_context_sha256 != bundle.verification_context_sha256 {
        return Err("runtime_trust_context_hash_mismatch");
    }
    checks.push(passed("runtime_trust.bundle_binding"));
    Ok(RuntimeTrustFloorEntry {
        verifier_id: body.verifier_id.clone(),
        key_id: body.key_id.clone(),
        highest_version: body.version,
        latest_bundle_sha256: body_hash,
        latest_revocation_checkpoint_sha256: body.revocation_checkpoint_sha256.clone(),
    })
}

fn is_runtime_verifier_trust_bundle_schema(schema: &str) -> bool {
    matches!(schema, CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA)
}

pub(crate) fn validate_runtime_trust_floor_transition(
    existing: Option<RuntimeTrustFloorEntry>,
    next: &RuntimeTrustFloorEntry,
    previous_hash_sha256: Option<&str>,
) -> Result<(), ChioRuntimeError> {
    if let Some(floor) = existing {
        if next.highest_version < floor.highest_version {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_trust_rollback",
                detail: "runtime trust input version is below persisted floor".to_string(),
            });
        }
        if next.highest_version == floor.highest_version
            && next.latest_bundle_sha256 != floor.latest_bundle_sha256
        {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_trust_same_version_mismatch",
                detail: "runtime trust input reused a floor version with different content"
                    .to_string(),
            });
        }
        if next.highest_version > floor.highest_version
            && previous_hash_sha256 != Some(floor.latest_bundle_sha256.as_str())
        {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_trust_previous_hash_mismatch",
                detail: "runtime trust input does not extend the persisted floor".to_string(),
            });
        }
    } else if next.highest_version > 1 && previous_hash_sha256.is_none() {
        return Err(ChioRuntimeError::Rejected {
            code: "runtime_trust_previous_hash_missing",
            detail: "runtime trust input above version one must carry a previous hash".to_string(),
        });
    }
    Ok(())
}

fn rejected_report(
    report_schema: &str,
    admission_id: &str,
    failure_code: &'static str,
    checks: Vec<RuntimeAdmissionCheck>,
) -> RuntimeAdmissionReport {
    rejected_report_with_policy(report_schema, admission_id, failure_code, checks, None)
}

fn rejected_report_with_destructive_release_failure(
    report_schema: &str,
    admission_id: &str,
    failure_code: &'static str,
    checks: Vec<RuntimeAdmissionCheck>,
    lease_id: &str,
    release_failure_reason: &str,
) -> RuntimeAdmissionReport {
    let mut report = rejected_report(report_schema, admission_id, failure_code, checks);
    if let Some(runtime) = report
        .receipt_metadata
        .get_mut(runtime_receipt_metadata_key(report_schema))
        .and_then(serde_json::Value::as_object_mut)
    {
        runtime.insert(
            "reserved_destructive_lease_id".to_string(),
            serde_json::Value::String(lease_id.to_string()),
        );
        runtime.insert(
            "reservation_release_failed".to_string(),
            serde_json::Value::Bool(true),
        );
        runtime.insert(
            "reservation_release_failure_reason".to_string(),
            serde_json::Value::String(release_failure_reason.to_string()),
        );
    }
    report
}

fn rejected_report_with_ambiguous_destructive_consumption(
    report_schema: &str,
    admission_id: &str,
    checks: Vec<RuntimeAdmissionCheck>,
    lease_id: &str,
    failure_reason: &str,
) -> RuntimeAdmissionReport {
    let mut report = rejected_report(
        report_schema,
        admission_id,
        "destructive_lease_consume_error",
        checks,
    );
    if let Some(runtime) = report
        .receipt_metadata
        .get_mut(runtime_receipt_metadata_key(report_schema))
        .and_then(serde_json::Value::as_object_mut)
    {
        runtime.insert(
            "ambiguous_destructive_lease_id".to_string(),
            serde_json::Value::String(lease_id.to_string()),
        );
        runtime.insert(
            "reservation_ownership_ambiguous".to_string(),
            serde_json::Value::Bool(true),
        );
        runtime.insert(
            "reservation_consumption_failure_reason".to_string(),
            serde_json::Value::String(failure_reason.to_string()),
        );
    }
    report
}

fn rejected_report_with_policy(
    report_schema: &str,
    admission_id: &str,
    failure_code: &'static str,
    checks: Vec<RuntimeAdmissionCheck>,
    pheromone_policy_decision: Option<RuntimePheromonePolicyDecision>,
) -> RuntimeAdmissionReport {
    let metadata_key = runtime_receipt_metadata_key(report_schema);
    RuntimeAdmissionReport {
        schema: report_schema.to_string(),
        admission_id: admission_id.to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
        pheromone_advisory: None,
        pheromone_policy_decision: pheromone_policy_decision.clone(),
        receipt_metadata: serde_json::json!({
            metadata_key: {
                "admission_id": admission_id,
                "accepted": false,
                "failure_code": failure_code,
                "pheromone_policy_decision": pheromone_policy_decision
            }
        }),
    }
}

fn receipt_metadata(
    report_schema: &str,
    bundle: &RuntimeAdmissionBundle,
    accepted: bool,
    failure_code: Option<&str>,
    reserved_destructive_lease_id: Option<&str>,
    pheromone_advisory: Option<&RuntimePheromoneAdvisory>,
    pheromone_policy_decision: Option<&RuntimePheromonePolicyDecision>,
) -> serde_json::Value {
    let metadata_key = runtime_receipt_metadata_key(report_schema);
    serde_json::json!({
        metadata_key: {
            "admission_id": bundle.admission_id,
            "accepted": accepted,
            "failure_code": failure_code,
            "workflow_id": bundle.workflow_id,
            "workflow_grant_id": bundle.workflow_grant_id,
            "step_index": bundle.step_index,
            "destructive": bundle.destructive,
            "lease_id": bundle.lease_id,
            "reserved_destructive_lease_id": reserved_destructive_lease_id,
            "governance_receipt_id": bundle.governance_receipt_id,
            "trust_bundle_sha256": bundle.trust_bundle_sha256,
            "verification_context_sha256": bundle.verification_context_sha256,
            "pheromone_advisory": pheromone_advisory,
            "pheromone_policy_decision": pheromone_policy_decision
        }
    })
}

fn runtime_receipt_metadata_key(_report_schema: &str) -> &'static str {
    "chio_runtime"
}

pub(crate) fn trust_floor_identity(verifier_id: &str, key_id: &str) -> String {
    format!("{verifier_id}:{key_id}")
}
