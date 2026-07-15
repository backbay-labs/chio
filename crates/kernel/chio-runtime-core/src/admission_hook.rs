use crate::*;

use chio_core_types::PublicKey;

mod dsse;
mod metadata;
mod request;
mod store_artifacts;
mod swarm_authority;
mod swarm_ref;
mod treaty_evidence;
mod treaty_ref;

use crate::pheromone_policy::{evaluate_runtime_pheromone_policy, RuntimePolicyEvaluationInput};
use metadata::{runtime_context_denial_metadata, runtime_denial_metadata};
use request::{admission_ref_from_request, request_has_chio_runtime_context};
use swarm_authority::verify_swarm_authority_reference_from_store;
use swarm_ref::swarm_ref_from_request;
use treaty_evidence::verify_treaty_reference_from_store;
use treaty_ref::treaty_ref_from_request;

fn continuation_reservation_metadata(
    admission_id: &str,
    destructive_lease_id: Option<&str>,
    treaty_continuation_id: Option<&str>,
    swarm_continuation_id: Option<&str>,
) -> serde_json::Value {
    let mut runtime = serde_json::Map::from_iter([(
        "admission_id".to_string(),
        serde_json::Value::String(admission_id.to_string()),
    )]);
    if let Some(lease_id) = destructive_lease_id {
        runtime.insert(
            "reserved_destructive_lease_id".to_string(),
            serde_json::Value::String(lease_id.to_string()),
        );
    }
    if let Some(continuation_id) = treaty_continuation_id {
        runtime.insert(
            "reserved_treaty_continuation_id".to_string(),
            serde_json::Value::String(continuation_id.to_string()),
        );
    }
    if let Some(continuation_id) = swarm_continuation_id {
        runtime.insert(
            "reserved_swarm_continuation_id".to_string(),
            serde_json::Value::String(continuation_id.to_string()),
        );
    }
    serde_json::json!({ "chio_runtime": runtime })
}

fn release_failure_metadata<E: std::fmt::Display>(
    mut metadata: serde_json::Value,
    reservations: &serde_json::Value,
    error: &E,
) -> serde_json::Value {
    if !metadata.is_object() {
        metadata = serde_json::json!({ "admission_metadata": metadata });
    }
    let Some(metadata_object) = metadata.as_object_mut() else {
        return metadata;
    };
    let runtime = metadata_object
        .entry("chio_runtime".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !runtime.is_object() {
        *runtime = serde_json::json!({});
    }
    let Some(runtime_object) = runtime.as_object_mut() else {
        return metadata;
    };
    if let Some(reserved) = reservations
        .get("chio_runtime")
        .and_then(serde_json::Value::as_object)
    {
        for key in [
            "admission_id",
            "reserved_destructive_lease_id",
            "reserved_treaty_continuation_id",
            "reserved_swarm_continuation_id",
        ] {
            if let Some(value) = reserved.get(key) {
                runtime_object.insert(key.to_string(), value.clone());
            }
        }
    }
    runtime_object.insert(
        "reservation_release_failed".to_string(),
        serde_json::Value::Bool(true),
    );
    let current_reason = runtime_object
        .get("reservation_release_failure_reason")
        .and_then(serde_json::Value::as_str);
    let failure_reason = match current_reason {
        Some(current_reason) => format!("{current_reason}; {error}"),
        None => error.to_string(),
    };
    runtime_object.insert(
        "reservation_release_failure_reason".to_string(),
        serde_json::Value::String(failure_reason),
    );
    metadata
}

fn ambiguous_consumption_metadata(
    mut metadata: serde_json::Value,
    reservation_key: &str,
    reservation_id: &str,
    failure_reason: &str,
) -> serde_json::Value {
    let runtime = metadata
        .as_object_mut()
        .and_then(|metadata| metadata.get_mut("chio_runtime"))
        .and_then(serde_json::Value::as_object_mut);
    if let Some(runtime) = runtime {
        runtime.insert(
            reservation_key.to_string(),
            serde_json::Value::String(reservation_id.to_string()),
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
    metadata
}

#[derive(Debug)]
struct ReservationReleaseFailure {
    reservations: serde_json::Value,
    reason: String,
}

impl std::fmt::Display for ReservationReleaseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

fn strip_released_reservation_metadata(
    mut metadata: serde_json::Value,
    released_reservations: &serde_json::Value,
) -> serde_json::Value {
    let released_runtime = released_reservations
        .get("chio_runtime")
        .and_then(serde_json::Value::as_object);
    if let (Some(runtime), Some(released_runtime)) = (
        metadata
            .get_mut("chio_runtime")
            .and_then(serde_json::Value::as_object_mut),
        released_runtime,
    ) {
        let reservation_keys = [
            "reserved_destructive_lease_id",
            "reserved_treaty_continuation_id",
            "reserved_swarm_continuation_id",
        ];
        for key in reservation_keys {
            if released_runtime.contains_key(key) {
                runtime.remove(key);
            }
        }
        if !reservation_keys
            .iter()
            .any(|key| runtime.contains_key(*key))
        {
            runtime.remove("reservation_release_failed");
            runtime.remove("reservation_release_failure_reason");
        }
    }
    metadata
}

#[derive(Debug, Clone)]
pub struct ChioRuntimeAdmissionHook<S> {
    profile: RuntimeAdmissionProfile,
    store: S,
    runtime_trust_input: Option<SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    pheromone_query_report: Option<SignedRuntimePheromoneQueryReport>,
    runtime_pheromone_policy: Option<SignedRuntimePheromonePolicy>,
    runtime_peer_weights: Option<SignedRuntimePeerWeights>,
    swarm_witness_keys: Vec<PublicKey>,
    fixed_now_unix_ms: Option<u64>,
}

impl<S> ChioRuntimeAdmissionHook<S> {
    #[must_use]
    pub fn new(profile: RuntimeAdmissionProfile, store: S) -> Self {
        Self {
            profile,
            store,
            runtime_trust_input: None,
            trusted_verifier_keys: Vec::new(),
            pheromone_query_report: None,
            runtime_pheromone_policy: None,
            runtime_peer_weights: None,
            swarm_witness_keys: Vec::new(),
            fixed_now_unix_ms: None,
        }
    }

    #[must_use]
    pub fn with_runtime_trust_input(
        mut self,
        runtime_trust_input: SignedRuntimeVerifierTrustBundle,
        trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    ) -> Self {
        self.runtime_trust_input = Some(runtime_trust_input);
        self.trusted_verifier_keys = trusted_verifier_keys;
        self
    }

    #[must_use]
    pub fn with_pheromone_query_report(
        mut self,
        report: SignedRuntimePheromoneQueryReport,
    ) -> Self {
        self.pheromone_query_report = Some(report);
        self
    }

    #[must_use]
    pub fn with_runtime_pheromone_policy(
        mut self,
        policy: SignedRuntimePheromonePolicy,
        peer_weights: SignedRuntimePeerWeights,
    ) -> Self {
        self.runtime_pheromone_policy = Some(policy);
        self.runtime_peer_weights = Some(peer_weights);
        self
    }

    #[must_use]
    pub fn with_swarm_witness_keys(mut self, witness_keys: Vec<PublicKey>) -> Self {
        self.swarm_witness_keys = witness_keys;
        self
    }

    #[must_use]
    pub fn with_fixed_now_unix_ms(mut self, now_unix_ms: u64) -> Self {
        self.fixed_now_unix_ms = Some(now_unix_ms);
        self
    }
}

impl<S> ChioRuntimeAdmissionHook<S>
where
    S: RuntimeAdmissionStore + Send + Sync,
{
    fn revalidate_admitted_request(
        &self,
        context: &KernelRuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        let admission_ref = match admission_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(_) if !request_has_chio_runtime_context(context.request) => {
                if context.request.federated_origin_kernel_id.is_some() {
                    return Err(KernelError::Internal(
                        "runtime admission revalidation requires treaty context for a federated request"
                            .to_string(),
                    ));
                }
                return Ok(());
            }
            Err(code) => {
                return Err(KernelError::Internal(format!(
                    "runtime admission revalidation rejected the request context: {code}"
                )));
            }
        };

        let runtime = context
            .admission_metadata
            .and_then(|metadata| metadata.get("chio_runtime"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                KernelError::Internal(
                    "runtime admission revalidation metadata is missing".to_string(),
                )
            })?;
        if runtime.get("accepted").and_then(serde_json::Value::as_bool) != Some(true)
            || runtime
                .get("admission_id")
                .and_then(serde_json::Value::as_str)
                != Some(admission_ref.admission_id.as_str())
        {
            return Err(KernelError::Internal(
                "runtime admission revalidation metadata does not identify the admitted decision"
                    .to_string(),
            ));
        }

        let now_unix_ms = self.fixed_now_unix_ms.unwrap_or(context.now_unix_ms);
        if self.profile.schema != CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA
            || now_unix_ms < self.profile.issued_at_unix_ms
            || now_unix_ms >= self.profile.expires_at_unix_ms
            || context.local_kernel_id != self.profile.local_kernel_id
        {
            return Err(KernelError::Internal(
                "runtime admission profile is not valid at the dispatch boundary".to_string(),
            ));
        }

        let binding = RuntimeRequestBinding::from_tool_call_request(
            context.request,
            &context.local_kernel_id,
        )
        .map_err(|error| {
            KernelError::Internal(format!(
                "runtime admission request binding revalidation failed: {error}"
            ))
        })?;
        let bundle = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.store.bundle(&admission_ref.admission_id)
        })) {
            Ok(Ok(Some(bundle))) => bundle,
            Ok(Ok(None)) => {
                return Err(KernelError::Internal(
                    "runtime admission bundle disappeared before dispatch".to_string(),
                ));
            }
            Ok(Err(error)) => {
                return Err(KernelError::Internal(format!(
                    "runtime admission bundle revalidation failed: {error}"
                )));
            }
            Err(_) => {
                return Err(KernelError::Internal(
                    "runtime admission bundle revalidation panicked".to_string(),
                ));
            }
        };
        if bundle.schema != CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA
            || bundle.admission_id != admission_ref.admission_id
            || bundle.binding != binding
            || bundle.binding.host_kernel_id != self.profile.local_kernel_id
        {
            return Err(KernelError::Internal(
                "runtime admission bundle changed before dispatch".to_string(),
            ));
        }
        if let Some(expected_hash) = admission_ref.bundle_sha256.as_deref() {
            let actual_hash = runtime_admission_bundle_sha256(&bundle).map_err(|error| {
                KernelError::Internal(format!(
                    "runtime admission bundle hash revalidation failed: {error}"
                ))
            })?;
            if actual_hash != expected_hash {
                return Err(KernelError::Internal(
                    "runtime admission bundle hash changed before dispatch".to_string(),
                ));
            }
        }

        let metadata_matches_bundle = runtime
            .get("workflow_id")
            .and_then(serde_json::Value::as_str)
            == Some(bundle.workflow_id.as_str())
            && runtime
                .get("workflow_grant_id")
                .and_then(serde_json::Value::as_str)
                == Some(bundle.workflow_grant_id.as_str())
            && runtime
                .get("step_index")
                .and_then(serde_json::Value::as_u64)
                == Some(bundle.step_index)
            && runtime
                .get("destructive")
                .and_then(serde_json::Value::as_bool)
                == Some(bundle.destructive)
            && runtime.get("lease_id") == Some(&serde_json::json!(bundle.lease_id))
            && runtime.get("governance_receipt_id")
                == Some(&serde_json::json!(bundle.governance_receipt_id))
            && runtime
                .get("trust_bundle_sha256")
                .and_then(serde_json::Value::as_str)
                == Some(bundle.trust_bundle_sha256.as_str())
            && runtime
                .get("verification_context_sha256")
                .and_then(serde_json::Value::as_str)
                == Some(bundle.verification_context_sha256.as_str());
        if !metadata_matches_bundle {
            return Err(KernelError::Internal(
                "runtime admission metadata changed before dispatch".to_string(),
            ));
        }

        let mut checks = Vec::new();
        if let Some(runtime_trust_input) = self.runtime_trust_input.as_ref() {
            if runtime_trust_input.body.verifier_id != self.profile.verifier_id {
                return Err(KernelError::Internal(
                    "runtime trust input verifier changed before dispatch".to_string(),
                ));
            }
            let trust_floor_entry = crate::admission::validate_runtime_trust_input(
                runtime_trust_input,
                &self.trusted_verifier_keys,
                &bundle,
                now_unix_ms,
                &mut checks,
            )
            .map_err(|code| {
                KernelError::Internal(format!("runtime trust input revalidation failed: {code}"))
            })?;
            let persisted_floor =
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.store.runtime_trust_floor(
                        &trust_floor_entry.verifier_id,
                        &trust_floor_entry.key_id,
                    )
                })) {
                    Ok(Ok(Some(floor))) => floor,
                    Ok(Ok(None)) => {
                        return Err(KernelError::Internal(
                            "runtime trust floor disappeared before dispatch".to_string(),
                        ));
                    }
                    Ok(Err(error)) => {
                        return Err(KernelError::Internal(format!(
                            "runtime trust floor revalidation failed: {error}"
                        )));
                    }
                    Err(_) => {
                        return Err(KernelError::Internal(
                            "runtime trust floor revalidation panicked".to_string(),
                        ));
                    }
                };
            crate::admission::validate_runtime_trust_floor_transition(
                Some(persisted_floor.clone()),
                &trust_floor_entry,
                runtime_trust_input.body.previous_hash_sha256.as_deref(),
            )
            .map_err(|error| {
                KernelError::Internal(format!("runtime trust floor revalidation failed: {error}"))
            })?;
            if persisted_floor != trust_floor_entry {
                return Err(KernelError::Internal(
                    "runtime trust floor changed before dispatch".to_string(),
                ));
            }
        } else if !self.trusted_verifier_keys.is_empty() {
            return Err(KernelError::Internal(
                "runtime trust input disappeared before dispatch".to_string(),
            ));
        }

        let swarm_reference = swarm_ref_from_request(context.request).map_err(|code| {
            KernelError::Internal(format!(
                "runtime swarm reference revalidation failed: {code}"
            ))
        })?;
        let verified_swarm_route_metadata = runtime.get("verified_swarm_route_metadata");
        let swarm_continuation_id = swarm_reference
            .as_ref()
            .map(|reference| {
                verify_swarm_authority_reference_from_store(
                    &self.store,
                    reference,
                    &self.swarm_witness_keys,
                    verified_swarm_route_metadata,
                    now_unix_ms,
                )
                .map(|verified| verified.continuation_id_to_consume)
            })
            .transpose()
            .map_err(|error| {
                KernelError::Internal(format!(
                    "runtime swarm authority revalidation failed: {error}"
                ))
            })?
            .flatten();

        let mut action_class_id = None;
        let treaty_continuation_id = match treaty_ref_from_request(context.request) {
            Ok(Some(treaty_ref)) => {
                action_class_id = Some(treaty_ref.action_class_id.clone());
                Some(
                    verify_treaty_reference_from_store(
                        &self.store,
                        &admission_ref.admission_id,
                        &treaty_ref,
                        context.request,
                        now_unix_ms,
                    )
                    .map_err(|error| {
                        KernelError::Internal(format!(
                            "runtime treaty revalidation failed: {error}"
                        ))
                    })?
                    .continuation_id,
                )
                .flatten()
            }
            Ok(None) if context.request.federated_origin_kernel_id.is_some() => {
                return Err(KernelError::Internal(
                    "runtime treaty context disappeared before dispatch".to_string(),
                ));
            }
            Ok(None) => None,
            Err(code) => {
                return Err(KernelError::Internal(format!(
                    "runtime treaty reference revalidation failed: {code}"
                )));
            }
        };

        for (key, expected) in [
            (
                "reserved_destructive_lease_id",
                bundle
                    .destructive
                    .then_some(bundle.lease_id.as_deref())
                    .flatten(),
            ),
            (
                "reserved_treaty_continuation_id",
                treaty_continuation_id.as_deref(),
            ),
            (
                "reserved_swarm_continuation_id",
                swarm_continuation_id.as_deref(),
            ),
        ] {
            if runtime.get(key).and_then(serde_json::Value::as_str) != expected {
                return Err(KernelError::Internal(format!(
                    "runtime admission reservation {key} changed before dispatch"
                )));
            }
        }

        let (policy_decision, _) =
            evaluate_runtime_pheromone_policy(RuntimePolicyEvaluationInput {
                policy: self.runtime_pheromone_policy.as_ref(),
                peer_weights: self.runtime_peer_weights.as_ref(),
                query_report: self.pheromone_query_report.as_ref(),
                runtime_trust_input: self.runtime_trust_input.as_ref(),
                trusted_verifier_keys: &self.trusted_verifier_keys,
                bundle: &bundle,
                action_class_id: action_class_id.as_deref(),
                now_unix_ms,
                checks: &mut checks,
            })
            .map_err(|code| {
                KernelError::Internal(format!(
                    "runtime pheromone policy revalidation failed: {code}"
                ))
            })?;
        if policy_decision
            .as_ref()
            .is_some_and(|decision| matches!(decision.decision.as_str(), "deny" | "escalate"))
        {
            return Err(KernelError::Internal(
                "runtime pheromone policy no longer allows dispatch".to_string(),
            ));
        }
        Ok(())
    }

    fn release_reservations(
        &self,
        metadata: &serde_json::Value,
    ) -> Result<(), ReservationReleaseFailure> {
        let Some(runtime) = metadata
            .get("chio_runtime")
            .and_then(serde_json::Value::as_object)
        else {
            return Ok(());
        };
        let Some(admission_id) = runtime
            .get("admission_id")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(());
        };
        let mut failed_runtime = serde_json::Map::from_iter([(
            "admission_id".to_string(),
            serde_json::Value::String(admission_id.to_string()),
        )]);
        let mut release_failures = Vec::new();

        if let Some(lease_id) = runtime
            .get("reserved_destructive_lease_id")
            .and_then(serde_json::Value::as_str)
        {
            let failure = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.store.release_destructive_lease(lease_id, admission_id)
            })) {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(format!("destructive lease `{lease_id}`: {error}")),
                Err(_) => Some(format!(
                    "destructive lease `{lease_id}`: release callback panicked"
                )),
            };
            if let Some(failure) = failure {
                failed_runtime.insert(
                    "reserved_destructive_lease_id".to_string(),
                    serde_json::Value::String(lease_id.to_string()),
                );
                release_failures.push(failure);
            }
        }
        if let Some(continuation_id) = runtime
            .get("reserved_treaty_continuation_id")
            .and_then(serde_json::Value::as_str)
        {
            let failure = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.store
                    .release_treaty_continuation(continuation_id, admission_id)
            })) {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(format!("treaty continuation `{continuation_id}`: {error}")),
                Err(_) => Some(format!(
                    "treaty continuation `{continuation_id}`: release callback panicked"
                )),
            };
            if let Some(failure) = failure {
                failed_runtime.insert(
                    "reserved_treaty_continuation_id".to_string(),
                    serde_json::Value::String(continuation_id.to_string()),
                );
                release_failures.push(failure);
            }
        }
        if let Some(continuation_id) = runtime
            .get("reserved_swarm_continuation_id")
            .and_then(serde_json::Value::as_str)
        {
            let failure = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.store
                    .release_swarm_continuation(continuation_id, admission_id)
            })) {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(format!("swarm continuation `{continuation_id}`: {error}")),
                Err(_) => Some(format!(
                    "swarm continuation `{continuation_id}`: release callback panicked"
                )),
            };
            if let Some(failure) = failure {
                failed_runtime.insert(
                    "reserved_swarm_continuation_id".to_string(),
                    serde_json::Value::String(continuation_id.to_string()),
                );
                release_failures.push(failure);
            }
        }

        if release_failures.is_empty() {
            return Ok(());
        }
        Err(ReservationReleaseFailure {
            reservations: serde_json::json!({ "chio_runtime": failed_runtime }),
            reason: format!(
                "runtime admission reservation release failures: {}",
                release_failures.join("; ")
            ),
        })
    }

    fn denial_metadata_after_release(
        &self,
        metadata: serde_json::Value,
        reservations: &serde_json::Value,
    ) -> serde_json::Value {
        match self.release_reservations(reservations) {
            Ok(()) => metadata,
            Err(failure) => release_failure_metadata(metadata, &failure.reservations, &failure),
        }
    }
}

impl<S> RuntimeAdmissionHook for ChioRuntimeAdmissionHook<S>
where
    S: RuntimeAdmissionStore + Send + Sync,
{
    fn name(&self) -> &str {
        "chio-runtime-admission"
    }

    fn evaluate(
        &self,
        context: &KernelRuntimeAdmissionContext<'_>,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        let admission_ref = match admission_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(_) if !request_has_chio_runtime_context(context.request) => {
                if context.request.federated_origin_kernel_id.is_some() {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime admission context missing",
                        Some(runtime_context_denial_metadata(
                            "missing_chio_treaty_context",
                        )),
                    ));
                }
                return Ok(KernelRuntimeAdmissionDecision::allow(None));
            }
            Err(code) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission reference missing or invalid",
                    Some(runtime_context_denial_metadata(code)),
                ));
            }
        };
        let binding = match RuntimeRequestBinding::from_tool_call_request(
            context.request,
            &context.local_kernel_id,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission request binding failed",
                    Some(runtime_denial_metadata(
                        &admission_ref.admission_id,
                        error.code(),
                    )),
                ));
            }
        };
        let _preloaded_bundle = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.store.bundle(&admission_ref.admission_id)
        })) {
            Ok(Ok(Some(bundle))) => {
                if let Some(expected_hash) = admission_ref.bundle_sha256.as_deref() {
                    let actual = runtime_admission_bundle_sha256(&bundle)
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                    if actual != expected_hash {
                        return Ok(KernelRuntimeAdmissionDecision::deny(
                            "chio runtime admission bundle hash mismatch",
                            Some(runtime_denial_metadata(
                                &admission_ref.admission_id,
                                "admission_bundle_hash_mismatch",
                            )),
                        ));
                    }
                }
                Some(bundle)
            }
            Ok(Ok(None)) => None,
            Ok(Err(error)) => return Err(KernelError::Internal(error.to_string())),
            Err(_) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission bundle lookup panicked",
                    Some(runtime_denial_metadata(
                        &admission_ref.admission_id,
                        "admission_bundle_store_error",
                    )),
                ));
            }
        };
        let admission_now_unix_ms = self.fixed_now_unix_ms.unwrap_or(context.now_unix_ms);
        let mut treaty_continuation_id_to_consume = None;
        let mut swarm_continuation_id_to_consume = None;
        let mut verified_swarm_route_metadata = None;
        let mut federation_treaty_material = None;
        let mut runtime_action_class_id = None;
        let swarm_reference = match swarm_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(code) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chio swarm-bound runtime admission reference invalid",
                    Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                ));
            }
        };
        if let Some(reference) = swarm_reference.as_ref() {
            match verify_swarm_authority_reference_from_store(
                &self.store,
                reference,
                &self.swarm_witness_keys,
                context.extra_metadata,
                admission_now_unix_ms,
            ) {
                Ok(verified) => {
                    swarm_continuation_id_to_consume = verified.continuation_id_to_consume;
                    verified_swarm_route_metadata = Some(verified.route_metadata);
                }
                Err(ChioRuntimeError::Rejected { code, .. }) => {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio swarm-bound runtime admission denied",
                        Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                    ));
                }
                Err(error) => return Err(KernelError::Internal(error.to_string())),
            }
        }
        match treaty_ref_from_request(context.request) {
            Ok(Some(treaty_ref)) => {
                runtime_action_class_id = Some(treaty_ref.action_class_id.clone());
                match verify_treaty_reference_from_store(
                    &self.store,
                    &admission_ref.admission_id,
                    &treaty_ref,
                    context.request,
                    admission_now_unix_ms,
                ) {
                    Ok(verified) => {
                        treaty_continuation_id_to_consume = verified.continuation_id;
                        federation_treaty_material = verified.federation_treaty_material;
                    }
                    Err(ChioRuntimeError::Rejected { code, .. }) => {
                        return Ok(KernelRuntimeAdmissionDecision::deny(
                            "chio treaty-bound runtime admission denied",
                            Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                        ));
                    }
                    Err(error) => return Err(KernelError::Internal(error.to_string())),
                }
            }
            Ok(None) => {
                if context.request.federated_origin_kernel_id.is_some() {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime admission context missing",
                        Some(runtime_denial_metadata(
                            &admission_ref.admission_id,
                            "missing_chio_treaty_context",
                        )),
                    ));
                }
            }
            Err(code) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chio treaty-bound runtime admission reference invalid",
                    Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                ));
            }
        }
        if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.store
                    .consume_treaty_continuation(continuation_id, &admission_ref.admission_id)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(ChioRuntimeError::Rejected { code, .. })) => {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime continuation replay denied",
                        Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                    ));
                }
                Ok(Err(error)) => {
                    let metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(
                            &admission_ref.admission_id,
                            "treaty_continuation_consume_error",
                        ),
                        "ambiguous_treaty_continuation_id",
                        continuation_id,
                        &error.to_string(),
                    );
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        format!("chio treaty-bound runtime continuation failed: {error}"),
                        Some(metadata),
                    ));
                }
                Err(_) => {
                    let metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(
                            &admission_ref.admission_id,
                            "treaty_continuation_consume_error",
                        ),
                        "ambiguous_treaty_continuation_id",
                        continuation_id,
                        "treaty continuation consume callback panicked",
                    );
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime continuation callback panicked",
                        Some(metadata),
                    ));
                }
            }
        }
        if let Some(continuation_id) = swarm_continuation_id_to_consume.as_deref() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.store
                    .consume_swarm_continuation(continuation_id, &admission_ref.admission_id)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(ChioRuntimeError::Rejected { code, .. })) => {
                    let reservations = continuation_reservation_metadata(
                        &admission_ref.admission_id,
                        None,
                        treaty_continuation_id_to_consume.as_deref(),
                        None,
                    );
                    let metadata = self.denial_metadata_after_release(
                        runtime_denial_metadata(&admission_ref.admission_id, code),
                        &reservations,
                    );
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio swarm-bound runtime continuation replay denied",
                        Some(metadata),
                    ));
                }
                Ok(Err(error)) => {
                    let reservations = continuation_reservation_metadata(
                        &admission_ref.admission_id,
                        None,
                        treaty_continuation_id_to_consume.as_deref(),
                        None,
                    );
                    let base_metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(
                            &admission_ref.admission_id,
                            "swarm_continuation_consume_error",
                        ),
                        "ambiguous_swarm_continuation_id",
                        continuation_id,
                        &error.to_string(),
                    );
                    let metadata = self.denial_metadata_after_release(base_metadata, &reservations);
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        format!("chio swarm-bound runtime continuation failed: {error}"),
                        Some(metadata),
                    ));
                }
                Err(_) => {
                    let reservations = continuation_reservation_metadata(
                        &admission_ref.admission_id,
                        None,
                        treaty_continuation_id_to_consume.as_deref(),
                        None,
                    );
                    let base_metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(
                            &admission_ref.admission_id,
                            "swarm_continuation_consume_error",
                        ),
                        "ambiguous_swarm_continuation_id",
                        continuation_id,
                        "swarm continuation consume callback panicked",
                    );
                    let metadata = self.denial_metadata_after_release(base_metadata, &reservations);
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio swarm-bound runtime continuation callback panicked",
                        Some(metadata),
                    ));
                }
            }
        }
        let reservation_tracker = RuntimeAdmissionReservationTracker::default();
        let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluate_runtime_admission_tracked(
                RuntimeAdmissionInput {
                    profile: &self.profile,
                    store: &self.store,
                    admission_id: &admission_ref.admission_id,
                    request: &binding,
                    action_class_id: runtime_action_class_id.as_deref(),
                    runtime_trust_input: self.runtime_trust_input.as_ref(),
                    trusted_verifier_keys: &self.trusted_verifier_keys,
                    pheromone_query_report: self.pheromone_query_report.as_ref(),
                    runtime_pheromone_policy: self.runtime_pheromone_policy.as_ref(),
                    runtime_peer_weights: self.runtime_peer_weights.as_ref(),
                    now_unix_ms: admission_now_unix_ms,
                },
                Some(&reservation_tracker),
            )
        })) {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                let reservations = continuation_reservation_metadata(
                    &admission_ref.admission_id,
                    None,
                    treaty_continuation_id_to_consume.as_deref(),
                    swarm_continuation_id_to_consume.as_deref(),
                );
                let metadata = self.denial_metadata_after_release(
                    runtime_denial_metadata(
                        &admission_ref.admission_id,
                        "runtime_admission_evaluation_error",
                    ),
                    &reservations,
                );
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    format!("chio runtime admission evaluation failed: {error}"),
                    Some(metadata),
                ));
            }
            Err(_) => {
                let destructive_lease_id = reservation_tracker.destructive_lease_id();
                let reservations = continuation_reservation_metadata(
                    &admission_ref.admission_id,
                    destructive_lease_id.as_deref(),
                    treaty_continuation_id_to_consume.as_deref(),
                    swarm_continuation_id_to_consume.as_deref(),
                );
                let metadata = self.denial_metadata_after_release(
                    runtime_denial_metadata(
                        &admission_ref.admission_id,
                        "runtime_admission_evaluation_error",
                    ),
                    &reservations,
                );
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission evaluation panicked",
                    Some(metadata),
                ));
            }
        };
        if report.accepted {
            let mut metadata = report.receipt_metadata;
            let runtime_metadata_key = "chio_runtime";
            if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                metadata[runtime_metadata_key]["reserved_treaty_continuation_id"] =
                    serde_json::json!(continuation_id);
            }
            if let Some(continuation_id) = swarm_continuation_id_to_consume.as_deref() {
                metadata[runtime_metadata_key]["reserved_swarm_continuation_id"] =
                    serde_json::json!(continuation_id);
            }
            if let Some(route_metadata) = verified_swarm_route_metadata {
                metadata[runtime_metadata_key]["verified_swarm_route_metadata"] = route_metadata;
            }
            if let Some(material) = federation_treaty_material {
                return Ok(
                    KernelRuntimeAdmissionDecision::allow_with_verified_treaty_material(
                        Some(metadata),
                        material,
                    ),
                );
            }
            Ok(KernelRuntimeAdmissionDecision::allow(Some(metadata)))
        } else {
            // A failed release has ambiguous effects. Retrying it could erase
            // a marker reacquired after the callback returned.
            let release_previously_failed = report
                .receipt_metadata
                .get("chio_runtime")
                .and_then(|runtime| runtime.get("reservation_release_failed"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let destructive_lease_id = (!release_previously_failed)
                .then(|| {
                    report
                        .receipt_metadata
                        .get("chio_runtime")
                        .and_then(|runtime| runtime.get("reserved_destructive_lease_id"))
                        .and_then(serde_json::Value::as_str)
                })
                .flatten();
            let reservations = continuation_reservation_metadata(
                &admission_ref.admission_id,
                destructive_lease_id,
                treaty_continuation_id_to_consume.as_deref(),
                swarm_continuation_id_to_consume.as_deref(),
            );
            let metadata = match self.release_reservations(&reservations) {
                Ok(()) => {
                    strip_released_reservation_metadata(report.receipt_metadata, &reservations)
                }
                Err(failure) => release_failure_metadata(
                    report.receipt_metadata,
                    &failure.reservations,
                    &failure,
                ),
            };
            Ok(KernelRuntimeAdmissionDecision::deny(
                "chio runtime admission denied",
                Some(metadata),
            ))
        }
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.release_reservations(metadata)
            .map_err(|failure| KernelError::Internal(failure.reason))
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(
        &self,
        context: &KernelRuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        self.revalidate_admitted_request(context)
    }
}
