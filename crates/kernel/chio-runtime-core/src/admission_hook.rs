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

use metadata::{runtime_context_denial_metadata, runtime_denial_metadata};
use request::{admission_ref_from_request, request_has_chio_runtime_context};
use swarm_authority::verify_swarm_authority_reference_from_store;
use swarm_ref::swarm_ref_from_request;
use treaty_evidence::verify_treaty_reference_from_store;
use treaty_ref::treaty_ref_from_request;

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
        if let Some(expected_hash) = admission_ref.bundle_sha256.as_deref() {
            match self.store.bundle(&admission_ref.admission_id) {
                Ok(Some(bundle)) => match runtime_admission_bundle_sha256(&bundle) {
                    Ok(actual) if actual == expected_hash => {}
                    Ok(_) => {
                        return Ok(KernelRuntimeAdmissionDecision::deny(
                            "chio runtime admission bundle hash mismatch",
                            Some(runtime_denial_metadata(
                                &admission_ref.admission_id,
                                "admission_bundle_hash_mismatch",
                            )),
                        ));
                    }
                    Err(error) => {
                        return Err(KernelError::Internal(error.to_string()));
                    }
                },
                Ok(None) => {}
                Err(error) => return Err(KernelError::Internal(error.to_string())),
            }
        }
        let admission_now_unix_ms = self.fixed_now_unix_ms.unwrap_or(context.now_unix_ms);
        let mut treaty_continuation_id_to_consume = None;
        let mut swarm_continuation_id_to_consume = None;
        let mut federation_treaty_dsse = None;
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
                    admission_now_unix_ms,
                ) {
                    Ok(verified) => {
                        treaty_continuation_id_to_consume = verified.continuation_id;
                        federation_treaty_dsse = verified.federation_treaty_dsse;
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
            match self
                .store
                .consume_treaty_continuation(continuation_id, &admission_ref.admission_id)
            {
                Ok(()) => {}
                Err(ChioRuntimeError::Rejected { code, .. }) => {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime continuation replay denied",
                        Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                    ));
                }
                Err(error) => return Err(KernelError::Internal(error.to_string())),
            }
        }
        if let Some(continuation_id) = swarm_continuation_id_to_consume.as_deref() {
            match self
                .store
                .consume_swarm_continuation(continuation_id, &admission_ref.admission_id)
            {
                Ok(()) => {}
                Err(ChioRuntimeError::Rejected { code, .. }) => {
                    if let Some(treaty_continuation_id) =
                        treaty_continuation_id_to_consume.as_deref()
                    {
                        self.store
                            .release_treaty_continuation(
                                treaty_continuation_id,
                                &admission_ref.admission_id,
                            )
                            .map_err(|error| KernelError::Internal(error.to_string()))?;
                    }
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio swarm-bound runtime continuation replay denied",
                        Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                    ));
                }
                Err(error) => {
                    if let Some(treaty_continuation_id) =
                        treaty_continuation_id_to_consume.as_deref()
                    {
                        self.store
                            .release_treaty_continuation(
                                treaty_continuation_id,
                                &admission_ref.admission_id,
                            )
                            .map_err(|release_error| {
                                KernelError::Internal(release_error.to_string())
                            })?;
                    }
                    return Err(KernelError::Internal(error.to_string()));
                }
            }
        }
        let report = match evaluate_runtime_admission(RuntimeAdmissionInput {
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
        }) {
            Ok(report) => report,
            Err(error) => {
                if let Some(continuation_id) = swarm_continuation_id_to_consume.as_deref() {
                    self.store
                        .release_swarm_continuation(continuation_id, &admission_ref.admission_id)
                        .map_err(|release_error| {
                            KernelError::Internal(release_error.to_string())
                        })?;
                }
                if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                    self.store
                        .release_treaty_continuation(continuation_id, &admission_ref.admission_id)
                        .map_err(|release_error| {
                            KernelError::Internal(release_error.to_string())
                        })?;
                }
                return Err(KernelError::Internal(error.to_string()));
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
            if let Some(treaty_dsse) = federation_treaty_dsse {
                metadata[runtime_metadata_key]["federation_treaty_dsse"] = treaty_dsse;
            }
            Ok(KernelRuntimeAdmissionDecision::allow(Some(metadata)))
        } else {
            if let Some(continuation_id) = swarm_continuation_id_to_consume.as_deref() {
                self.store
                    .release_swarm_continuation(continuation_id, &admission_ref.admission_id)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
            if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                self.store
                    .release_treaty_continuation(continuation_id, &admission_ref.admission_id)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
            Ok(KernelRuntimeAdmissionDecision::deny(
                "chio runtime admission denied",
                Some(report.receipt_metadata),
            ))
        }
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
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
        if let Some(lease_id) = runtime
            .get("reserved_destructive_lease_id")
            .and_then(serde_json::Value::as_str)
        {
            self.store
                .release_destructive_lease(lease_id, admission_id)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
        }
        if let Some(continuation_id) = runtime
            .get("reserved_treaty_continuation_id")
            .and_then(serde_json::Value::as_str)
        {
            self.store
                .release_treaty_continuation(continuation_id, admission_id)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
        }
        if let Some(continuation_id) = runtime
            .get("reserved_swarm_continuation_id")
            .and_then(serde_json::Value::as_str)
        {
            self.store
                .release_swarm_continuation(continuation_id, admission_id)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
        }
        Ok(())
    }
}
