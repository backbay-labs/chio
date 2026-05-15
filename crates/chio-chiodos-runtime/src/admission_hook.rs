use crate::*;

#[derive(Debug, Clone)]
pub struct ChiodosRuntimeAdmissionHook<S> {
    profile: RuntimeAdmissionProfile,
    store: S,
    runtime_trust_input: Option<SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    pheromone_query_report: Option<SignedRuntimePheromoneQueryReport>,
    runtime_pheromone_policy: Option<SignedRuntimePheromonePolicy>,
    runtime_peer_weights: Option<SignedRuntimePeerWeights>,
    fixed_now_unix_ms: Option<u64>,
}

impl<S> ChiodosRuntimeAdmissionHook<S> {
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
    pub fn with_fixed_now_unix_ms(mut self, now_unix_ms: u64) -> Self {
        self.fixed_now_unix_ms = Some(now_unix_ms);
        self
    }
}

impl<S> RuntimeAdmissionHook for ChiodosRuntimeAdmissionHook<S>
where
    S: RuntimeAdmissionStore + Send + Sync,
{
    fn name(&self) -> &str {
        "chiodos-runtime-admission"
    }

    fn evaluate(
        &self,
        context: &KernelRuntimeAdmissionContext<'_>,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        let admission_ref = match admission_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(_) if !request_has_chiodos_runtime_context(context.request) => {
                return Ok(KernelRuntimeAdmissionDecision::allow(None));
            }
            Err(code) => {
                let metadata = serde_json::json!({
                    "chiodos_runtime": {
                        "accepted": false,
                        "failure_code": code
                    }
                });
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chiodos runtime admission reference missing or invalid",
                    Some(metadata),
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
                    "chiodos runtime admission request binding failed",
                    Some(serde_json::json!({
                        "chiodos_runtime": {
                            "admission_id": admission_ref.admission_id,
                            "accepted": false,
                            "failure_code": error.code()
                        }
                    })),
                ));
            }
        };
        if let Some(expected_hash) = admission_ref.bundle_sha256.as_deref() {
            match self.store.bundle(&admission_ref.admission_id) {
                Ok(Some(bundle)) => match runtime_admission_bundle_sha256(&bundle) {
                    Ok(actual) if actual == expected_hash => {}
                    Ok(_) => {
                        return Ok(KernelRuntimeAdmissionDecision::deny(
                            "chiodos runtime admission bundle hash mismatch",
                            Some(serde_json::json!({
                                "chiodos_runtime": {
                                    "admission_id": admission_ref.admission_id,
                                    "accepted": false,
                                    "failure_code": "admission_bundle_hash_mismatch"
                                }
                            })),
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
        let mut runtime_action_class_id = None;
        match treaty_ref_from_request(context.request) {
            Ok(Some(treaty_ref)) => {
                runtime_action_class_id = Some(treaty_ref.action_class_id.clone());
                match verify_treaty_reference_from_store(
                    &self.store,
                    &admission_ref.admission_id,
                    &treaty_ref,
                    admission_now_unix_ms,
                ) {
                    Ok(continuation_id) => {
                        treaty_continuation_id_to_consume = continuation_id;
                    }
                    Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                        return Ok(KernelRuntimeAdmissionDecision::deny(
                            "chiodos treaty-bound runtime admission denied",
                            Some(serde_json::json!({
                                "chiodos_runtime": {
                                    "admission_id": admission_ref.admission_id,
                                    "accepted": false,
                                    "failure_code": code
                                }
                            })),
                        ));
                    }
                    Err(error) => return Err(KernelError::Internal(error.to_string())),
                }
            }
            Ok(None) => {
                if context.request.federated_origin_kernel_id.is_some() {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chiodos treaty-bound runtime admission context missing",
                        Some(serde_json::json!({
                            "chiodos_runtime": {
                                "admission_id": admission_ref.admission_id,
                                "accepted": false,
                                "failure_code": "missing_chiodos_treaty_context"
                            }
                        })),
                    ));
                }
            }
            Err(code) => {
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chiodos treaty-bound runtime admission reference invalid",
                    Some(serde_json::json!({
                        "chiodos_runtime": {
                            "admission_id": admission_ref.admission_id,
                            "accepted": false,
                            "failure_code": code
                        }
                    })),
                ));
            }
        }
        if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
            match self
                .store
                .consume_treaty_continuation(continuation_id, &admission_ref.admission_id)
            {
                Ok(()) => {}
                Err(ChiodosRuntimeError::Rejected { code, .. }) => {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chiodos treaty-bound runtime continuation replay denied",
                        Some(serde_json::json!({
                            "chiodos_runtime": {
                                "admission_id": admission_ref.admission_id,
                                "accepted": false,
                                "failure_code": code
                            }
                        })),
                    ));
                }
                Err(error) => return Err(KernelError::Internal(error.to_string())),
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
            if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                metadata["chiodos_runtime"]["reserved_treaty_continuation_id"] =
                    serde_json::json!(continuation_id);
            }
            Ok(KernelRuntimeAdmissionDecision::allow(Some(metadata)))
        } else {
            if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                self.store
                    .release_treaty_continuation(continuation_id, &admission_ref.admission_id)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
            Ok(KernelRuntimeAdmissionDecision::deny(
                "chiodos runtime admission denied",
                Some(report.receipt_metadata),
            ))
        }
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        let Some(runtime) = metadata
            .get("chiodos_runtime")
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
        Ok(())
    }
}

impl RuntimeRequestBinding {
    pub fn from_tool_call_request(
        request: &ToolCallRequest,
        host_kernel_id: &str,
    ) -> Result<Self, ChiodosRuntimeError> {
        Ok(Self {
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            tool_args_sha256: tool_args_sha256(&request.arguments)?,
            origin_kernel_id: request.federated_origin_kernel_id.clone(),
            host_kernel_id: host_kernel_id.to_string(),
        })
    }
}

struct AdmissionReference {
    admission_id: String,
    bundle_sha256: Option<String>,
}

struct TreatyReference {
    treaty_scope_id: String,
    treaty_scope_sha256: String,
    ladder_intersection_id: String,
    ladder_intersection_sha256: String,
    action_class_id: String,
    continuation: Option<TreatyEvidenceReference>,
    lineage_bundle: Option<TreatyEvidenceReference>,
    bilateral_dsse: Option<TreatyEvidenceReference>,
    bilateral_invocation: Option<TreatyEvidenceReference>,
}

#[derive(Debug, Clone)]
struct TreatyEvidenceReference {
    evidence_id: String,
    artifact_sha256: String,
}

fn admission_ref_from_request(
    request: &ToolCallRequest,
) -> Result<AdmissionReference, &'static str> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Err("missing_governed_intent");
    };
    let Some(context) = intent.context.as_ref() else {
        return Err("missing_chiodos_admission_context");
    };
    let Some(admission) = context.get("chiodosAdmission") else {
        return Err("missing_chiodos_admission_context");
    };
    let Some(object) = admission.as_object() else {
        return Err("invalid_chiodos_admission_context");
    };
    let Some(admission_id) = object.get("admissionId").and_then(|value| value.as_str()) else {
        return Err("missing_admission_id");
    };
    if admission_id.trim().is_empty() {
        return Err("missing_admission_id");
    }
    let bundle_sha256 = object
        .get("bundleSha256")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    Ok(AdmissionReference {
        admission_id: admission_id.to_string(),
        bundle_sha256,
    })
}

fn request_has_chiodos_runtime_context(request: &ToolCallRequest) -> bool {
    request
        .governed_intent
        .as_ref()
        .and_then(|intent| intent.context.as_ref())
        .and_then(serde_json::Value::as_object)
        .is_some_and(|context| {
            context.contains_key("chiodosAdmission") || context.contains_key("chiodosTreaty")
        })
}

fn treaty_ref_from_request(
    request: &ToolCallRequest,
) -> Result<Option<TreatyReference>, &'static str> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Ok(None);
    };
    let Some(context) = intent.context.as_ref() else {
        return Ok(None);
    };
    let Some(treaty) = context.get("chiodosTreaty") else {
        return Ok(None);
    };
    let Some(object) = treaty.as_object() else {
        return Err("invalid_chiodos_treaty_context");
    };
    for forbidden in [
        "trustRoot",
        "trustRoots",
        "trustBundle",
        "treatyScope",
        "ladderManifest",
        "signingKey",
        "peerDirectory",
    ] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_trust_root");
        }
    }
    for forbidden in [
        "dynamicTrust",
        "dynamicTrustBundle",
        "runtimeTrustInput",
        "peerDiscovery",
    ] {
        if object.contains_key(forbidden) {
            return Err("request_smuggled_dynamic_trust");
        }
    }
    let Some(treaty_scope_id) = object.get("treatyScopeId").and_then(|value| value.as_str()) else {
        return Err("missing_treaty_scope_id");
    };
    let Some(treaty_scope_sha256) = object
        .get("treatyScopeSha256")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_treaty_scope_hash");
    };
    let Some(ladder_intersection_id) = object
        .get("ladderIntersectionId")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_ladder_intersection_id");
    };
    let Some(ladder_intersection_sha256) = object
        .get("ladderIntersectionSha256")
        .and_then(|value| value.as_str())
    else {
        return Err("missing_ladder_intersection_hash");
    };
    let Some(action_class_id) = object.get("actionClassId").and_then(|value| value.as_str()) else {
        return Err("missing_action_class_id");
    };
    if treaty_scope_id.trim().is_empty()
        || ladder_intersection_id.trim().is_empty()
        || action_class_id.trim().is_empty()
    {
        return Err("invalid_chiodos_treaty_context");
    }
    if !is_sha256_hex(treaty_scope_sha256) || !is_sha256_hex(ladder_intersection_sha256) {
        return Err("invalid_chiodos_treaty_hash");
    }
    let continuation = treaty_evidence_ref_from_context(
        object,
        &["crossKernelContinuation", "continuation"],
        &["continuationId"],
        &["continuationSha256"],
    )?;
    let lineage_bundle = treaty_evidence_ref_from_context(
        object,
        &["receiptLineageBundle", "lineageBundle"],
        &["receiptLineageBundleId", "lineageBundleId"],
        &["receiptLineageBundleSha256", "lineageBundleSha256"],
    )?;
    let bilateral_dsse = treaty_evidence_ref_from_context(
        object,
        &["bilateralDsse", "bilateralDsseEnvelope"],
        &["bilateralDsseId", "bilateralDsseEnvelopeId"],
        &["bilateralDsseSha256", "bilateralDsseEnvelopeSha256"],
    )?;
    let bilateral_invocation = treaty_evidence_ref_from_context(
        object,
        &["bilateralInvocation"],
        &["bilateralInvocationId"],
        &["bilateralInvocationSha256"],
    )?;
    Ok(Some(TreatyReference {
        treaty_scope_id: treaty_scope_id.to_string(),
        treaty_scope_sha256: treaty_scope_sha256.to_string(),
        ladder_intersection_id: ladder_intersection_id.to_string(),
        ladder_intersection_sha256: ladder_intersection_sha256.to_string(),
        action_class_id: action_class_id.to_string(),
        continuation,
        lineage_bundle,
        bilateral_dsse,
        bilateral_invocation,
    }))
}

fn treaty_evidence_ref_from_context(
    object: &serde_json::Map<String, serde_json::Value>,
    object_fields: &[&str],
    id_fields: &[&str],
    hash_fields: &[&str],
) -> Result<Option<TreatyEvidenceReference>, &'static str> {
    for field in object_fields {
        if let Some(value) = object.get(*field) {
            let Some(ref_object) = value.as_object() else {
                return Err("invalid_chiodos_treaty_evidence_ref");
            };
            let evidence_id = ref_object
                .get("id")
                .or_else(|| ref_object.get("evidenceId"))
                .or_else(|| ref_object.get("artifactId"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chiodos_treaty_evidence_ref")?;
            let artifact_sha256 = ref_object
                .get("sha256")
                .or_else(|| ref_object.get("artifactSha256"))
                .and_then(|value| value.as_str())
                .ok_or("missing_chiodos_treaty_evidence_ref")?;
            return treaty_evidence_ref(evidence_id, artifact_sha256);
        }
    }

    let evidence_id = id_fields
        .iter()
        .find_map(|field| object.get(*field).and_then(|value| value.as_str()));
    let artifact_sha256 = hash_fields
        .iter()
        .find_map(|field| object.get(*field).and_then(|value| value.as_str()));
    match (evidence_id, artifact_sha256) {
        (Some(evidence_id), Some(artifact_sha256)) => {
            treaty_evidence_ref(evidence_id, artifact_sha256)
        }
        (None, None) => Ok(None),
        _ => Err("missing_chiodos_treaty_evidence_ref"),
    }
}

fn treaty_evidence_ref(
    evidence_id: &str,
    artifact_sha256: &str,
) -> Result<Option<TreatyEvidenceReference>, &'static str> {
    if evidence_id.trim().is_empty() || !is_sha256_hex(artifact_sha256) {
        return Err("invalid_chiodos_treaty_evidence_ref");
    }
    Ok(Some(TreatyEvidenceReference {
        evidence_id: evidence_id.to_string(),
        artifact_sha256: artifact_sha256.to_string(),
    }))
}

fn verify_treaty_reference_from_store<S: RuntimeAdmissionStore>(
    store: &S,
    admission_id: &str,
    treaty_ref: &TreatyReference,
    now_unix_ms: u64,
) -> Result<Option<String>, ChiodosRuntimeError> {
    let Some(bundle) = store.bundle(admission_id)? else {
        return rejected(
            "missing_admission_bundle",
            "cross-boundary request referenced an admission bundle that is not in the verifier-owned store",
        );
    };
    let Some(treaty_scope_record) =
        store.treaty_runtime_artifact("treaty_scope", &treaty_ref.treaty_scope_id)?
    else {
        return rejected(
            "chiodos_treaty_missing_scope",
            "cross-boundary request referenced a treaty scope that is not in the verifier-owned store",
        );
    };
    if treaty_scope_record.artifact_sha256 != treaty_ref.treaty_scope_sha256 {
        return rejected(
            "chiodos_treaty_scope_hash_mismatch",
            "cross-boundary request treaty scope hash does not match verifier-owned store",
        );
    }
    let treaty_scope: TreatyScope = serde_json::from_value(treaty_scope_record.raw_json)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    if treaty_scope.trust_bundle_sha256 != bundle.trust_bundle_sha256 {
        return rejected(
            "chiodos_treaty_scope_hash_mismatch",
            "treaty scope trust bundle hash does not match the verifier-owned admission bundle",
        );
    }

    let Some(intersection_record) =
        store.treaty_runtime_artifact("ladder_intersection", &treaty_ref.ladder_intersection_id)?
    else {
        return rejected(
            "chiodos_treaty_missing_intersection",
            "cross-boundary request referenced a ladder intersection that is not in the verifier-owned store",
        );
    };
    if intersection_record.artifact_sha256 != treaty_ref.ladder_intersection_sha256 {
        return rejected(
            "chiodos_treaty_intersection_mismatch",
            "cross-boundary request ladder intersection hash does not match verifier-owned store",
        );
    }
    let ladder_intersection: LadderIntersection =
        serde_json::from_value(intersection_record.raw_json)
            .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    let action = ladder_intersection
        .action_classes
        .iter()
        .find(|action| action.action_class_id == treaty_ref.action_class_id);
    let requires_lineage = action.is_some_and(|action| {
        action
            .evidence_required
            .iter()
            .any(|evidence| evidence == "receipt_lineage")
    });
    let requires_bilateral = action.is_some_and(|action| {
        action
            .evidence_required
            .iter()
            .any(|evidence| evidence == "bilateral_invocation")
    });

    let continuation = treaty_ref
        .continuation
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, CrossKernelContinuation>(
                store,
                "cross_kernel_continuation",
                reference,
                "chiodos_treaty_missing_continuation",
                "chiodos_treaty_continuation_hash_mismatch",
            )
        })
        .transpose()?;
    let lineage_bundle = treaty_ref
        .lineage_bundle
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, ReceiptLineageBundle>(
                store,
                "receipt_lineage_bundle",
                reference,
                "chiodos_treaty_missing_required_evidence",
                "chiodos_treaty_lineage_hash_mismatch",
            )
        })
        .transpose()?;
    let bilateral_invocation = treaty_ref
        .bilateral_invocation
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, BilateralInvocation>(
                store,
                "bilateral_invocation",
                reference,
                "chiodos_treaty_missing_bilateral_evidence",
                "chiodos_treaty_bilateral_hash_mismatch",
            )
        })
        .transpose()?;
    let bilateral_dsse = treaty_ref
        .bilateral_dsse
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, chio_federation::DsseEnvelope>(
                store,
                "bilateral_dsse_envelope",
                reference,
                "chiodos_treaty_missing_bilateral_evidence",
                "chiodos_treaty_bilateral_hash_mismatch",
            )
        })
        .transpose()?;

    let mut present_evidence = Vec::new();
    let mut verified_evidence = Vec::new();
    let mut bilateral_invocation_sha256 = None;
    if let Some((continuation, continuation_sha256)) = continuation.as_ref() {
        verify_continuation_evidence(
            continuation,
            &treaty_scope,
            &bundle.binding,
            &treaty_ref.action_class_id,
            now_unix_ms,
        )?;
        if let Some((lineage_bundle, _lineage_bundle_sha256)) = lineage_bundle.as_ref() {
            let lineage_statement_sha256 =
                verify_lineage_bundle_evidence(lineage_bundle, continuation, continuation_sha256)?;
            present_evidence.push("receipt_lineage".to_string());
            verified_evidence.push(CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: lineage_statement_sha256,
                verified: true,
            });
        }
        if let Some((invocation, _invocation_sha256)) = bilateral_invocation.as_ref() {
            let consistency_model = action
                .map(|action| action.consistency_model.as_str())
                .unwrap_or("totally_ordered");
            let treaty_evidence = TreatyEvidenceReview {
                treaty_scope: &treaty_scope,
                bundle: &bundle,
                request: &bundle.binding,
                action_class_id: &treaty_ref.action_class_id,
                ladder_intersection_sha256: &treaty_ref.ladder_intersection_sha256,
                consistency_model,
                continuation_sha256,
            };
            let invocation_binding_sha256 = verify_bilateral_invocation_evidence(
                invocation,
                &treaty_evidence,
                lineage_bundle.as_ref().map(|(bundle, _)| bundle),
            )?;
            present_evidence.push("bilateral_invocation".to_string());
            bilateral_invocation_sha256 = Some(invocation_binding_sha256);
        }
        if let Some((envelope, _envelope_sha256)) = bilateral_dsse.as_ref() {
            let treaty_evidence = TreatyEvidenceReview {
                treaty_scope: &treaty_scope,
                bundle: &bundle,
                request: &bundle.binding,
                action_class_id: &treaty_ref.action_class_id,
                ladder_intersection_sha256: &treaty_ref.ladder_intersection_sha256,
                consistency_model: action
                    .map(|action| action.consistency_model.as_str())
                    .unwrap_or("totally_ordered"),
                continuation_sha256,
            };
            verify_treaty_dsse_evidence(
                envelope,
                &treaty_evidence,
                lineage_bundle.as_ref(),
                bilateral_invocation
                    .as_ref()
                    .map(|(invocation, _)| invocation),
            )?;
            if let Some(invocation_sha256) = bilateral_invocation_sha256.as_ref() {
                verified_evidence.push(CrossBoundaryEvidenceRef {
                    evidence_class: "bilateral_invocation".to_string(),
                    artifact_sha256: invocation_sha256.clone(),
                    verified: true,
                });
            }
        }
    } else if requires_lineage
        || requires_bilateral
        || treaty_ref.lineage_bundle.is_some()
        || treaty_ref.bilateral_invocation.is_some()
        || treaty_ref.bilateral_dsse.is_some()
    {
        return rejected(
            "chiodos_treaty_missing_continuation",
            "cross-boundary request did not reference a stored continuation",
        );
    }

    let report = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty_scope,
        ladder_intersection: &ladder_intersection,
        expected_ladder_intersection_sha256: Some(treaty_ref.ladder_intersection_sha256.clone()),
        action_class_id: &treaty_ref.action_class_id,
        present_evidence,
        verified_evidence,
        now_unix_ms,
    })?;
    if report.accepted {
        Ok(continuation
            .as_ref()
            .map(|(continuation, _)| continuation.continuation_id.clone()))
    } else {
        rejected(
            static_treaty_failure_code(report.failure_code.as_deref()),
            "cross-boundary treaty admission rejected",
        )
    }
}

fn load_treaty_artifact<S, T>(
    store: &S,
    evidence_kind: &str,
    reference: &TreatyEvidenceReference,
    missing_code: &'static str,
    mismatch_code: &'static str,
) -> Result<(T, String), ChiodosRuntimeError>
where
    S: RuntimeAdmissionStore,
    T: DeserializeOwned,
{
    let Some(record) = store.treaty_runtime_artifact(evidence_kind, &reference.evidence_id)? else {
        return rejected(
            missing_code,
            "cross-boundary request referenced treaty evidence that is not in the verifier-owned store",
        );
    };
    if record.artifact_sha256 != reference.artifact_sha256 {
        return rejected(
            mismatch_code,
            "cross-boundary request treaty evidence hash does not match verifier-owned store",
        );
    }
    let artifact_sha256 = record.artifact_sha256;
    let artifact: T = serde_json::from_value(record.raw_json)
        .map_err(|error| ChiodosRuntimeError::Json(error.to_string()))?;
    Ok((artifact, artifact_sha256))
}

fn verify_continuation_evidence(
    continuation: &CrossKernelContinuation,
    treaty_scope: &TreatyScope,
    request: &RuntimeRequestBinding,
    action_class_id: &str,
    now_unix_ms: u64,
) -> Result<(), ChiodosRuntimeError> {
    validate_cross_kernel_continuation(continuation)?;
    if now_unix_ms < continuation.issued_at_unix_ms
        || now_unix_ms >= continuation.expires_at_unix_ms
    {
        return rejected(
            "chiodos_treaty_continuation_stale",
            "cross-kernel continuation is outside its validity window",
        );
    }
    let audience = format!("{}.{}", request.server_id, request.tool_name);
    if continuation.capability_id != request.capability_id
        || continuation.action_class_id != action_class_id
        || continuation.target_kernel_id != request.host_kernel_id
        || request.origin_kernel_id.as_deref() != Some(continuation.source_kernel_id.as_str())
        || continuation.audience_tool != audience
        || !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|participant| participant == &continuation.source_kernel_id)
        || !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|participant| participant == &continuation.target_kernel_id)
    {
        return rejected(
            "chiodos_treaty_continuation_mismatch",
            "cross-kernel continuation does not bind the requested treaty dispatch",
        );
    }
    Ok(())
}

fn verify_lineage_bundle_evidence(
    bundle: &ReceiptLineageBundle,
    continuation: &CrossKernelContinuation,
    continuation_sha256: &str,
) -> Result<String, ChiodosRuntimeError> {
    verify_receipt_lineage_bundle(bundle)?;
    for statement in &bundle.statements {
        if statement.continuation_sha256 == continuation_sha256
            && statement.source_kernel_id == continuation.source_kernel_id
            && statement.target_kernel_id == continuation.target_kernel_id
            && statement.parent_receipt_sha256 == continuation.parent_receipt_sha256
        {
            return receipt_lineage_statement_sha256(statement);
        }
    }
    rejected(
        "chiodos_treaty_lineage_mismatch",
        "receipt lineage bundle does not bind the referenced continuation",
    )
}

struct TreatyEvidenceReview<'a> {
    treaty_scope: &'a TreatyScope,
    bundle: &'a RuntimeAdmissionBundle,
    request: &'a RuntimeRequestBinding,
    action_class_id: &'a str,
    ladder_intersection_sha256: &'a str,
    consistency_model: &'a str,
    continuation_sha256: &'a str,
}

fn verify_bilateral_invocation_evidence(
    invocation: &BilateralInvocation,
    review: &TreatyEvidenceReview<'_>,
    lineage_bundle: Option<&ReceiptLineageBundle>,
) -> Result<String, ChiodosRuntimeError> {
    validate_bilateral_invocation(invocation)?;
    if review.treaty_scope.participant_kernel_ids.len() != 2
        || invocation.signer_kernel_ids.len() != 2
    {
        return rejected(
            "chiodos_treaty_bilateral_mismatch",
            "bilateral invocation requires exactly two treaty participants and signers",
        );
    }
    if invocation.treaty_id != review.treaty_scope.treaty_id
        || invocation.ladder_intersection_sha256 != review.ladder_intersection_sha256
        || invocation.continuation_sha256 != review.continuation_sha256
        || invocation.action_class_id != review.action_class_id
        || invocation.consistency_model != review.consistency_model
        || invocation.capability_id != review.request.capability_id
        || invocation.request_sha256 != review.request.tool_args_sha256
    {
        return rejected(
            "chiodos_treaty_bilateral_mismatch",
            "bilateral invocation does not bind the requested treaty dispatch",
        );
    }
    let participants: BTreeSet<_> = review.treaty_scope.participant_kernel_ids.iter().collect();
    let signers: BTreeSet<_> = invocation.signer_kernel_ids.iter().collect();
    if participants != signers {
        return rejected(
            "chiodos_treaty_bilateral_mismatch",
            "bilateral invocation signer set does not match treaty participants",
        );
    }
    let invocation_sha256 = bilateral_invocation_binding_sha256(invocation)?;
    if let Some(bundle) = lineage_bundle {
        if invocation.local_receipt_sha256 != bundle.root_receipt_sha256
            || invocation.remote_receipt_sha256 != bundle.leaf_receipt_sha256
            || !bundle.statements.iter().any(|statement| {
                statement.bilateral_invocation_sha256 == invocation_sha256
                    && receipt_lineage_statement_sha256(statement)
                        .is_ok_and(|hash| hash == invocation.lineage_statement_sha256)
            })
        {
            return rejected(
                "chiodos_treaty_bilateral_mismatch",
                "bilateral invocation does not bind the receipt lineage bundle",
            );
        }
    }
    Ok(invocation_sha256)
}

fn verify_treaty_dsse_evidence(
    envelope: &chio_federation::DsseEnvelope,
    review: &TreatyEvidenceReview<'_>,
    lineage_bundle: Option<&(ReceiptLineageBundle, String)>,
    invocation: Option<&BilateralInvocation>,
) -> Result<(), ChiodosRuntimeError> {
    let Ok((statement, _)) = envelope.decode_statement() else {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE evidence could not be decoded",
        );
    };
    if statement.predicate_type != chio_federation::PREDICATE_TYPE_CHIODOS_BILATERAL {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is not a strict Chiodos predicate",
        );
    }
    let Some(treaty) = statement.predicate.treaty_binding_ref.as_ref() else {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is missing treaty binding refs",
        );
    };
    if treaty.treaty_id != review.treaty_scope.treaty_id
        || treaty.treaty_scope_sha256 != treaty_scope_sha256(review.treaty_scope)?
        || treaty.ladder_intersection_sha256 != review.ladder_intersection_sha256
        || treaty.continuation_sha256 != review.continuation_sha256
        || treaty.action_class_id != review.action_class_id
        || treaty.consistency_model != review.consistency_model
        || treaty.request_sha256 != review.request.tool_args_sha256
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE treaty binding does not match the requested dispatch",
        );
    }
    if statement
        .predicate
        .tool_args_hash
        .as_ref()
        .map(|hash| hash.value.as_str())
        != Some(treaty.request_sha256.as_str())
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE tool argument hash does not match the treaty request binding",
        );
    }
    if treaty.lease_refs != review.bundle.lease_id.iter().cloned().collect::<Vec<_>>() {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE lease refs do not match the verifier-owned admission bundle",
        );
    }
    if treaty.governance_refs
        != review
            .bundle
            .governance_receipt_id
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE governance refs do not match the verifier-owned admission bundle",
        );
    }
    let participants: BTreeSet<_> = review.treaty_scope.participant_kernel_ids.iter().collect();
    let signers: BTreeSet<_> = treaty.signer_kernel_ids.iter().collect();
    if review.treaty_scope.participant_kernel_ids.len() != 2 || treaty.signer_kernel_ids.len() != 2
    {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE evidence requires exactly two treaty participants and signers",
        );
    }
    if participants != signers {
        return rejected(
            "chiodos_treaty_dsse_binding_mismatch",
            "bilateral DSSE signer set does not match treaty participants",
        );
    }
    let signer_a_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[0])?;
    let signer_b_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[1])?;
    if signer_a_public_key == signer_b_public_key {
        return rejected(
            "chiodos_treaty_unverified_required_evidence",
            "bilateral DSSE signer public keys are not independent",
        );
    }
    chio_federation::verify_chiodos_dsse_envelope(
        envelope,
        signer_a_public_key,
        signer_b_public_key,
    )
    .map_err(|_| ChiodosRuntimeError::Rejected {
        code: "chiodos_treaty_unverified_required_evidence",
        detail: "bilateral DSSE signature verification failed".to_string(),
    })?;
    if let Some((bundle, bundle_sha256)) = lineage_bundle {
        if treaty.lineage_bundle_sha256 != bundle_sha256.as_str()
            || treaty.local_receipt_sha256 != bundle.root_receipt_sha256
            || treaty.remote_receipt_sha256 != bundle.leaf_receipt_sha256
        {
            return rejected(
                "chiodos_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match lineage bundle",
            );
        }
    }
    if let Some(invocation) = invocation {
        if treaty.consistency_model != invocation.consistency_model
            || treaty.outcome_sha256 != invocation.outcome_sha256
            || treaty.local_receipt_sha256 != invocation.local_receipt_sha256
            || treaty.remote_receipt_sha256 != invocation.remote_receipt_sha256
            || treaty.signer_kernel_ids != invocation.signer_kernel_ids
        {
            return rejected(
                "chiodos_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match bilateral invocation",
            );
        }
    }
    Ok(())
}

fn treaty_participant_public_key<'a>(
    treaty_scope: &'a TreatyScope,
    kernel_id: &str,
) -> Result<&'a PublicKey, ChiodosRuntimeError> {
    let Some(index) = treaty_scope
        .participant_kernel_ids
        .iter()
        .position(|participant| participant == kernel_id)
    else {
        return rejected(
            "chiodos_treaty_missing_participant",
            "treaty participant public key is missing",
        );
    };
    treaty_scope
        .participant_public_keys
        .get(index)
        .ok_or_else(|| ChiodosRuntimeError::Rejected {
            code: "chiodos_treaty_missing_participant",
            detail: "treaty participant public key is missing".to_string(),
        })
}

fn static_treaty_failure_code(code: Option<&str>) -> &'static str {
    match code {
        Some("chiodos_treaty_stale") => "chiodos_treaty_stale",
        Some("chiodos_treaty_intersection_mismatch") => "chiodos_treaty_intersection_mismatch",
        Some("chiodos_treaty_missing_intersection_binding") => {
            "chiodos_treaty_missing_intersection_binding"
        }
        Some("chiodos_treaty_action_class_not_allowed") => {
            "chiodos_treaty_action_class_not_allowed"
        }
        Some("chiodos_treaty_missing_required_evidence") => {
            "chiodos_treaty_missing_required_evidence"
        }
        Some("chiodos_treaty_unverified_required_evidence") => {
            "chiodos_treaty_unverified_required_evidence"
        }
        _ => "chiodos_treaty_unverified_required_evidence",
    }
}
