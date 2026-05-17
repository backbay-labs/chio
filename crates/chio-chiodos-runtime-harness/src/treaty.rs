use crate::evidence_io::canonical_sha256_json;
use crate::kernel::runtime_loopback_policy_summary;
use crate::scenario::RuntimeLoopbackStep;
use crate::RuntimeLoopbackError;

pub(crate) struct RuntimeLoopbackTreatyContext {
    pub(crate) treaty_scope: chio_chiodos_runtime::TreatyScope,
    pub(crate) treaty_scope_sha256: String,
    pub(crate) ladder_intersection: chio_chiodos_runtime::LadderIntersection,
    pub(crate) ladder_intersection_sha256: String,
    pub(crate) continuation: chio_chiodos_runtime::CrossKernelContinuation,
    pub(crate) continuation_sha256: String,
    pub(crate) lineage_bundle_id: String,
    pub(crate) intent_context: serde_json::Value,
}

pub(crate) fn insert_runtime_loopback_treaty_context(
    hook_store: &chio_chiodos_runtime::InMemoryRuntimeAdmissionStore,
    step_index: usize,
    step: &RuntimeLoopbackStep,
    vendor_key: &chio_core::Keypair,
    arguments: &serde_json::Value,
) -> Result<RuntimeLoopbackTreatyContext, RuntimeLoopbackError> {
    let source_kernel_id = step.request.origin_kernel_id.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chiodos runtime loopback treaty context requires an origin kernel",
        )
    })?;
    let target_kernel_id = step.request.host_kernel_id.clone();
    let action_class_id = format!("workflow.cross_kernel.{}", step.request.tool_name);
    let issued_at_unix_ms = 1_700_000_000_000_u64;
    let expires_at_unix_ms = 1_900_000_000_000_u64;
    let origin_key = chio_chiodos_loopback::runtime_buyer_keypair();
    let manifest_hashes = vec![
        chio_core::sha256_hex(format!("runtime-loopback:{source_kernel_id}:manifest").as_bytes()),
        chio_core::sha256_hex(format!("runtime-loopback:{target_kernel_id}:manifest").as_bytes()),
    ];
    let treaty_scope = chio_chiodos_runtime::TreatyScope {
        schema: chio_chiodos_runtime::CHIODOS_TREATY_SCOPE_SCHEMA.to_string(),
        treaty_id: format!("treaty:runtime-loopback:{step_index}"),
        participant_kernel_ids: vec![source_kernel_id.clone(), target_kernel_id.clone()],
        participant_public_keys: vec![origin_key.public_key(), vendor_key.public_key()],
        ladder_manifest_sha256s: manifest_hashes.clone(),
        allowed_action_classes: vec![action_class_id.clone()],
        issued_at_unix_ms,
        expires_at_unix_ms,
        revocation_epoch_sha256: chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:revocations").as_bytes(),
        ),
        trust_bundle_sha256: step.admission_bundle.trust_bundle_sha256.clone(),
    };
    let treaty_scope_sha256 =
        chio_chiodos_runtime::treaty_scope_sha256(&treaty_scope).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback treaty scope hash: {error}"
            ))
        })?;
    let mut participant_modes = std::collections::BTreeMap::new();
    participant_modes.insert(source_kernel_id.clone(), "receipt_backed".to_string());
    participant_modes.insert(target_kernel_id.clone(), "receipt_backed".to_string());
    let requires_bilateral =
        step.admission_bundle.destructive || step.admission_bundle.governance_receipt_id.is_some();
    let evidence_required = if requires_bilateral {
        vec![
            "receipt_lineage".to_string(),
            "bilateral_invocation".to_string(),
        ]
    } else {
        vec!["receipt_lineage".to_string()]
    };
    let ladder_intersection = chio_chiodos_runtime::LadderIntersection {
        schema: chio_chiodos_runtime::CHIODOS_LADDER_INTERSECTION_SCHEMA.to_string(),
        intersection_id: format!("intersection:runtime-loopback:{step_index}"),
        treaty_id: treaty_scope.treaty_id.clone(),
        participant_kernel_ids: treaty_scope.participant_kernel_ids.clone(),
        ladder_manifest_sha256s: manifest_hashes,
        generated_at_unix_ms: issued_at_unix_ms,
        expires_at_unix_ms,
        action_classes: vec![chio_chiodos_runtime::LadderIntersectionActionClass {
            action_class_id: action_class_id.clone(),
            mode: "receipt_backed".to_string(),
            destructive: step.admission_bundle.destructive,
            consistency_model: "totally_ordered".to_string(),
            co_sign: if requires_bilateral {
                "bilateral_required".to_string()
            } else {
                "none".to_string()
            },
            evidence_required,
            participant_modes,
        }],
    };
    let ladder_intersection_sha256 = chio_chiodos_runtime::ladder_intersection_sha256(
        &ladder_intersection,
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chiodos runtime loopback ladder intersection hash: {error}"
        ))
    })?;
    let parent_receipt_sha256 =
        chio_core::sha256_hex(format!("runtime-loopback:{step_index}:parent-receipt").as_bytes());
    let outcome_sha256 = chio_core::sha256_hex(
        format!("runtime-loopback:{step_index}:pre-dispatch-outcome").as_bytes(),
    );
    let action = chio_core::receipt::ToolCallAction::from_parameters(arguments.clone()).map_err(
        |error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback receipt action hash: {error}"
            ))
        },
    )?;
    let proof_receipt = chio_core::receipt::ChioReceipt::sign(
        chio_core::receipt::ChioReceiptBody {
            id: format!("runtime-loopback-receipt:{step_index}"),
            timestamp: issued_at_unix_ms / 1000,
            capability_id: step.request.capability_id.clone(),
            tool_server: step.request.server_id.clone(),
            tool_name: step.request.tool_name.clone(),
            action,
            decision: chio_core::receipt::Decision::Allow,
            content_hash: outcome_sha256.clone(),
            policy_hash: chio_core::sha256_hex(
                format!("runtime-loopback:{step_index}:policy").as_bytes(),
            ),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: vendor_key.public_key(),
        },
        vendor_key,
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("Chiodos runtime loopback receipt signing: {error}"))
    })?;
    let child_receipt_sha256 = canonical_sha256_json(
        &proof_receipt,
        "Chiodos runtime loopback receipt canonical hash",
    )?;
    let continuation = chio_chiodos_runtime::CrossKernelContinuation {
        schema: chio_chiodos_runtime::CHIODOS_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: format!("continuation:runtime-loopback:{step_index}"),
        source_kernel_id: source_kernel_id.clone(),
        target_kernel_id: target_kernel_id.clone(),
        parent_receipt_sha256: parent_receipt_sha256.clone(),
        parent_session_anchor_sha256: chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:session-anchor").as_bytes(),
        ),
        capability_id: step.request.capability_id.clone(),
        action_class_id: action_class_id.clone(),
        audience_tool: format!("{}.{}", step.request.server_id, step.request.tool_name),
        nonce: format!("runtime-loopback-continuation-nonce-{step_index}"),
        issued_at_unix_ms,
        expires_at_unix_ms,
    };
    let continuation_sha256 =
        canonical_sha256_json(&continuation, "Chiodos runtime loopback continuation hash")?;
    let mut bilateral_invocation = chio_chiodos_runtime::BilateralInvocation {
        schema: chio_chiodos_runtime::CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: format!("bilateral:runtime-loopback:{step_index}"),
        treaty_id: treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: step.request.capability_id.clone(),
        request_sha256: step.request.tool_args_sha256.clone(),
        outcome_sha256: outcome_sha256.clone(),
        local_receipt_sha256: parent_receipt_sha256.clone(),
        remote_receipt_sha256: child_receipt_sha256,
        signer_kernel_ids: vec![source_kernel_id.clone(), target_kernel_id.clone()],
    };
    let bilateral_invocation_binding_sha256 =
        chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback bilateral invocation binding hash: {error}"
                ))
            },
        )?;
    let lineage_statement = chio_chiodos_runtime::ReceiptLineageStatement {
        schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: format!("lineage:runtime-loopback:{step_index}"),
        parent_receipt_sha256: parent_receipt_sha256.clone(),
        child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: bilateral_invocation_binding_sha256.clone(),
        evidence_class: "verified".to_string(),
        source_kernel_id: source_kernel_id.clone(),
        target_kernel_id: target_kernel_id.clone(),
    };
    let lineage_statement_sha256 = canonical_sha256_json(
        &lineage_statement,
        "Chiodos runtime loopback lineage statement hash",
    )?;
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
    let rebound_bilateral_invocation_sha256 =
        chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback bilateral invocation rebound binding hash: {error}"
                ))
            },
        )?;
    if rebound_bilateral_invocation_sha256 != bilateral_invocation_binding_sha256 {
        return Err(RuntimeLoopbackError::message(format!(
            "Chiodos runtime loopback bilateral invocation binding changed after lineage back-fill: expected {bilateral_invocation_binding_sha256}, got {rebound_bilateral_invocation_sha256}"
        )));
    }
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256.clone();
    let lineage_bundle = chio_chiodos_runtime::ReceiptLineageBundle {
        schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: format!("lineage-bundle:runtime-loopback:{step_index}"),
        root_receipt_sha256: parent_receipt_sha256.clone(),
        leaf_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        statements: vec![lineage_statement],
    };
    let lineage_bundle_sha256 = canonical_sha256_json(
        &lineage_bundle,
        "Chiodos runtime loopback lineage bundle hash",
    )?;
    let bilateral_dsse = if requires_bilateral {
        let lease_id = step.admission_bundle.lease_id.clone().ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime loopback treaty context requires a lease id".to_string(),
            )
        })?;
        let governance_receipt_id = step
            .admission_bundle
            .governance_receipt_id
            .clone()
            .ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime loopback treaty context requires a governance receipt id"
                        .to_string(),
                )
            })?;
        let admission_report_sha256 = chio_core::sha256_hex(
            format!(
                "runtime-loopback:{step_index}:{}:admission-report",
                step.admission_bundle.admission_id
            )
            .as_bytes(),
        );
        let envelope = chio_federation::sign_chiodos_dsse_envelope(
            &proof_receipt,
            &origin_key,
            vendor_key,
            &source_kernel_id,
            &target_kernel_id,
            &step.request.tool_name,
            issued_at_unix_ms,
            chio_federation::BilateralPredicateExtensions {
                capability_lease_ref: Some(chio_federation::CapabilityLeaseRef {
                    lease_id: lease_id.clone(),
                    issuer: source_kernel_id.clone(),
                    expires_at_unix_ms,
                    scope_digest: Some(chio_federation::HashRecord {
                        alg: "sha256".to_string(),
                        value: chio_core::sha256_hex(
                            format!("runtime-loopback:{step_index}:lease-scope").as_bytes(),
                        ),
                    }),
                }),
                policy_evaluation_summary: Some(runtime_loopback_policy_summary(step)),
                governance_receipt_ref: Some(chio_federation::GovernanceReceiptRef {
                    receipt_id: governance_receipt_id.clone(),
                    kernel_id: source_kernel_id.clone(),
                    digest: chio_federation::HashRecord {
                        alg: "sha256".to_string(),
                        value: chio_core::sha256_hex(
                            format!("runtime-loopback:{step_index}:governance").as_bytes(),
                        ),
                    },
                }),
                consistency_anchor: Some(format!("chiodos:runtime-loopback:{step_index}")),
                consistency_model: Some("totally_ordered".to_string()),
                cross_org_visibility: None,
                treaty_binding_ref: Some(chio_federation::TreatyBindingRef {
                    treaty_id: treaty_scope.treaty_id.clone(),
                    treaty_scope_sha256: treaty_scope_sha256.clone(),
                    ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                    admission_report_sha256,
                    continuation_sha256: continuation_sha256.clone(),
                    lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                    action_class_id: action_class_id.clone(),
                    consistency_model: "totally_ordered".to_string(),
                    request_sha256: bilateral_invocation.request_sha256.clone(),
                    outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                    local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                    lease_refs: vec![lease_id],
                    governance_refs: vec![governance_receipt_id],
                    signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
                }),
            },
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback bilateral DSSE signing: {error}"
            ))
        })?;
        let envelope_id = format!("bilateral-dsse:runtime-loopback:{step_index}");
        let envelope_sha256 =
            canonical_sha256_json(&envelope, "Chiodos runtime loopback bilateral DSSE hash")?;
        Some((envelope_id, envelope_sha256, envelope))
    } else {
        None
    };
    hook_store
        .insert_treaty_runtime_artifact("treaty_scope", &treaty_scope.treaty_id, &treaty_scope)
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback treaty scope store: {error}"
            ))
        })?;
    hook_store
        .insert_treaty_runtime_artifact(
            "ladder_intersection",
            &ladder_intersection.intersection_id,
            &ladder_intersection,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback ladder intersection store: {error}"
            ))
        })?;
    hook_store
        .insert_treaty_runtime_artifact(
            "cross_kernel_continuation",
            &continuation.continuation_id,
            &continuation,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback continuation store: {error}"
            ))
        })?;
    hook_store
        .insert_treaty_runtime_artifact(
            "receipt_lineage_bundle",
            &lineage_bundle.bundle_id,
            &lineage_bundle,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback lineage bundle store: {error}"
            ))
        })?;
    if requires_bilateral {
        hook_store
            .insert_treaty_runtime_artifact(
                "bilateral_invocation",
                &bilateral_invocation.invocation_id,
                &bilateral_invocation,
            )
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback bilateral invocation store: {error}"
                ))
            })?;
    }
    if let Some((envelope_id, _envelope_sha256, envelope)) = bilateral_dsse.as_ref() {
        hook_store
            .insert_treaty_runtime_artifact("bilateral_dsse_envelope", envelope_id, envelope)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback bilateral DSSE store: {error}"
                ))
            })?;
    }

    let mut intent_context = serde_json::json!({
        "treatyScopeId": treaty_scope.treaty_id,
        "treatyScopeSha256": treaty_scope_sha256,
        "ladderIntersectionId": ladder_intersection.intersection_id,
        "ladderIntersectionSha256": ladder_intersection_sha256,
        "actionClassId": action_class_id,
        "crossKernelContinuation": {
            "id": continuation.continuation_id,
            "sha256": continuation_sha256
        },
        "receiptLineageBundle": {
            "id": lineage_bundle.bundle_id,
            "sha256": lineage_bundle_sha256
        }
    });
    if requires_bilateral {
        let object = intent_context.as_object_mut().ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime loopback treaty context must be an object".to_string(),
            )
        })?;
        object.insert(
            "bilateralInvocation".to_string(),
            serde_json::json!({
                "id": bilateral_invocation.invocation_id,
                "sha256": bilateral_invocation_sha256
            }),
        );
        if let Some((envelope_id, envelope_sha256, _envelope)) = bilateral_dsse {
            object.insert(
                "bilateralDsse".to_string(),
                serde_json::json!({
                    "id": envelope_id,
                    "sha256": envelope_sha256
                }),
            );
        }
    }
    Ok(RuntimeLoopbackTreatyContext {
        treaty_scope,
        treaty_scope_sha256,
        ladder_intersection,
        ladder_intersection_sha256,
        continuation,
        continuation_sha256,
        lineage_bundle_id: lineage_bundle.bundle_id,
        intent_context,
    })
}
