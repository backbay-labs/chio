use crate::evidence_io::canonical_sha256_json;
use crate::kernel::runtime_loopback_policy_summary;
use crate::scenario::RuntimeLoopbackStep;
use crate::RuntimeLoopbackError;

pub(crate) struct RuntimeLoopbackTreatyContext {
    pub(crate) treaty_scope: chio_runtime_core::TreatyScope,
    pub(crate) treaty_scope_sha256: String,
    pub(crate) ladder_intersection: chio_runtime_core::LadderIntersection,
    pub(crate) ladder_intersection_sha256: String,
    pub(crate) continuation: chio_runtime_core::CrossKernelContinuation,
    pub(crate) continuation_sha256: String,
    pub(crate) lineage_bundle_id: String,
    pub(crate) intent_context: serde_json::Value,
}

pub(crate) fn insert_runtime_loopback_treaty_context(
    hook_store: &chio_runtime_core::InMemoryRuntimeAdmissionStore,
    step_index: usize,
    step: &RuntimeLoopbackStep,
    vendor_key: &chio_core::Keypair,
    arguments: &serde_json::Value,
) -> Result<RuntimeLoopbackTreatyContext, RuntimeLoopbackError> {
    let source_kernel_id = step.request.origin_kernel_id.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chio runtime loopback treaty context requires an origin kernel",
        )
    })?;
    let target_kernel_id = step.request.host_kernel_id.clone();
    let action_class_id = format!("workflow.cross_kernel.{}", step.request.tool_name);
    let issued_at_unix_ms = 1_700_000_000_000_u64;
    let expires_at_unix_ms = 1_900_000_000_000_u64;
    let origin_key = chio_attest_loopback::runtime_buyer_keypair();
    let manifest_hashes = vec![
        chio_core::sha256_hex(format!("runtime-loopback:{source_kernel_id}:manifest").as_bytes()),
        chio_core::sha256_hex(format!("runtime-loopback:{target_kernel_id}:manifest").as_bytes()),
    ];
    let treaty_scope = chio_runtime_core::TreatyScope {
        schema: chio_runtime_core::CHIO_FEDERATION_TREATY_SCOPE_SCHEMA.to_string(),
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
        chio_runtime_core::treaty_scope_sha256(&treaty_scope).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback treaty scope hash: {error}"
            ))
        })?;
    let mut participant_modes = std::collections::BTreeMap::new();
    participant_modes.insert(source_kernel_id.clone(), "receipt_backed".to_string());
    participant_modes.insert(target_kernel_id.clone(), "receipt_backed".to_string());
    let governance_receipt_id = step.admission_bundle.governance_receipt_id.clone();
    let evidence_required = vec![
        "receipt_lineage".to_string(),
        "bilateral_invocation".to_string(),
    ];
    let ladder_intersection = chio_runtime_core::LadderIntersection {
        schema: chio_runtime_core::CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA.to_string(),
        intersection_id: format!("intersection:runtime-loopback:{step_index}"),
        treaty_id: treaty_scope.treaty_id.clone(),
        participant_kernel_ids: treaty_scope.participant_kernel_ids.clone(),
        ladder_manifest_sha256s: manifest_hashes,
        generated_at_unix_ms: issued_at_unix_ms,
        expires_at_unix_ms,
        action_classes: vec![chio_runtime_core::LadderIntersectionActionClass {
            action_class_id: action_class_id.clone(),
            mode: "receipt_backed".to_string(),
            destructive: step.admission_bundle.destructive,
            consistency_model: "totally-ordered".to_string(),
            co_sign: "bilateral_required".to_string(),
            co_sign_quorum: None,
            evidence_required,
            participant_modes,
        }],
    };
    let ladder_intersection_sha256 =
        chio_runtime_core::ladder_intersection_sha256(&ladder_intersection).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback ladder intersection hash: {error}"
            ))
        })?;
    let parent_receipt_sha256 =
        chio_core::sha256_hex(format!("runtime-loopback:{step_index}:parent-receipt").as_bytes());
    let outcome_sha256 = chio_core::sha256_hex(
        format!("runtime-loopback:{step_index}:pre-dispatch-outcome").as_bytes(),
    );
    let action = chio_core::receipt::decision::ToolCallAction::from_parameters(arguments.clone())
        .map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime loopback receipt action hash: {error}"
        ))
    })?;
    let proof_receipt = chio_core::receipt::body::ChioReceipt::sign(
        chio_core::receipt::body::ChioReceiptBody {
            id: format!("runtime-loopback-receipt:{step_index}"),
            timestamp: issued_at_unix_ms / 1000,
            capability_id: step.request.capability_id.clone(),
            tool_server: step.request.server_id.clone(),
            tool_name: step.request.tool_name.clone(),
            action,
            decision: Some(chio_core::receipt::decision::Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: vec![chio_core::receipt::metadata::ActorRef {
                actor_id: "agent:chio-loopback".to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: outcome_sha256.clone(),
            policy_hash: chio_core::sha256_hex(
                format!("runtime-loopback:{step_index}:policy").as_bytes(),
            ),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: vendor_key.public_key(),
            bbs_projection_version: None,
        },
        vendor_key,
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio runtime loopback receipt signing: {error}"))
    })?;
    let child_receipt_sha256 = canonical_sha256_json(
        &proof_receipt,
        "Chio runtime loopback receipt canonical hash",
    )?;
    let continuation = chio_runtime_core::CrossKernelContinuation {
        schema: chio_runtime_core::CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
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
        canonical_sha256_json(&continuation, "Chio runtime loopback continuation hash")?;
    let mut bilateral_invocation = chio_runtime_core::BilateralInvocation {
        schema: chio_runtime_core::CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: format!("bilateral:runtime-loopback:{step_index}"),
        treaty_id: treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: action_class_id.clone(),
        consistency_model: "totally-ordered".to_string(),
        capability_id: step.request.capability_id.clone(),
        request_sha256: step.request.tool_args_sha256.clone(),
        outcome_sha256: outcome_sha256.clone(),
        local_receipt_sha256: parent_receipt_sha256.clone(),
        remote_receipt_sha256: child_receipt_sha256,
        signer_kernel_ids: vec![source_kernel_id.clone(), target_kernel_id.clone()],
    };
    let bilateral_invocation_binding_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback bilateral invocation binding hash: {error}"
                ))
            },
        )?;
    let lineage_statement = chio_runtime_core::ReceiptLineageStatement {
        schema: chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
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
        "Chio runtime loopback lineage statement hash",
    )?;
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
    let rebound_bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback bilateral invocation rebound binding hash: {error}"
                ))
            },
        )?;
    if rebound_bilateral_invocation_sha256 != bilateral_invocation_binding_sha256 {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime loopback bilateral invocation binding changed after lineage back-fill: expected {bilateral_invocation_binding_sha256}, got {rebound_bilateral_invocation_sha256}"
        )));
    }
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256.clone();
    let lineage_bundle = chio_runtime_core::ReceiptLineageBundle {
        schema: chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: format!("lineage-bundle:runtime-loopback:{step_index}"),
        root_receipt_sha256: parent_receipt_sha256.clone(),
        leaf_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        statements: vec![lineage_statement],
    };
    let lineage_bundle_sha256 =
        canonical_sha256_json(&lineage_bundle, "Chio runtime loopback lineage bundle hash")?;
    let lease_id = step.admission_bundle.lease_id.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chio runtime loopback treaty context requires a lease id".to_string(),
        )
    })?;
    let admission_report_sha256 = chio_core::sha256_hex(
        format!(
            "runtime-loopback:{step_index}:{}:admission-report",
            step.admission_bundle.admission_id
        )
        .as_bytes(),
    );
    let governance_receipt_ref = governance_receipt_id.clone().map(|governance_receipt_id| {
        chio_federation::bilateral_dsse::GovernanceReceiptRef {
            receipt_id: governance_receipt_id,
            kernel_id: source_kernel_id.clone(),
            digest: chio_federation::bilateral_dsse::HashRecord {
                alg: "sha256".to_string(),
                value: chio_core::sha256_hex(
                    format!("runtime-loopback:{step_index}:governance").as_bytes(),
                ),
            },
        }
    });
    let dsse_consistency_model = chio_runtime_core::bilateral_dsse_consistency_model(
        &bilateral_invocation.consistency_model,
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime loopback DSSE consistency model: {error}"
        ))
    })?
    .to_string();
    let envelope = chio_federation::bilateral_dsse::sign_chio_bilateral_dsse_envelope(
        &proof_receipt,
        &origin_key,
        vendor_key,
        &source_kernel_id,
        &target_kernel_id,
        &step.request.tool_name,
        issued_at_unix_ms,
        chio_federation::bilateral_dsse::BilateralPredicateExtensions {
            capability_lease_ref: Some(chio_federation::bilateral_dsse::CapabilityLeaseRef {
                lease_id: lease_id.clone(),
                issuer: source_kernel_id.clone(),
                expires_at_unix_ms,
                scope_digest: Some(chio_federation::bilateral_dsse::HashRecord {
                    alg: "sha256".to_string(),
                    value: chio_core::sha256_hex(
                        format!("runtime-loopback:{step_index}:lease-scope").as_bytes(),
                    ),
                }),
            }),
            policy_evaluation_summary: Some(runtime_loopback_policy_summary(step)),
            governance_receipt_ref,
            consistency_anchor: Some(format!("chio:runtime-loopback:{step_index}")),
            consistency_model: Some(dsse_consistency_model.clone()),
            cross_org_visibility: None,
            treaty_binding_ref: Some(chio_federation::bilateral_dsse::TreatyBindingRef {
                treaty_id: treaty_scope.treaty_id.clone(),
                treaty_scope_sha256: treaty_scope_sha256.clone(),
                ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                admission_report_sha256,
                continuation_sha256: continuation_sha256.clone(),
                lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                action_class_id: action_class_id.clone(),
                consistency_model: dsse_consistency_model,
                request_sha256: bilateral_invocation.request_sha256.clone(),
                outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                lease_refs: vec![lease_id],
                governance_refs: governance_receipt_id.into_iter().collect(),
                signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
            }),
        },
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime loopback bilateral DSSE signing: {error}"
        ))
    })?;
    let envelope_id = format!("bilateral-dsse:runtime-loopback:{step_index}");
    let envelope_sha256 =
        canonical_sha256_json(&envelope, "Chio runtime loopback bilateral DSSE hash")?;
    let bilateral_dsse = Some((envelope_id, envelope_sha256, envelope));
    hook_store
        .insert_treaty_runtime_artifact("treaty_scope", &treaty_scope.treaty_id, &treaty_scope)
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback treaty scope store: {error}"
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
                "Chio runtime loopback ladder intersection store: {error}"
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
                "Chio runtime loopback continuation store: {error}"
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
                "Chio runtime loopback lineage bundle store: {error}"
            ))
        })?;
    hook_store
        .insert_treaty_runtime_artifact(
            "bilateral_invocation",
            &bilateral_invocation.invocation_id,
            &bilateral_invocation,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback bilateral invocation store: {error}"
            ))
        })?;
    if let Some((envelope_id, _envelope_sha256, envelope)) = bilateral_dsse.as_ref() {
        hook_store
            .insert_treaty_runtime_artifact("bilateral_dsse_envelope", envelope_id, envelope)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback bilateral DSSE store: {error}"
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
    let object = intent_context.as_object_mut().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chio runtime loopback treaty context must be an object".to_string(),
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

#[cfg(test)]
mod tests {
    use super::insert_runtime_loopback_treaty_context;
    use crate::scenario::RuntimeLoopbackStep;
    use chio_runtime_core::RuntimeAdmissionStore;

    fn fixed_hash(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn destructive_runtime_loopback_step() -> RuntimeLoopbackStep {
        let request = chio_runtime_core::RuntimeRequestBinding {
            request_id: "req-loopback-treaty".to_string(),
            capability_id: "cap-chio-workflow".to_string(),
            server_id: "vendor-c.payments".to_string(),
            tool_name: "stage_refund".to_string(),
            tool_args_sha256: "47e6e096b5d5888a3f90d057de3bce595d8ea5dd8624ccde387bb739d5a6464b"
                .to_string(),
            origin_kernel_id: Some("did:chio:buyer-kernel".to_string()),
            host_kernel_id: "did:chio:vendor-c".to_string(),
        };
        RuntimeLoopbackStep {
            admission_profile: chio_runtime_core::RuntimeAdmissionProfile {
                schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
                profile_id: "profile-loopback-treaty".to_string(),
                local_kernel_id: "did:chio:vendor-c".to_string(),
                verifier_id: "did:chio:buyer-verifier".to_string(),
                issued_at_unix_ms: 1_800_000_000_000,
                expires_at_unix_ms: 1_800_003_600_000,
            },
            admission_bundle: chio_runtime_core::RuntimeAdmissionBundle {
                schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
                admission_id: "adm-loopback-treaty".to_string(),
                binding: request.clone(),
                workflow_id: "wf-chio-refund-001".to_string(),
                workflow_grant_id: "cap-chio-workflow".to_string(),
                step_index: 2,
                destructive: true,
                lease_id: Some("lease-vendor-c-refund".to_string()),
                governance_receipt_id: Some("gov-refund-stage-authorization".to_string()),
                trust_bundle_sha256: fixed_hash('b'),
                verification_context_sha256: fixed_hash('c'),
            },
            request,
            arguments: Some(serde_json::json!({
                "caseRef": "refund-250",
                "tool": "stage_refund",
                "workflowId": "wf-chio-refund-001"
            })),
        }
    }

    fn stored_schema(
        store: &chio_runtime_core::InMemoryRuntimeAdmissionStore,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<String, crate::RuntimeLoopbackError> {
        let record = store
            .treaty_runtime_artifact(evidence_kind, evidence_id)
            .map_err(|error| {
                crate::RuntimeLoopbackError::message(format!(
                    "runtime treaty artifact lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(format!(
                    "missing runtime treaty artifact {evidence_kind}/{evidence_id}"
                ))
            })?;
        record
            .raw_json
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(format!(
                    "runtime treaty artifact {evidence_kind}/{evidence_id} has no schema"
                ))
            })
    }

    fn stored_artifact_json(
        store: &chio_runtime_core::InMemoryRuntimeAdmissionStore,
        evidence_kind: &str,
        evidence_id: &str,
    ) -> Result<serde_json::Value, crate::RuntimeLoopbackError> {
        store
            .treaty_runtime_artifact(evidence_kind, evidence_id)
            .map_err(|error| {
                crate::RuntimeLoopbackError::message(format!(
                    "runtime treaty artifact lookup failed: {error}"
                ))
            })?
            .map(|record| record.raw_json)
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(format!(
                    "missing runtime treaty artifact {evidence_kind}/{evidence_id}"
                ))
            })
    }

    #[test]
    fn runtime_loopback_treaty_context_emits_chio_federation_schemas(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let step = destructive_runtime_loopback_step();
        let store = chio_runtime_core::InMemoryRuntimeAdmissionStore::new();
        let vendor_key = chio_attest_loopback::runtime_vendor_keypair(2).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback vendor key failed: {error}"
            ))
        })?;
        let context = insert_runtime_loopback_treaty_context(
            &store,
            2,
            &step,
            &vendor_key,
            step.arguments.as_ref().ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback test step missing arguments".to_string(),
                )
            })?,
        )?;

        assert_eq!(
            context.treaty_scope.schema,
            chio_runtime_core::CHIO_FEDERATION_TREATY_SCOPE_SCHEMA
        );
        assert_eq!(
            context.ladder_intersection.schema,
            chio_runtime_core::CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA
        );
        assert_eq!(
            context.continuation.schema,
            chio_runtime_core::CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA
        );
        assert_eq!(
            stored_schema(&store, "treaty_scope", &context.treaty_scope.treaty_id)?,
            chio_runtime_core::CHIO_FEDERATION_TREATY_SCOPE_SCHEMA
        );
        assert_eq!(
            stored_schema(
                &store,
                "ladder_intersection",
                &context.ladder_intersection.intersection_id
            )?,
            chio_runtime_core::CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA
        );
        assert_eq!(
            stored_schema(
                &store,
                "cross_kernel_continuation",
                &context.continuation.continuation_id
            )?,
            chio_runtime_core::CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA
        );
        assert_eq!(
            stored_schema(&store, "receipt_lineage_bundle", &context.lineage_bundle_id)?,
            chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA
        );
        let bilateral_id = context
            .intent_context
            .pointer("/bilateralInvocation/id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback treaty context missing bilateral invocation id".to_string(),
                )
            })?;
        assert_eq!(
            stored_schema(&store, "bilateral_invocation", bilateral_id)?,
            chio_runtime_core::CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA
        );
        let bilateral_dsse_id = context
            .intent_context
            .pointer("/bilateralDsse/id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback treaty context missing bilateral DSSE id".to_string(),
                )
            })?;
        let envelope: chio_federation::bilateral_dsse::DsseEnvelope = serde_json::from_value(
            stored_artifact_json(&store, "bilateral_dsse_envelope", bilateral_dsse_id)?,
        )
        .map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback bilateral DSSE parse failed: {error}"
            ))
        })?;
        let (statement, _) = envelope.decode_statement().map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback bilateral DSSE decode failed: {error}"
            ))
        })?;
        assert_eq!(
            statement
                .predicate
                .treaty_binding_ref
                .as_ref()
                .map(|binding| binding.governance_refs.as_slice()),
            Some(&["gov-refund-stage-authorization".to_string()][..])
        );
        Ok(())
    }

    #[test]
    fn runtime_loopback_treaty_context_emits_dsse_for_routine_federated_steps(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let mut step = destructive_runtime_loopback_step();
        step.admission_bundle.destructive = false;
        step.admission_bundle.governance_receipt_id = None;
        let store = chio_runtime_core::InMemoryRuntimeAdmissionStore::new();
        let vendor_key = chio_attest_loopback::runtime_vendor_keypair(0).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback vendor key failed: {error}"
            ))
        })?;
        let context = insert_runtime_loopback_treaty_context(
            &store,
            0,
            &step,
            &vendor_key,
            step.arguments.as_ref().ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback test step missing arguments".to_string(),
                )
            })?,
        )?;

        let bilateral_id = context
            .intent_context
            .pointer("/bilateralInvocation/id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback treaty context missing bilateral invocation id".to_string(),
                )
            })?;
        assert_eq!(
            stored_schema(&store, "bilateral_invocation", bilateral_id)?,
            chio_runtime_core::CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA
        );
        let bilateral_dsse_id = context
            .intent_context
            .pointer("/bilateralDsse/id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback treaty context missing bilateral DSSE id".to_string(),
                )
            })?;
        let envelope: chio_federation::bilateral_dsse::DsseEnvelope = serde_json::from_value(
            stored_artifact_json(&store, "bilateral_dsse_envelope", bilateral_dsse_id)?,
        )
        .map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback bilateral DSSE parse failed: {error}"
            ))
        })?;
        let (statement, _) = envelope.decode_statement().map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback bilateral DSSE decode failed: {error}"
            ))
        })?;
        let binding = statement.predicate.treaty_binding_ref.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "runtime loopback bilateral DSSE missing treaty binding".to_string(),
            )
        })?;
        assert_eq!(
            binding.lease_refs,
            vec!["lease-vendor-c-refund".to_string()]
        );
        assert!(binding.governance_refs.is_empty());
        assert!(statement.predicate.governance_receipt_ref.is_none());
        Ok(())
    }
}
