use std::sync::atomic::{AtomicU64, Ordering};

use chio_kernel::{ChioKernel, ToolCallRequest as KernelToolCallRequest};

use crate::evidence_io::unix_now_ms;
use crate::runtime_loopback_capability_window;
use crate::scenario::RuntimeLoopbackStep;
use crate::treaty::{insert_runtime_loopback_treaty_context, RuntimeLoopbackTreatyContext};
use crate::RuntimeLoopbackError;

pub(crate) struct RuntimeLoopbackExecution {
    pub(crate) receipt: chio_core::receipt::body::ChioReceipt,
    pub(crate) treaty: Option<RuntimeLoopbackTreatyContext>,
}

static RUNTIME_LOOPBACK_RECEIPT_STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct RuntimeLoopbackToolServer {
    id: String,
    tool_name: String,
    step_index: usize,
}

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for RuntimeLoopbackToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        if tool_name != self.tool_name {
            return Err(chio_kernel::KernelError::ToolServerError(format!(
                "runtime loopback tool {tool_name} is not registered on {}",
                self.id
            )));
        }
        Ok(serde_json::json!({
            "stepIndex": self.step_index,
            "serverId": self.id,
            "toolName": tool_name,
            "arguments": arguments,
            "runtimeReceiptSource": "chio_kernel_live_loopback"
        }))
    }
}

fn runtime_loopback_capability(
    issuer: &chio_core::Keypair,
    subject: &chio_core::Keypair,
    capability_id: &str,
    server_id: &str,
    tool_name: &str,
    now_unix_ms: u64,
) -> Result<chio_core::capability::token::CapabilityToken, RuntimeLoopbackError> {
    let (issued_at, expires_at) = runtime_loopback_capability_window(now_unix_ms);
    let scope = chio_core::capability::scope::ChioScope {
        grants: vec![chio_core::capability::scope::ToolGrant {
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![chio_core::capability::scope::Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    };
    let body = chio_core::capability::token::CapabilityTokenBody {
        id: capability_id.to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at,
        expires_at,
        delegation_chain: Vec::new(),
    };
    chio_core::capability::token::CapabilityToken::sign(body, issuer).map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio runtime loopback capability signing: {error}"))
    })
}

pub(crate) fn runtime_loopback_policy_summary(
    step: &RuntimeLoopbackStep,
) -> chio_federation::bilateral_dsse::PolicyEvaluationSummary {
    let policy_version = "chio-ladder-v1".to_string();
    chio_federation::bilateral_dsse::PolicyEvaluationSummary {
        server_a_verdict: chio_federation::bilateral_dsse::PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: format!("buyer-policy:{}", step.request.tool_name),
            policy_version: policy_version.clone(),
            rationale_code: Some("lease-bound".to_string()),
        },
        server_b_verdict: chio_federation::bilateral_dsse::PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: format!(
                "{}-policy:{}",
                step.request.host_kernel_id, step.request.tool_name
            ),
            policy_version,
            rationale_code: Some("manifest-bound".to_string()),
        },
        joint_disposition: Some("allow".to_string()),
    }
}

fn runtime_loopback_vendor_id(step: &RuntimeLoopbackStep) -> Result<String, RuntimeLoopbackError> {
    let host_kernel_id = step.request.host_kernel_id.trim();
    if host_kernel_id.is_empty() || host_kernel_id != step.request.host_kernel_id {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime loopback host kernel id {:?} cannot derive vendor id",
            step.request.host_kernel_id
        )));
    }

    Ok(host_kernel_id
        .strip_prefix("did:chio:")
        .unwrap_or(host_kernel_id)
        .to_string())
}

fn runtime_loopback_receipt_metadata(
    step: &RuntimeLoopbackStep,
) -> Result<serde_json::Value, RuntimeLoopbackError> {
    Ok(serde_json::json!({
        "workflow_id": step.admission_bundle.workflow_id.clone(),
        "vendor_id": runtime_loopback_vendor_id(step)?,
    }))
}

type RuntimeLoopbackPolicyInputs = (
    chio_runtime_core::SignedRuntimeVerifierTrustBundle,
    Vec<chio_runtime_core::RuntimeTrustedVerifierKey>,
    chio_runtime_core::SignedRuntimePheromoneQueryReport,
    chio_runtime_core::SignedRuntimePheromonePolicy,
    chio_runtime_core::SignedRuntimePeerWeights,
);

pub(crate) fn runtime_loopback_policy_inputs(
    step: &RuntimeLoopbackStep,
    evaluation_now_unix_ms: u64,
) -> Result<RuntimeLoopbackPolicyInputs, RuntimeLoopbackError> {
    let verifier_key = chio_core::Keypair::from_seed(&[1_u8; 32]);
    let verifier_id = step.admission_profile.verifier_id.clone();
    let key_id = "verifier-key-1".to_string();
    let issued_at_unix_ms = step.admission_profile.issued_at_unix_ms;
    let expires_at_unix_ms = step.admission_profile.expires_at_unix_ms;
    let trusted_keys = vec![chio_runtime_core::RuntimeTrustedVerifierKey {
        verifier_id: verifier_id.clone(),
        key_id: key_id.clone(),
        public_key: verifier_key.public_key(),
        valid_from_unix_ms: issued_at_unix_ms,
        valid_until_unix_ms: expires_at_unix_ms,
        status: "active".to_string(),
    }];
    let trust_body = chio_runtime_core::RuntimeVerifierTrustBundleV4 {
        schema: chio_runtime_core::CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
        verifier_id: verifier_id.clone(),
        key_id: key_id.clone(),
        version: 1,
        previous_hash_sha256: None,
        trust_bundle_sha256: step.admission_bundle.trust_bundle_sha256.clone(),
        verification_context_sha256: step.admission_bundle.verification_context_sha256.clone(),
        revocation_checkpoint_sha256: "d".repeat(64),
        revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
        issued_at_unix_ms,
        expires_at_unix_ms,
    };
    let signed_trust =
        chio_core::receipt::lineage::SignedExportEnvelope::sign(trust_body, &verifier_key)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback trust signing: {error}"
                ))
            })?;
    let weights_body = chio_runtime_core::RuntimePeerWeights {
        schema: chio_runtime_core::CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
        verifier_id: verifier_id.clone(),
        key_id: key_id.clone(),
        reputation_epoch: 7,
        issued_at_unix_ms,
        expires_at_unix_ms,
        weights: vec![chio_runtime_core::RuntimePeerWeight {
            peer_kernel_id: step.request.host_kernel_id.clone(),
            weight: 1.0,
        }],
    };
    let peer_weights_sha256 = chio_runtime_core::runtime_peer_weights_sha256(&weights_body)
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback peer weights hash: {error}"
            ))
        })?;
    let policy_body = chio_runtime_core::RuntimePheromonePolicy {
        schema: chio_runtime_core::CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
        policy_id: "policy-runtime-loopback-risk".to_string(),
        verifier_id: verifier_id.clone(),
        key_id: key_id.clone(),
        policy_version: 1,
        mode: "enforce".to_string(),
        issued_at_unix_ms,
        expires_at_unix_ms,
        allowed_reputation_epochs: vec![7],
        max_query_report_age_ms: 60_000,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: step.admission_bundle.trust_bundle_sha256.clone(),
        peer_weights_sha256,
        rules: vec![chio_runtime_core::RuntimePheromonePolicyRule {
            rule_id: "review-high-runtime-risk".to_string(),
            subject_class: "workflow.destructive_step".to_string(),
            subject_class_namespace: "chio.runtime".to_string(),
            action_class_id: "*".to_string(),
            direction: "deny_if_at_or_above".to_string(),
            threshold_total_strength: 0.9,
            effect: "require_review".to_string(),
        }],
    };
    let signed_policy =
        chio_core::receipt::lineage::SignedExportEnvelope::sign(policy_body, &verifier_key)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback policy signing: {error}"
                ))
            })?;
    let signed_weights =
        chio_core::receipt::lineage::SignedExportEnvelope::sign(weights_body, &verifier_key)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback peer weights signing: {error}"
                ))
            })?;
    let query_report_body = serde_json::json!({
        "schema": "chio.pheromone.query-report.v1",
        "accepted": true,
        "concentration": {
            "subjectClass": "workflow.destructive_step",
            "subjectClassNamespace": "chio.runtime",
            "totalStrength": 0.1,
            "distinctOriginPairs": 1,
            "reputationEpoch": 7,
            "evaluatedAtUnixMs": evaluation_now_unix_ms.saturating_sub(2_000)
        }
    });
    let signed_query_report =
        chio_core::receipt::lineage::SignedExportEnvelope::sign(query_report_body, &verifier_key)
            .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback pheromone query report signing: {error}"
            ))
        })?;
    Ok((
        signed_trust,
        trusted_keys,
        signed_query_report,
        signed_policy,
        signed_weights,
    ))
}

pub(crate) fn execute_runtime_loopback_step(
    step_index: usize,
    step: &RuntimeLoopbackStep,
    arguments: serde_json::Value,
    now_unix_ms: u64,
) -> Result<RuntimeLoopbackExecution, RuntimeLoopbackError> {
    let (expected_kernel_id, expected_server_id, expected_tool_name) =
        chio_attest_loopback::runtime_vendor_binding(step_index).map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio runtime loopback vendor binding: {error}"))
        })?;
    if step.request.server_id != expected_server_id || step.request.tool_name != expected_tool_name
    {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime loopback step {} targets {}:{} but expected {}:{}",
            step_index,
            step.request.server_id,
            step.request.tool_name,
            expected_server_id,
            expected_tool_name
        )));
    }
    if step.request.host_kernel_id != expected_kernel_id {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime loopback step {} host kernel {} does not match {}",
            step_index, step.request.host_kernel_id, expected_kernel_id
        )));
    }
    let actual_args_sha256 = chio_runtime_core::tool_args_sha256(&arguments).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime loopback argument hash for step {}: {error}",
            step_index
        ))
    })?;
    if actual_args_sha256 != step.request.tool_args_sha256 {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime loopback step {} arguments hash {} does not match request {}",
            step_index, actual_args_sha256, step.request.tool_args_sha256
        )));
    }
    let vendor_key = chio_attest_loopback::runtime_vendor_keypair(step_index).map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio runtime loopback vendor key: {error}"))
    })?;
    let agent_key = runtime_loopback_agent_keypair(step_index);
    let capability = runtime_loopback_capability(
        &vendor_key,
        &agent_key,
        &step.request.capability_id,
        &step.request.server_id,
        &step.request.tool_name,
        now_unix_ms,
    )?;
    let mut kernel = ChioKernel::new(chio_kernel::KernelConfig {
        keypair: vendor_key.clone(),
        ca_public_keys: vec![vendor_key.public_key()],
        max_delegation_depth: 5,
        policy_hash: chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:policy").as_bytes(),
        ),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
    });
    kernel.set_federation_local_kernel_id(step.request.host_kernel_id.clone());
    let receipt_store_nonce =
        RUNTIME_LOOPBACK_RECEIPT_STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let receipt_store_path = std::env::temp_dir().join(format!(
        "chio-runtime-loopback-{}-{}-{}-{}.sqlite3",
        std::process::id(),
        unix_now_ms(),
        step_index,
        receipt_store_nonce
    ));
    let receipt_store =
        chio_store_sqlite::SqliteReceiptStore::open(&receipt_store_path).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback receipt store open: {error}"
            ))
        })?;
    kernel
        .set_receipt_store(Box::new(receipt_store))
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback receipt store install: {error}"
            ))
        })?;
    // The kernel dispatches fail-closed against ephemeral revocation state, so
    // this isolated proof-regeneration kernel needs a durable revocation store
    // of its own. Give it a temp sibling of the receipt store; the revocation
    // set is empty and never survives the run.
    let revocation_store_path = receipt_store_path.with_extension("revocations.sqlite3");
    let revocation_store = chio_store_sqlite::SqliteRevocationStore::open(&revocation_store_path)
        .map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime loopback revocation store open: {error}"
        ))
    })?;
    kernel.set_revocation_store(Box::new(revocation_store));
    let peer_pin_now_unix_ms = now_unix_ms;
    if let Some(origin_kernel_id) = step.request.origin_kernel_id.as_deref() {
        let origin_key = chio_attest_loopback::runtime_buyer_keypair();
        let now_secs = peer_pin_now_unix_ms / 1000;
        let trust = chio_federation::trust_establishment::KernelTrustExchange::new(
            &step.request.host_kernel_id,
            vendor_key.clone(),
        )
        .with_trusted_peer(origin_kernel_id, origin_key.public_key());
        let envelope = chio_federation::trust_establishment::PeerHandshakeEnvelope::sign(
            origin_kernel_id,
            &step.request.host_kernel_id,
            &format!("loopback-origin-nonce-{step_index}"),
            now_secs,
            &origin_key,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback peer handshake signing: {error}"
            ))
        })?;
        let peer = trust
            .accept_envelope(&envelope, origin_kernel_id, now_secs)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback peer pinning: {error}"
                ))
            })?;
        kernel = kernel.with_federation_peers(vec![peer]);
        kernel.set_federation_cosigner(std::sync::Arc::new(
            chio_federation::bilateral::InProcessCoSigner::new(
                origin_kernel_id,
                origin_key,
                vendor_key.public_key(),
            ),
        ));
    }
    let hook_store = chio_runtime_core::InMemoryRuntimeAdmissionStore::new();
    hook_store
        .insert_bundle(step.admission_bundle.clone())
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback hook store update: {error}"
            ))
        })?;
    let chio_treaty = if step.request.origin_kernel_id.is_some() {
        Some(insert_runtime_loopback_treaty_context(
            &hook_store,
            step_index,
            step,
            &vendor_key,
            &arguments,
        )?)
    } else {
        None
    };
    let (signed_trust, trusted_keys, query_report, signed_policy, signed_weights) =
        runtime_loopback_policy_inputs(step, now_unix_ms)?;
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        chio_runtime_core::ChioRuntimeAdmissionHook::new(
            step.admission_profile.clone(),
            hook_store,
        )
        .with_runtime_trust_input(signed_trust, trusted_keys)
        .with_pheromone_query_report(query_report)
        .with_runtime_pheromone_policy(signed_policy, signed_weights)
        .with_fixed_now_unix_ms(now_unix_ms),
    ));
    kernel.register_tool_server(Box::new(RuntimeLoopbackToolServer {
        id: step.request.server_id.clone(),
        tool_name: step.request.tool_name.clone(),
        step_index,
    }));
    let bundle_sha256 = chio_runtime_core::runtime_admission_bundle_sha256(&step.admission_bundle)
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback bundle hash for step {}: {error}",
                step_index
            ))
        })?;
    let governed_intent = chio_core::capability::governance::GovernedTransactionIntent {
        id: format!("intent:chio-runtime-loopback:{}", step_index),
        server_id: step.request.server_id.clone(),
        tool_name: step.request.tool_name.clone(),
        purpose: "Chio live runtime loopback proof regeneration".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(if let Some(chio_treaty) = chio_treaty.as_ref() {
            serde_json::json!({
                "chioAdmission": {
                    "admissionId": step.admission_bundle.admission_id,
                    "bundleSha256": bundle_sha256
                },
                "chioTreaty": chio_treaty.intent_context
            })
        } else {
            serde_json::json!({
                "chioAdmission": {
                    "admissionId": step.admission_bundle.admission_id,
                    "bundleSha256": bundle_sha256
                }
            })
        }),
    };
    let request = KernelToolCallRequest {
        request_id: step.request.request_id.clone(),
        capability,
        tool_name: step.request.tool_name.clone(),
        server_id: step.request.server_id.clone(),
        agent_id: agent_key.public_key().to_hex(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(governed_intent),
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: step.request.origin_kernel_id.clone(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio runtime loopback executor: {error}"))
        })?;
    let receipt_metadata = runtime_loopback_receipt_metadata(step)?;
    let receipt_id_seed = format!("rcpt-runtime-loopback-{step_index}");
    let _fixed_runtime_scope =
        chio_kernel::scope_fixed_runtime_for_current_thread(now_unix_ms / 1000, [receipt_id_seed]);
    let response = runtime
        .block_on(kernel.evaluate_tool_call_with_metadata(&request, Some(receipt_metadata)))
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback kernel evaluation step {}: {error}",
                step_index
            ))
        })?;
    if !matches!(response.verdict, chio_kernel::Verdict::Allow) {
        let failure_code = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata
                    .pointer("/chio_runtime/failure_code")
                    .or_else(|| metadata.pointer("/chio_runtime/failure_code"))
            })
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown_runtime_loopback_failure");
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime loopback kernel denied step {}: {} ({failure_code})",
            step_index,
            response
                .reason
                .as_deref()
                .unwrap_or("unknown_runtime_loopback_denial")
        )));
    }
    Ok(RuntimeLoopbackExecution {
        receipt: response.receipt,
        treaty: chio_treaty,
    })
}

fn runtime_loopback_agent_keypair(step_index: usize) -> chio_core::Keypair {
    let mut seed = [0u8; 32];
    seed[0] = 73;
    seed[31] = u8::try_from(step_index).unwrap_or(u8::MAX);
    chio_core::Keypair::from_seed(&seed)
}

#[cfg(test)]
mod tests {
    use super::{runtime_loopback_policy_inputs, runtime_loopback_receipt_metadata};
    use crate::scenario::RuntimeLoopbackStep;

    fn fixed_hash(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn runtime_loopback_step() -> RuntimeLoopbackStep {
        let request = chio_runtime_core::RuntimeRequestBinding {
            request_id: "req-loopback-policy".to_string(),
            capability_id: "cap-loopback-policy".to_string(),
            server_id: "server.vendor".to_string(),
            tool_name: "vendor.write_refund".to_string(),
            tool_args_sha256: fixed_hash('a'),
            origin_kernel_id: Some("kernel.buyer".to_string()),
            host_kernel_id: "kernel.vendor".to_string(),
        };
        RuntimeLoopbackStep {
            admission_profile: chio_runtime_core::RuntimeAdmissionProfile {
                schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
                profile_id: "profile-loopback-policy".to_string(),
                local_kernel_id: "kernel.vendor".to_string(),
                verifier_id: "did:chio:buyer-verifier".to_string(),
                issued_at_unix_ms: 1_800_000_000_000,
                expires_at_unix_ms: 1_800_003_600_000,
            },
            admission_bundle: chio_runtime_core::RuntimeAdmissionBundle {
                schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
                admission_id: "adm-loopback-policy".to_string(),
                binding: request.clone(),
                workflow_id: "wf-loopback-policy".to_string(),
                workflow_grant_id: "grant-loopback-policy".to_string(),
                step_index: 0,
                destructive: false,
                lease_id: None,
                governance_receipt_id: None,
                trust_bundle_sha256: fixed_hash('b'),
                verification_context_sha256: fixed_hash('c'),
            },
            request,
            arguments: None,
        }
    }

    #[test]
    fn runtime_loopback_policy_inputs_emit_chio_runtime_schemas(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let step = runtime_loopback_step();

        let (signed_trust, _trusted_keys, _query_report, signed_policy, signed_weights) =
            runtime_loopback_policy_inputs(&step, 1_800_000_010_000)?;

        assert_eq!(
            signed_trust.body.schema,
            chio_runtime_core::CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA
        );
        assert_eq!(
            signed_weights.body.schema,
            chio_runtime_core::CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA
        );
        assert_eq!(
            signed_policy.body.schema,
            chio_runtime_core::CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA
        );
        Ok(())
    }

    #[test]
    fn runtime_loopback_receipt_metadata_binds_workflow_and_vendor(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let step = runtime_loopback_step();
        let metadata = runtime_loopback_receipt_metadata(&step)?;

        assert_eq!(metadata["workflow_id"], "wf-loopback-policy");
        assert_eq!(metadata["vendor_id"], "kernel.vendor");
        Ok(())
    }
}
