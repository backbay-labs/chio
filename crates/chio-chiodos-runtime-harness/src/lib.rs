//! Live runtime loopback harness for Chiodos proof regeneration.

use std::fs;
use std::path::Path;

use chio_kernel::{ChioKernel, ToolCallRequest as KernelToolCallRequest};

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct RuntimeLoopbackError {
    message: String,
}

impl RuntimeLoopbackError {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub fn run_runtime_loopback_scenario(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<(), RuntimeLoopbackError> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RuntimeLoopbackScenario {
        run_id: String,
        #[serde(default)]
        admission_profile: Option<chio_chiodos_runtime::RuntimeAdmissionProfile>,
        #[serde(default)]
        admission_bundle: Option<chio_chiodos_runtime::RuntimeAdmissionBundle>,
        #[serde(default)]
        request: Option<chio_chiodos_runtime::RuntimeRequestBinding>,
        #[serde(default)]
        steps: Vec<RuntimeLoopbackStep>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RuntimeLoopbackStep {
        admission_profile: chio_chiodos_runtime::RuntimeAdmissionProfile,
        admission_bundle: chio_chiodos_runtime::RuntimeAdmissionBundle,
        request: chio_chiodos_runtime::RuntimeRequestBinding,
        #[serde(default)]
        arguments: Option<serde_json::Value>,
    }

    #[derive(Clone)]
    struct RuntimeLoopbackTreatyContext {
        treaty_scope: chio_chiodos_runtime::TreatyScope,
        treaty_scope_sha256: String,
        ladder_intersection: chio_chiodos_runtime::LadderIntersection,
        ladder_intersection_sha256: String,
        continuation: chio_chiodos_runtime::CrossKernelContinuation,
        continuation_sha256: String,
        lineage_bundle_id: String,
        intent_context: serde_json::Value,
    }

    struct RuntimeLoopbackExecution {
        receipt: chio_core::receipt::ChioReceipt,
        treaty: Option<RuntimeLoopbackTreatyContext>,
    }

    struct RuntimeLoopbackBuyerClosure {
        step_index: usize,
        admission_report: chio_chiodos_runtime::CrossBoundaryAdmissionReport,
        admission_report_sha256: String,
        continuation: chio_chiodos_runtime::CrossKernelContinuation,
        lineage_statement: chio_chiodos_runtime::ReceiptLineageStatement,
        lineage_statement_sha256: String,
        lineage_bundle: chio_chiodos_runtime::ReceiptLineageBundle,
        bilateral_invocation: chio_chiodos_runtime::BilateralInvocation,
        bilateral_invocation_sha256: String,
        bilateral_dsse: chio_federation::DsseEnvelope,
        bilateral_dsse_sha256: String,
    }

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
    ) -> Result<chio_core::capability::CapabilityToken, RuntimeLoopbackError> {
        let (issued_at, expires_at) = runtime_loopback_capability_window(now_unix_ms);
        let scope = chio_core::capability::ChioScope {
            grants: vec![chio_core::capability::ToolGrant {
                server_id: server_id.to_string(),
                tool_name: tool_name.to_string(),
                operations: vec![chio_core::capability::Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        };
        let body = chio_core::capability::CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope,
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
        };
        chio_core::capability::CapabilityToken::sign(body, issuer).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback capability signing: {error}"
            ))
        })
    }

    fn runtime_loopback_policy_summary(
        step: &RuntimeLoopbackStep,
    ) -> chio_federation::PolicyEvaluationSummary {
        let policy_version = "chiodos-ladder-v1".to_string();
        chio_federation::PolicyEvaluationSummary {
            server_a_verdict: chio_federation::PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: format!("buyer-policy:{}", step.request.tool_name),
                policy_version: policy_version.clone(),
                rationale_code: Some("lease-bound".to_string()),
            },
            server_b_verdict: chio_federation::PolicyVerdict {
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

    type RuntimeLoopbackPolicyInputs = (
        chio_chiodos_runtime::SignedRuntimeVerifierTrustBundle,
        Vec<chio_chiodos_runtime::RuntimeTrustedVerifierKey>,
        chio_chiodos_runtime::SignedRuntimePheromoneQueryReport,
        chio_chiodos_runtime::SignedRuntimePheromonePolicy,
        chio_chiodos_runtime::SignedRuntimePeerWeights,
    );

    fn runtime_loopback_policy_inputs(
        step: &RuntimeLoopbackStep,
        evaluation_now_unix_ms: u64,
    ) -> Result<RuntimeLoopbackPolicyInputs, RuntimeLoopbackError> {
        let verifier_key = chio_core::Keypair::from_seed(&[1_u8; 32]);
        let verifier_id = step.admission_profile.verifier_id.clone();
        let key_id = "verifier-key-1".to_string();
        let issued_at_unix_ms = step.admission_profile.issued_at_unix_ms;
        let expires_at_unix_ms = step.admission_profile.expires_at_unix_ms;
        let trusted_keys = vec![chio_chiodos_runtime::RuntimeTrustedVerifierKey {
            verifier_id: verifier_id.clone(),
            key_id: key_id.clone(),
            public_key: verifier_key.public_key(),
            valid_from_unix_ms: issued_at_unix_ms,
            valid_until_unix_ms: expires_at_unix_ms,
            status: "active".to_string(),
        }];
        let trust_body = chio_chiodos_runtime::RuntimeVerifierTrustBundleV4 {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA_V4
                .to_string(),
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
            chio_core::receipt::SignedExportEnvelope::sign(trust_body, &verifier_key).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime loopback trust signing: {error}"
                    ))
                },
            )?;
        let weights_body = chio_chiodos_runtime::RuntimePeerWeights {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
            verifier_id: verifier_id.clone(),
            key_id: key_id.clone(),
            reputation_epoch: 7,
            issued_at_unix_ms,
            expires_at_unix_ms,
            weights: vec![chio_chiodos_runtime::RuntimePeerWeight {
                peer_kernel_id: step.request.host_kernel_id.clone(),
                weight: 1.0,
            }],
        };
        let peer_weights_sha256 = chio_chiodos_runtime::runtime_peer_weights_sha256(&weights_body)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback peer weights hash: {error}"
                ))
            })?;
        let policy_body = chio_chiodos_runtime::RuntimePheromonePolicy {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
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
            rules: vec![chio_chiodos_runtime::RuntimePheromonePolicyRule {
                rule_id: "review-high-runtime-risk".to_string(),
                subject_class: "workflow.destructive_step".to_string(),
                subject_class_namespace: "chiodos.runtime".to_string(),
                action_class_id: "*".to_string(),
                direction: "deny_if_at_or_above".to_string(),
                threshold_total_strength: 0.9,
                effect: "require_review".to_string(),
            }],
        };
        let signed_policy =
            chio_core::receipt::SignedExportEnvelope::sign(policy_body, &verifier_key).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime loopback policy signing: {error}"
                    ))
                },
            )?;
        let signed_weights =
            chio_core::receipt::SignedExportEnvelope::sign(weights_body, &verifier_key).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime loopback peer weights signing: {error}"
                    ))
                },
            )?;
        let query_report_body = serde_json::json!({
            "schema": "chio.pheromone.query-report.v1",
            "accepted": true,
            "concentration": {
                "subjectClass": "workflow.destructive_step",
                "subjectClassNamespace": "chiodos.runtime",
                "totalStrength": 0.1,
                "distinctOriginPairs": 1,
                "reputationEpoch": 7,
                "evaluatedAtUnixMs": evaluation_now_unix_ms.saturating_sub(2_000)
            }
        });
        let signed_query_report =
            chio_core::receipt::SignedExportEnvelope::sign(query_report_body, &verifier_key)
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime loopback pheromone query report signing: {error}"
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

    fn execute_runtime_loopback_step(
        step_index: usize,
        step: &RuntimeLoopbackStep,
        arguments: serde_json::Value,
        now_unix_ms: u64,
    ) -> Result<RuntimeLoopbackExecution, RuntimeLoopbackError> {
        let (expected_kernel_id, expected_server_id, expected_tool_name) =
            chio_chiodos_loopback::runtime_vendor_binding(step_index).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback vendor binding: {error}"
                ))
            })?;
        if step.request.server_id != expected_server_id
            || step.request.tool_name != expected_tool_name
        {
            return Err(RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback step {} targets {}:{} but expected {}:{}",
                step_index,
                step.request.server_id,
                step.request.tool_name,
                expected_server_id,
                expected_tool_name
            )));
        }
        if step.request.host_kernel_id != expected_kernel_id {
            return Err(RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback step {} host kernel {} does not match {}",
                step_index, step.request.host_kernel_id, expected_kernel_id
            )));
        }
        let actual_args_sha256 =
            chio_chiodos_runtime::tool_args_sha256(&arguments).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback argument hash for step {}: {error}",
                    step_index
                ))
            })?;
        if actual_args_sha256 != step.request.tool_args_sha256 {
            return Err(RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback step {} arguments hash {} does not match request {}",
                step_index, actual_args_sha256, step.request.tool_args_sha256
            )));
        }
        let vendor_key =
            chio_chiodos_loopback::runtime_vendor_keypair(step_index).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback vendor key: {error}"
                ))
            })?;
        let agent_key = chio_core::Keypair::generate();
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
            policy_hash: format!("chiodos-runtime-loopback-policy:{}", step_index),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        });
        kernel.set_federation_local_kernel_id(step.request.host_kernel_id.clone());
        let receipt_store_path = std::env::temp_dir().join(format!(
            "chio-runtime-loopback-{}-{}.sqlite3",
            std::process::id(),
            step_index
        ));
        if receipt_store_path.exists() {
            fs::remove_file(&receipt_store_path).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "failed to clear Chiodos runtime loopback receipt store {}: {error}",
                    receipt_store_path.display()
                ))
            })?;
        }
        let receipt_store = chio_store_sqlite::SqliteReceiptStore::open(&receipt_store_path)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback receipt store open: {error}"
                ))
            })?;
        kernel.set_receipt_store(Box::new(receipt_store));
        let peer_pin_now_unix_ms = unix_now_ms();
        if let Some(origin_kernel_id) = step.request.origin_kernel_id.as_deref() {
            let origin_key = chio_chiodos_loopback::runtime_buyer_keypair();
            let now_secs = peer_pin_now_unix_ms / 1000;
            let trust = chio_federation::KernelTrustExchange::new(
                &step.request.host_kernel_id,
                vendor_key.clone(),
            )
            .with_trusted_peer(origin_kernel_id, origin_key.public_key());
            let envelope = chio_federation::PeerHandshakeEnvelope::sign(
                origin_kernel_id,
                &step.request.host_kernel_id,
                &format!("loopback-origin-nonce-{step_index}"),
                now_secs,
                &origin_key,
            )
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback peer handshake signing: {error}"
                ))
            })?;
            let peer = trust
                .accept_envelope(&envelope, origin_kernel_id, now_secs)
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime loopback peer pinning: {error}"
                    ))
                })?;
            kernel = kernel.with_federation_peers(vec![peer]);
            kernel.set_federation_cosigner(std::sync::Arc::new(
                chio_federation::InProcessCoSigner::new(
                    origin_kernel_id,
                    origin_key,
                    vendor_key.public_key(),
                ),
            ));
        }
        let hook_store = chio_chiodos_runtime::InMemoryRuntimeAdmissionStore::new();
        hook_store
            .insert_bundle(step.admission_bundle.clone())
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback hook store update: {error}"
                ))
            })?;
        let chiodos_treaty = if step.request.origin_kernel_id.is_some() {
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
            chio_chiodos_runtime::ChiodosRuntimeAdmissionHook::new(
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
        let bundle_sha256 = chio_chiodos_runtime::runtime_admission_bundle_sha256(
            &step.admission_bundle,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback bundle hash for step {}: {error}",
                step_index
            ))
        })?;
        let governed_intent = chio_core::capability::GovernedTransactionIntent {
            id: format!("intent:chiodos-runtime-loopback:{}", step_index),
            server_id: step.request.server_id.clone(),
            tool_name: step.request.tool_name.clone(),
            purpose: "Chiodos live runtime loopback proof regeneration".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(if let Some(chiodos_treaty) = chiodos_treaty.as_ref() {
                serde_json::json!({
                    "chiodosAdmission": {
                        "admissionId": step.admission_bundle.admission_id,
                        "bundleSha256": bundle_sha256
                    },
                    "chiodosTreaty": chiodos_treaty.intent_context
                })
            } else {
                serde_json::json!({
                "chiodosAdmission": {
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
            governed_intent: Some(governed_intent),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: step.request.origin_kernel_id.clone(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                RuntimeLoopbackError::message(format!("Chiodos runtime loopback executor: {error}"))
            })?;
        let response = runtime
            .block_on(kernel.evaluate_tool_call(&request))
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback kernel evaluation step {}: {error}",
                    step_index
                ))
            })?;
        if !matches!(response.verdict, chio_kernel::Verdict::Allow) {
            let failure_code = response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/chiodos_runtime/failure_code"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown_runtime_loopback_failure");
            return Err(RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback kernel denied step {}: {} ({failure_code})",
                step_index,
                response
                    .reason
                    .as_deref()
                    .unwrap_or("unknown_runtime_loopback_denial")
            )));
        }
        Ok(RuntimeLoopbackExecution {
            receipt: response.receipt,
            treaty: chiodos_treaty,
        })
    }

    fn insert_runtime_loopback_treaty_context(
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
            chio_core::sha256_hex(
                format!("runtime-loopback:{source_kernel_id}:manifest").as_bytes(),
            ),
            chio_core::sha256_hex(
                format!("runtime-loopback:{target_kernel_id}:manifest").as_bytes(),
            ),
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
        let treaty_scope_sha256 = chio_chiodos_runtime::treaty_scope_sha256(&treaty_scope)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback treaty scope hash: {error}"
                ))
            })?;
        let mut participant_modes = std::collections::BTreeMap::new();
        participant_modes.insert(source_kernel_id.clone(), "receipt_backed".to_string());
        participant_modes.insert(target_kernel_id.clone(), "receipt_backed".to_string());
        let requires_bilateral = step.admission_bundle.destructive
            || step.admission_bundle.governance_receipt_id.is_some();
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
        let parent_receipt_sha256 = chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:parent-receipt").as_bytes(),
        );
        let outcome_sha256 = chio_core::sha256_hex(
            format!("runtime-loopback:{step_index}:pre-dispatch-outcome").as_bytes(),
        );
        let action = chio_core::receipt::ToolCallAction::from_parameters(arguments.clone())
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback receipt action hash: {error}"
                ))
            })?;
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
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback receipt signing: {error}"
            ))
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
            chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation)
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime loopback bilateral invocation binding hash: {error}"
                    ))
                })?;
        let lineage_statement = chio_chiodos_runtime::ReceiptLineageStatement {
            schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            statement_id: format!("lineage:runtime-loopback:{step_index}"),
            parent_receipt_sha256: parent_receipt_sha256.clone(),
            child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            bilateral_invocation_sha256: bilateral_invocation_binding_sha256,
            evidence_class: "verified".to_string(),
            source_kernel_id: source_kernel_id.clone(),
            target_kernel_id: target_kernel_id.clone(),
        };
        let lineage_statement_sha256 = canonical_sha256_json(
            &lineage_statement,
            "Chiodos runtime loopback lineage statement hash",
        )?;
        bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
        let bilateral_invocation_sha256 = canonical_sha256_json(
            &bilateral_invocation,
            "Chiodos runtime loopback bilateral invocation hash",
        )?;
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

    fn build_runtime_loopback_buyer_closure(
        step_index: usize,
        step: &RuntimeLoopbackStep,
        treaty_context: &RuntimeLoopbackTreatyContext,
        baseline_package: &chio_chiodos::ChiodosProofPackage,
        now_unix_ms: u64,
    ) -> Result<
        (
            chio_chiodos::ChiodosProofPackage,
            RuntimeLoopbackBuyerClosure,
        ),
        RuntimeLoopbackError,
    > {
        let workflow_step = baseline_package
            .workflow_receipt
            .steps
            .get(step_index)
            .ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure missing workflow step {step_index}"
                ))
            })?;
        let tool_receipt_id = workflow_step.tool_receipt_id.as_ref().ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure step {} is missing tool receipt id",
                workflow_step.step_index
            ))
        })?;
        let receipt = baseline_package
            .tool_receipts
            .iter()
            .find(|receipt| receipt.id == *tool_receipt_id)
            .ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure missing tool receipt {tool_receipt_id}"
                ))
            })?;
        let tool_receipt_sha256 =
            canonical_sha256_json(receipt, "Chiodos runtime buyer closure receipt hash")?;
        let local_receipt_sha256 =
            workflow_step.parent_receipt_sha256.clone().ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime buyer closure requires a parent workflow receipt hash"
                        .to_string(),
                )
            })?;
        let outcome_sha256 = workflow_step.output_hash.clone().ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime buyer closure step is missing an output hash".to_string(),
            )
        })?;
        let mut bilateral_invocation = chio_chiodos_runtime::BilateralInvocation {
            schema: chio_chiodos_runtime::CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
            invocation_id: format!("bilateral:runtime-loopback:closure:{step_index}"),
            treaty_id: treaty_context.treaty_scope.treaty_id.clone(),
            ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
            continuation_sha256: treaty_context.continuation_sha256.clone(),
            lineage_statement_sha256: String::new(),
            action_class_id: format!("workflow.cross_kernel.{}", step.request.tool_name),
            consistency_model: "totally_ordered".to_string(),
            capability_id: step.request.capability_id.clone(),
            request_sha256: receipt.action.parameter_hash.clone(),
            outcome_sha256: outcome_sha256.clone(),
            local_receipt_sha256: local_receipt_sha256.clone(),
            remote_receipt_sha256: tool_receipt_sha256.clone(),
            signer_kernel_ids: vec![
                treaty_context.continuation.source_kernel_id.clone(),
                treaty_context.continuation.target_kernel_id.clone(),
            ],
        };
        let action_class_id = treaty_context
            .ladder_intersection
            .action_classes
            .first()
            .map(|action| action.action_class_id.clone())
            .ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime buyer closure treaty intersection has no action class"
                        .to_string(),
                )
            })?;
        bilateral_invocation.action_class_id = action_class_id.clone();
        let bilateral_invocation_sha256 =
            chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation)
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime buyer closure bilateral invocation hash: {error}"
                    ))
                })?;
        let lineage_statement = chio_chiodos_runtime::ReceiptLineageStatement {
            schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            statement_id: format!("lineage:runtime-loopback:closure:{step_index}"),
            parent_receipt_sha256: local_receipt_sha256.clone(),
            child_receipt_sha256: tool_receipt_sha256.clone(),
            continuation_sha256: treaty_context.continuation_sha256.clone(),
            bilateral_invocation_sha256: bilateral_invocation_sha256.clone(),
            evidence_class: "verified".to_string(),
            source_kernel_id: treaty_context.continuation.source_kernel_id.clone(),
            target_kernel_id: treaty_context.continuation.target_kernel_id.clone(),
        };
        let lineage_statement_sha256 = canonical_sha256_json(
            &lineage_statement,
            "Chiodos runtime buyer closure lineage statement hash",
        )?;
        bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
        let lineage_bundle = chio_chiodos_runtime::ReceiptLineageBundle {
            schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
            bundle_id: format!("{}:closure", treaty_context.lineage_bundle_id),
            root_receipt_sha256: local_receipt_sha256.clone(),
            leaf_receipt_sha256: tool_receipt_sha256.clone(),
            statements: vec![lineage_statement.clone()],
        };
        let lineage_bundle_sha256 = canonical_sha256_json(
            &lineage_bundle,
            "Chiodos runtime buyer closure lineage bundle hash",
        )?;
        let admission_report = chio_chiodos_runtime::evaluate_cross_boundary_admission(
            chio_chiodos_runtime::CrossBoundaryAdmissionInput {
                treaty_scope: &treaty_context.treaty_scope,
                ladder_intersection: &treaty_context.ladder_intersection,
                expected_ladder_intersection_sha256: Some(
                    treaty_context.ladder_intersection_sha256.clone(),
                ),
                action_class_id: &action_class_id,
                present_evidence: vec![
                    "receipt_lineage".to_string(),
                    "bilateral_invocation".to_string(),
                ],
                verified_evidence: vec![
                    chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                        evidence_class: "receipt_lineage".to_string(),
                        artifact_sha256: lineage_statement_sha256.clone(),
                        verified: true,
                    },
                    chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                        evidence_class: "bilateral_invocation".to_string(),
                        artifact_sha256: bilateral_invocation_sha256.clone(),
                        verified: true,
                    },
                ],
                now_unix_ms,
            },
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure admission report: {error}"
            ))
        })?;
        if !admission_report.accepted {
            return Err(RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure admission rejected: {}",
                admission_report
                    .failure_code
                    .as_deref()
                    .unwrap_or("unknown_treaty_closure_failure")
            )));
        }
        let admission_report_sha256 = canonical_sha256_json(
            &admission_report,
            "Chiodos runtime buyer closure admission report hash",
        )?;
        let lease_id = step.admission_bundle.lease_id.clone().ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime buyer closure requires a capability lease".to_string(),
            )
        })?;
        let lease = baseline_package
            .capability_leases
            .iter()
            .find(|lease| lease.body.lease_id == lease_id)
            .ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure missing lease {lease_id}"
                ))
            })?;
        let governance_receipt = workflow_step
            .governance_receipt_id
            .as_ref()
            .into_iter()
            .chain(step.admission_bundle.governance_receipt_id.as_ref())
            .find_map(|receipt_id| {
                baseline_package
                    .governance_receipts
                    .iter()
                    .find(|receipt| receipt.body.receipt_id == *receipt_id)
            })
            .or_else(|| {
                if baseline_package.governance_receipts.len() == 1 {
                    baseline_package.governance_receipts.first()
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime buyer closure requires a package governance receipt"
                        .to_string(),
                )
            })?;
        let governance_digest = canonical_sha256_json(
            governance_receipt,
            "Chiodos runtime buyer closure governance receipt digest",
        )?;
        let buyer_key = chio_chiodos_loopback::runtime_buyer_keypair();
        let vendor_key =
            chio_chiodos_loopback::runtime_vendor_keypair(step_index).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure vendor key: {error}"
                ))
            })?;
        let bilateral_dsse = chio_federation::sign_chiodos_dsse_envelope(
            receipt,
            &buyer_key,
            &vendor_key,
            &treaty_context.continuation.source_kernel_id,
            &treaty_context.continuation.target_kernel_id,
            &step.request.tool_name,
            now_unix_ms,
            chio_federation::BilateralPredicateExtensions {
                capability_lease_ref: Some(chio_federation::CapabilityLeaseRef {
                    lease_id: lease.body.lease_id.clone(),
                    issuer: lease.body.issuer.clone(),
                    expires_at_unix_ms: lease.body.expires_at_unix_ms,
                    scope_digest: Some(chio_federation::HashRecord {
                        alg: "sha256".to_string(),
                        value: lease.body.scope_digest.clone(),
                    }),
                }),
                policy_evaluation_summary: Some(runtime_loopback_policy_summary(step)),
                governance_receipt_ref: Some(chio_federation::GovernanceReceiptRef {
                    receipt_id: governance_receipt.body.receipt_id.clone(),
                    kernel_id: governance_receipt.body.authorizing_kernel.clone(),
                    digest: chio_federation::HashRecord {
                        alg: "sha256".to_string(),
                        value: governance_digest,
                    },
                }),
                consistency_anchor: workflow_step.consistency_anchor.clone(),
                consistency_model: Some(admission_report.consistency_model.clone()),
                cross_org_visibility: None,
                treaty_binding_ref: Some(chio_federation::TreatyBindingRef {
                    treaty_id: admission_report.treaty_id.clone(),
                    treaty_scope_sha256: treaty_context.treaty_scope_sha256.clone(),
                    ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
                    admission_report_sha256: admission_report_sha256.clone(),
                    continuation_sha256: treaty_context.continuation_sha256.clone(),
                    lineage_bundle_sha256,
                    action_class_id: admission_report.action_class_id.clone(),
                    consistency_model: admission_report.consistency_model.clone(),
                    request_sha256: bilateral_invocation.request_sha256.clone(),
                    outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                    local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                    lease_refs: vec![lease.body.lease_id.clone()],
                    governance_refs: vec![governance_receipt.body.receipt_id.clone()],
                    signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
                }),
            },
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure strict DSSE signing: {error}"
            ))
        })?;
        let bilateral_dsse_sha256 =
            canonical_sha256_json(&bilateral_dsse, "Chiodos runtime buyer closure DSSE hash")?;
        let mut runtime_artifacts = baseline_package
            .tool_receipts
            .iter()
            .cloned()
            .zip(baseline_package.bilateral_envelopes.iter().cloned())
            .zip(baseline_package.workflow_receipt.steps.iter().cloned())
            .map(|((tool_receipt, bilateral_envelope), workflow_step)| {
                chio_chiodos_loopback::RuntimeProofArtifact {
                    tool_receipt,
                    bilateral_envelope,
                    workflow_step,
                }
            })
            .collect::<Vec<_>>();
        let artifact = runtime_artifacts.get_mut(step_index).ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure missing artifact {step_index}"
            ))
        })?;
        artifact.bilateral_envelope = bilateral_dsse.clone();
        artifact.workflow_step.bilateral_dsse_sha256 = Some(bilateral_dsse_sha256.clone());
        let mut parent = None;
        for artifact in &mut runtime_artifacts {
            artifact.workflow_step.parent_receipt_sha256 = parent.clone();
            parent = Some(canonical_sha256_json(
                &artifact.workflow_step,
                "Chiodos runtime buyer closure workflow step hash",
            )?);
        }
        let package =
            chio_chiodos_loopback::proof_package_from_runtime_artifacts(runtime_artifacts)
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime buyer closure proof package: {error}"
                    ))
                })?;
        Ok((
            package,
            RuntimeLoopbackBuyerClosure {
                step_index,
                admission_report,
                admission_report_sha256,
                continuation: treaty_context.continuation.clone(),
                lineage_statement,
                lineage_statement_sha256,
                lineage_bundle,
                bilateral_invocation,
                bilateral_invocation_sha256,
                bilateral_dsse,
                bilateral_dsse_sha256,
            },
        ))
    }

    let scenario: RuntimeLoopbackScenario = serde_json::from_str(&read_utf8_json_file(
        scenario,
        "Chiodos runtime loopback scenario",
    )?)
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("Chiodos runtime loopback scenario parse: {error}"))
    })?;
    let steps = if scenario.steps.is_empty() {
        let admission_profile = scenario.admission_profile.ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime loopback scenario missing admissionProfile".to_string(),
            )
        })?;
        let admission_bundle = scenario.admission_bundle.ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime loopback scenario missing admissionBundle".to_string(),
            )
        })?;
        let request = scenario.request.ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime loopback scenario missing request".to_string(),
            )
        })?;
        vec![RuntimeLoopbackStep {
            admission_profile,
            admission_bundle,
            request,
            arguments: None,
        }]
    } else {
        scenario.steps
    };
    fs::create_dir_all(store_dir).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to create Chiodos runtime store directory {}: {error}",
            store_dir.display()
        ))
    })?;
    fs::create_dir_all(out_dir).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to create Chiodos runtime output directory {}: {error}",
            out_dir.display()
        ))
    })?;
    let store_path = store_dir.join("admission-store.json");
    let store =
        chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback admission store open: {error}"
            ))
        })?;
    let mut accepted = true;
    let mut failure_code = None;
    let mut evidence_paths = Vec::new();
    let mut admission_hashes = Vec::new();
    let mut step_evidence = Vec::new();
    let mut source_records = Vec::new();
    let mut evidence_manifest_entries = Vec::new();
    let mut live_tool_receipts = Vec::new();
    let mut live_treaty_contexts = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let admission_id = step.admission_bundle.admission_id.clone();
        store
            .insert_bundle(step.admission_bundle.clone())
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime loopback admission store update: {error}"
                ))
            })?;
        let (signed_trust, trusted_keys, query_report, signed_policy, signed_weights) =
            runtime_loopback_policy_inputs(step, now_unix_ms)?;
        let admission_report = chio_chiodos_runtime::evaluate_runtime_admission(
            chio_chiodos_runtime::RuntimeAdmissionInput {
                profile: &step.admission_profile,
                store: &store,
                admission_id: &admission_id,
                request: &step.request,
                action_class_id: None,
                runtime_trust_input: Some(&signed_trust),
                trusted_verifier_keys: &trusted_keys,
                pheromone_query_report: Some(&query_report),
                runtime_pheromone_policy: Some(&signed_policy),
                runtime_peer_weights: Some(&signed_weights),
                now_unix_ms,
            },
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!("Chiodos runtime loopback admission: {error}"))
        })?;
        let suffix = if steps.len() == 1 {
            String::new()
        } else {
            format!("-{}", index + 1)
        };
        let admission_report_name = format!("runtime-admission-report{suffix}.json");
        let admission_json = chio_chiodos_runtime::runtime_admission_report_json(&admission_report)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime admission report JSON: {error}"
                ))
            })?;
        let admission_artifact_hash = write_runtime_json_artifact_string(
            out_dir,
            "admission_report",
            &admission_report_name,
            &admission_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let admission_hash = chio_core::sha256_hex(admission_json.as_bytes());
        if admission_artifact_hash.is_empty() {
            return Err(RuntimeLoopbackError::message(
                "Chiodos runtime admission artifact hash was empty".to_string(),
            ));
        }
        admission_hashes.push(admission_hash.clone());
        if !admission_report.accepted {
            accepted = false;
            failure_code = admission_report.failure_code.clone();
            break;
        }
        let arguments = step.arguments.clone().ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime accepted step {} did not carry executable arguments",
                step.admission_bundle.step_index
            ))
        })?;
        let execution = execute_runtime_loopback_step(index, step, arguments, now_unix_ms)?;
        live_tool_receipts.push(execution.receipt);
        live_treaty_contexts.push(execution.treaty);
    }
    let mut proof_package_sha256 = None;
    let mut verifier_report_sha256 = None;
    let mut workflow_receipt_sha256 = None;
    let mut trust_bundle_sha256 = None;
    let mut verification_context_sha256 = None;
    let mut parity_report: Option<chio_chiodos_runtime::RuntimeProofParityReport> = None;
    let mut principal_admission_report_sha256 = None;
    let mut proof_checks = vec!["runtime_source_records.bound".to_string()];

    if accepted {
        if live_tool_receipts.len() != steps.len() {
            return Err(RuntimeLoopbackError::message(format!(
                "Chiodos runtime captured {} live receipts for {} accepted steps",
                live_tool_receipts.len(),
                steps.len()
            )));
        }
        let captured_receipt_hashes = live_tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chiodos runtime captured receipt canonical hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        proof_checks.push("runtime_kernel_receipts.captured".to_string());
        let baseline_package =
            chio_chiodos_loopback::proof_package_from_runtime_receipts(live_tool_receipts.clone())
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime proof package build from live receipts: {error}"
                    ))
                })?;
        let baseline_receipt_hashes = baseline_package
            .tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chiodos runtime package receipt canonical hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if baseline_receipt_hashes != captured_receipt_hashes {
            return Err(RuntimeLoopbackError::message(
                "Chiodos runtime proof package did not preserve captured live receipts".to_string(),
            ));
        }
        proof_checks.push("runtime_live_receipts.bound_to_proof_package".to_string());
        let parity_package = baseline_package.clone();
        let buyer_closure_index = steps
            .iter()
            .enumerate()
            .find(|(index, step)| {
                step.admission_bundle.destructive
                    && step.admission_bundle.governance_receipt_id.is_some()
                    && live_treaty_contexts
                        .get(*index)
                        .and_then(Option::as_ref)
                        .is_some()
            })
            .map(|(index, _)| index);
        let (package, buyer_closure) = if let Some(index) = buyer_closure_index {
            let treaty_context = live_treaty_contexts
                .get(index)
                .and_then(Option::as_ref)
                .ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime buyer closure missing treaty context for step {index}"
                    ))
                })?;
            let (package, closure) = build_runtime_loopback_buyer_closure(
                index,
                &steps[index],
                treaty_context,
                &baseline_package,
                now_unix_ms,
            )?;
            proof_checks.push("runtime_treaty_buyer_closure.bound".to_string());
            (package, Some(closure))
        } else {
            (baseline_package, None)
        };
        let package_receipt_hashes = package
            .tool_receipts
            .iter()
            .map(|receipt| {
                canonical_sha256_json(receipt, "Chiodos runtime final package receipt hash")
            })
            .collect::<Result<Vec<_>, _>>()?;
        if package_receipt_hashes != captured_receipt_hashes {
            return Err(RuntimeLoopbackError::message(
                "Chiodos runtime final proof package did not preserve captured live receipts"
                    .to_string(),
            ));
        }
        let context = chio_chiodos_loopback::verification_context();
        let trust_bundle_document =
            chio_chiodos_loopback::verifier_trust_bundle_document_for_package(&package).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime verifier trust bundle build: {error}"
                    ))
                },
            )?;
        let trust_bundle =
            chio_chiodos::ChiodosVerifierTrustBundle::from_document(trust_bundle_document.clone())
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime verifier trust bundle parse: {error}"
                    ))
                })?;
        let verifier_report =
            chio_chiodos::verify_package_report(&package, &trust_bundle, &context);

        let package_json = chio_chiodos::package_json(&package).map_err(|error| {
            RuntimeLoopbackError::message(format!("Chiodos runtime proof package JSON: {error}"))
        })?;
        let package_json_value: serde_json::Value =
            serde_json::from_str(&package_json).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime proof package JSON value: {error}"
                ))
            })?;
        let trust_bundle_json = chio_chiodos::verifier_trust_bundle_json(&trust_bundle_document)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime verifier trust bundle JSON: {error}"
                ))
            })?;
        write_runtime_json_artifact_string(
            out_dir,
            "verifier_trust_bundle",
            "verifier-trust-bundle.json",
            &trust_bundle_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let context_json = chio_chiodos::verification_context_json(&context).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime verification context JSON: {error}"
            ))
        })?;
        write_runtime_json_artifact_string(
            out_dir,
            "verification_context",
            "verification-context.json",
            &context_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let verifier_report_json =
            chio_chiodos::report_json(&verifier_report).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime verifier report JSON: {error}"
                ))
            })?;
        let verifier_report_artifact_sha256 = write_runtime_json_artifact_string(
            out_dir,
            "verifier_report",
            "verifier-report.json",
            &verifier_report_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        write_runtime_json_artifact(
            out_dir,
            "workflow_receipt",
            "workflow-receipt.json",
            &package.workflow_receipt,
            "Chiodos runtime workflow receipt JSON",
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;

        verifier_report_sha256 = Some(canonical_sha256_json(
            &verifier_report,
            "Chiodos runtime verifier report canonical hash",
        )?);
        workflow_receipt_sha256 = Some(canonical_sha256_json(
            &package.workflow_receipt,
            "Chiodos runtime workflow receipt canonical hash",
        )?);
        trust_bundle_sha256 = Some(trust_bundle.document_sha256().to_string());
        verification_context_sha256 = Some(
            chio_chiodos::verification_context_sha256(&context).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime verification context hash: {error}"
                ))
            })?,
        );
        if verifier_report_sha256.as_deref() != Some(verifier_report_artifact_sha256.as_str()) {
            proof_checks.push("runtime_verifier_report.canonical_hash_recorded".to_string());
        }

        for (index, step) in package.workflow_receipt.steps.iter().enumerate() {
            let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime workflow step {} missing tool receipt id",
                    step.step_index
                ))
            })?;
            let receipt = package
                .tool_receipts
                .iter()
                .find(|receipt| receipt.id == *tool_receipt_id)
                .ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime package missing tool receipt {}",
                        tool_receipt_id
                    ))
                })?;
            let envelope = package.bilateral_envelopes.get(index).ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime package missing DSSE envelope for step {}",
                    step.step_index
                ))
            })?;
            let receipt_name = format!("tool-receipt-{}.json", index + 1);
            let dsse_name = format!("bilateral-dsse-{}.json", index + 1);
            let workflow_step_name = format!("workflow-step-{}.json", index + 1);
            let tool_receipt_sha256 =
                canonical_sha256_json(receipt, "Chiodos runtime tool receipt canonical hash")?;
            let bilateral_dsse_sha256 =
                canonical_sha256_json(envelope, "Chiodos runtime bilateral DSSE canonical hash")?;
            let workflow_step_sha256 =
                canonical_sha256_json(step, "Chiodos runtime workflow step canonical hash")?;
            write_runtime_json_artifact(
                out_dir,
                "tool_receipt",
                &receipt_name,
                receipt,
                "Chiodos runtime tool receipt JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_dsse",
                &dsse_name,
                envelope,
                "Chiodos runtime bilateral DSSE JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "workflow_step",
                &workflow_step_name,
                step,
                "Chiodos runtime workflow step JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            let admission_report_sha256 = admission_hashes
                .get(index)
                .or_else(|| admission_hashes.last())
                .cloned()
                .ok_or_else(|| {
                    RuntimeLoopbackError::message(
                        "Chiodos runtime proof generation missing admission report hash"
                            .to_string(),
                    )
                })?;
            step_evidence.push(chio_chiodos_runtime::RuntimeStepEvidence {
                schema: chio_chiodos_runtime::CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
                step_index: u64::try_from(step.step_index).map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime step index conversion failed: {error}"
                    ))
                })?,
                admission_id: steps
                    .get(index)
                    .or_else(|| steps.last())
                    .map(|runtime_step| runtime_step.admission_bundle.admission_id.clone())
                    .ok_or_else(|| {
                        RuntimeLoopbackError::message(
                            "Chiodos runtime proof generation missing admission id".to_string(),
                        )
                    })?,
                admission_report_sha256: admission_report_sha256.clone(),
                tool_receipt_id: tool_receipt_id.clone(),
                tool_receipt_sha256: tool_receipt_sha256.clone(),
                output_sha256: step.output_hash.clone().ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime workflow step {} missing output hash",
                        step.step_index
                    ))
                })?,
                bilateral_dsse_sha256: bilateral_dsse_sha256.clone(),
                workflow_step_sha256: workflow_step_sha256.clone(),
                parent_receipt_sha256: step.parent_receipt_sha256.clone(),
                consistency_anchor: step.consistency_anchor.clone().ok_or_else(|| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime workflow step {} missing consistency anchor",
                        step.step_index
                    ))
                })?,
                destructive: step.destructive.unwrap_or(false),
                lease_id: package
                    .capability_leases
                    .get(index)
                    .map(|lease| lease.body.lease_id.clone()),
                governance_receipt_id: step.governance_receipt_id.clone(),
            });
            source_records.push(chio_chiodos_runtime::RuntimeProofSourceRecord {
                step_index: u64::try_from(step.step_index).map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime source step conversion failed: {error}"
                    ))
                })?,
                admission_report_sha256,
                tool_receipt_sha256,
                bilateral_dsse_sha256,
                workflow_step_sha256,
            });
        }

        if let Some(closure) = buyer_closure.as_ref() {
            let step = step_evidence.get_mut(closure.step_index).ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure missing step evidence {}",
                    closure.step_index
                ))
            })?;
            step.admission_report_sha256 = closure.admission_report_sha256.clone();
            let source_record = source_records.get_mut(closure.step_index).ok_or_else(|| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure missing source record {}",
                    closure.step_index
                ))
            })?;
            source_record.admission_report_sha256 = closure.admission_report_sha256.clone();
            principal_admission_report_sha256 = Some(closure.admission_report_sha256.clone());
            write_runtime_json_artifact(
                out_dir,
                "cross_boundary_admission_report",
                "cross-boundary-admission-report.json",
                &closure.admission_report,
                "Chiodos runtime buyer closure admission report JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "cross_kernel_continuation",
                "cross-kernel-continuation.json",
                &closure.continuation,
                "Chiodos runtime buyer closure continuation JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "receipt_lineage_statement",
                "receipt-lineage-statement.json",
                &closure.lineage_statement,
                "Chiodos runtime buyer closure lineage statement JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "receipt_lineage_bundle",
                "receipt-lineage-bundle.json",
                &closure.lineage_bundle,
                "Chiodos runtime buyer closure lineage bundle JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_invocation",
                "bilateral-invocation.json",
                &closure.bilateral_invocation,
                "Chiodos runtime buyer closure bilateral invocation JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
            write_runtime_json_artifact(
                out_dir,
                "bilateral_dsse_envelope",
                "bilateral-dsse-envelope.json",
                &closure.bilateral_dsse,
                "Chiodos runtime buyer closure bilateral DSSE JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
        }

        let proof_package_canonical_sha256 = canonical_sha256_json(
            &package_json_value,
            "Chiodos runtime proof package canonical hash",
        )?;
        proof_package_sha256 = Some(proof_package_canonical_sha256.clone());
        write_runtime_json_artifact_string(
            out_dir,
            "proof_package",
            "proof-package.json",
            &package_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        write_json_string(
            &out_dir.join("buyer-auditor-proof-package.json"),
            &format!("{package_json}\n"),
        )?;
        if let Some(closure) = buyer_closure.as_ref() {
            let workflow_sha256 = workflow_receipt_sha256.clone().ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime buyer packet missing workflow receipt hash".to_string(),
                )
            })?;
            let verifier_sha256 = verifier_report_sha256.clone().ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime buyer packet missing verifier report hash".to_string(),
                )
            })?;
            let packet = chio_chiodos_runtime::BuyerAttestationPacket {
                schema: chio_chiodos_runtime::CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA.to_string(),
                packet_id: format!("buyer-packet:{}", scenario.run_id),
                buyer_id: closure.continuation.source_kernel_id.clone(),
                capability_id: closure.bilateral_invocation.capability_id.clone(),
                treaty_scope_sha256: closure.admission_report.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: closure
                    .admission_report
                    .ladder_intersection_sha256
                    .clone(),
                cross_boundary_admission_report_sha256: closure.admission_report_sha256.clone(),
                continuation_sha256: closure.bilateral_invocation.continuation_sha256.clone(),
                receipt_lineage_statement_sha256: closure.lineage_statement_sha256.clone(),
                bilateral_invocation_sha256: closure.bilateral_invocation_sha256.clone(),
                bilateral_dsse_sha256: closure.bilateral_dsse_sha256.clone(),
                workflow_receipt_sha256: workflow_sha256,
                proof_package_sha256: proof_package_canonical_sha256.clone(),
                verifier_report_sha256: verifier_sha256,
                budget_refs: vec![format!(
                    "budget.reserve:{}",
                    closure.bilateral_invocation.capability_id
                )],
                settlement_claimed: false,
            };
            write_runtime_json_artifact(
                out_dir,
                "buyer_attestation_packet",
                "buyer-attestation-packet.json",
                &packet,
                "Chiodos runtime buyer attestation packet JSON",
                &mut evidence_manifest_entries,
                &mut evidence_paths,
            )?;
        }

        let static_package = chio_chiodos_loopback::fixture_proof_package().map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos static three-vendor proof package: {error}"
            ))
        })?;
        let static_report = chio_chiodos_loopback::fixture_verifier_report().map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos static three-vendor verifier report: {error}"
            ))
        })?;
        let parity_trust_bundle_document =
            chio_chiodos_loopback::verifier_trust_bundle_document_for_package(&parity_package)
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime parity trust bundle build: {error}"
                    ))
                })?;
        let parity_trust_bundle =
            chio_chiodos::ChiodosVerifierTrustBundle::from_document(parity_trust_bundle_document)
                .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime parity trust bundle parse: {error}"
                ))
            })?;
        let parity_verifier_report =
            chio_chiodos::verify_package_report(&parity_package, &parity_trust_bundle, &context);
        let (compared_fields, mismatches) = runtime_proof_parity(&static_package, &parity_package)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!("Chiodos runtime proof parity: {error}"))
            })?;
        let parity_accepted = mismatches.is_empty() && parity_verifier_report.accepted;
        parity_report = Some(chio_chiodos_runtime::RuntimeProofParityReport {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PROOF_PARITY_REPORT_SCHEMA.to_string(),
            run_id: scenario.run_id.clone(),
            accepted: parity_accepted,
            failure_code: if parity_accepted {
                None
            } else {
                Some("runtime_proof_semantic_parity_mismatch".to_string())
            },
            generated_at_unix_ms: now_unix_ms,
            static_proof_package_sha256: chio_chiodos::package_sha256(&static_package).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos static proof package hash: {error}"
                    ))
                },
            )?,
            runtime_proof_package_sha256: chio_chiodos::package_sha256(&parity_package).map_err(
                |error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime parity proof package hash: {error}"
                    ))
                },
            )?,
            static_verifier_report_sha256: canonical_sha256_json(
                &static_report,
                "Chiodos static verifier report canonical hash",
            )?,
            runtime_verifier_report_sha256: canonical_sha256_json(
                &parity_verifier_report,
                "Chiodos runtime parity verifier report hash",
            )?,
            compared_fields,
            mismatches,
        });

        if verifier_report.accepted && parity_report.as_ref().is_some_and(|report| report.accepted)
        {
            proof_checks.push("runtime_semantic_proof_regeneration.verified".to_string());
        } else {
            accepted = false;
            failure_code = if verifier_report.accepted {
                Some("runtime_proof_semantic_parity_mismatch".to_string())
            } else {
                verifier_report
                    .failure
                    .as_ref()
                    .map(|failure| failure.code.clone())
                    .or_else(|| Some("runtime_proof_semantic_verifier_rejected".to_string()))
            };
        }
    } else {
        proof_checks.push("runtime_admission.denied".to_string());
    }

    let proof_regeneration_report = chio_chiodos_runtime::RuntimeProofRegenerationReport {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA.to_string(),
        run_id: scenario.run_id.clone(),
        accepted,
        failure_code: if accepted { None } else { failure_code.clone() },
        generated_at_unix_ms: now_unix_ms,
        proof_package_sha256,
        verifier_report_sha256,
        workflow_receipt_sha256,
        source_records: source_records.clone(),
        checks: proof_checks,
    };
    let proof_regeneration_json =
        chio_chiodos_runtime::runtime_proof_regeneration_report_json(&proof_regeneration_report)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime proof regeneration report: {error}"
                ))
            })?;
    write_runtime_json_artifact_string(
        out_dir,
        "proof_regeneration_report",
        "proof-regeneration-report.json",
        &proof_regeneration_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let proof_regeneration_report_sha256 = canonical_sha256_json(
        &proof_regeneration_report,
        "Chiodos runtime proof regeneration report canonical hash",
    )?;
    if let Some(parity_report) = parity_report.as_ref() {
        let parity_json = chio_chiodos_runtime::runtime_proof_parity_report_json(parity_report)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime proof parity report: {error}"
                ))
            })?;
        write_runtime_json_artifact_string(
            out_dir,
            "proof_parity_report",
            "runtime-proof-parity-report.json",
            &parity_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
    }
    let runtime_admission_report_sha256 = principal_admission_report_sha256
        .clone()
        .unwrap_or_else(|| chio_core::sha256_hex(admission_hashes.join(":").as_bytes()));
    let workflow_report = chio_chiodos_runtime::RuntimeWorkflowRunReport {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
        run_id: scenario.run_id.clone(),
        accepted,
        failure_code,
        generated_at_unix_ms: now_unix_ms,
        admission_report_sha256: runtime_admission_report_sha256.clone(),
        evidence_paths: evidence_paths.clone(),
        step_evidence,
        proof_regeneration_report_sha256: Some(proof_regeneration_report_sha256.clone()),
    };
    let workflow_report_json = chio_chiodos_runtime::runtime_workflow_run_report_json(
        &workflow_report,
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("Chiodos runtime workflow run report: {error}"))
    })?;
    write_runtime_json_artifact_string(
        out_dir,
        "runtime_run_report",
        "runtime-run-report.json",
        &workflow_report_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    write_runtime_json_artifact_string(
        out_dir,
        "workflow_run_report",
        "workflow-run-report.json",
        &workflow_report_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let workflow_run_report_sha256 = canonical_sha256_json(
        &workflow_report,
        "Chiodos runtime workflow run report canonical hash",
    )?;
    let manifest = chio_chiodos_runtime::RuntimeEvidenceManifest {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
        run_id: scenario.run_id.clone(),
        generated_at_unix_ms: now_unix_ms,
        workflow_run_report_sha256: workflow_run_report_sha256.clone(),
        proof_regeneration_report_sha256: proof_regeneration_report_sha256.clone(),
        entries: evidence_manifest_entries.clone(),
    };
    let manifest_json =
        chio_chiodos_runtime::runtime_evidence_manifest_json(&manifest).map_err(|error| {
            RuntimeLoopbackError::message(format!("Chiodos runtime evidence manifest: {error}"))
        })?;
    write_runtime_json_artifact_string(
        out_dir,
        "runtime_evidence_manifest",
        "runtime-evidence-manifest.json",
        &manifest_json,
        &mut evidence_manifest_entries,
        &mut evidence_paths,
    )?;
    let evidence_manifest_sha256 = canonical_sha256_json(
        &manifest,
        "Chiodos runtime evidence manifest canonical hash",
    )?;
    if accepted {
        let regeneration_input = chio_chiodos_runtime::RuntimeProofRegenerationInput {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA
                .to_string(),
            run_id: scenario.run_id,
            evidence_manifest_sha256,
            workflow_run_report_sha256,
            admission_report_sha256: runtime_admission_report_sha256,
            trust_bundle_sha256: trust_bundle_sha256.ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime proof input missing trust bundle hash".to_string(),
                )
            })?,
            verification_context_sha256: verification_context_sha256.ok_or_else(|| {
                RuntimeLoopbackError::message(
                    "Chiodos runtime proof input missing context hash".to_string(),
                )
            })?,
            source_records,
        };
        let input_json =
            chio_chiodos_runtime::runtime_proof_regeneration_input_json(&regeneration_input)
                .map_err(|error| {
                    RuntimeLoopbackError::message(format!(
                        "Chiodos runtime proof regeneration input: {error}"
                    ))
                })?;
        write_runtime_json_artifact_string(
            out_dir,
            "proof_regeneration_input",
            "runtime-proof-regeneration-input.json",
            &input_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
    }
    if workflow_report.accepted {
        Ok(())
    } else {
        Err(RuntimeLoopbackError::message(format!(
            "Chiodos runtime loopback rejected request: {}",
            workflow_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_runtime_loopback_failure")
        )))
    }
}

fn write_runtime_json_artifact<T: serde::Serialize>(
    out_dir: &Path,
    role: &str,
    relative_path: &str,
    value: &T,
    label: &str,
    entries: &mut Vec<chio_chiodos_runtime::RuntimeEvidenceManifestEntry>,
    evidence_paths: &mut Vec<String>,
) -> Result<String, RuntimeLoopbackError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| RuntimeLoopbackError::message(format!("{label}: {error}")))?;
    write_runtime_json_artifact_string(out_dir, role, relative_path, &json, entries, evidence_paths)
}

fn write_runtime_json_artifact_string(
    out_dir: &Path,
    role: &str,
    relative_path: &str,
    json: &str,
    entries: &mut Vec<chio_chiodos_runtime::RuntimeEvidenceManifestEntry>,
    evidence_paths: &mut Vec<String>,
) -> Result<String, RuntimeLoopbackError> {
    validate_runtime_relative_path(relative_path)?;
    let json_with_newline = format!("{json}\n");
    let sha256 = chio_core::sha256_hex(json_with_newline.as_bytes());
    let byte_count = u64::try_from(json_with_newline.len()).map_err(|error| {
        RuntimeLoopbackError::message(format!("Chiodos runtime artifact byte count: {error}"))
    })?;
    write_json_string(&out_dir.join(relative_path), &json_with_newline)?;
    entries.push(chio_chiodos_runtime::RuntimeEvidenceManifestEntry {
        role: role.to_string(),
        path: relative_path.to_string(),
        sha256: sha256.clone(),
        byte_count,
    });
    if !evidence_paths.iter().any(|path| path == relative_path) {
        evidence_paths.push(relative_path.to_string());
    }
    Ok(sha256)
}

fn validate_runtime_relative_path(relative_path: &str) -> Result<(), RuntimeLoopbackError> {
    if relative_path.trim() != relative_path
        || relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path.contains(':')
        || relative_path.contains("//")
        || relative_path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(RuntimeLoopbackError::message(format!(
            "Chiodos runtime artifact path {relative_path:?} is not safe relative evidence"
        )));
    }
    Ok(())
}

fn canonical_sha256_json<T: serde::Serialize>(
    value: &T,
    label: &str,
) -> Result<String, RuntimeLoopbackError> {
    let bytes = chio_core_types::canonical::canonical_json_bytes(value)
        .map_err(|error| RuntimeLoopbackError::message(format!("{label}: {error}")))?;
    Ok(chio_core::sha256_hex(&bytes))
}

fn runtime_proof_parity(
    static_package: &chio_chiodos::ChiodosProofPackage,
    runtime_package: &chio_chiodos::ChiodosProofPackage,
) -> Result<
    (
        Vec<String>,
        Vec<chio_chiodos_runtime::RuntimeProofParityMismatch>,
    ),
    RuntimeLoopbackError,
> {
    let compared_fields = vec![
        "proof_claims".to_string(),
        "workflow_id".to_string(),
        "workflow_step_count".to_string(),
        "workflow_step_semantics".to_string(),
        "workflow_intersection_id".to_string(),
        "workflow_step_class_bindings".to_string(),
        "workflow_required_vendor_signers".to_string(),
        "tool_receipt_targets".to_string(),
        "tool_receipt_semantics".to_string(),
        "bilateral_dsse_predicate_semantics".to_string(),
        "lease_scope_semantics".to_string(),
        "governance_authorization_presence".to_string(),
        "destructive_step_flags".to_string(),
    ];
    let mut mismatches = Vec::new();
    compare_runtime_proof_field(
        "proof_claims",
        &static_package.claims,
        &runtime_package.claims,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_id",
        &static_package.workflow_id,
        &runtime_package.workflow_id,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_count",
        &static_package.workflow_receipt.steps.len(),
        &runtime_package.workflow_receipt.steps.len(),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_semantics",
        &workflow_step_semantics(static_package),
        &workflow_step_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_intersection_id",
        &static_package.workflow_intersection.intersection_id,
        &runtime_package.workflow_intersection.intersection_id,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_class_bindings",
        &static_package.workflow_intersection.step_class_bindings,
        &runtime_package.workflow_intersection.step_class_bindings,
        &mut mismatches,
    )?;
    let static_signers: Vec<&str> = static_package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|signer| signer.vendor_id.as_str())
        .collect();
    let runtime_signers: Vec<&str> = runtime_package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|signer| signer.vendor_id.as_str())
        .collect();
    compare_runtime_proof_field(
        "workflow_required_vendor_signers",
        &static_signers,
        &runtime_signers,
        &mut mismatches,
    )?;
    let static_receipt_targets: Vec<(&str, &str, &str)> = static_package
        .tool_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.capability_id.as_str(),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
            )
        })
        .collect();
    let runtime_receipt_targets: Vec<(&str, &str, &str)> = runtime_package
        .tool_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.capability_id.as_str(),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
            )
        })
        .collect();
    compare_runtime_proof_field(
        "tool_receipt_targets",
        &static_receipt_targets,
        &runtime_receipt_targets,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "tool_receipt_semantics",
        &tool_receipt_semantics(static_package),
        &tool_receipt_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "bilateral_dsse_predicate_semantics",
        &bilateral_dsse_predicate_semantics(static_package)?,
        &bilateral_dsse_predicate_semantics(runtime_package)?,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "lease_scope_semantics",
        &lease_scope_semantics(static_package),
        &lease_scope_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "governance_authorization_presence",
        &governance_authorization_presence(static_package),
        &governance_authorization_presence(runtime_package),
        &mut mismatches,
    )?;
    let static_destructive: Vec<Option<bool>> = static_package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.destructive)
        .collect();
    let runtime_destructive: Vec<Option<bool>> = runtime_package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.destructive)
        .collect();
    compare_runtime_proof_field(
        "destructive_step_flags",
        &static_destructive,
        &runtime_destructive,
        &mut mismatches,
    )?;
    Ok((compared_fields, mismatches))
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct WorkflowStepParityBinding {
    step_index: usize,
    server_id: String,
    tool_name: String,
    allowed: bool,
    has_tool_receipt: bool,
    has_output_hash: bool,
    has_bilateral_dsse: bool,
    has_governance_receipt: bool,
    has_parent_receipt: bool,
    has_consistency_anchor: bool,
    destructive: Option<bool>,
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ToolReceiptParityBinding {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    action_parameter_hash: String,
    decision_allowed: bool,
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct BilateralDssePredicateParityBinding {
    predicate_type: String,
    tool_server_a: String,
    tool_server_b: String,
    tool_name: String,
    co_sign: String,
    consistency_model: String,
    tool_args_hash: Option<String>,
    has_capability_lease_ref: bool,
    has_capability_lease_scope_digest: bool,
    has_governance_receipt_ref: bool,
    has_consistency_anchor: bool,
    has_treaty_binding: bool,
}

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LeaseScopeParityBinding {
    workflow_id: String,
    workflow_grant_id: String,
    step_index: usize,
    tool_name: String,
    peer_kernel_id: String,
    action_class_id: String,
    subject: String,
    action_class: String,
    tool_args_hash: String,
    destructive: bool,
}

fn workflow_step_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<WorkflowStepParityBinding> {
    package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| WorkflowStepParityBinding {
            step_index: step.step_index,
            server_id: step.server_id.clone(),
            tool_name: step.tool_name.clone(),
            allowed: step.allowed,
            has_tool_receipt: step.tool_receipt_id.is_some(),
            has_output_hash: step.output_hash.is_some(),
            has_bilateral_dsse: step.bilateral_dsse_sha256.is_some(),
            has_governance_receipt: step.governance_receipt_id.is_some(),
            has_parent_receipt: step.parent_receipt_sha256.is_some(),
            has_consistency_anchor: step.consistency_anchor.is_some(),
            destructive: step.destructive,
        })
        .collect()
}

fn tool_receipt_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<ToolReceiptParityBinding> {
    package
        .tool_receipts
        .iter()
        .map(|receipt| ToolReceiptParityBinding {
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            action_parameter_hash: receipt.action.parameter_hash.clone(),
            decision_allowed: matches!(&receipt.decision, chio_core::receipt::Decision::Allow),
        })
        .collect()
}

fn bilateral_dsse_predicate_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Result<Vec<BilateralDssePredicateParityBinding>, RuntimeLoopbackError> {
    package
        .bilateral_envelopes
        .iter()
        .map(|envelope| {
            let (statement, _) = envelope.decode_statement().map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime parity DSSE statement decode: {error}"
                ))
            })?;
            let predicate = statement.predicate;
            Ok(BilateralDssePredicateParityBinding {
                predicate_type: statement.predicate_type,
                tool_server_a: predicate.tool_server_a.kernel_id,
                tool_server_b: predicate.tool_server_b.kernel_id,
                tool_name: predicate.tool_name,
                co_sign: predicate.co_sign,
                consistency_model: predicate.consistency_model,
                tool_args_hash: predicate.tool_args_hash.map(|hash| hash.value),
                has_capability_lease_ref: predicate.capability_lease_ref.is_some(),
                has_capability_lease_scope_digest: predicate
                    .capability_lease_ref
                    .is_some_and(|lease| lease.scope_digest.is_some()),
                has_governance_receipt_ref: predicate.governance_receipt_ref.is_some(),
                has_consistency_anchor: predicate.consistency_anchor.is_some(),
                has_treaty_binding: predicate.treaty_binding_ref.is_some(),
            })
        })
        .collect()
}

fn lease_scope_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<LeaseScopeParityBinding> {
    package
        .lease_scope_bindings
        .iter()
        .map(|binding| LeaseScopeParityBinding {
            workflow_id: binding.workflow_id.clone(),
            workflow_grant_id: binding.workflow_grant_id.clone(),
            step_index: binding.step_index,
            tool_name: binding.tool_name.clone(),
            peer_kernel_id: binding.peer_kernel_id.clone(),
            action_class_id: binding.action_class_id.clone(),
            subject: binding.subject.clone(),
            action_class: format!("{:?}", binding.action_class),
            tool_args_hash: binding.tool_args_hash.clone(),
            destructive: binding.destructive,
        })
        .collect()
}

fn governance_authorization_presence(package: &chio_chiodos::ChiodosProofPackage) -> Vec<bool> {
    package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.governance_receipt_id.is_some())
        .collect()
}

fn compare_runtime_proof_field<T: serde::Serialize + PartialEq>(
    field: &str,
    static_value: &T,
    runtime_value: &T,
    mismatches: &mut Vec<chio_chiodos_runtime::RuntimeProofParityMismatch>,
) -> Result<(), RuntimeLoopbackError> {
    if static_value != runtime_value {
        mismatches.push(chio_chiodos_runtime::RuntimeProofParityMismatch {
            field: field.to_string(),
            static_value_sha256: canonical_sha256_json(
                static_value,
                "Chiodos runtime static parity field hash",
            )?,
            runtime_value_sha256: canonical_sha256_json(
                runtime_value,
                "Chiodos runtime regenerated parity field hash",
            )?,
        });
    }
    Ok(())
}

fn read_utf8_json_file(path: &Path, label: &str) -> Result<String, RuntimeLoopbackError> {
    let bytes = fs::read(path).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to read {label} {}: {error}",
            path.display()
        ))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "{label} {} is not UTF-8 JSON: {error}",
            path.display()
        ))
    })
}

fn write_json_string(path: &Path, json: &str) -> Result<(), RuntimeLoopbackError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "failed to create Chiodos output directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    fs::write(path, json).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to write Chiodos JSON {}: {error}",
            path.display()
        ))
    })
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| {
            let millis = duration.as_millis();
            u64::try_from(millis).unwrap_or(u64::MAX)
        })
        .unwrap_or(0)
}

pub fn runtime_loopback_capability_window(now_unix_ms: u64) -> (u64, u64) {
    let scenario_now = now_unix_ms / 1000;
    let wall_now = unix_now_ms() / 1000;
    (
        scenario_now.min(wall_now).saturating_sub(60),
        scenario_now.max(wall_now).saturating_add(157_680_000),
    )
}
