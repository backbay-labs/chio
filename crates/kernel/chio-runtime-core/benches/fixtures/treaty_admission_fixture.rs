use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    metadata::ActorRef,
};
use chio_federation::bilateral_dsse::{
    sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    GovernanceReceiptRef, HashRecord, PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef,
};
use chio_federation::trust_establishment::{KernelTrustExchange, PeerHandshakeEnvelope};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_runtime_core::{
    bilateral_dsse_consistency_model, bilateral_invocation_binding_sha256,
    compute_ladder_intersection, governance_ladder_manifest_sha256, ladder_intersection_sha256,
    runtime_admission_bundle_sha256, tool_args_sha256, treaty_scope_sha256, BilateralInvocation,
    ChioRuntimeAdmissionHook, CrossKernelContinuation, GovernanceLadderActionClass,
    GovernanceLadderManifest, InMemoryRuntimeAdmissionStore, ReceiptLineageBundle,
    ReceiptLineageStatement, RuntimeAdmissionBundle, RuntimeAdmissionProfile,
    RuntimeRequestBinding, TreatyScope, CHIO_BILATERAL_INVOCATION_SCHEMA,
    CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA, CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA,
    CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA, CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
    CHIO_TREATY_SCOPE_SCHEMA,
};
use chio_store_sqlite::SqliteReceiptStore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::{tempdir, TempDir};
use tokio::runtime::{Builder, Runtime};

const NOW_UNIX_MS: u64 = 1_800_000_001_000;
const CAPABILITY_ID: &str = "cap-bench-treaty-deny";
const ACTION_CLASS_ID: &str = "workflow.destructive.vendor_call";

pub struct TreatyPredispatchDenyFixture {
    kernel: ChioKernel,
    base_request: ToolCallRequest,
    base_bundle: RuntimeAdmissionBundle,
    store: InMemoryRuntimeAdmissionStore,
    request_sequence: AtomicU64,
    last_receipt_id: Mutex<Option<String>>,
    tool_invocations: Arc<AtomicU64>,
    runtime: Runtime,
    _receipt_directory: TempDir,
}

impl TreatyPredispatchDenyFixture {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let args = serde_json::json!({
            "record": "vendor-ledger-7",
            "value": "closed"
        });
        let binding = RuntimeRequestBinding {
            request_id: "req-bench-treaty-deny".to_string(),
            capability_id: CAPABILITY_ID.to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            tool_args_sha256: tool_args_sha256(&args)?,
            origin_kernel_id: Some("kernel.buyer".to_string()),
            host_kernel_id: "kernel.vendor-b".to_string(),
        };
        let bundle = RuntimeAdmissionBundle {
            schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
            admission_id: "adm-bench-treaty-deny".to_string(),
            binding,
            workflow_id: "wf-bench-treaty-deny".to_string(),
            workflow_grant_id: "grant-bench-treaty-deny".to_string(),
            step_index: 1,
            destructive: true,
            lease_id: Some("lease-bench-treaty-deny".to_string()),
            governance_receipt_id: Some("gov-bench-treaty-deny".to_string()),
            trust_bundle_sha256: "b".repeat(64),
            verification_context_sha256: "c".repeat(64),
        };
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        let artifacts = TreatyArtifacts::new(&args)?;
        let store = InMemoryRuntimeAdmissionStore::new();
        artifacts.insert_into(&store)?;
        let request = treaty_request(args, bundle_sha256, &artifacts)?;
        let profile = RuntimeAdmissionProfile {
            schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
            profile_id: "profile-bench-treaty-deny".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            verifier_id: "did:chio:buyer-verifier".to_string(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
        };
        let hook = ChioRuntimeAdmissionHook::new(profile, store.clone())
            .with_fixed_now_unix_ms(NOW_UNIX_MS);
        let tool_invocations = Arc::new(AtomicU64::new(0));
        let config = kernel_config();
        let peer_now_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let origin_keypair = Keypair::from_seed(&[21_u8; 32]);
        let trust = KernelTrustExchange::new("kernel.vendor-b", config.keypair.clone())
            .with_trusted_peer("kernel.buyer", origin_keypair.public_key());
        let peer_envelope = PeerHandshakeEnvelope::sign(
            "kernel.buyer",
            "kernel.vendor-b",
            "nonce-bench-treaty-peer",
            peer_now_unix_secs,
            &origin_keypair,
        )?;
        let peer = trust.accept_envelope(&peer_envelope, "kernel.buyer", peer_now_unix_secs)?;
        let mut kernel = ChioKernel::new(config).with_federation_peers(vec![peer]);
        kernel.set_federation_local_kernel_id("kernel.vendor-b");
        let receipt_directory = tempdir()?;
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(
            receipt_directory.path().join("receipts.sqlite3"),
        )?))?;
        kernel.register_tool_server(Box::new(CountingToolServer {
            invocations: Arc::clone(&tool_invocations),
        }));
        kernel.set_runtime_admission_hook(Arc::new(hook));
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let fixture = Self {
            kernel,
            base_request: request,
            base_bundle: bundle,
            store,
            request_sequence: AtomicU64::new(0),
            last_receipt_id: Mutex::new(None),
            tool_invocations,
            runtime,
            _receipt_directory: receipt_directory,
        };
        let smoke_request = fixture.prepare_request()?;
        assert!(
            fixture.evaluate_once(&smoke_request),
            "real treaty admission hook fixture must deny the unanimous policy verdict"
        );
        Ok(fixture)
    }

    pub fn prepare_request(&self) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
        let sequence = self.request_sequence.fetch_add(1, Ordering::SeqCst);
        let request_id = format!("req-bench-treaty-deny-{sequence}");
        let admission_id = format!("adm-bench-treaty-deny-{sequence}");
        let mut bundle = self.base_bundle.clone();
        bundle.admission_id.clone_from(&admission_id);
        bundle.binding.request_id.clone_from(&request_id);
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        self.store.insert_bundle(bundle)?;

        let mut request = self.base_request.clone();
        request.request_id = request_id;
        let intent = request
            .governed_intent
            .as_mut()
            .ok_or_else(|| std::io::Error::other("benchmark governed intent is missing"))?;
        intent.id = format!("intent-bench-treaty-deny-{sequence}");
        let admission = intent
            .context
            .as_mut()
            .and_then(|context| context.get_mut("chioAdmission"))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| std::io::Error::other("benchmark admission context is missing"))?;
        admission.insert(
            "admissionId".to_string(),
            serde_json::Value::String(admission_id),
        );
        admission.insert(
            "bundleSha256".to_string(),
            serde_json::Value::String(bundle_sha256),
        );
        Ok(request)
    }

    pub fn evaluate_once(&self, request: &ToolCallRequest) -> bool {
        let invocations_before = self.tool_invocations.load(Ordering::SeqCst);
        let response = match self
            .runtime
            .block_on(self.kernel.evaluate_tool_call(request))
        {
            Ok(response) => response,
            Err(error) => panic!("real treaty admission hook benchmark failed: {error}"),
        };
        let denied_before_dispatch = response.verdict == Verdict::Deny
            && response.reason.as_deref() == Some("chio treaty-bound runtime admission denied")
            && response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["chio_runtime"]["failure_code"].as_str())
                == Some("chio_treaty_policy_denied")
            && self.tool_invocations.load(Ordering::SeqCst) == invocations_before;
        if !denied_before_dispatch {
            panic!(
                "unexpected treaty benchmark response: {response:#?}; tool invocations before={invocations_before}, after={}",
                self.tool_invocations.load(Ordering::SeqCst)
            );
        }
        let mut last_receipt_id = match self.last_receipt_id.lock() {
            Ok(last_receipt_id) => last_receipt_id,
            Err(error) => panic!("benchmark receipt-id tracker is poisoned: {error}"),
        };
        if last_receipt_id.as_deref() == Some(response.receipt.id.as_str()) {
            panic!(
                "benchmark request {} replayed receipt {}",
                request.request_id, response.receipt.id
            );
        }
        *last_receipt_id = Some(response.receipt.id);
        true
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::from_seed(&[25_u8; 32]),
        ca_public_keys: vec![Keypair::from_seed(&[23_u8; 32]).public_key()],
        max_delegation_depth: 5,
        policy_hash: "policy-bench-treaty-deny".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

struct CountingToolServer {
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingToolServer {
    fn server_id(&self) -> &str {
        "vendor-ledger"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["close_account".to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "arguments": arguments
        }))
    }
}

struct TreatyArtifacts {
    scope: TreatyScope,
    scope_sha256: String,
    intersection: chio_runtime_core::LadderIntersection,
    intersection_sha256: String,
    continuation: CrossKernelContinuation,
    continuation_sha256: String,
    lineage: ReceiptLineageBundle,
    lineage_sha256: String,
    invocation: BilateralInvocation,
    invocation_sha256: String,
    dsse_id: String,
    dsse: chio_federation::bilateral_dsse::DsseEnvelope,
    dsse_sha256: String,
}

impl TreatyArtifacts {
    fn new(args: &serde_json::Value) -> Result<Self, Box<dyn std::error::Error>> {
        let buyer_manifest = treaty_manifest("kernel.buyer");
        let vendor_manifest = treaty_manifest("kernel.vendor-b");
        let signer_a = Keypair::from_seed(&[21_u8; 32]);
        let signer_b = Keypair::from_seed(&[22_u8; 32]);
        let scope = TreatyScope {
            schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
            treaty_id: "treaty-bench-buyer-vendor".to_string(),
            participant_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
            participant_public_keys: vec![signer_a.public_key(), signer_b.public_key()],
            ladder_manifest_sha256s: vec![
                governance_ladder_manifest_sha256(&buyer_manifest)?,
                governance_ladder_manifest_sha256(&vendor_manifest)?,
            ],
            allowed_action_classes: vec![ACTION_CLASS_ID.to_string()],
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
            revocation_epoch_sha256: "d".repeat(64),
            trust_bundle_sha256: "b".repeat(64),
        };
        let scope_sha256 = treaty_scope_sha256(&scope)?;
        let intersection =
            compute_ladder_intersection(&scope, &[buyer_manifest, vendor_manifest], NOW_UNIX_MS)?;
        let intersection_sha256 = ladder_intersection_sha256(&intersection)?;
        let continuation = CrossKernelContinuation {
            schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
            continuation_id: "continue-bench-treaty-deny".to_string(),
            source_kernel_id: "kernel.buyer".to_string(),
            target_kernel_id: "kernel.vendor-b".to_string(),
            parent_receipt_sha256: "1".repeat(64),
            parent_session_anchor_sha256: "2".repeat(64),
            capability_id: CAPABILITY_ID.to_string(),
            action_class_id: ACTION_CLASS_ID.to_string(),
            audience_tool: "vendor-ledger.close_account".to_string(),
            nonce: "nonce-bench-treaty-deny".to_string(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
        };
        let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);
        let mut invocation = BilateralInvocation {
            schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
            invocation_id: "invoke-bench-treaty-deny".to_string(),
            treaty_id: scope.treaty_id.clone(),
            ladder_intersection_sha256: intersection_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            lineage_statement_sha256: String::new(),
            action_class_id: ACTION_CLASS_ID.to_string(),
            consistency_model: "totally_ordered".to_string(),
            capability_id: CAPABILITY_ID.to_string(),
            request_sha256: tool_args_sha256(args)?,
            outcome_sha256: "5".repeat(64),
            local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
            remote_receipt_sha256: String::new(),
            signer_kernel_ids: scope.participant_kernel_ids.clone(),
        };
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: invocation.invocation_id.clone(),
                timestamp: NOW_UNIX_MS / 1_000,
                capability_id: CAPABILITY_ID.to_string(),
                tool_server: "vendor-ledger".to_string(),
                tool_name: "close_account".to_string(),
                action: ToolCallAction::from_parameters(args.clone())?,
                decision: Some(Decision::Allow),
                receipt_kind: ReceiptKind::MediatedDecision,
                boundary_class: BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: vec![ActorRef {
                    actor_id: "agent:bench/treaty-admission".to_string(),
                    actor_kind: Some("agent".to_string()),
                }],
                content_hash: invocation.outcome_sha256.clone(),
                policy_hash: "policy-bench-treaty-deny".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: TrustLevel::default(),
                tenant_id: None,
                kernel_key: signer_b.public_key(),
                bbs_projection_version: None,
            },
            &signer_b,
        )?;
        invocation.remote_receipt_sha256 = sha256_hex(&canonical_json_bytes(&receipt)?);
        let invocation_binding_sha256 = bilateral_invocation_binding_sha256(&invocation)?;
        let lineage_statement = ReceiptLineageStatement {
            schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            statement_id: "lineage-bench-treaty-deny".to_string(),
            parent_receipt_sha256: invocation.local_receipt_sha256.clone(),
            child_receipt_sha256: invocation.remote_receipt_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            bilateral_invocation_sha256: invocation_binding_sha256.clone(),
            evidence_class: "verified".to_string(),
            source_kernel_id: continuation.source_kernel_id.clone(),
            target_kernel_id: continuation.target_kernel_id.clone(),
        };
        invocation.lineage_statement_sha256 =
            sha256_hex(&canonical_json_bytes(&lineage_statement)?);
        let lineage = ReceiptLineageBundle {
            schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
            bundle_id: "lineage-bundle-bench-treaty-deny".to_string(),
            root_receipt_sha256: lineage_statement.parent_receipt_sha256.clone(),
            leaf_receipt_sha256: lineage_statement.child_receipt_sha256.clone(),
            statements: vec![lineage_statement],
        };
        let lineage_sha256 = sha256_hex(&canonical_json_bytes(&lineage)?);
        let invocation_sha256 = bilateral_invocation_binding_sha256(&invocation)?;
        if invocation_sha256 != invocation_binding_sha256 {
            return Err("bilateral invocation binding changed after lineage completion".into());
        }
        let dsse_consistency_model =
            bilateral_dsse_consistency_model(&invocation.consistency_model)?.to_string();
        let dsse = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &signer_a,
            &signer_b,
            &invocation.signer_kernel_ids[0],
            &invocation.signer_kernel_ids[1],
            "close_account",
            NOW_UNIX_MS,
            BilateralPredicateExtensions {
                capability_lease_ref: Some(CapabilityLeaseRef {
                    lease_id: "lease-bench-treaty-deny".to_string(),
                    issuer: invocation.signer_kernel_ids[0].clone(),
                    expires_at_unix_ms: 1_800_003_600_000,
                    scope_digest: None,
                }),
                policy_evaluation_summary: Some(unanimous_deny_summary()),
                governance_receipt_ref: Some(GovernanceReceiptRef {
                    receipt_id: "gov-bench-treaty-deny".to_string(),
                    kernel_id: invocation.signer_kernel_ids[1].clone(),
                    digest: HashRecord {
                        alg: "sha256".to_string(),
                        value: "6".repeat(64),
                    },
                }),
                consistency_anchor: Some("anchor-bench-treaty-deny".to_string()),
                consistency_model: Some(dsse_consistency_model.clone()),
                cross_org_visibility: Some("treaty_only".to_string()),
                treaty_binding_ref: Some(TreatyBindingRef {
                    treaty_id: invocation.treaty_id.clone(),
                    treaty_scope_sha256: scope_sha256.clone(),
                    ladder_intersection_sha256: intersection_sha256.clone(),
                    admission_report_sha256: "7".repeat(64),
                    continuation_sha256: continuation_sha256.clone(),
                    lineage_bundle_sha256: lineage_sha256.clone(),
                    action_class_id: ACTION_CLASS_ID.to_string(),
                    consistency_model: dsse_consistency_model,
                    request_sha256: invocation.request_sha256.clone(),
                    outcome_sha256: invocation.outcome_sha256.clone(),
                    local_receipt_sha256: invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256: invocation.remote_receipt_sha256.clone(),
                    lease_refs: vec!["lease-bench-treaty-deny".to_string()],
                    governance_refs: vec!["gov-bench-treaty-deny".to_string()],
                    signer_kernel_ids: invocation.signer_kernel_ids.clone(),
                }),
            },
        )?;
        let dsse_sha256 = sha256_hex(&canonical_json_bytes(&dsse)?);
        Ok(Self {
            scope,
            scope_sha256,
            intersection,
            intersection_sha256,
            continuation,
            continuation_sha256,
            lineage,
            lineage_sha256,
            invocation,
            invocation_sha256,
            dsse_id: "bilateral-dsse-bench-treaty-deny".to_string(),
            dsse,
            dsse_sha256,
        })
    }

    fn insert_into(
        &self,
        store: &InMemoryRuntimeAdmissionStore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        store.insert_treaty_runtime_artifact("treaty_scope", &self.scope.treaty_id, &self.scope)?;
        store.insert_treaty_runtime_artifact(
            "ladder_intersection",
            &self.intersection.intersection_id,
            &self.intersection,
        )?;
        store.insert_treaty_runtime_artifact(
            "cross_kernel_continuation",
            &self.continuation.continuation_id,
            &self.continuation,
        )?;
        store.insert_treaty_runtime_artifact(
            "receipt_lineage_bundle",
            &self.lineage.bundle_id,
            &self.lineage,
        )?;
        store.insert_treaty_runtime_artifact(
            "bilateral_invocation",
            &self.invocation.invocation_id,
            &self.invocation,
        )?;
        store.insert_treaty_runtime_artifact(
            "bilateral_dsse_envelope",
            &self.dsse_id,
            &self.dsse,
        )?;
        Ok(())
    }
}

fn treaty_manifest(kernel_id: &str) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder-{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: format!("did:chio:{kernel_id}"),
        key_id: "ladder-key-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![GovernanceLadderActionClass {
            action_class_id: ACTION_CLASS_ID.to_string(),
            mode: "receipt_backed".to_string(),
            destructive: true,
            consistency_model: "totally_ordered".to_string(),
            co_sign: "bilateral_required".to_string(),
            co_sign_quorum: None,
            evidence_required: vec![
                "bilateral_dsse".to_string(),
                "bilateral_invocation".to_string(),
                "receipt_lineage".to_string(),
            ],
            aliases: Vec::new(),
        }],
    }
}

fn unanimous_deny_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        server_b_verdict: PolicyVerdict {
            verdict: "deny".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: Some("high_risk".to_string()),
        },
        joint_disposition: Some("deny".to_string()),
    }
}

fn treaty_request(
    args: serde_json::Value,
    bundle_sha256: String,
    artifacts: &TreatyArtifacts,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let issuer = Keypair::from_seed(&[23_u8; 32]);
    let subject = Keypair::from_seed(&[24_u8; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: CAPABILITY_ID.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "vendor-ledger".to_string(),
                    tool_name: "close_account".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 1_700_000_000,
            expires_at: 1_900_000_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    Ok(ToolCallRequest {
        request_id: "req-bench-treaty-deny".to_string(),
        capability: capability.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-bench-treaty-deny".to_string(),
            server_id: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            purpose: "benchmark receiver-owned treaty denial".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioAdmission": {
                    "admissionId": "adm-bench-treaty-deny",
                    "bundleSha256": bundle_sha256
                },
                "chioTreaty": {
                    "treatyScopeId": artifacts.scope.treaty_id,
                    "treatyScopeSha256": artifacts.scope_sha256,
                    "ladderIntersectionId": artifacts.intersection.intersection_id,
                    "ladderIntersectionSha256": artifacts.intersection_sha256,
                    "actionClassId": ACTION_CLASS_ID,
                    "crossKernelContinuation": {
                        "id": artifacts.continuation.continuation_id,
                        "sha256": artifacts.continuation_sha256
                    },
                    "receiptLineageBundle": {
                        "id": artifacts.lineage.bundle_id,
                        "sha256": artifacts.lineage_sha256
                    },
                    "bilateralInvocation": {
                        "id": artifacts.invocation.invocation_id,
                        "sha256": artifacts.invocation_sha256
                    },
                    "bilateralDsse": {
                        "id": artifacts.dsse_id,
                        "sha256": artifacts.dsse_sha256
                    }
                }
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
    })
}
