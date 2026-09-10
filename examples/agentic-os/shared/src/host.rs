use crate::Run;
use anyhow::{Context, Result};
use chio_core::{
    capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::CapabilityToken,
    },
    crypto::{Keypair, PublicKey},
};
use chio_kernel::{
    ChioKernel, KernelConfig, ToolCallOutput, ToolCallRequest, ToolServerConnection,
};
use serde_json::{json, Value};
use std::{io::Write, path::Path, sync::Arc};

pub fn private_directory(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

pub struct Host {
    pub kernel: Arc<ChioKernel>,
    pub signer: PublicKey,
    issuer: Keypair,
    pub budget: chio_store_sqlite::SqliteBudgetStore,
}

impl Host {
    pub fn open(
        path: &Path,
        policy: &str,
        servers: Vec<Box<dyn ToolServerConnection>>,
    ) -> Result<Self> {
        Self::open_priced(path, policy, servers, false)
    }

    pub fn open_priced(
        path: &Path,
        policy: &str,
        servers: Vec<Box<dyn ToolServerConnection>>,
        priced: bool,
    ) -> Result<Self> {
        private_directory(path)?;
        let authority =
            chio_control_plane::DurableAdmissionRuntime::open(&path.join("admission.db"))?;
        let keypair = authority.kernel_keypair();
        let signer = keypair.public_key();
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: keypair.clone(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 8,
            policy_hash: chio_core::sha256_hex(policy.as_bytes()),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        });
        kernel.set_receipt_store(Box::new(chio_store_sqlite::SqliteReceiptStore::open(
            path.join("receipts.db"),
        )?))?;
        if priced {
            kernel.set_payment_adapter(Box::new(
                chio_store_sqlite::SqliteFindingOperatorPaymentAdapter::open(
                    path.join("payments.db"),
                )
                .map_err(anyhow::Error::msg)?,
            ));
        }
        // Read-only tools consume authority too. Include them in durable quota accounting.
        kernel.configure_durable_admission(
            chio_kernel::admission_operation::DurableAdmissionMode::All,
            false,
        )?;
        authority.attach(&mut kernel)?;
        let budget = authority
            .local_budget_store()
            .context("Local accounting is required")?;
        for server in servers {
            kernel.register_tool_server(server);
        }
        write_json(
            &path.join("trusted-kernel.json"),
            &json!({"public_key":signer.to_hex()}),
        )?;
        Ok(Self {
            kernel: Arc::new(kernel),
            signer,
            issuer: keypair,
            budget,
        })
    }

    pub fn approve(
        &self,
        request: &ToolCallRequest,
        approved: bool,
        expires_at: u64,
    ) -> Result<chio_core::capability::governance::GovernedApprovalToken> {
        use chio_core::capability::governance::{
            GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        };
        let now = crate::events::now_ms() / 1000;
        Ok(GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: uuid::Uuid::new_v4().to_string(),
                approver: self.signer.clone(),
                subject: request.capability.subject.clone(),
                governed_intent_hash: request
                    .governed_intent
                    .as_ref()
                    .context("Approval requires a governed intent")?
                    .binding_hash()?,
                request_id: request.request_id.clone(),
                threshold_proposal_hash: None,
                issued_at: now,
                expires_at,
                decision: if approved {
                    GovernedApprovalDecision::Approved
                } else {
                    GovernedApprovalDecision::Denied
                },
            },
            &self.issuer,
        )?)
    }

    pub fn mint_graph(
        &self,
        request: chio_swarm_authority::SwarmFanoutRequest,
    ) -> Result<chio_swarm_authority::SwarmAuthorityBundle> {
        Ok(chio_swarm_authority::mint_swarm_fanout(
            request,
            &self.issuer,
        )?)
    }
    pub fn complete_graph(
        &self,
        bundle: chio_swarm_authority::SwarmAuthorityBundle,
        completed: Vec<chio_swarm_authority::SwarmTaskCompletion>,
        result: Value,
    ) -> Result<chio_swarm_authority::SwarmAuthorityBundle> {
        let digest = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&result)?);
        Ok(chio_swarm_authority::complete_swarm_fanout(
            bundle,
            completed,
            digest,
            crate::events::now_ms(),
            &self.issuer,
        )?)
    }

    pub fn issue(&self, server: &str, tools: &[&str], calls: u32) -> Result<CapabilityToken> {
        let grants = tools
            .iter()
            .map(|tool| grant(server, tool, calls))
            .collect();
        Ok(self.kernel.issue_capability(
            &Keypair::generate().public_key(),
            ChioScope {
                grants,
                ..Default::default()
            },
            300,
        )?)
    }

    pub fn root(&self, server: &str, tools: &[&str], calls: u32) -> Result<Root> {
        let coordinator = Keypair::generate();
        let grants = tools
            .iter()
            .map(|tool| {
                let mut grant = grant(server, tool, calls);
                grant.operations.push(Operation::Delegate);
                grant
            })
            .collect();
        let token = self.kernel.issue_capability(
            &coordinator.public_key(),
            ChioScope {
                grants,
                ..Default::default()
            },
            300,
        )?;
        self.kernel.set_capability_trust_root(
            self.signer.clone(),
            chio_core::capability::attenuation::scope_hash(&token.scope)?,
        );
        self.kernel
            .register_budget_parent(token.id.clone(), 10_000)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Root { token, coordinator })
    }

    pub fn delegate(
        &self,
        run: &Run,
        root: &Root,
        actor: &str,
        tools: &[&str],
        calls: u32,
        share_bps: u16,
    ) -> Result<CapabilityToken> {
        use chio_core::capability::{
            attenuation::{
                compute_attenuation_witness, delegate, scope_hash, Attenuation, AttenuationProof,
            },
            token::{CapabilityTokenAttenuationBody, CapabilityTokenBody},
        };
        use chio_core::delegation_receipt::ScopeAttenuation;
        let subject = Keypair::generate();
        let now = crate::events::now_ms() / 1000;
        let expires_at = (now + 120).min(root.token.expires_at);
        let mut steps = Vec::new();
        let mut grants = Vec::new();
        for original in &root.token.scope.grants {
            if tools.contains(&original.tool_name.as_str()) {
                steps.push(Attenuation::RemoveOperation {
                    server_id: original.server_id.clone(),
                    tool_name: original.tool_name.clone(),
                    operation: Operation::Delegate,
                });
                steps.push(Attenuation::ReduceBudget {
                    server_id: original.server_id.clone(),
                    tool_name: original.tool_name.clone(),
                    max_invocations: calls,
                });
                grants.push(grant(&original.server_id, &original.tool_name, calls));
            } else {
                steps.push(Attenuation::RemoveTool {
                    server_id: original.server_id.clone(),
                    tool_name: original.tool_name.clone(),
                });
            }
        }
        anyhow::ensure!(
            grants.len() == tools.len(),
            "Cannot delegate an unregistered responsibility"
        );
        steps.push(Attenuation::ShortenExpiry {
            new_expires_at: expires_at,
        });
        let scope = ChioScope {
            grants,
            ..Default::default()
        };
        let delegation = delegate(
            &root.token,
            &scope,
            &root.coordinator,
            &subject.public_key(),
            ScopeAttenuation {
                steps,
                child_expires_at: Some(expires_at),
                budget_share_bps: Some(share_bps),
            },
            now,
            *uuid::Uuid::new_v4().as_bytes(),
        )?;
        let token = CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: uuid::Uuid::new_v4().to_string(),
                    issuer: self.signer.clone(),
                    subject: subject.public_key(),
                    scope: scope.clone(),
                    issued_at: now,
                    expires_at,
                    delegation_chain: delegation.complete_chain(),
                    aggregate_invocation_budget: None,
                },
                caveats: Vec::new(),
                scope_attenuations: delegation.attenuation.steps.clone(),
                attenuation_proof: AttenuationProof {
                    parent_scope_hash: scope_hash(&root.token.scope)?,
                    child_scope_hash: scope_hash(&scope)?,
                    normalized_subset_proof: compute_attenuation_witness(
                        &root.token.scope,
                        &scope,
                    )?,
                },
                budget_share_bps: Some(share_bps),
            },
            &self.issuer,
        )?;
        run.emit(
            "authority.delegated",
            actor,
            "Delegated a bounded responsibility",
            json!({"capability":token,"delegation":delegation}),
        )?;
        Ok(token)
    }

    pub async fn call(
        &self,
        run: &Run,
        actor: &str,
        cap: &CapabilityToken,
        server: &str,
        tool: &str,
        arguments: Value,
    ) -> Result<Call> {
        self.call_controlled(
            run,
            actor,
            request(cap, server, tool, arguments),
            None,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await
    }

    pub async fn call_controlled(
        &self,
        run: &Run,
        actor: &str,
        request: ToolCallRequest,
        metadata: Option<Value>,
        cancellation: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Call> {
        let cap = &request.capability;
        let server = request.server_id.as_str();
        let tool = request.tool_name.as_str();
        let arguments = request.arguments.clone();
        run.emit(
            "call.started",
            actor,
            &format!("Call {tool}"),
            json!({
                "request_id":request.request_id,"server":server,"tool":tool,
                "arguments":arguments,"capability_id":cap.id,"scope":cap.scope,
                "expires_at":cap.expires_at,"subject":cap.subject.to_hex(),
            }),
        )?;
        let session = self
            .kernel
            .open_session(cap.subject.to_hex(), vec![cap.clone()])?;
        self.kernel.activate_session(&session)?;
        let context = chio_core::OperationContext::new(
            session.clone(),
            chio_core::RequestId::new(request.request_id.clone()),
            cap.subject.to_hex(),
        );
        let operation = chio_core::ToolCallOperation {
            capability: cap.clone(),
            server_id: server.into(),
            tool_name: tool.into(),
            arguments,
            governed_intent: request.governed_intent.clone(),
            approval_token: request.approval_token.clone(),
            approval_tokens: request.approval_tokens.clone(),
            threshold_approval_proposal: request.threshold_approval_proposal.clone(),
            supplemental_authorization: request.supplemental_authorization.clone(),
            execution_nonce: request
                .execution_nonce
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
            model_metadata: request.model_metadata.clone(),
            extra_metadata: metadata,
        };
        let mut client = crate::client::ApplicationClient(cancellation);
        let evaluated = Box::pin(
            self.kernel
                .evaluate_tool_call_operation_with_nested_flow_client_async(
                    &context,
                    &operation,
                    &mut client,
                ),
        )
        .await;
        let closed = self.kernel.close_session(&session);
        let response = evaluated?;
        closed?;
        anyhow::ensure!(
            response.receipt.kernel_key == self.signer,
            "Receipt signer differs from this host's selected key"
        );
        anyhow::ensure!(
            response.receipt.verify_signature()?,
            "Receipt signature failed"
        );
        let receipt = serde_json::to_value(&response.receipt)?;
        let output = match response.output {
            Some(ToolCallOutput::Value(output)) => output,
            None => Value::Null,
            Some(ToolCallOutput::Stream(_)) => {
                anyhow::bail!("This application expects a retained value result")
            }
        };
        let allowed = receipt["decision"]["verdict"] == "allow";
        let receipt_id = response.receipt.id.clone();
        let result = json!({"request_id":request.request_id,"receipt_id":receipt_id,
            "receipt":receipt,"trusted_kernel":self.signer.to_hex(),
            "output":output,"reason":response.reason,"terminal_state":response.terminal_state});
        run.emit(
            if allowed {
                "call.allowed"
            } else {
                "call.denied"
            },
            actor,
            &format!("{} {tool}", if allowed { "Allowed" } else { "Refused" }),
            result,
        )?;
        Ok(Call {
            allowed,
            output,
            receipt_id,
            reason: response.reason,
        })
    }
}

pub struct Root {
    pub token: CapabilityToken,
    coordinator: Keypair,
}

pub struct Call {
    pub allowed: bool,
    pub output: Value,
    pub receipt_id: String,
    pub reason: Option<String>,
}
impl Call {
    pub fn require_output(self) -> Result<Value> {
        anyhow::ensure!(
            self.allowed,
            "Tool request was refused; inspect its receipt"
        );
        anyhow::ensure!(
            !self.output.is_null(),
            "Tool did not return a completed result"
        );
        Ok(self.output)
    }
}

pub fn grant(server: &str, tool: &str, calls: u32) -> ToolGrant {
    ToolGrant {
        server_id: server.into(),
        tool_name: tool.into(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: Some(calls),
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

pub fn request(
    cap: &CapabilityToken,
    server: &str,
    tool: &str,
    arguments: Value,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        capability: cap.clone(),
        tool_name: tool.into(),
        server_id: server.into(),
        agent_id: cap.subject.to_hex(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

pub fn text<'a>(input: &'a Value, field: &str, maximum: usize) -> Result<&'a str> {
    let value = input
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Provide {field}"))?;
    anyhow::ensure!(
        !value.trim().is_empty() && value.len() <= maximum,
        "{field} must contain 1 to {maximum} UTF-8 bytes"
    );
    Ok(value)
}
