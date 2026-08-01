//! `chio mcp governed-sim` -- deterministic no-key governed-x402 smoke runner.
//!
//! Executes one governed MustPrepay tool call through a local kernel wired with
//! the sim payment adapter (or no adapter for the deny path) and writes the
//! resulting signed receipt bundle to `--out`. Exits nonzero on denial.
//!
//! Used by the no-key CI lane; not a user-facing production subcommand.

use super::*;
use super::payment_config::PaymentAdapterConfig;

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote,
    MeteredSettlementMode,
};
use chio_core::capability::scope::{Constraint, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_kernel::{
    KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest,
    ToolInvocationCost, ToolServerConnection,
};

const SIM_SERVER_ID: &str = "governed-sim-srv";
const SIM_TOOL_NAME: &str = "compute";
const SIM_COST_UNITS: u64 = 75;
const SIM_BUDGET_MAX_UNITS: u64 = 100;
const SIM_TOTAL_BUDGET_UNITS: u64 = 1000;
const SIM_APPROVAL_THRESHOLD_UNITS: u64 = 50;
const SIM_TTL_SECS: u64 = 300;

/// CLI args for `chio mcp governed-sim`.
#[derive(clap::Args, Debug)]
pub(crate) struct GovernedSimArgs {
    /// Payment adapter: `sim` (deterministic no-broadcast) or `none` (absent, deny path).
    #[arg(long, default_value = "sim")]
    pub payment_adapter: String,

    /// Run a governed MustPrepay tool call through the kernel.
    #[arg(long, default_value_t = false)]
    pub governed_mustprepay: bool,

    /// Path to write the receipt bundle JSON.
    #[arg(long)]
    pub out: std::path::PathBuf,
}

/// Flat-cost in-process tool server for the governed sim smoke path.
struct SimFlatCostServer;

#[async_trait::async_trait]
impl ToolServerConnection for SimFlatCostServer {
    fn server_id(&self) -> &str {
        SIM_SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![SIM_TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({ "result": "ok" }))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let output = self.invoke(tool_name, arguments, bridge).await?;
        Ok((
            output,
            Some(ToolInvocationCost {
                units: SIM_COST_UNITS,
                currency: "USD".to_string(),
                breakdown: None,
            }),
        ))
    }
}

/// Dispatch entry-point for `chio mcp governed-sim`.
///
/// Builds an ephemeral kernel, registers a flat-cost tool server, wires the
/// selected payment adapter, and executes one governed MustPrepay tool call.
/// Writes the signed receipt bundle to `--out` regardless of verdict, then
/// returns an error (exit 1) on denial so the no-key CI lane can capture the
/// nonzero exit code for the fail-closed assertion.
pub(crate) fn cmd_mcp_governed_sim(args: &GovernedSimArgs) -> Result<(), CliError> {
    if !args.governed_mustprepay {
        return Err(CliError::cli_other_error(
            "--governed-mustprepay is required for chio mcp governed-sim".to_string(),
        ));
    }

    let kernel_kp = Keypair::generate();
    let mut kernel = chio_kernel::ChioKernel::new(KernelConfig {
        keypair: kernel_kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "governed-x402-sim-smoke".to_string(),
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
    // This command is an explicit local payment simulation. Production kernels
    // keep the safe default and require durable admission before financial dispatch.
    kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    kernel.register_tool_server(Box::new(SimFlatCostServer));

    match args.payment_adapter.as_str() {
        "sim" => {
            kernel.set_payment_adapter(PaymentAdapterConfig::Sim.build_adapter());
        }
        "none" => {}
        other => {
            return Err(CliError::cli_other_error(format!(
                "unknown --payment-adapter {other:?}; expected sim or none"
            )));
        }
    }

    let agent_kp = Keypair::generate();
    let grant = ToolGrant {
        server_id: SIM_SERVER_ID.to_string(),
        tool_name: SIM_TOOL_NAME.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove {
                threshold_units: SIM_APPROVAL_THRESHOLD_UNITS,
            },
        ],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: SIM_BUDGET_MAX_UNITS,
            currency: "USD".to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: SIM_TOTAL_BUDGET_UNITS,
            currency: "USD".to_string(),
        }),
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, SIM_TTL_SECS)
        .map_err(|e| CliError::cli_other_error(format!("capability issuance: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let intent = GovernedTransactionIntent {
        id: "governed-sim-intent-1".to_string(),
        server_id: SIM_SERVER_ID.to_string(),
        tool_name: SIM_TOOL_NAME.to_string(),
        purpose: "no-key CI smoke".to_string(),
        max_amount: Some(MonetaryAmount {
            units: SIM_BUDGET_MAX_UNITS,
            currency: "USD".to_string(),
        }),
        commerce: None,
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: "governed-sim-q-1".to_string(),
                provider: "billing.chio.sim".to_string(),
                billing_unit: "call".to_string(),
                quoted_units: 1,
                quoted_cost: MonetaryAmount {
                    units: SIM_BUDGET_MAX_UNITS,
                    currency: "USD".to_string(),
                },
                issued_at: now.saturating_sub(5),
                expires_at: Some(now + SIM_TTL_SECS),
            },
            max_billed_units: Some(2),
            verified_outcome: None,
        }),
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };

    let intent_hash = intent
        .binding_hash()
        .map_err(|e| CliError::cli_other_error(format!("intent binding hash: {e}")))?;

    let approval_token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "governed-sim-approval-1".to_string(),
            approver: kernel_kp.public_key(),
            subject: agent_kp.public_key(),
            governed_intent_hash: intent_hash,
            request_id: "governed-sim-req-1".to_string(),
            threshold_proposal_hash: None,
            issued_at: now.saturating_sub(1),
            expires_at: now + SIM_TTL_SECS,
            decision: GovernedApprovalDecision::Approved,
        },
        &kernel_kp,
    )
    .map_err(|e| CliError::cli_other_error(format!("approval token sign: {e}")))?;

    let request = ToolCallRequest {
        request_id: "governed-sim-req-1".to_string(),
        capability: cap,
        tool_name: SIM_TOOL_NAME.to_string(),
        server_id: SIM_SERVER_ID.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_token: Some(approval_token),
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .map_err(|e| CliError::cli_other_error(format!("kernel evaluation: {e}")))?;

    let receipt_json = serde_json::to_vec_pretty(&response.receipt)
        .map_err(|e| CliError::cli_other_error(format!("receipt serialize: {e}")))?;
    std::fs::write(&args.out, &receipt_json).map_err(|e| {
        CliError::cli_io_error(format!("write receipt to {:?}: {e}", args.out))
    })?;

    if response.verdict != chio_kernel::Verdict::Allow {
        return Err(CliError::cli_other_error(format!(
            "governed MustPrepay denied: {}",
            response.reason.unwrap_or_else(|| "no reason given".to_string())
        )));
    }

    Ok(())
}
