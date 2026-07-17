//! CLI selection of the kernel payment adapter. Sim is the safe default; the
//! http variants delegate to an external facilitator. No custody or broadcast
//! variant is exposed (custody-neutral).

use chio_kernel::{AcpPaymentAdapter, PaymentAdapter, SimPaymentAdapter, X402PaymentAdapter};

#[derive(Debug, Clone)]
pub enum PaymentAdapterConfig {
    Sim,
    HttpX402 { base_url: String, bearer_token: Option<String> },
    HttpAcp { base_url: String, bearer_token: Option<String> },
}

impl PaymentAdapterConfig {
    #[must_use]
    pub fn default_safe() -> Self {
        Self::Sim
    }

    /// Read the payment adapter config from environment variables.
    ///
    /// `CHIO_PAYMENT_ADAPTER`: `sim` (default), `http-x402`, `http-acp`.
    /// `CHIO_PAYMENT_BASE_URL`: required when the adapter is `http-x402` or `http-acp`.
    /// `CHIO_PAYMENT_BEARER_TOKEN`: optional bearer token for http adapters.
    ///
    /// Returns `Ok(None)` when `CHIO_PAYMENT_ADAPTER` is absent or set to `sim`
    /// (the caller then uses the documented default). Returns `Err` when the
    /// variable is present but its value is not a recognized adapter kind -
    /// an unrecognized value would otherwise silently mask a misconfigured
    /// real payment rail.
    pub fn from_env() -> Result<Option<Self>, String> {
        let kind = match std::env::var("CHIO_PAYMENT_ADAPTER") {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let base_url = std::env::var("CHIO_PAYMENT_BASE_URL").unwrap_or_default();
        let bearer_token = std::env::var("CHIO_PAYMENT_BEARER_TOKEN").ok();
        match kind.as_str() {
            "sim" | "" => Ok(None),
            "http-x402" => Ok(Some(Self::HttpX402 { base_url, bearer_token })),
            "http-acp" => Ok(Some(Self::HttpAcp { base_url, bearer_token })),
            other => Err(format!(
                "CHIO_PAYMENT_ADAPTER: unrecognized adapter kind {:?}; \
                 expected one of: sim, http-x402, http-acp",
                other
            )),
        }
    }

    /// Load-time config-consistency check (house rule: invalid policies reject
    /// at load time). This is a config-shape check only; the authoritative
    /// fail-closed enforcement is the kernel runtime MustPrepay gate.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Sim => Ok(()),
            Self::HttpX402 { base_url, .. } | Self::HttpAcp { base_url, .. } => {
                if base_url.trim().is_empty() {
                    return Err("http payment adapter requires a non-empty base_url".to_string());
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn build_adapter(&self) -> Box<dyn PaymentAdapter> {
        match self {
            Self::Sim => Box::new(SimPaymentAdapter::new()),
            Self::HttpX402 { base_url, bearer_token } => {
                let mut adapter = X402PaymentAdapter::new(base_url.clone());
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token.clone());
                }
                Box::new(adapter)
            }
            Self::HttpAcp { base_url, bearer_token } => {
                let mut adapter = AcpPaymentAdapter::new(base_url.clone());
                if let Some(token) = bearer_token {
                    adapter = adapter.with_bearer_token(token.clone());
                }
                Box::new(adapter)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn default_is_sim_and_safe() {
        assert!(matches!(PaymentAdapterConfig::default_safe(), PaymentAdapterConfig::Sim));
    }

    #[test]
    fn unknown_adapter_kind_errors_at_load_time_not_silently_downgrades() {
        // A present-but-unrecognized CHIO_PAYMENT_ADAPTER must produce an error,
        // not silently fall back to Sim. This prevents a misconfigured real rail
        // from being masked by a silent default.
        std::env::set_var("CHIO_PAYMENT_ADAPTER", "mystery-rail");
        let result = PaymentAdapterConfig::from_env();
        std::env::remove_var("CHIO_PAYMENT_ADAPTER");
        let error = result.test_expect_err("unknown adapter kind must fail at load time");
        assert!(
            error.contains("mystery-rail") && error.contains("unrecognized"),
            "error must identify the unknown kind: {error}"
        );
    }

    #[test]
    fn http_x402_requires_non_empty_base_url() {
        let cfg = PaymentAdapterConfig::HttpX402 {
            base_url: "   ".to_string(),
            bearer_token: None,
        };
        let error = cfg.validate().test_expect_err("blank base_url must reject at load time");
        assert!(error.contains("base_url"));
    }

    #[test]
    fn valid_variants_pass_validation_and_build() {
        let sim = PaymentAdapterConfig::Sim;
        sim.validate().test_unwrap();
        let _ = sim.build_adapter();
        let http = PaymentAdapterConfig::HttpAcp {
            base_url: "https://facilitator.example".to_string(),
            bearer_token: Some("tok".to_string()),
        };
        http.validate().test_unwrap();
        let _ = http.build_adapter();
    }

    #[test]
    fn governed_mustprepay_via_cli_sim() {
        use chio_core::capability::governance::{
            GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
            GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote,
            MeteredSettlementMode,
        };
        use chio_core::capability::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
        use chio_core::crypto::Keypair;
        use chio_kernel::{
            ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest,
            ToolInvocationCost, ToolServerConnection, Verdict,
        };

        struct FlatCostServer {
            cost_units: u64,
        }

        #[async_trait::async_trait]
        impl ToolServerConnection for FlatCostServer {
            fn server_id(&self) -> &str {
                "cli-sim-srv"
            }

            fn tool_names(&self) -> Vec<String> {
                vec!["compute".to_string()]
            }

            async fn invoke(
                &self,
                _tool_name: &str,
                _arguments: serde_json::Value,
                _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
            ) -> Result<serde_json::Value, KernelError> {
                Ok(serde_json::json!({"ok": true}))
            }

            async fn invoke_with_cost(
                &self,
                tool_name: &str,
                arguments: serde_json::Value,
                bridge: Option<&mut dyn NestedFlowBridge>,
            ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
                let output = self.invoke(tool_name, arguments, bridge).await?;
                let cost = ToolInvocationCost {
                    units: self.cost_units,
                    currency: "USD".to_string(),
                    breakdown: None,
                };
                Ok((output, Some(cost)))
            }
        }

        let kernel_kp = Keypair::generate();
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: kernel_kp.clone(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "cli-sim-test".to_string(),
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
            dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
        });

        kernel.register_tool_server(Box::new(FlatCostServer { cost_units: 75 }));

        let adapter_config = PaymentAdapterConfig::default_safe();
        adapter_config.validate().test_unwrap();
        kernel
            .set_payment_adapter(adapter_config.build_adapter())
            .test_unwrap();

        let agent_kp = Keypair::generate();
        let grant = ToolGrant {
            server_id: "cli-sim-srv".to_string(),
            tool_name: "compute".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![
                Constraint::GovernedIntentRequired,
                Constraint::RequireApprovalAbove { threshold_units: 50 },
            ],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        };
        let scope = ChioScope { grants: vec![grant], ..ChioScope::default() };
        let cap = kernel
            .issue_capability(&agent_kp.public_key(), scope, 3600)
            .test_unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let intent = GovernedTransactionIntent {
            id: "intent-cli-sim-1".to_string(),
            server_id: "cli-sim-srv".to_string(),
            tool_name: "compute".to_string(),
            purpose: "prepaid invocation".to_string(),
            max_amount: Some(MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            }),
            commerce: None,
            metered_billing: Some(MeteredBillingContext {
                settlement_mode: MeteredSettlementMode::MustPrepay,
                quote: MeteredBillingQuote {
                    quote_id: "q-cli-sim-1".to_string(),
                    provider: "billing.chio".to_string(),
                    billing_unit: "call".to_string(),
                    quoted_units: 1,
                    quoted_cost: MonetaryAmount {
                        units: 100,
                        currency: "USD".to_string(),
                    },
                    issued_at: now.saturating_sub(5),
                    expires_at: Some(now + 300),
                },
                max_billed_units: Some(2),
            }),
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
        };

        let intent_hash = intent.binding_hash().test_unwrap();
        let approval_token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "approval-cli-sim-1".to_string(),
                approver: kernel_kp.public_key(),
                subject: agent_kp.public_key(),
                governed_intent_hash: intent_hash,
                request_id: "req-cli-sim-1".to_string(),
                issued_at: now.saturating_sub(1),
                expires_at: now + 300,
                decision: GovernedApprovalDecision::Approved,
            },
            &kernel_kp,
        )
        .test_unwrap();

        let request = ToolCallRequest {
            request_id: "req-cli-sim-1".to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cli-sim-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        let response = kernel.evaluate_tool_call_blocking(&request).test_unwrap();

        assert_eq!(response.verdict, Verdict::Allow, "MustPrepay call must be allowed");

        let financial = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|m| m.get("financial"))
            .test_expect("receipt must carry financial metadata");

        let payment_ref = financial["payment_reference"]
            .as_str()
            .test_expect("settled receipt must carry payment_reference");

        assert!(
            payment_ref.starts_with("sim-"),
            "payment_reference must carry a sim- id from SimPaymentAdapter; got {payment_ref}"
        );
    }
}
