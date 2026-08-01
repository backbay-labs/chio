// End-to-end kernel coverage for the sim payment adapter.
//
// Included by `src/kernel/tests.rs`; imports resolve through the surrounding
// `kernel::tests` scope. All helpers from `tests/support.rs` and
// `tests/support_monetary.rs` are in scope.

use chio_core::capability::governance::{
    MeteredBillingContext, MeteredBillingQuote, MeteredSettlementMode,
};

fn make_mustprepay_intent(
    id: &str,
    server: &str,
    tool: &str,
    max_units: u64,
    currency: &str,
) -> GovernedTransactionIntent {
    let now = current_unix_timestamp();
    GovernedTransactionIntent {
        id: id.to_string(),
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        purpose: "prepaid invocation".to_string(),
        max_amount: Some(MonetaryAmount {
            units: max_units,
            currency: currency.to_string(),
        }),
        commerce: None,
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: format!("q-{id}"),
                provider: "billing.chio".to_string(),
                billing_unit: "1k_tokens".to_string(),
                quoted_units: 10,
                quoted_cost: MonetaryAmount {
                    units: max_units,
                    currency: currency.to_string(),
                },
                issued_at: now.saturating_sub(5),
                expires_at: Some(now + 300),
            },
            max_billed_units: Some(15),
            verified_outcome: None,
        }),
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    }
}

struct MustPrepayFixture {
    kernel: ChioKernel,
    cap: CapabilityToken,
    agent_kp: Keypair,
}

fn build_mustprepay_fixture(cost: u64) -> MustPrepayFixture {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", cost, "USD")));
    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    MustPrepayFixture { kernel, cap, agent_kp }
}

fn mustprepay_tool_call(
    request_id: &str,
    cap: &CapabilityToken,
    agent_kp: &Keypair,
    intent: GovernedTransactionIntent,
    kernel: &ChioKernel,
) -> ToolCallRequest {
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
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
    }
}

fn expect_financial_meta(response: &ToolCallResponse) -> &serde_json::Value {
    response
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("response must carry financial metadata")
}

// sim authorize -> capture -> receipt fold stamps a sim-* payment reference.
#[test]
fn sim_adapter_settles_governed_mustprepay_onto_receipt() {
    let MustPrepayFixture { mut kernel, cap, agent_kp } = build_mustprepay_fixture(75);
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));

    let intent =
        make_mustprepay_intent("intent-sim-settle", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-sim-settle", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let financial = expect_financial_meta(&response);
    let payment_reference = financial["payment_reference"]
        .as_str()
        .expect("settled receipt must carry payment_reference");
    assert!(
        payment_reference.starts_with("sim-"),
        "payment_reference must be a sim- id; got {payment_reference}"
    );
    let status = financial["settlement_status"].as_str().unwrap_or("");
    assert!(
        status == "settled" || status == "pending",
        "settlement_status must be settled or pending; got {status}"
    );
}

// MustPrepay with no adapter configured denies fail-closed.
#[test]
fn governed_mustprepay_without_adapter_is_denied_end_to_end() {
    let MustPrepayFixture { kernel, cap, agent_kp } = build_mustprepay_fixture(75);
    // no adapter set

    let intent =
        make_mustprepay_intent("intent-sim-deny", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-sim-deny", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("MustPrepay"),
        "denial must mention MustPrepay; got: {reason}"
    );
}

// A quote above the grant's per-invocation ceiling must deny before the rail is
// touched: the pre-execution hold debits that ceiling, so a larger prepayment
// would move more money than the budget layer ever accounts for.
#[test]
fn governed_mustprepay_quote_above_per_invocation_ceiling_is_denied() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-over-per-call", "cost-srv", "compute", 500, "USD");
    let request = mustprepay_tool_call("req-over-per-call", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("exceeds the grant per-invocation cost limit"),
        "denial must name the per-invocation ceiling; got: {reason}"
    );
}

// The cumulative ceiling bounds the quote too, even where the per-invocation
// ceiling admits it.
#[test]
fn governed_mustprepay_quote_above_cumulative_ceiling_is_denied() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    // The quote matches the per-invocation ceiling exactly, so only the
    // cumulative ceiling can reject it.
    let grant = make_governed_monetary_grant("cost-srv", "compute", 500, 100, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-over-total", "cost-srv", "compute", 500, "USD");
    let request = mustprepay_tool_call("req-over-total", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("exceeds the grant cumulative cost limit"),
        "denial must name the cumulative ceiling; got: {reason}"
    );
}

// A grant declaring only a cumulative ceiling debits nothing per call, so its
// stated total authority would never bind across repeated prepayments.
#[test]
fn governed_mustprepay_against_cumulative_only_grant_is_denied() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    let mut grant = make_no_ceiling_mustprepay_grant();
    grant.max_total_cost = Some(MonetaryAmount { units: 1000, currency: "USD".to_string() });
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-total-only", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-total-only", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("cumulative-only grant cannot be accounted"),
        "denial must name the unaccountable cumulative-only shape; got: {reason}"
    );
}

// The server reports zero actual cost after MustPrepay captured the quoted amount.
// The receipt retains that final prepayment rather than claiming a release after
// dispatch may already have occurred.
#[test]
fn sim_adapter_zero_actual_cost_retains_prepaid_charge() {
    let MustPrepayFixture { mut kernel, cap, agent_kp } = build_mustprepay_fixture(0);
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));

    let intent =
        make_mustprepay_intent("intent-sim-zero", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-sim-zero", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let financial = expect_financial_meta(&response);
    let payment_reference = financial["payment_reference"]
        .as_str()
        .expect("zero-cost receipt must carry payment_reference from authorize");
    assert!(
        payment_reference.starts_with("sim-"),
        "zero-cost payment_reference must be a sim- id; got {payment_reference}"
    );
    // Released -> Settled in the kernel's settlement vocabulary.
    assert_eq!(
        financial["settlement_status"].as_str().unwrap_or(""),
        "settled",
        "zero-cost call must produce settled status after release"
    );
    assert_eq!(
        financial["cost_charged"].as_u64().unwrap_or(u64::MAX),
        100,
        "MustPrepay records the quoted amount captured before dispatch"
    );
}

// A cancellation after dispatch retains the payment authorization and budget
// hold: the tool may have acted, so releasing or reversing would fail open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sim_adapter_abort_after_dispatch_retains_authorization() {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let payment = TrackingPaymentAdapter::new();

    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "cost-srv".to_string(),
        started: std::sync::Arc::clone(&started),
        invocations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-sim-abort", "cost-srv", "compute", 100, "USD");
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        "req-sim-abort",
    );
    let request = ToolCallRequest {
        request_id: "req-sim-abort".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
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

    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("pending tool should be invoked before abort");
    eval.abort();
    let join = eval.await.expect_err("aborted evaluation should not complete");
    assert!(join.is_cancelled());

    // Dispatch began, so the committed budget remains consumed.
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.committed_cost_units().unwrap(), 100);

    // Post-dispatch abort does not settle, release, or refund an outcome that may
    // have taken effect.
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "adapter.authorize() must have been called once"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "post-dispatch abort must retain the payment authorization"
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "post-dispatch abort must not refund an ambiguous outcome"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an unfinished tool call has no post-execution capture"
    );
}

// A grant without monetary ceiling whose approval threshold forces governed
// admission. Shared by the no-charge MustPrepay settlement tests below.
fn make_no_ceiling_mustprepay_grant() -> ToolGrant {
    ToolGrant {
        server_id: "cost-srv".to_string(),
        tool_name: "compute".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![
            Constraint::GovernedIntentRequired,
            Constraint::RequireApprovalAbove { threshold_units: 50 },
        ],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

// Governed MustPrepay where the grant carries no monetary ceiling:
// the budget layer yields PreExecutionBudgetMutation::None (charge_result == None),
// bypassing the cost path. The unsettled authorization the adapter returns must be
// captured post-execution so the receipt records a genuinely settled prepayment
// rather than a perpetual pending hold.
#[test]
fn mustprepay_no_budget_charge_authorizes_payment_and_stamps_receipt() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    // Server reports a cost; the grant has no monetary ceiling so charge_result is None.
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    // Grant without monetary limits: GovernedIntentRequired + approval threshold
    // ensure validate_governed_transaction runs, but no cost ceiling means the budget
    // layer returns PreExecutionBudgetMutation::None.
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3600,
        )
        .unwrap();

    // Intent quotes 100 USD (above threshold 50), so an approval token is required.
    let intent = make_mustprepay_intent("intent-no-charge", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-no-charge", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let financial = expect_financial_meta(&response);
    let payment_reference = financial["payment_reference"]
        .as_str()
        .expect("receipt must carry payment_reference when payment was authorized");
    assert!(
        payment_reference.starts_with("sim-"),
        "payment_reference must be a sim- id; got {payment_reference}"
    );
    let status = financial["settlement_status"].as_str().unwrap_or("");
    assert_eq!(
        status, "settled",
        "no-ceiling MustPrepay must capture the hold to a settled prepayment; got {status}"
    );
}

// The no-charge MustPrepay settlement must invoke the adapter's capture exactly
// once on the unsettled authorization the adapter returned.
#[test]
fn mustprepay_no_budget_charge_captures_unsettled_authorization() {
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3600,
        )
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-no-charge-cap", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-no-charge-cap", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "adapter.authorize() must have been called once"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "adapter.capture() must settle the unsettled prepayment exactly once"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a captured prepayment must not be released"
    );
    let financial = expect_financial_meta(&response);
    assert_eq!(
        financial["settlement_status"].as_str().unwrap_or(""),
        "settled",
        "captured no-ceiling prepayment must record settled"
    );
}

// A no-ceiling MustPrepay whose tool ran and whose payment was captured must write
// the full financial envelope: the receipt `financial` object must deserialize as
// `FinancialReceiptMetadata` and carry the prepaid quote amount, currency, and a
// settled status. A partial fragment (payment_reference + settlement_status only)
// fails to deserialize and drops the prepaid spend from receipt queries and
// dashboards.
#[test]
fn mustprepay_no_budget_charge_receipt_financial_deserializes_with_quote() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3600,
        )
        .unwrap();

    // The intent quotes 100 USD (quoted_cost.units == max_units).
    let intent =
        make_mustprepay_intent("intent-no-charge-full", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-no-charge-full", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    let financial = expect_financial_meta(&response);
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial.clone())
        .expect("no-ceiling MustPrepay financial must deserialize as FinancialReceiptMetadata");
    assert_eq!(
        parsed.cost_charged, 100,
        "the prepaid quote amount must be recorded as the realized spend"
    );
    assert_eq!(parsed.currency, "USD");
    assert_eq!(parsed.settlement_status, crate::SettlementStatus::Settled);
    assert!(
        parsed.payment_reference.is_some(),
        "the settled prepayment reference must be present"
    );
}

// Fail-closed: when the adapter returns an unsettled authorization whose capture
// cannot settle, the no-charge MustPrepay call is DENIED rather than admitted with
// a perpetual pending receipt.
#[test]
fn mustprepay_no_budget_charge_uncapturable_authorization_denies() {
    let payment = UncapturablePaymentAdapter::default();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3600,
        )
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-no-charge-deny", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-no-charge-deny", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "an unsettled prepayment that cannot be captured must fail closed"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a fail-closed deny must void the unsettled hold so the payer's funds are not left frozen"
    );
}

// A dispatch error is ambiguous because the tool may already have applied its
// side effect. The payment authorization stays retained for operator recovery.
#[test]
fn mustprepay_no_budget_charge_retains_hold_after_ambiguous_dispatch() {
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(FailingMonetaryServer {
        id: "cost-srv".to_string(),
    }));

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3600,
        )
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-no-charge-abort", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-no-charge-abort", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "adapter.authorize() must have been called once"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a post-dispatch error must not release a possibly consumed authorization"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an aborted dispatch must not capture the hold"
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an unsettled hold is released, never refunded"
    );
}

// A no-ceiling MustPrepay intent whose declared max_amount is absent but whose
// quote.quoted_cost is the amount that will actually be prepaid.
fn make_no_ceiling_mustprepay_intent_over_threshold(
    id: &str,
    quoted_units: u64,
    currency: &str,
) -> GovernedTransactionIntent {
    let mut intent = make_mustprepay_intent(id, "cost-srv", "compute", quoted_units, currency);
    // The prepaid amount is quote.quoted_cost; drop the declared max_amount so only
    // the quote can drive the approval-threshold decision.
    intent.max_amount = None;
    intent
}

// The amount actually prepaid for a no-ceiling MustPrepay intent is
// quote.quoted_cost, so a quote above RequireApprovalAbove must be gated even when
// max_amount is absent. Denied without an approval token, admitted with one.
#[test]
fn governed_mustprepay_quote_above_threshold_requires_approval() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let agent_kp = Keypair::generate();
    // make_no_ceiling_mustprepay_grant gates approval above 50 units.
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3600,
        )
        .unwrap();

    // Quote 100 > threshold 50, max_amount absent: the prepaid quote alone forces approval.
    let intent = make_no_ceiling_mustprepay_intent_over_threshold("intent-quote-gate", 100, "USD");

    let no_token = ToolCallRequest {
        request_id: "req-quote-gate-deny".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent.clone()),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let denied = kernel.evaluate_tool_call_blocking(&no_token).unwrap();
    assert_eq!(
        denied.verdict,
        Verdict::Deny,
        "a MustPrepay quote above the approval threshold must be denied without an approval token"
    );
    let reason = denied.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("approval token required"),
        "denial must cite the missing approval token; got: {reason}"
    );

    let with_token =
        mustprepay_tool_call("req-quote-gate-allow", &cap, &agent_kp, intent, &kernel);
    let allowed = kernel.evaluate_tool_call_blocking(&with_token).unwrap();
    assert_eq!(
        allowed.verdict,
        Verdict::Allow,
        "a valid approval token must admit the prepaid MustPrepay quote"
    );
}

// Request-building helpers for the with-charge MustPrepay gating tests. A grant
// with a small per-invocation ceiling yields a provisional budget charge below
// the approval threshold, while the MustPrepay quote (the amount actually
// prepaid) sits above it.
fn mustprepay_request_without_token(
    request_id: &str,
    cap: &CapabilityToken,
    agent_kp: &Keypair,
    intent: GovernedTransactionIntent,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

// A MustPrepay quote is an actual spend boundary, so it must not exceed the
// grant's per-invocation ceiling even when an approval token could authorize the
// governed action.
#[test]
fn governed_mustprepay_rejects_quote_above_grant_ceiling() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 5, "USD")));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let mut intent =
        make_mustprepay_intent("intent-charge-quote-gate", "cost-srv", "compute", 100, "USD");
    intent.max_amount = None;

    let no_token =
        mustprepay_request_without_token("req-charge-quote-deny", &cap, &agent_kp, intent.clone());
    let denied = kernel.evaluate_tool_call_blocking(&no_token).unwrap();
    assert_eq!(
        denied.verdict,
        Verdict::Deny,
        "a MustPrepay quote above the grant ceiling must be denied"
    );
    let reason = denied.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("grant per-invocation cost limit"),
        "denial must cite the grant ceiling; got: {reason}"
    );
}

// A MustPrepay whose quote and provisional charge both sit below the approval
// threshold still passes without a token: the fix must not over-gate.
#[test]
fn governed_mustprepay_with_charge_below_threshold_passes_without_token() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 5, "USD")));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 40, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // Quote 40 < threshold 50 and charge 10 < 50: no approval token is required.
    let mut intent =
        make_mustprepay_intent("intent-charge-under-gate", "cost-srv", "compute", 40, "USD");
    intent.max_amount = None;

    let no_token =
        mustprepay_request_without_token("req-charge-under-allow", &cap, &agent_kp, intent);
    let allowed = kernel.evaluate_tool_call_blocking(&no_token).unwrap();
    assert_eq!(
        allowed.verdict,
        Verdict::Allow,
        "a MustPrepay quote below the approval threshold must pass without an approval token"
    );
}

// Authorizes an unsettled hold whose capture always fails, exercising the
// fail-closed settlement path. Counts releases so a leaked hold is observable.
#[derive(Debug, Clone, Default)]
struct UncapturablePaymentAdapter {
    released: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PaymentAdapter for UncapturablePaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "sim-uncapturable".to_string(),
            state: crate::payment::PaymentAuthorizationState::Held,
            metadata: serde_json::json!({ "adapter": "uncapturable" }),
        })
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Declined("capture unavailable".to_string()))
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "uncapturable" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "uncapturable" }),
        })
    }
}

// Captures the prepaid hold at authorize time (settled == true) and counts every
// unwind operation so an aborted no-charge invocation's cleanup is observable.
#[derive(Debug, Clone, Default)]
struct SettledAtAuthorizeTrackingAdapter {
    authorized: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    captured: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    released: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    refunded: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PaymentAdapter for SettledAtAuthorizeTrackingAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorized
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: "sim-settled-authorize".to_string(),
            state: crate::payment::PaymentAuthorizationState::PrepaidFinal,
            metadata: serde_json::json!({ "adapter": "settled-at-authorize" }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.captured
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "settled-at-authorize" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.released
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "settled-at-authorize" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.refunded
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "settled-at-authorize" }),
        })
    }
}

// A final prepayment is also retained after an ambiguous dispatch error because
// refunding could pay back a tool action that actually completed.
#[test]
fn settled_no_charge_mustprepay_ambiguous_dispatch_retains_payment() {
    let payment = SettledAtAuthorizeTrackingAdapter::default();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(FailingMonetaryServer {
        id: "cost-srv".to_string(),
    }));

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_no_ceiling_mustprepay_grant()]),
            3600,
        )
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-settled-abort", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-settled-abort", &cap, &agent_kp, intent, &kernel);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "adapter.authorize() must have been called once"
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a post-dispatch error must not refund a possibly completed prepayment"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a settled authorization must never be released on abort"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an aborted dispatch must not capture the hold again"
    );
}

// The reserve-for-caller path never dispatches the tool on this kernel: the
// caller presents the minted nonce to a downstream tool server, which reconciles
// the reserved hold without re-entering payment authorization. A governed
// MustPrepay intent therefore has no later settlement point, so a nonce must not
// be minted until the prepayment is settled here. A prepayment that cannot be
// settled must fail closed with no nonce and no reserved hold, or the caller could
// execute a MustPrepay spend downstream with no payment ever occurring.
#[test]
fn reserving_authorization_denies_governed_mustprepay_without_settled_prepayment() {
    let MustPrepayFixture { mut kernel, cap, agent_kp } = build_mustprepay_fixture(75);
    let payment = UncapturablePaymentAdapter::default();
    kernel.set_payment_adapter(Box::new(payment.clone()));
    install_strict_nonce_store(&mut kernel);

    let intent = make_mustprepay_intent("intent-reserve-deny", "cost-srv", "compute", 100, "USD");
    let request =
        mustprepay_tool_call("req-reserve-mustprepay-deny", &cap, &agent_kp, intent, &kernel);

    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();

    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "a MustPrepay reserve whose prepayment cannot settle must fail closed: {:?}",
        response.reason
    );
    assert!(
        response.execution_nonce.is_none(),
        "no execution nonce may be minted for an unpaid MustPrepay reserve"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the unsettled prepaid hold must be released so the payer's funds are not frozen"
    );
    // The reserved budget hold was reversed, not stranded open: a later
    // authorization on the fully-bounded grant is not blocked by a dead reservation.
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        0,
        "a denied MustPrepay reserve must leave no committed exposure"
    );
}

// A governed MustPrepay reserve whose prepayment settles is admitted: the budget
// hold stays reserved and an execution nonce is minted for the downstream caller.
// The prepayment is authorized AND captured before the nonce exists, so the spend
// the caller later executes has already been paid.
#[test]
fn reserving_authorization_admits_governed_mustprepay_with_settled_prepayment() {
    let MustPrepayFixture { mut kernel, cap, agent_kp } = build_mustprepay_fixture(75);
    let payment = TrackingPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone()));
    install_strict_nonce_store(&mut kernel);

    let intent = make_mustprepay_intent("intent-reserve-allow", "cost-srv", "compute", 100, "USD");
    let request =
        mustprepay_tool_call("req-reserve-mustprepay-allow", &cap, &agent_kp, intent, &kernel);

    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();

    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "a settled MustPrepay prepayment must admit the reserve: {:?}",
        response.reason
    );
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        response.execution_nonce.is_some(),
        "a settled MustPrepay reserve must mint an execution nonce for the downstream caller"
    );
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the prepayment must be authorized before the nonce is minted"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the prepayment must be settled (captured) before the nonce is minted"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a settled prepayment must not be released"
    );
}

// A governed MustPrepay reserve captures the prepayment before the reservation
// nonce is minted. If the reservation stamp then fails, the budget hold is
// reversed and the caller receives no nonce, so the captured prepayment must be
// refunded: otherwise a retry re-captures and the payer is charged for a
// reservation that was never handed out (money loss and double-charge). Once the
// stamp write recovers, the success path still captures the prepayment exactly
// once and mints the nonce, with no refund or release.
#[test]
fn reserving_mustprepay_stamp_failure_refunds_captured_prepayment() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let payment = TrackingPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone()));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: InMemoryBudgetStore::new(),
        fail_mark: std::sync::Arc::clone(&fail_mark),
    }));
    install_strict_nonce_store(&mut kernel);

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent =
        make_mustprepay_intent("intent-reserve-stamp-fail", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call(
        "req-reserve-mustprepay-stamp-fail",
        &cap,
        &agent_kp,
        intent,
        &kernel,
    );

    // The reservation stamp fails after the prepayment is captured.
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("stamp") || err.to_string().contains("reservation"),
        "the reservation stamp failure must surface: {err}"
    );

    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the prepayment must have been captured once before the stamp failed"
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a captured prepayment must be refunded when the reservation tears down, \
         so the payer is not left net-charged for a reservation that was denied"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a captured prepayment must be refunded, never released, on tear-down"
    );

    // The reserved budget hold was reversed, not stranded open.
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        0,
        "a torn-down MustPrepay reserve must leave no committed exposure"
    );

    // Once the stamp write recovers, the success path captures the prepayment
    // exactly once more and mints a nonce, with no further refund or release.
    fail_mark.store(false, Ordering::SeqCst);
    let intent_ok =
        make_mustprepay_intent("intent-reserve-stamp-ok", "cost-srv", "compute", 100, "USD");
    let request_ok = mustprepay_tool_call(
        "req-reserve-mustprepay-stamp-ok",
        &cap,
        &agent_kp,
        intent_ok,
        &kernel,
    );
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request_ok, None)
        .unwrap();
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "the recovered reservation must be admitted: {:?}",
        reserved.reason
    );
    assert!(
        reserved.execution_nonce.is_some(),
        "a settled MustPrepay reserve must mint an execution nonce for the downstream caller"
    );
    assert_eq!(
        payment.captured.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the recovered success path must capture the prepayment exactly once more"
    );
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the success path must not refund the captured prepayment"
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the success path must not release the settled prepayment"
    );
}

// The reserve-for-caller prepayment gate is scoped to governed MustPrepay intents.
// A plain monetary reserve with a payment adapter configured is unchanged: it
// reserves the hold and mints a nonce without authorizing any prepayment (the tool
// is billed at reconcile time downstream).
#[test]
fn reserving_authorization_leaves_non_mustprepay_path_unchanged() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let payment = TrackingPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone()));
    install_strict_nonce_store(&mut kernel);

    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = reserve_request("req-reserve-plain", &cap, &agent_kp);

    let response = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let nonce = *response
        .execution_nonce
        .clone()
        .expect("a non-MustPrepay reserve must still mint an execution nonce");
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a non-MustPrepay reserve must not authorize a prepayment"
    );

    // Reconciling the non-MustPrepay reserve stamps no payment reference: nothing
    // was prepaid, so there is no rail transaction to name on the receipt.
    let realized = ToolInvocationCost {
        units: 40,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);
    let financial = expect_financial_meta(&reconciled);
    assert!(
        financial.get("payment_reference").is_none()
            || financial["payment_reference"].is_null(),
        "a non-MustPrepay reconcile must not carry a payment_reference: {financial}"
    );
}

// A distinct-id adapter: the authorization hold id and the capture (rail
// settlement) transaction id differ, so a reconcile receipt that echoes the
// capture transaction id can be told apart from one that merely echoes the hold
// id.
struct DistinctCapturePaymentAdapter;

impl PaymentAdapter for DistinctCapturePaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "auth_hold_ref".to_string(),
            state: crate::payment::PaymentAuthorizationState::Held,
            metadata: serde_json::json!({ "adapter": "distinct" }),
        })
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "rail_txn_ref".to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "distinct" }),
        })
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "rail_release_ref".to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "distinct" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "distinct" }),
        })
    }
}

// A governed MustPrepay mediated reserve captures a prepayment before minting the
// nonce; the later authoritative reconcile receipt must name the rail transaction
// that funded the spend so operators can tie the settlement to its payment. The
// stamped reference is the capture transaction id, not the authorization hold id.
#[test]
fn reconcile_stamps_mustprepay_prepayment_rail_reference() {
    let MustPrepayFixture { mut kernel, cap, agent_kp } = build_mustprepay_fixture(75);
    kernel.set_payment_adapter(Box::new(DistinctCapturePaymentAdapter));
    install_strict_nonce_store(&mut kernel);

    let intent = make_mustprepay_intent("intent-reserve-recon", "cost-srv", "compute", 100, "USD");
    let request =
        mustprepay_tool_call("req-reserve-mustprepay-recon", &cap, &agent_kp, intent, &kernel);

    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "a settled MustPrepay prepayment must admit the reserve: {:?}",
        reserved.reason
    );
    let nonce = *reserved
        .execution_nonce
        .clone()
        .expect("a settled MustPrepay reserve mints a nonce");

    let realized = ToolInvocationCost {
        units: 40,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    let financial = expect_financial_meta(&reconciled);
    assert_eq!(
        financial["payment_reference"].as_str(),
        Some("rail_txn_ref"),
        "the reconcile receipt must carry the rail transaction id that funded the prepayment: {financial}"
    );
}

// Records the amount and currency presented to authorize so a test can assert
// which figure funds the prepayment. Holds unsettled so the caller settles it.
// Also records the amount, currency, and call counts of refund/release so an
// abort-unwind test can assert which figure is returned to the payer.
#[derive(Debug, Clone, Default)]
struct AmountRecordingPaymentAdapter {
    authorized_amount: std::sync::Arc<std::sync::atomic::AtomicU64>,
    authorized_currency: std::sync::Arc<std::sync::Mutex<String>>,
    refunded_amount: std::sync::Arc<std::sync::atomic::AtomicU64>,
    refunded_currency: std::sync::Arc<std::sync::Mutex<String>>,
    refund_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    release_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PaymentAdapter for AmountRecordingPaymentAdapter {
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorized_amount
            .store(request.amount_units, std::sync::atomic::Ordering::SeqCst);
        *self.authorized_currency.lock().unwrap() = request.currency.clone();
        Ok(PaymentAuthorization {
            authorization_id: "sim-amount-recording".to_string(),
            state: crate::payment::PaymentAuthorizationState::Held,
            metadata: serde_json::json!({ "adapter": "amount-recording" }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "amount-recording" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.release_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "amount-recording" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.refunded_amount
            .store(amount_units, std::sync::atomic::Ordering::SeqCst);
        *self.refunded_currency.lock().unwrap() = currency.to_string();
        self.refund_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "amount-recording" }),
        })
    }
}

// Authorize a real, open budget hold matching a fabricated provisional charge
// (see `make_provisional_charge`) so the abort-unwind's `reverse_budget_charge`
// is a clean, receipt-free reversal rather than a fault over a missing hold.
fn authorize_provisional_hold(
    kernel: &ChioKernel,
    capability_id: &str,
    exposure_units: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    kernel
        .with_budget_store(|store| {
            let decision =
                store.authorize_budget_hold(crate::budget_store::BudgetAuthorizeHoldRequest {
                    capability_id: capability_id.to_string(),
                    grant_index: 0,
                    max_invocations: None,
                    requested_exposure_units: exposure_units,
                    max_cost_per_invocation: Some(1_000),
                    max_total_cost_units: Some(10_000),
                    hold_id: Some("hold-provisional".to_string()),
                    event_id: Some("hold-provisional:authorize".to_string()),
                    authority: None,
                    invocation_quotas: Vec::new(),
                    cumulative_approval: None,
                    admission_binding: None,
                })?;
            assert!(
                matches!(
                    decision,
                    crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
                ),
                "provisional hold must authorize"
            );
            Ok(())
        })
        .map_err(|error| -> Box<dyn std::error::Error> {
            format!("authorize provisional hold: {error}").into()
        })?;
    Ok(())
}

// A settled MustPrepay authorization that funded the tool from the prepaid quote
// (100) while a smaller provisional budget hold (10, cross-currency) accompanied
// it. When the invocation aborts, the payer must be refunded the quote amount it
// actually prepaid, in the quote's currency, not the provisional hold's smaller
// figure. Refunding the hold amount would leave the payer charged the difference
// for a tool that never completed.
#[test]
fn aborted_settled_mustprepay_charge_refunds_the_quoted_amount(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_monetary_config());
    let adapter = AmountRecordingPaymentAdapter::default();
    let refunded_amount = adapter.refunded_amount.clone();
    let refunded_currency = adapter.refunded_currency.clone();
    let refund_calls = adapter.refund_calls.clone();
    kernel.set_payment_adapter(Box::new(adapter));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    authorize_provisional_hold(&kernel, &cap.id, 10)?;

    let intent = make_mustprepay_intent("intent-abort-refund", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-abort-refund", &cap, &agent_kp, intent, &kernel);

    // Provisional per-invocation hold of 10 in a different currency accompanies
    // the 100 USD quote that actually funded the authorization.
    let charge = make_provisional_charge(10, "EUR");
    let authorization = PaymentAuthorization {
        authorization_id: "auth-settled-abort".to_string(),
        state: crate::payment::PaymentAuthorizationState::PrepaidFinal,
        metadata: serde_json::json!({ "adapter": "amount-recording" }),
    };

    kernel.unwind_pre_dispatch_monetary_invocation(
        &request,
        &cap,
        Some(&charge),
        Some(&authorization),
    )?;

    assert_eq!(
        refund_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a settled MustPrepay abort must refund exactly once"
    );
    assert_eq!(
        refunded_amount.load(std::sync::atomic::Ordering::SeqCst),
        100,
        "the refund must return the prepaid quote (100), not the provisional hold (10)"
    );
    assert_eq!(
        refunded_currency.lock().unwrap().as_str(),
        "USD",
        "the refund must be in the quote's currency, not the provisional charge's"
    );
    Ok(())
}

// A settled NON-MustPrepay metered charge has no prepaid quote, so an abort must
// refund the charged amount in the charge's currency. The quote-first refund
// precedence must not disturb the plain metered path.
#[test]
fn aborted_settled_non_mustprepay_charge_refunds_the_charged_amount(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_monetary_config());
    let adapter = AmountRecordingPaymentAdapter::default();
    let refunded_amount = adapter.refunded_amount.clone();
    let refunded_currency = adapter.refunded_currency.clone();
    let refund_calls = adapter.refund_calls.clone();
    kernel.set_payment_adapter(Box::new(adapter));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    authorize_provisional_hold(&kernel, &cap.id, 10)?;

    // No governed intent means no MustPrepay quote: the charge alone was funded.
    let request = ToolCallRequest {
        request_id: "req-abort-metered-refund".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let charge = make_provisional_charge(10, "USD");
    let authorization = PaymentAuthorization {
        authorization_id: "auth-settled-metered".to_string(),
        state: crate::payment::PaymentAuthorizationState::PrepaidFinal,
        metadata: serde_json::json!({ "adapter": "amount-recording" }),
    };

    kernel.unwind_pre_dispatch_monetary_invocation(
        &request,
        &cap,
        Some(&charge),
        Some(&authorization),
    )?;

    assert_eq!(
        refund_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a settled metered abort must refund exactly once"
    );
    assert_eq!(
        refunded_amount.load(std::sync::atomic::Ordering::SeqCst),
        10,
        "a non-MustPrepay charge must refund the charged amount"
    );
    assert_eq!(
        refunded_currency.lock().unwrap().as_str(),
        "USD",
        "a non-MustPrepay charge must refund in the charge's currency"
    );
    Ok(())
}

// An UNSETTLED authorization was never captured, so an abort must release the
// hold, not refund it, whether or not a MustPrepay quote is present.
#[test]
fn aborted_unsettled_mustprepay_charge_releases_not_refunds(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_monetary_config());
    let adapter = AmountRecordingPaymentAdapter::default();
    let refund_calls = adapter.refund_calls.clone();
    let release_calls = adapter.release_calls.clone();
    kernel.set_payment_adapter(Box::new(adapter));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    authorize_provisional_hold(&kernel, &cap.id, 10)?;

    let intent =
        make_mustprepay_intent("intent-abort-release", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-abort-release", &cap, &agent_kp, intent, &kernel);
    let charge = make_provisional_charge(10, "USD");
    let authorization = PaymentAuthorization {
        authorization_id: "auth-unsettled-abort".to_string(),
        state: crate::payment::PaymentAuthorizationState::Held,
        metadata: serde_json::json!({ "adapter": "amount-recording" }),
    };

    kernel.unwind_pre_dispatch_monetary_invocation(
        &request,
        &cap,
        Some(&charge),
        Some(&authorization),
    )?;

    assert_eq!(
        release_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an unsettled authorization must be released"
    );
    assert_eq!(
        refund_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an unsettled authorization must not be refunded"
    );
    Ok(())
}

// A fabricated provisional monetary budget hold used to drive
// `authorize_payment_if_needed` directly, modelling the charge a grant with a
// per-invocation ceiling would produce alongside a MustPrepay quote.
fn make_provisional_charge(cost_charged: u64, currency: &str) -> BudgetChargeResult {
    BudgetChargeResult {
        grant_index: 0,
        cost_charged,
        currency: currency.to_string(),
        budget_total: 1000,
        new_committed_cost_units: cost_charged,
        budget_hold_id: "hold-provisional".to_string(),
        authorize_metadata: BudgetCommitMetadata {
            authority: None,
            guarantee_level: crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic,
            budget_profile: crate::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile:
                crate::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: None,
            event_id: None,
            recorded_at_unix_seconds: None,
        },
        invocation_capture: None,
    }
}

// A governed MustPrepay intent whose quote (100) is the amount the payer prepays
// while a provisional per-invocation budget hold (10) accompanies it. The
// prepayment must fund the quoted cost, not the provisional hold, or the tool
// executes against an underfunded prepayment. The charge is fabricated in a
// different currency to prove the quote's currency (not the charge's) is what is
// authorized for a cross-currency quote.
#[test]
fn governed_mustprepay_with_charge_funds_the_quoted_cost_not_the_hold() {
    let mut kernel = make_kernel(make_monetary_config());
    let adapter = AmountRecordingPaymentAdapter::default();
    let authorized_amount = adapter.authorized_amount.clone();
    let authorized_currency = adapter.authorized_currency.clone();
    kernel.set_payment_adapter(Box::new(adapter));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 5, "USD")));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent = make_mustprepay_intent("intent-charge-fund", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-charge-fund", &cap, &agent_kp, intent, &kernel);

    // Provisional budget hold of 10 in a different currency accompanies the quote.
    let charge = make_provisional_charge(10, "EUR");

    let authorization = kernel
        .authorize_payment_if_needed(&request, Some(&charge), None, 0, None)
        .expect("MustPrepay-with-charge authorization must succeed")
        .expect("MustPrepay-with-charge must authorize a prepayment");
    assert!(
        !authorization.state.is_final(),
        "the recording adapter holds the authorization unsettled"
    );
    assert_eq!(
        authorized_amount.load(std::sync::atomic::Ordering::SeqCst),
        100,
        "a MustPrepay prepayment must fund the quoted cost (100), not the provisional budget hold (10)"
    );
    assert_eq!(
        authorized_currency.lock().unwrap().as_str(),
        "USD",
        "the prepayment must be authorized in the quote's currency, not the charge's"
    );
}

// Regression: a no-ceiling MustPrepay grant is non-monetary, so admission writes
// no HoldPlaced journal row and reaches payment authorization with `charge_result:
// None`. With the dispatch-intent payment journal ACTIVE (the enum default, not the
// Off that every other monetary test forces), advancing HoldPlaced -> Authorized
// would fail closed against the missing predecessor row and deny a prepayment that
// the rail may already have captured, releasing (not refunding) a settled capture:
// money loss. The authorization must succeed journal-free.
#[test]
fn no_ceiling_mustprepay_authorizes_with_the_payment_journal_active() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 5, "USD")));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let intent = make_mustprepay_intent("intent-no-ceiling", "cost-srv", "compute", 100, "USD");
    let request = mustprepay_tool_call("req-no-ceiling", &cap, &agent_kp, intent, &kernel);

    // `None` models the no-ceiling admission outcome: no monetary charge, hence no
    // HoldPlaced row. This must not deny; the prepayment is journal-free by design.
    let authorization = kernel
        .authorize_payment_if_needed(&request, None, None, 0, None)
        .expect("a no-ceiling MustPrepay must authorize with the journal active, not deny")
        .expect("a no-ceiling MustPrepay must authorize a prepayment");
    assert!(
        authorization.state.is_final(),
        "the sim adapter completes a prepaid no-broadcast authorization"
    );
}

// A non-MustPrepay request with a provisional budget charge and no MustPrepay
// quote still authorizes the charged amount: the quote-first reorder must not
// disturb the metered charge path.
#[test]
fn non_mustprepay_charge_authorizes_the_charged_amount() {
    let mut kernel = make_kernel(make_monetary_config());
    let adapter = AmountRecordingPaymentAdapter::default();
    let authorized_amount = adapter.authorized_amount.clone();
    let authorized_currency = adapter.authorized_currency.clone();
    kernel.set_payment_adapter(Box::new(adapter));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 5, "USD")));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 10, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // No governed intent means no MustPrepay quote: the charge alone drives payment.
    let request = ToolCallRequest {
        request_id: "req-metered-charge".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let charge = make_provisional_charge(10, "USD");

    kernel
        .authorize_payment_if_needed(&request, Some(&charge), None, 0, None)
        .expect("metered charge authorization must succeed")
        .expect("a metered charge must authorize a payment");
    assert_eq!(
        authorized_amount.load(std::sync::atomic::Ordering::SeqCst),
        10,
        "a non-MustPrepay metered charge must authorize the charged amount"
    );
    assert_eq!(
        authorized_currency.lock().unwrap().as_str(),
        "USD",
        "a metered charge must authorize in the charge's currency"
    );
}
