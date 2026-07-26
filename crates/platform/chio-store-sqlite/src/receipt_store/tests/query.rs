use super::super::*;
use super::support::*;
use chio_kernel::ReceiptStore;

#[test]
fn bounded_cost_page_and_count_queries_use_scope_appropriate_indexes() {
    let path = unique_db_path("chio-receipts-cost-query-plan");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let query = ReceiptQuery {
        min_cost: Some(100),
        max_cost: Some(200),
        cost_currency: Some("USD".to_string()),
        tenant_filter: Some("tenant-a".to_string()),
        read_context: Some(chio_kernel::ReceiptReadContext::admin_service()),
        ..ReceiptQuery::default()
    };
    let min_cost = 100_u64.to_be_bytes();
    let max_cost = 200_u64.to_be_bytes();
    let connection = store.connection().test_unwrap();

    for (tenant_fragment, tenant, expected_index) in [
        (
            "(r.tenant_id = ?12)",
            Some("tenant-a"),
            "idx_chio_tool_receipts_cost",
        ),
        ("(?12 IS NULL)", None, "idx_chio_tool_receipts_cost_global"),
    ] {
        let (data_sql, count_sql) =
            crate::receipt_store::evidence_retention::receipt_query_sql(&query, tenant_fragment)
                .test_unwrap();
        for sql in [data_sql, count_sql] {
            let plan = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .test_unwrap()
                .query_map(
                    rusqlite::params![
                        None::<String>,
                        None::<String>,
                        None::<String>,
                        None::<String>,
                        None::<i64>,
                        None::<i64>,
                        min_cost.as_slice(),
                        max_cost.as_slice(),
                        None::<String>,
                        None::<i64>,
                        50_i64,
                        tenant,
                        "USD",
                    ],
                    |row| row.get::<_, String>(3),
                )
                .test_unwrap()
                .collect::<Result<Vec<_>, _>>()
                .test_unwrap()
                .join("\n");
            assert!(
                plan.split_whitespace().any(|token| token == expected_index),
                "unexpected query plan: {plan}"
            );
        }
    }

    drop(connection);
    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_receipt_store_lists_filtered_receipts() {
    let path = unique_db_path("chio-receipts-filtered");
    let store = SqliteReceiptStore::open(&path).test_unwrap();

    store.append_chio_receipt(&sample_receipt()).test_unwrap();
    store
        .append_child_receipt(&sample_child_receipt())
        .test_unwrap();

    let tool_receipts = store
        .list_tool_receipts(
            10,
            Some("cap-1"),
            Some("shell"),
            Some("bash"),
            Some("allow"),
        )
        .test_unwrap();
    assert_eq!(tool_receipts.len(), 1);
    assert_eq!(tool_receipts[0].capability_id, "cap-1");
    assert_eq!(tool_receipts[0].tool_name, "bash");

    let child_receipts = store
        .list_child_receipts(
            10,
            Some("sess-1"),
            Some("parent-1"),
            Some("child-1"),
            Some("create_message"),
            Some("completed"),
        )
        .test_unwrap();
    assert_eq!(child_receipts.len(), 1);
    assert_eq!(child_receipts[0].session_id.as_str(), "sess-1");
    assert_eq!(child_receipts[0].request_id.as_str(), "child-1");

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_analytics_groups_by_agent_tool_and_time() {
    let path = unique_db_path("chio-receipts-analytics");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let keypair = Keypair::generate();

    let make_receipt = |id: &str,
                        subject_key: &str,
                        tool_server: &str,
                        tool_name: &str,
                        decision: Decision,
                        timestamp: u64,
                        cost_charged: u64,
                        attempted_cost: Option<u64>| {
        let financial = if cost_charged > 0 || attempted_cost.is_some() {
            Some(FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: "USD".to_string(),
                budget_remaining: 1_000,
                budget_total: 2_000,
                delegation_depth: 0,
                root_budget_holder: "root-agent".to_string(),
                payment_reference: None,
                settlement_status: if attempted_cost.is_some() {
                    SettlementStatus::NotApplicable
                } else {
                    SettlementStatus::Settled
                },
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            })
        } else {
            None
        };
        let metadata = serde_json::json!({
            "attribution": ReceiptAttributionMetadata {
                subject_key: subject_key.to_string(),
                issuer_key: "issuer-key".to_string(),
                delegation_depth: 0,
                grant_index: Some(0),
            },
            "financial": financial,
        });

        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: format!("cap-{subject_key}"),
                tool_server: tool_server.to_string(),
                tool_name: tool_name.to_string(),
                action: valid_tool_action(serde_json::json!({})),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                decision: Some(decision),
                content_hash: format!("content-{id}"),
                policy_hash: "policy-analytics".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .test_unwrap()
    };

    store
        .append_chio_receipt(&make_receipt(
            "analytics-1",
            "agent-a",
            "shell",
            "bash",
            Decision::Allow,
            86_400,
            100,
            None,
        ))
        .test_unwrap();
    store
        .append_chio_receipt(&make_receipt(
            "analytics-2",
            "agent-a",
            "shell",
            "bash",
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            86_450,
            0,
            Some(50),
        ))
        .test_unwrap();
    store
        .append_chio_receipt(&make_receipt(
            "analytics-3",
            "agent-b",
            "files",
            "read",
            Decision::Incomplete {
                reason: "stream ended".to_string(),
            },
            172_800,
            0,
            None,
        ))
        .test_unwrap();

    let analytics = store
        .query_receipt_analytics(&ReceiptAnalyticsQuery {
            group_limit: Some(10),
            time_bucket: Some(AnalyticsTimeBucket::Day),
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
            ..ReceiptAnalyticsQuery::default()
        })
        .test_unwrap();

    assert_eq!(analytics.summary.total_receipts, 3);
    assert_eq!(analytics.summary.allow_count, 1);
    assert_eq!(analytics.summary.deny_count, 1);
    assert_eq!(analytics.summary.incomplete_count, 1);
    assert_eq!(analytics.summary.total_cost_charged, 100);
    assert_eq!(analytics.summary.total_attempted_cost, 50);
    assert_eq!(
        analytics.summary.reliability_score,
        Some(0.5),
        "allow / (allow + incomplete)"
    );
    assert_eq!(
        analytics.summary.compliance_rate,
        Some(2.0 / 3.0),
        "1 - deny / total"
    );
    assert_eq!(
        analytics.summary.budget_utilization_rate,
        Some(100.0 / 150.0)
    );

    assert_eq!(analytics.by_agent.len(), 2);
    assert_eq!(analytics.by_agent[0].subject_key, "agent-a");
    assert_eq!(analytics.by_agent[0].metrics.total_receipts, 2);

    assert_eq!(analytics.by_tool.len(), 2);
    assert_eq!(analytics.by_tool[0].tool_server, "shell");
    assert_eq!(analytics.by_tool[0].tool_name, "bash");
    assert_eq!(analytics.by_tool[0].metrics.total_receipts, 2);

    assert_eq!(analytics.by_time.len(), 2);
    assert_eq!(analytics.by_time[0].bucket_start, 86_400);
    assert_eq!(analytics.by_time[1].bucket_start, 172_800);

    let _ = fs::remove_file(path);
}

#[test]
fn cost_attribution_report_aggregates_matching_corpus_and_limits_detail_rows() {
    let path = unique_db_path("chio-receipts-cost-attribution");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer_kp,
    )
    .test_unwrap();
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-child".to_string(),
            issuer: root_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_100,
            expires_at: 9_000,
            delegation_chain: vec![chio_core::capability::attenuation::DelegationLink::sign(
                chio_core::capability::attenuation::DelegationLinkBody {
                    capability_id: root.id.clone(),
                    delegator: root_kp.public_key(),
                    delegatee: leaf_kp.public_key(),
                    attenuations: Vec::new(),
                    timestamp: 1_100,
                    scope_hash: None,
                    aggregate_budget: None,
                    cumulative_approval: None,
                },
                &root_kp,
            )
            .test_unwrap()],
            aggregate_invocation_budget: None,
        },
        &root_kp,
    )
    .test_unwrap();

    store.record_capability_snapshot(&root, None).test_unwrap();
    store
        .record_capability_snapshot(&child, Some("cap-root"))
        .test_unwrap();

    let make_financial_receipt = |id: &str,
                                  capability_id: &str,
                                  subject_key: Option<String>,
                                  root_budget_holder: &str,
                                  delegation_depth: u32,
                                  timestamp: u64,
                                  decision: Decision,
                                  cost_charged: u64,
                                  attempted_cost: Option<u64>| {
        let attribution = subject_key.map(|subject_key| ReceiptAttributionMetadata {
            subject_key,
            issuer_key: issuer_hex.clone(),
            delegation_depth,
            grant_index: Some(0),
        });
        let metadata = serde_json::json!({
            "attribution": attribution,
            "financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: "USD".to_string(),
                budget_remaining: 900,
                budget_total: 1_000,
                delegation_depth,
                root_budget_holder: root_budget_holder.to_string(),
                payment_reference: None,
                settlement_status: if attempted_cost.is_some() && cost_charged == 0 {
                    SettlementStatus::NotApplicable
                } else {
                    SettlementStatus::Settled
                },
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            }
        });

        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: valid_tool_action(serde_json::json!({})),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                decision: Some(decision),
                content_hash: format!("content-{id}"),
                policy_hash: "policy-cost".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: receipt_kp.public_key(),
                bbs_projection_version: None,
            },
            &receipt_kp,
        )
        .test_unwrap()
    };

    store
        .append_chio_receipt(&make_financial_receipt(
            "cost-1",
            "cap-child",
            Some(leaf_hex.clone()),
            &root_hex,
            1,
            1_200,
            Decision::Allow,
            125,
            None,
        ))
        .test_unwrap();
    store
        .append_chio_receipt(&make_financial_receipt(
            "cost-2",
            "cap-child",
            Some(leaf_hex.clone()),
            &root_hex,
            1,
            1_201,
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            0,
            Some(75),
        ))
        .test_unwrap();
    store
        .append_chio_receipt(&make_financial_receipt(
            "cost-3",
            "cap-orphan",
            None,
            "orphan-root",
            2,
            1_202,
            Decision::Allow,
            50,
            None,
        ))
        .test_unwrap();

    let report = store
        .query_cost_attribution_report(&CostAttributionQuery {
            limit: Some(1),
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
            ..CostAttributionQuery::default()
        })
        .test_unwrap();

    assert_eq!(report.summary.matching_receipts, 3);
    assert_eq!(report.summary.returned_receipts, 1);
    assert_eq!(report.summary.total_cost_charged, 175);
    assert_eq!(report.summary.total_attempted_cost, 75);
    assert_eq!(report.summary.max_delegation_depth, 2);
    assert_eq!(report.summary.distinct_root_subjects, 2);
    assert_eq!(report.summary.distinct_leaf_subjects, 1);
    assert_eq!(report.summary.lineage_gap_count, 1);
    assert!(report.summary.truncated);

    assert_eq!(report.by_root.len(), 2);
    assert_eq!(
        report.by_root[0].root_subject_key.as_str(),
        root_hex.as_str()
    );
    assert_eq!(report.by_root[0].receipt_count, 2);
    assert_eq!(report.by_root[0].total_cost_charged, 125);
    assert_eq!(report.by_root[0].total_attempted_cost, 75);
    assert_eq!(report.by_root[0].distinct_leaf_subjects, 1);

    assert_eq!(report.by_leaf.len(), 1);
    assert_eq!(
        report.by_leaf[0].root_subject_key.as_str(),
        root_hex.as_str()
    );
    assert_eq!(
        report.by_leaf[0].leaf_subject_key.as_str(),
        leaf_hex.as_str()
    );
    assert_eq!(report.by_leaf[0].receipt_count, 2);
    assert_eq!(report.by_leaf[0].total_cost_charged, 125);
    assert_eq!(report.by_leaf[0].total_attempted_cost, 75);

    assert_eq!(report.receipts.len(), 1);
    assert_eq!(report.receipts[0].capability_id, "cap-child");
    assert_eq!(
        report.receipts[0].root_subject_key.as_deref(),
        Some(root_hex.as_str())
    );
    assert_eq!(
        report.receipts[0].leaf_subject_key.as_deref(),
        Some(leaf_hex.as_str())
    );
    assert!(report.receipts[0].lineage_complete);
    assert_eq!(report.receipts[0].chain.len(), 2);

    let _ = fs::remove_file(path);
}

#[test]
fn economic_receipt_projection_report_joins_signed_envelope_with_reconciliation_state() {
    let path = unique_db_path("chio-receipts-economic-projection");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-economic".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "model".to_string(),
                    tool_name: "infer".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer_kp,
    )
    .test_unwrap();
    store
        .record_capability_snapshot(&capability, None)
        .test_unwrap();

    let quote = MeteredBillingQuote {
        quote_id: "quote-economic-1".to_string(),
        provider: "meterco".to_string(),
        billing_unit: "tokens".to_string(),
        quoted_units: 100,
        quoted_cost: MonetaryAmount {
            units: 400,
            currency: "USD".to_string(),
        },
        issued_at: 1_900,
        expires_at: Some(3_600),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-economic-1".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "model".to_string(),
            tool_name: "infer".to_string(),
            action: valid_tool_action(serde_json::json!({ "prompt": "hello" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-economic-1".to_string(),
            policy_hash: "policy-economic-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex,
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 400,
                    currency: "USD".to_string(),
                    budget_remaining: 600,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: Some("payref-economic-1".to_string()),
                    settlement_status: SettlementStatus::Pending,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: Some(450),
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-economic-1".to_string(),
                    intent_hash: "intent-hash-economic-1".to_string(),
                    purpose: "metered inference".to_string(),
                    server_id: "model".to_string(),
                    tool_name: "infer".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: Some(MeteredBillingReceiptMetadata {
                        settlement_mode: MeteredSettlementMode::HoldCapture,
                        quote: quote.clone(),
                        max_billed_units: Some(110),
                        usage_evidence: None,
                    }),
                    approval: Some(GovernedApprovalReceiptMetadata {
                        token_id: "approval-economic-1".to_string(),
                        approver_key: subject_hex.clone(),
                        approval_artifact_digest: None,
                        approved: true,
                    }),
                    runtime_assurance: None,
                    call_chain: None,
                    autonomy: None,
                    economic_authorization: Some(EconomicAuthorizationReceiptMetadata {
                        version: EconomicAuthorizationReceiptMetadataVersion::V1,
                        economic_intent_digest: None,
                        payee_binding_digest: None,
                        pre_action_authority_digest: None,
                        credit_authority_digest: None,
                        economic_mode: EconomicAuthorizationMode::MeteredHoldCapture,
                        payer: EconomicPayerReceiptMetadata {
                            party_id: "agent-economic".to_string(),
                            funding_source_ref: "payref-economic-1".to_string(),
                            custody_provider: None,
                            obligor_ref: None,
                        },
                        merchant: EconomicMerchantReceiptMetadata {
                            merchant_id: "model".to_string(),
                            merchant_of_record: None,
                            order_ref: Some("req-economic-1".to_string()),
                        },
                        payee: EconomicPayeeReceiptMetadata {
                            beneficiary_id: "model".to_string(),
                            settlement_destination_ref: "payref-economic-1".to_string(),
                        },
                        rail: EconomicRailReceiptMetadata {
                            kind: "metered_billing".to_string(),
                            asset: "USD".to_string(),
                            network: None,
                            facilitator: Some("meterco".to_string()),
                            contract_or_account_ref: Some("payref-economic-1".to_string()),
                        },
                        amount_bounds: EconomicAmountBoundsReceiptMetadata {
                            approved_max: MonetaryAmount {
                                units: 500,
                                currency: "USD".to_string(),
                            },
                            hold_amount: Some(MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            }),
                            settlement_cap: MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            },
                        },
                        pricing_basis: Some(EconomicPricingBasisReceiptMetadata {
                            quote_hash: Some("quote-hash-economic-1".to_string()),
                            tariff_hash: None,
                            quote_expiry: quote.expires_at,
                        }),
                        metering: Some(EconomicMeteringReceiptMetadata {
                            provider: "meterco".to_string(),
                            meter_profile_hash: "meter-profile-economic-1".to_string(),
                            max_billable_units: Some(110),
                            billing_unit: Some("tokens".to_string()),
                        }),
                        liability_refs: None,
                        budget: EconomicBudgetReceiptMetadata {
                            grant_index: 0,
                            cost_charged: 400,
                            currency: "USD".to_string(),
                            budget_remaining: 600,
                            budget_total: 1_000,
                            delegation_depth: 0,
                            root_budget_holder: subject_hex.clone(),
                            attempted_cost: Some(450),
                        },
                        settlement: EconomicSettlementReceiptMetadata {
                            settlement_status: SettlementStatus::Pending,
                        },
                    }),
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
            bbs_projection_version: None,
        },
        &receipt_kp,
    )
    .test_unwrap();
    let receipt_id = receipt.id.clone();
    store.append_chio_receipt(&receipt).test_unwrap();
    store
        .upsert_settlement_reconciliation(
            &receipt_id,
            SettlementReconciliationState::Open,
            Some("capture pending"),
        )
        .test_unwrap();
    store
        .upsert_metered_billing_reconciliation(
            &receipt_id,
            &MeteredBillingEvidenceRecord {
                usage_evidence:
                    chio_core::receipt::governance::MeteredUsageEvidenceReceiptMetadata {
                        evidence_kind: "provider-export".to_string(),
                        evidence_id: "usage-economic-1".to_string(),
                        observed_units: 120,
                        evidence_sha256: Some("usage-sha-economic-1".to_string()),
                    },
                billed_cost: MonetaryAmount {
                    units: 450,
                    currency: "USD".to_string(),
                },
                recorded_at: 2_010,
            },
            MeteredBillingReconciliationState::Open,
            Some("meter overrun"),
        )
        .test_unwrap();

    let report = store
        .query_economic_receipt_projection_report(&OperatorReportQuery {
            capability_id: Some("cap-economic".to_string()),
            economic_limit: Some(10),
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
            ..OperatorReportQuery::default()
        })
        .test_unwrap();

    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.returned_receipts, 1);
    assert_eq!(report.summary.metered_receipts, 1);
    assert_eq!(report.summary.pending_settlement_receipts, 1);
    assert_eq!(report.summary.failed_settlement_receipts, 0);
    assert_eq!(report.summary.settlement_actionable_receipts, 1);
    assert_eq!(report.summary.metering_actionable_receipts, 1);
    assert_eq!(report.summary.metering_evidence_missing_receipts, 0);
    assert_eq!(report.summary.metering_financial_mismatch_receipts, 1);
    assert!(!report.summary.truncated);

    assert_eq!(report.receipts.len(), 1);
    let row = &report.receipts[0];
    assert_eq!(row.receipt_id, receipt_id);
    assert_eq!(row.subject_key.as_deref(), Some(subject_hex.as_str()));
    assert_eq!(
        row.economic_authorization.economic_mode,
        EconomicAuthorizationMode::MeteredHoldCapture
    );
    assert_eq!(
        row.economic_authorization.rail.facilitator.as_deref(),
        Some("meterco")
    );
    assert_eq!(row.settlement.settlement_status, SettlementStatus::Pending);
    assert!(row.settlement.action_required);
    assert_eq!(row.settlement.note.as_deref(), Some("capture pending"));
    assert_eq!(
        row.metering
            .as_ref()
            .and_then(|metering| metering.evidence.as_ref())
            .map(|evidence| evidence.usage_evidence.observed_units),
        Some(120)
    );
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.exceeds_quoted_units));
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.exceeds_max_billed_units));
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.exceeds_quoted_cost));
    assert!(row
        .metering
        .as_ref()
        .is_some_and(|metering| metering.financial_mismatch));
    assert_eq!(
        row.metering
            .as_ref()
            .and_then(|metering| metering.note.as_deref()),
        Some("meter overrun")
    );

    let _ = fs::remove_file(path);
}

#[test]
fn economic_completion_flow_report_bundles_receipts_underwriting_and_credit_artifacts() {
    let path = unique_db_path("chio-receipts-economic-flow");
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt_kp = Keypair::generate();
    let subject_key = "subject-flow";
    let capability_id = format!("cap-{subject_key}");
    let quote = MeteredBillingQuote {
        quote_id: "quote-flow-1".to_string(),
        provider: "meterco".to_string(),
        billing_unit: "tokens".to_string(),
        quoted_units: 100,
        quoted_cost: MonetaryAmount {
            units: 400,
            currency: "USD".to_string(),
        },
        issued_at: 1_900,
        expires_at: Some(3_600),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-flow-1".to_string(),
            timestamp: 2_000,
            capability_id: capability_id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo flow" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-flow-1".to_string(),
            policy_hash: "policy-flow-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: "issuer-flow".to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 400,
                    currency: "USD".to_string(),
                    budget_remaining: 600,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_key.to_string(),
                    payment_reference: Some("payref-flow-1".to_string()),
                    settlement_status: SettlementStatus::Pending,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: Some(450),
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-flow-1".to_string(),
                    intent_hash: "intent-hash-flow-1".to_string(),
                    purpose: "metered flow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: Some(MeteredBillingReceiptMetadata {
                        settlement_mode: MeteredSettlementMode::HoldCapture,
                        quote: quote.clone(),
                        max_billed_units: Some(110),
                        usage_evidence: None,
                    }),
                    approval: None,
                    runtime_assurance: None,
                    call_chain: None,
                    autonomy: None,
                    economic_authorization: Some(EconomicAuthorizationReceiptMetadata {
                        version: EconomicAuthorizationReceiptMetadataVersion::V1,
                        economic_intent_digest: None,
                        payee_binding_digest: None,
                        pre_action_authority_digest: None,
                        credit_authority_digest: None,
                        economic_mode: EconomicAuthorizationMode::MeteredHoldCapture,
                        payer: EconomicPayerReceiptMetadata {
                            party_id: subject_key.to_string(),
                            funding_source_ref: "payref-flow-1".to_string(),
                            custody_provider: None,
                            obligor_ref: None,
                        },
                        merchant: EconomicMerchantReceiptMetadata {
                            merchant_id: "shell".to_string(),
                            merchant_of_record: None,
                            order_ref: Some("req-flow-1".to_string()),
                        },
                        payee: EconomicPayeeReceiptMetadata {
                            beneficiary_id: "shell".to_string(),
                            settlement_destination_ref: "payref-flow-1".to_string(),
                        },
                        rail: EconomicRailReceiptMetadata {
                            kind: "metered_billing".to_string(),
                            asset: "USD".to_string(),
                            network: None,
                            facilitator: Some("meterco".to_string()),
                            contract_or_account_ref: Some("payref-flow-1".to_string()),
                        },
                        amount_bounds: EconomicAmountBoundsReceiptMetadata {
                            approved_max: MonetaryAmount {
                                units: 500,
                                currency: "USD".to_string(),
                            },
                            hold_amount: Some(MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            }),
                            settlement_cap: MonetaryAmount {
                                units: 450,
                                currency: "USD".to_string(),
                            },
                        },
                        pricing_basis: Some(EconomicPricingBasisReceiptMetadata {
                            quote_hash: Some("quote-hash-flow-1".to_string()),
                            tariff_hash: None,
                            quote_expiry: quote.expires_at,
                        }),
                        metering: Some(EconomicMeteringReceiptMetadata {
                            provider: "meterco".to_string(),
                            meter_profile_hash: "meter-profile-flow-1".to_string(),
                            max_billable_units: Some(110),
                            billing_unit: Some("tokens".to_string()),
                        }),
                        liability_refs: None,
                        budget: EconomicBudgetReceiptMetadata {
                            grant_index: 0,
                            cost_charged: 400,
                            currency: "USD".to_string(),
                            budget_remaining: 600,
                            budget_total: 1_000,
                            delegation_depth: 0,
                            root_budget_holder: subject_key.to_string(),
                            attempted_cost: Some(450),
                        },
                        settlement: EconomicSettlementReceiptMetadata {
                            settlement_status: SettlementStatus::Pending,
                        },
                    }),
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
            bbs_projection_version: None,
        },
        &receipt_kp,
    )
    .test_unwrap();
    let receipt_id = receipt.id.clone();
    store.append_chio_receipt(&receipt).test_unwrap();
    store
        .upsert_settlement_reconciliation(
            &receipt_id,
            SettlementReconciliationState::Open,
            Some("awaiting capture"),
        )
        .test_unwrap();
    store
        .upsert_metered_billing_reconciliation(
            &receipt_id,
            &MeteredBillingEvidenceRecord {
                usage_evidence:
                    chio_core::receipt::governance::MeteredUsageEvidenceReceiptMetadata {
                        evidence_kind: "provider-export".to_string(),
                        evidence_id: "usage-flow-1".to_string(),
                        observed_units: 120,
                        evidence_sha256: Some("usage-sha-flow-1".to_string()),
                    },
                billed_cost: MonetaryAmount {
                    units: 450,
                    currency: "USD".to_string(),
                },
                recorded_at: 2_010,
            },
            MeteredBillingReconciliationState::Open,
            Some("meter overrun"),
        )
        .test_unwrap();

    store
        .record_underwriting_decision(&sample_underwriting_decision(subject_key))
        .test_unwrap();
    store
        .record_credit_facility(&sample_credit_facility(subject_key))
        .test_unwrap();
    store
        .record_credit_bond(&signed_credit_bond_fixture(
            subject_key,
            "cfd-1",
            "cbd-1",
            1_700_000_200,
            1_700_086_600,
            chio_kernel::CreditBondDisposition::Hold,
            chio_kernel::CreditBondLifecycleState::Active,
            None,
        ))
        .test_unwrap();

    let report = store
        .query_economic_completion_flow_report(
            &chio_kernel::ExposureLedgerQuery {
                agent_subject: Some(subject_key.to_string()),
                receipt_limit: Some(10),
                decision_limit: Some(10),
                ..chio_kernel::ExposureLedgerQuery::default()
            },
            chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        )
        .test_unwrap();

    assert_eq!(report.schema, chio_kernel::ECONOMIC_COMPLETION_FLOW_SCHEMA);
    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.returned_receipts, 1);
    assert_eq!(report.summary.matching_underwriting_decisions, 1);
    assert_eq!(report.summary.returned_underwriting_decisions, 1);
    assert_eq!(report.summary.matching_credit_facilities, 1);
    assert_eq!(report.summary.returned_credit_facilities, 1);
    assert_eq!(report.summary.matching_credit_bonds, 1);
    assert_eq!(report.summary.returned_credit_bonds, 1);
    assert_eq!(report.summary.pending_settlement_receipts, 1);
    assert_eq!(report.summary.failed_settlement_receipts, 0);
    assert_eq!(report.summary.metering_actionable_receipts, 1);
    assert_eq!(
        report.summary.latest_underwriting_decision_id.as_deref(),
        Some("uwd-1")
    );
    assert_eq!(
        report.summary.latest_underwriting_outcome,
        Some(chio_kernel::UnderwritingDecisionOutcome::Approve)
    );
    assert_eq!(
        report.summary.latest_credit_facility_id.as_deref(),
        Some("cfd-1")
    );
    assert_eq!(
        report.summary.latest_credit_facility_disposition,
        Some(chio_kernel::CreditFacilityDisposition::Grant)
    );
    assert_eq!(
        report.summary.latest_credit_bond_id.as_deref(),
        Some("cbd-1")
    );
    assert_eq!(
        report.summary.latest_credit_bond_disposition,
        Some(chio_kernel::CreditBondDisposition::Hold)
    );
    assert_eq!(report.economic_receipts.receipts.len(), 1);
    assert_eq!(report.underwriting_decisions.decisions.len(), 1);
    assert_eq!(report.credit_facilities.facilities.len(), 1);
    assert_eq!(report.credit_bonds.bonds.len(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn compliance_report_counts_proof_and_lineage_coverage() {
    let path = unique_db_path("chio-receipts-compliance");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-compliance".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(4),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 1000,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &issuer_kp,
    )
    .test_unwrap();
    store.record_capability_snapshot(&token, None).test_unwrap();

    let make_receipt = |id: &str,
                        timestamp: u64,
                        decision: Decision,
                        settlement_status: SettlementStatus,
                        attempted_cost: Option<u64>| {
        let metadata = serde_json::json!({
            "attribution": ReceiptAttributionMetadata {
                subject_key: subject_hex.clone(),
                issuer_key: issuer_hex.clone(),
                delegation_depth: 0,
                grant_index: Some(0),
            },
            "financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged: if attempted_cost.is_some() { 0 } else { 250 },
                currency: "USD".to_string(),
                budget_remaining: 750,
                budget_total: 1000,
                delegation_depth: 0,
                root_budget_holder: subject_hex.clone(),
                payment_reference: None,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost,
            }
        });

        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: "cap-compliance".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: valid_tool_action(serde_json::json!({})),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                decision: Some(decision),
                content_hash: format!("content-{id}"),
                policy_hash: "policy-compliance".to_string(),
                evidence: Vec::new(),
                metadata: Some(metadata),
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: checkpoint_kp.public_key(),
                bbs_projection_version: None,
            },
            &checkpoint_kp,
        )
        .test_unwrap()
    };

    let seq = store
        .append_chio_receipt_returning_seq(&make_receipt(
            "compliance-1",
            2_000,
            Decision::Allow,
            SettlementStatus::Settled,
            None,
        ))
        .test_unwrap();
    store
        .append_chio_receipt(&make_receipt(
            "compliance-2",
            2_001,
            Decision::Deny {
                reason: "budget".to_string(),
                guard: "kernel".to_string(),
            },
            SettlementStatus::Pending,
            Some(100),
        ))
        .test_unwrap();

    let bytes = store
        .receipts_canonical_bytes_range(seq, seq)
        .test_unwrap()
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect::<Vec<_>>();
    let checkpoint = build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).test_unwrap();
    ReceiptStore::store_checkpoint(&store, &checkpoint).test_unwrap();

    let report = store
        .query_compliance_report(&OperatorReportQuery {
            agent_subject: Some(subject_hex.clone()),
            tool_server: Some("shell".to_string()),
            tool_name: Some("bash".to_string()),
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
            ..OperatorReportQuery::default()
        })
        .test_unwrap();

    assert_eq!(report.matching_receipts, 2);
    assert_eq!(report.evidence_ready_receipts, 1);
    assert_eq!(report.uncheckpointed_receipts, 1);
    assert_eq!(report.lineage_covered_receipts, 2);
    assert_eq!(report.lineage_gap_receipts, 0);
    assert_eq!(report.pending_settlement_receipts, 1);
    assert_eq!(report.failed_settlement_receipts, 0);
    assert!(!report.direct_evidence_export_supported);
    assert_eq!(
        report.child_receipt_scope,
        crate::EvidenceChildReceiptScope::OmittedNoJoinPath
    );
    assert!(report
        .export_scope_note
        .as_deref()
        .is_some_and(|note| note.contains("tool filters narrow the operator report only")));

    let _ = fs::remove_file(path);
}

#[test]
fn receipt_store_authorization_context_report_does_not_mark_asserted_call_chain_as_sender_bound() {
    let path = unique_db_path("chio-receipts-auth-asserted-call-chain");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let subject_kp = Keypair::generate();
    let issuer_kp = Keypair::generate();
    let receipt_kp = Keypair::generate();
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-auth-asserted".to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                ..ChioScope::default()
            },
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer_kp,
    )
    .test_unwrap();
    store
        .record_capability_snapshot(&capability, None)
        .test_unwrap();

    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-auth-asserted".to_string(),
            timestamp: 2_000,
            capability_id: capability.id.clone(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({ "cmd": "echo delegated" })),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-auth-asserted".to_string(),
            policy_hash: "policy-auth-asserted".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_hex.clone(),
                    issuer_key: issuer_hex.clone(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: 250,
                    currency: "USD".to_string(),
                    budget_remaining: 750,
                    budget_total: 1_000,
                    delegation_depth: 0,
                    root_budget_holder: subject_hex.clone(),
                    payment_reference: None,
                    settlement_status: SettlementStatus::Settled,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                },
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: "intent-auth-asserted".to_string(),
                    intent_hash: "intent-hash-auth-asserted".to_string(),
                    purpose: "delegate external partner workflow".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: Some(MonetaryAmount {
                        units: 250,
                        currency: "USD".to_string(),
                    }),
                    commerce: None,
                    metered_billing: None,
                    approval: Some(GovernedApprovalReceiptMetadata {
                        token_id: "approval-auth-asserted".to_string(),
                        approver_key: issuer_hex.clone(),
                        approval_artifact_digest: None,
                        approved: true,
                    }),
                    runtime_assurance: None,
                    call_chain: Some(GovernedCallChainProvenance::asserted(
                        GovernedCallChainContext {
                            chain_id: "chain-asserted".to_string(),
                            parent_request_id: "req-upstream-asserted".to_string(),
                            parent_receipt_id: Some("rcpt-upstream-asserted".to_string()),
                            origin_subject: "subject-root".to_string(),
                            delegator_subject: "subject-delegator".to_string(),
                        },
                    )),
                    autonomy: None,
                    economic_authorization: None,
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: receipt_kp.public_key(),
            bbs_projection_version: None,
        },
        &receipt_kp,
    )
    .test_unwrap();
    store.append_chio_receipt(&receipt).test_unwrap();

    let report = store
        .query_authorization_context_report(&OperatorReportQuery {
            capability_id: Some(capability.id),
            authorization_limit: Some(10),
            read_context: Some(chio_kernel::ReceiptReadContext::local_operator_admin_all()),
            ..OperatorReportQuery::default()
        })
        .test_unwrap();

    assert_eq!(report.summary.matching_receipts, 1);
    assert_eq!(report.summary.delegated_sender_bound_receipts, 0);
    assert_eq!(report.receipts.len(), 1);
    assert_eq!(
        report.receipts[0]
            .transaction_context
            .call_chain
            .as_ref()
            .test_expect("call-chain projection")
            .evidence_class,
        GovernedProvenanceEvidenceClass::Asserted
    );
    assert!(
        !report.receipts[0]
            .sender_constraint
            .delegated_call_chain_bound
    );

    let _ = fs::remove_file(path);
}
