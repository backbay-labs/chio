use chio_core::capability::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    metadata::ReceiptAttributionMetadata,
};
use chio_reputation::{
    compute_local_scorecard, BudgetUsageRecord, CapabilityLineageRecord, IncidentRecord,
    LocalReputationCorpus, MetricValue, ReputationConfig,
};

fn tool_grant(
    server_id: &str,
    tool_name: &str,
    operations: Vec<Operation>,
    constraints: Vec<Constraint>,
    max_invocations: Option<u32>,
) -> ToolGrant {
    ToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations,
        constraints,
        max_invocations,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn capability(
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    issued_at: u64,
    expires_at: u64,
    grants: Vec<ToolGrant>,
    parent_capability_id: Option<&str>,
) -> CapabilityLineageRecord {
    CapabilityLineageRecord {
        capability_id: capability_id.to_string(),
        subject_key: subject_key.to_string(),
        issuer_key: issuer_key.to_string(),
        issued_at,
        expires_at,
        scope: ChioScope {
            grants,
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        delegation_depth: parent_capability_id.is_some() as u64,
        parent_capability_id: parent_capability_id.map(ToOwned::to_owned),
    }
}

#[allow(clippy::too_many_arguments)]
fn receipt(
    kernel: &Keypair,
    id: &str,
    timestamp: u64,
    capability_id: &str,
    subject_key: &str,
    tool_server: &str,
    tool_name: &str,
    decision: Decision,
    policy_hash: &str,
    grant_index: Option<u32>,
) -> ChioReceipt {
    let metadata = serde_json::json!({
        "attribution": ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: "issuer".to_string(),
            delegation_depth: 0,
            grant_index,
        }
    });
    let body = ChioReceiptBody {
        id: id.to_string(),
        timestamp,
        capability_id: capability_id.to_string(),
        tool_server: tool_server.to_string(),
        tool_name: tool_name.to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"ok": true}))
            .unwrap_or_else(|error| panic!("hash receipt parameters: {error}")),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        decision: Some(decision),
        content_hash: "hash".to_string(),
        policy_hash: policy_hash.to_string(),
        evidence: vec![],
        metadata: Some(metadata),
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, kernel)
        .unwrap_or_else(|error| panic!("sign reputation receipt: {error}"))
}

fn score_value(score: MetricValue, label: &str) -> f64 {
    match score.as_option() {
        Some(value) => value,
        None => panic!("{label} score should be present"),
    }
}

#[test]
fn local_scorecard_renormalizes_when_incidents_are_unavailable() {
    let kernel = Keypair::generate();
    let subject = "agent-1";
    let corpus = LocalReputationCorpus {
        receipts: vec![
            receipt(
                &kernel,
                "r1",
                1_710_000_000,
                "cap-1",
                subject,
                "fs",
                "read_file",
                Decision::Allow,
                "policy-a",
                Some(0),
            ),
            receipt(
                &kernel,
                "r2",
                1_710_000_100,
                "cap-1",
                subject,
                "fs",
                "read_file",
                Decision::Deny {
                    reason: "nope".to_string(),
                    guard: "guard".to_string(),
                },
                "policy-a",
                Some(0),
            ),
            receipt(
                &kernel,
                "r3",
                1_710_086_400,
                "cap-2",
                subject,
                "http",
                "get",
                Decision::Allow,
                "policy-b",
                Some(0),
            ),
        ],
        capabilities: vec![
            capability(
                "cap-1",
                subject,
                "ca",
                1_709_999_000,
                1_710_100_000,
                vec![tool_grant(
                    "fs",
                    "read_file",
                    vec![Operation::Invoke],
                    vec![Constraint::PathPrefix("/safe".to_string())],
                    Some(10),
                )],
                None,
            ),
            capability(
                "cap-2",
                subject,
                "ca",
                1_710_000_000,
                1_710_100_000,
                vec![tool_grant(
                    "http",
                    "get",
                    vec![Operation::Invoke],
                    vec![Constraint::DomainExact("api.example.com".to_string())],
                    Some(4),
                )],
                None,
            ),
        ],
        budget_usage: vec![
            BudgetUsageRecord {
                capability_id: "cap-1".to_string(),
                grant_index: 0,
                invocation_count: 1,
                updated_at: 1_710_000_000,
                total_cost_charged: 0,
            },
            BudgetUsageRecord {
                capability_id: "cap-2".to_string(),
                grant_index: 0,
                invocation_count: 1,
                updated_at: 1_710_086_400,
                total_cost_charged: 0,
            },
        ],
        incident_reports: None,
    };

    let config =
        ReputationConfig::default().with_trusted_kernel_keys([kernel.public_key().to_hex()]);
    let scorecard = compute_local_scorecard(subject, 1_710_172_800, &corpus, &config);

    assert!(matches!(
        scorecard.incident_correlation.score,
        MetricValue::Unknown
    ));
    assert!(matches!(scorecard.composite_score, MetricValue::Known(value) if value > 0.0));
    assert!(scorecard.effective_weight_sum < 1.0);
    assert!(
        matches!(scorecard.boundary_pressure.deny_ratio, MetricValue::Known(value) if value > 0.0)
    );
}

#[test]
fn structural_delegation_hygiene_scores_attenuating_delegator_above_passthrough() {
    let kernel = Keypair::generate();
    let delegator = "agent-delegator";

    let passthrough_parent = capability(
        "parent-a",
        delegator,
        "ca",
        1_710_000_000,
        1_710_200_000,
        vec![tool_grant(
            "shell",
            "exec",
            vec![Operation::Invoke, Operation::Delegate],
            vec![],
            Some(100),
        )],
        None,
    );
    let passthrough_child = capability(
        "child-a",
        "delegatee-a",
        delegator,
        1_710_010_000,
        1_710_200_000,
        vec![tool_grant(
            "shell",
            "exec",
            vec![Operation::Invoke, Operation::Delegate],
            vec![],
            Some(100),
        )],
        Some("parent-a"),
    );

    let attenuating_parent = capability(
        "parent-b",
        delegator,
        "ca",
        1_710_000_000,
        1_710_300_000,
        vec![ToolGrant {
            server_id: "net".to_string(),
            tool_name: "post".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![],
            max_invocations: Some(50),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: None,
            dpop_required: None,
        }],
        None,
    );
    let attenuating_child = capability(
        "child-b",
        "delegatee-b",
        delegator,
        1_710_020_000,
        1_710_030_000,
        vec![ToolGrant {
            server_id: "net".to_string(),
            tool_name: "post".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::DomainExact("billing.example.com".to_string())],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            }),
            max_total_cost: None,
            dpop_required: None,
        }],
        Some("parent-b"),
    );

    let corpus = LocalReputationCorpus {
        receipts: vec![
            receipt(
                &kernel,
                "r1",
                1_710_040_000,
                "parent-a",
                delegator,
                "shell",
                "exec",
                Decision::Allow,
                "policy",
                Some(0),
            ),
            receipt(
                &kernel,
                "r2",
                1_710_040_100,
                "parent-b",
                delegator,
                "net",
                "post",
                Decision::Allow,
                "policy",
                Some(0),
            ),
        ],
        capabilities: vec![
            passthrough_parent,
            passthrough_child,
            attenuating_parent,
            attenuating_child,
        ],
        budget_usage: vec![],
        incident_reports: Some(vec![]),
    };

    let config =
        ReputationConfig::default().with_trusted_kernel_keys([kernel.public_key().to_hex()]);
    let scorecard = compute_local_scorecard(delegator, 1_710_172_800, &corpus, &config);

    assert_eq!(scorecard.delegation_hygiene.delegations_observed, 2);
    assert!(matches!(
        scorecard.delegation_hygiene.score,
        MetricValue::Known(value) if value > 0.45 && value < 0.85
    ));
    assert!(matches!(
        scorecard.delegation_hygiene.scope_reduction_rate,
        MetricValue::Known(value) if value > 0.0 && value < 1.0
    ));
}

#[test]
fn expanded_child_grants_do_not_score_as_reductions() {
    let delegator = "agent-delegator";
    let parent = capability(
        "parent-expanded",
        delegator,
        "ca",
        1_710_000_000,
        1_710_200_000,
        vec![tool_grant(
            "fs",
            "read_file",
            vec![Operation::Invoke],
            vec![],
            None,
        )],
        None,
    );
    let child = capability(
        "child-expanded",
        "delegatee",
        delegator,
        1_710_010_000,
        1_710_100_000,
        vec![tool_grant(
            "fs",
            "write_file",
            vec![Operation::Invoke],
            vec![],
            Some(5),
        )],
        Some("parent-expanded"),
    );
    let corpus = LocalReputationCorpus {
        receipts: vec![],
        capabilities: vec![parent, child],
        budget_usage: vec![],
        incident_reports: Some(vec![]),
    };

    let scorecard = compute_local_scorecard(
        delegator,
        1_710_020_000,
        &corpus,
        &ReputationConfig::default(),
    );

    assert_eq!(scorecard.delegation_hygiene.delegations_observed, 1);
    assert_eq!(
        scorecard.delegation_hygiene.scope_reduction_rate,
        MetricValue::Known(0.0)
    );
    assert_eq!(
        scorecard.delegation_hygiene.budget_reduction_rate,
        MetricValue::Known(0.0)
    );
    assert_eq!(
        scorecard.delegation_hygiene.ttl_reduction_rate,
        MetricValue::Known(1.0)
    );
}

#[test]
fn mature_agent_scores_above_concerning_agent() {
    let kernel = Keypair::generate();
    let now = 1_710_259_200;
    let mature = "agent-mature";
    let concerning = "agent-concerning";

    let mature_corpus = LocalReputationCorpus {
        receipts: vec![
            receipt(
                &kernel,
                "m1",
                now - 100,
                "m-cap-1",
                mature,
                "fs",
                "read",
                Decision::Allow,
                "policy-1",
                Some(0),
            ),
            receipt(
                &kernel,
                "m2",
                now - 90,
                "m-cap-1",
                mature,
                "fs",
                "read",
                Decision::Allow,
                "policy-1",
                Some(0),
            ),
            receipt(
                &kernel,
                "m3",
                now - 80,
                "m-cap-2",
                mature,
                "http",
                "get",
                Decision::Allow,
                "policy-2",
                Some(0),
            ),
            receipt(
                &kernel,
                "m4",
                now - 70,
                "m-cap-2",
                mature,
                "http",
                "get",
                Decision::Cancelled {
                    reason: "cancel".to_string(),
                },
                "policy-2",
                Some(0),
            ),
            receipt(
                &kernel,
                "m5",
                now - 60,
                "m-cap-3",
                mature,
                "db",
                "query",
                Decision::Allow,
                "policy-3",
                Some(0),
            ),
        ],
        capabilities: vec![
            capability(
                "m-cap-1",
                mature,
                "ca",
                now - 3_000_000,
                now + 100_000,
                vec![tool_grant(
                    "fs",
                    "read",
                    vec![Operation::Invoke],
                    vec![Constraint::PathPrefix("/docs".to_string())],
                    Some(10),
                )],
                None,
            ),
            capability(
                "m-cap-2",
                mature,
                "ca",
                now - 2_500_000,
                now + 100_000,
                vec![tool_grant(
                    "http",
                    "get",
                    vec![Operation::Invoke],
                    vec![Constraint::DomainExact("api.example.com".to_string())],
                    Some(10),
                )],
                None,
            ),
            capability(
                "m-cap-3",
                mature,
                "ca",
                now - 2_000_000,
                now + 100_000,
                vec![tool_grant(
                    "db",
                    "query",
                    vec![Operation::Invoke],
                    vec![Constraint::RegexMatch("^select".to_string())],
                    Some(10),
                )],
                None,
            ),
        ],
        budget_usage: vec![
            BudgetUsageRecord {
                capability_id: "m-cap-1".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: (now - 100) as i64,
                total_cost_charged: 0,
            },
            BudgetUsageRecord {
                capability_id: "m-cap-2".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: (now - 80) as i64,
                total_cost_charged: 0,
            },
            BudgetUsageRecord {
                capability_id: "m-cap-3".to_string(),
                grant_index: 0,
                invocation_count: 1,
                updated_at: (now - 60) as i64,
                total_cost_charged: 0,
            },
        ],
        incident_reports: Some(vec![]),
    };

    let concerning_corpus = LocalReputationCorpus {
        receipts: vec![
            receipt(
                &kernel,
                "c1",
                now - 100,
                "c-cap-1",
                concerning,
                "shell",
                "exec",
                Decision::Deny {
                    reason: "blocked".to_string(),
                    guard: "shell".to_string(),
                },
                "policy-x",
                Some(0),
            ),
            receipt(
                &kernel,
                "c2",
                now - 90,
                "c-cap-1",
                concerning,
                "shell",
                "exec",
                Decision::Deny {
                    reason: "blocked".to_string(),
                    guard: "shell".to_string(),
                },
                "policy-x",
                Some(0),
            ),
            receipt(
                &kernel,
                "c3",
                now - 80,
                "c-cap-1",
                concerning,
                "shell",
                "exec",
                Decision::Incomplete {
                    reason: "timeout".to_string(),
                },
                "policy-x",
                Some(0),
            ),
        ],
        capabilities: vec![capability(
            "c-cap-1",
            concerning,
            "ca",
            now - 10_000,
            now + 100_000,
            vec![
                tool_grant(
                    "shell",
                    "exec",
                    vec![Operation::Invoke, Operation::Delegate],
                    vec![],
                    Some(100),
                ),
                tool_grant("http", "post", vec![Operation::Invoke], vec![], Some(100)),
            ],
            None,
        )],
        budget_usage: vec![BudgetUsageRecord {
            capability_id: "c-cap-1".to_string(),
            grant_index: 0,
            invocation_count: 1,
            updated_at: (now - 80) as i64,
            total_cost_charged: 0,
        }],
        incident_reports: Some(vec![IncidentRecord {
            timestamp: now - 50,
            receipt_id: Some("c3".to_string()),
        }]),
    };

    let config =
        ReputationConfig::default().with_trusted_kernel_keys([kernel.public_key().to_hex()]);
    let mature_score = compute_local_scorecard(mature, now, &mature_corpus, &config);
    let concerning_score = compute_local_scorecard(concerning, now, &concerning_corpus, &config);

    let mature_value = score_value(mature_score.composite_score, "mature");
    let concerning_value = score_value(concerning_score.composite_score, "concerning");

    assert!(mature_value > concerning_value);
    assert!(mature_value > 0.6);
    assert!(concerning_value < 0.5);
}
