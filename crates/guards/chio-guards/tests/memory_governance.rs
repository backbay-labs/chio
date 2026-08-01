//! Integration tests for MemoryGovernanceGuard.
//!
//! Verify that:
//!
//! * writes to a collection not in `MemoryStoreAllowlist` are denied;
//! * writes exceeding `max_memory_entries` are denied;
//! * `max_retention_ttl_secs` is honored.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use chio_core::capability::{
    scope::{ChioScope, Constraint, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{
    FindingRetractionGuardConfig, FindingRetractionQuery, FindingRetractionResolution,
    FindingRetractionResolveError, FindingRetractionResolver, FindingStatusValue,
    MemoryGovernanceConfig, MemoryGovernanceGuard,
};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

fn signed_cap(kp: &Keypair, scope: &ChioScope) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-mem-governance".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, kp).expect("sign cap")
}

fn make_request_in_scope(
    kp: &Keypair,
    scope: &ChioScope,
    tool: &str,
    args: serde_json::Value,
) -> (ToolCallRequest, String, String) {
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-mem".to_string();
    let req = ToolCallRequest {
        request_id: "req-mem".to_string(),
        capability: signed_cap(kp, scope),
        tool_name: tool.to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: args,
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
    (req, agent_id, server_id)
}

fn eval_at<G: Guard>(
    guard: &G,
    kp: &Keypair,
    scope: &ChioScope,
    tool: &str,
    args: serde_json::Value,
    matched_grant_index: Option<usize>,
) -> Verdict {
    let (request, agent_id, server_id) = make_request_in_scope(kp, scope, tool, args);
    let ctx = GuardContext {
        request: &request,
        scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index,
    };
    guard.evaluate(&ctx).expect("guard evaluate").verdict
}

fn scope_with_constraints(constraints: Vec<Constraint>) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-mem".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

#[test]
fn write_outside_memory_store_allowlist_denied() {
    let guard = MemoryGovernanceGuard::new();
    let scope = scope_with_constraints(vec![Constraint::MemoryStoreAllowlist(vec![
        "agent-notes".to_string()
    ])]);
    let kp = Keypair::generate();

    // Write to a forbidden collection → Deny
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "secrets", "id": "x1"}),
        Some(0),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");

    // Write to the allowed collection → Allow
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "agent-notes", "id": "x1"}),
        Some(0),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn read_outside_memory_store_allowlist_denied() {
    let guard = MemoryGovernanceGuard::new();
    let scope = scope_with_constraints(vec![Constraint::MemoryStoreAllowlist(vec![
        "agent-notes".to_string()
    ])]);
    let kp = Keypair::generate();
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_query",
        serde_json::json!({"collection": "secrets"}),
        Some(0),
    );
    assert!(matches!(v, Verdict::Deny));
}

#[test]
fn writes_exceeding_max_memory_entries_denied() {
    let guard = MemoryGovernanceGuard::with_config(MemoryGovernanceConfig {
        max_memory_entries: Some(2),
        ..MemoryGovernanceConfig::default()
    })
    .expect("build guard");
    let scope = ChioScope::default();
    let kp = Keypair::generate();

    // First two writes succeed.
    for i in 0..2 {
        let v = eval_at(
            &guard,
            &kp,
            &scope,
            "vector_upsert",
            serde_json::json!({"collection": "agent-notes", "id": format!("id-{i}")}),
            None,
        );
        assert!(
            matches!(v, Verdict::Allow),
            "write {i} must Allow, got {v:?}"
        );
    }
    // Third write exceeds the cap.
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "agent-notes", "id": "id-3"}),
        None,
    );
    assert!(matches!(v, Verdict::Deny), "3rd write must Deny, got {v:?}");
}

#[test]
fn max_retention_ttl_honored() {
    let guard = MemoryGovernanceGuard::with_config(MemoryGovernanceConfig {
        max_retention_ttl_secs: Some(3_600),
        ..MemoryGovernanceConfig::default()
    })
    .expect("build guard");
    let scope = ChioScope::default();
    let kp = Keypair::generate();

    // TTL below cap → Allow
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "agent-notes", "id": "a", "ttl": 1_800}),
        None,
    );
    assert!(
        matches!(v, Verdict::Allow),
        "small TTL must Allow, got {v:?}"
    );

    // TTL above cap → Deny
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "agent-notes", "id": "b", "ttl": 7_200}),
        None,
    );
    assert!(matches!(v, Verdict::Deny), "over TTL must Deny, got {v:?}");

    // Missing TTL with a configured cap → Deny (indefinite retention)
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "agent-notes", "id": "c"}),
        None,
    );
    assert!(
        matches!(v, Verdict::Deny),
        "missing TTL must Deny, got {v:?}"
    );
}

#[test]
fn max_content_size_denies_unknown_or_oversized_content() {
    let guard = MemoryGovernanceGuard::with_config(MemoryGovernanceConfig {
        max_content_size_bytes: Some(4),
        ..MemoryGovernanceConfig::default()
    })
    .expect("build guard");
    let scope = ChioScope::default();
    let kp = Keypair::generate();

    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "agent-notes", "id": "missing-content"}),
        None,
    );
    assert!(
        matches!(v, Verdict::Deny),
        "missing content size must Deny, got {v:?}"
    );

    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({
            "collection": "agent-notes",
            "id": "oversized",
            "content": "hello",
        }),
        None,
    );
    assert!(
        matches!(v, Verdict::Deny),
        "oversized content must Deny, got {v:?}"
    );

    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({
            "collection": "agent-notes",
            "id": "small",
            "content": "ok",
        }),
        None,
    );
    assert!(
        matches!(v, Verdict::Allow),
        "small content must Allow, got {v:?}"
    );
}

#[test]
fn config_store_allowlist_composes_with_grant_allowlist() {
    let guard = MemoryGovernanceGuard::with_config(MemoryGovernanceConfig {
        store_allowlist: vec!["deployment-wide".to_string()],
        ..MemoryGovernanceConfig::default()
    })
    .expect("build guard");
    let scope = scope_with_constraints(vec![Constraint::MemoryStoreAllowlist(vec![
        "grant-scoped".to_string(),
    ])]);
    let kp = Keypair::generate();

    // Both allowlisted stores accepted.
    for store in ["deployment-wide", "grant-scoped"] {
        let v = eval_at(
            &guard,
            &kp,
            &scope,
            "vector_upsert",
            serde_json::json!({"collection": store, "id": "x"}),
            Some(0),
        );
        assert!(
            matches!(v, Verdict::Allow),
            "store {store} should allow, got {v:?}"
        );
    }
    // Anything else denied.
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({"collection": "forbidden", "id": "x"}),
        Some(0),
    );
    assert!(matches!(v, Verdict::Deny));
}

#[test]
fn non_memory_actions_pass_through() {
    let guard = MemoryGovernanceGuard::new();
    let scope = ChioScope::default();
    let kp = Keypair::generate();
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "read_file",
        serde_json::json!({"path": "/tmp/x"}),
        None,
    );
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn deny_patterns_block_matching_content() {
    let guard = MemoryGovernanceGuard::with_config(MemoryGovernanceConfig {
        deny_patterns: vec![r"(?i)password".to_string()],
        ..MemoryGovernanceConfig::default()
    })
    .expect("build guard");
    let scope = ChioScope::default();
    let kp = Keypair::generate();
    let v = eval_at(
        &guard,
        &kp,
        &scope,
        "vector_upsert",
        serde_json::json!({
            "collection": "agent-notes",
            "id": "x",
            "content": "user password = hunter2"
        }),
        None,
    );
    assert!(matches!(v, Verdict::Deny));
}

#[test]
fn invalid_regex_fails_initialization() {
    let cfg = MemoryGovernanceConfig {
        deny_patterns: vec!["(unclosed".to_string()],
        ..MemoryGovernanceConfig::default()
    };
    assert!(MemoryGovernanceGuard::with_config(cfg).is_err());
}

struct StubFindingResolver {
    resolver_id: &'static str,
    feed_id: &'static str,
    outcome: Result<FindingStatusValue, FindingRetractionResolveError>,
}

impl FindingRetractionResolver for StubFindingResolver {
    fn resolver_id(&self) -> &str {
        self.resolver_id
    }

    fn feed_id(&self) -> &str {
        self.feed_id
    }

    fn resolve(
        &self,
        _query: FindingRetractionQuery<'_>,
    ) -> Result<FindingRetractionResolution, FindingRetractionResolveError> {
        self.outcome
            .clone()
            .map(|value| FindingRetractionResolution {
                delivery_receipt_id: "delivery-1".to_owned(),
                finding_id: "finding-1".to_owned(),
                feed_id: self.feed_id.to_owned(),
                map_epoch: 3,
                epoch_id: "a".repeat(64),
                root_hash: "b".repeat(64),
                value,
            })
    }
}

fn finding_quarantine_config() -> MemoryGovernanceConfig {
    MemoryGovernanceConfig {
        finding_retraction: Some(FindingRetractionGuardConfig {
            resolver_id: "resolver-1".to_owned(),
            feed_id: "feed-1".to_owned(),
        }),
        ..MemoryGovernanceConfig::default()
    }
}

fn finding_guard(
    outcome: Result<FindingStatusValue, FindingRetractionResolveError>,
) -> MemoryGovernanceGuard {
    MemoryGovernanceGuard::with_config_and_retraction_resolver(
        finding_quarantine_config(),
        Arc::new(StubFindingResolver {
            resolver_id: "resolver-1",
            feed_id: "feed-1",
            outcome,
        }),
    )
    .expect("build finding quarantine guard")
}

#[test]
fn finding_quarantine_allows_only_fresh_live_exact_key_reads() {
    let scope = ChioScope::default();
    let kp = Keypair::generate();
    let live = eval_at(
        &finding_guard(Ok(FindingStatusValue::Live)),
        &kp,
        &scope,
        "vector_query",
        serde_json::json!({"collection": "memory", "id": "key-1"}),
        None,
    );
    assert!(matches!(live, Verdict::Allow));

    for value in [FindingStatusValue::Pending, FindingStatusValue::Retracted] {
        let denied = eval_at(
            &finding_guard(Ok(value)),
            &kp,
            &scope,
            "vector_query",
            serde_json::json!({"collection": "memory", "id": "key-1"}),
            None,
        );
        assert!(matches!(denied, Verdict::Deny));
    }

    let no_key = eval_at(
        &finding_guard(Ok(FindingStatusValue::Live)),
        &kp,
        &scope,
        "vector_query",
        serde_json::json!({"collection": "memory"}),
        None,
    );
    assert!(matches!(no_key, Verdict::Deny));
}

#[test]
fn finding_quarantine_denies_unavailable_state_and_resolver_substitution() {
    let scope = ChioScope::default();
    let kp = Keypair::generate();
    let unavailable = eval_at(
        &finding_guard(Err(FindingRetractionResolveError::StatusUnavailable(
            "offline".to_owned(),
        ))),
        &kp,
        &scope,
        "vector_query",
        serde_json::json!({"collection": "memory", "id": "key-1"}),
        None,
    );
    assert!(matches!(unavailable, Verdict::Deny));

    let substituted = MemoryGovernanceGuard::with_config_and_retraction_resolver(
        finding_quarantine_config(),
        Arc::new(StubFindingResolver {
            resolver_id: "other-resolver",
            feed_id: "feed-1",
            outcome: Ok(FindingStatusValue::Live),
        }),
    );
    assert!(substituted.is_err());

    let missing = MemoryGovernanceGuard::with_config(finding_quarantine_config());
    assert!(missing.is_err());
}
