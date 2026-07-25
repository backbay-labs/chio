use chio_core_types::capability::scope::{
    ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant,
};
use chio_kernel_core::normalized::{
    NormalizedConstraint, NormalizedMonetaryAmount, NormalizedOperation, NormalizedPromptGrant,
    NormalizedResourceGrant, NormalizedScope, NormalizedToolGrant,
};
use chio_kernel_core::scope::{resolve_matching_grants, ScopeMatchError};

fn grant(
    server_id: &str,
    tool_name: &str,
    operations: Vec<Operation>,
    constraints: Vec<Constraint>,
) -> ToolGrant {
    ToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations,
        constraints,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn normalized_tool(
    server_id: &str,
    tool_name: &str,
    operations: Vec<NormalizedOperation>,
) -> NormalizedToolGrant {
    NormalizedToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations,
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

#[test]
fn normalized_tool_subset_respects_operations_constraints_caps_and_dpop() {
    let mut parent = normalized_tool(
        "*",
        "*",
        vec![NormalizedOperation::Invoke, NormalizedOperation::ReadResult],
    );
    parent.constraints = vec![NormalizedConstraint::PathPrefix("/workspace".to_string())];
    parent.max_invocations = Some(10);
    parent.max_total_cost = Some(NormalizedMonetaryAmount {
        units: 500,
        currency: "USD".to_string(),
    });
    parent.dpop_required = Some(true);

    let mut child = normalized_tool("srv-prod", "file_read", vec![NormalizedOperation::Invoke]);
    child.constraints = parent.constraints.clone();
    child.max_invocations = Some(4);
    child.max_total_cost = Some(NormalizedMonetaryAmount {
        units: 250,
        currency: "USD".to_string(),
    });
    child.dpop_required = Some(true);
    assert!(child.is_subset_of(&parent));

    let mut missing_operation = child.clone();
    missing_operation.operations = vec![NormalizedOperation::Delegate];
    assert!(!missing_operation.is_subset_of(&parent));

    let mut missing_constraint = child.clone();
    missing_constraint.constraints.clear();
    assert!(!missing_constraint.is_subset_of(&parent));

    let mut over_invocation_cap = child.clone();
    over_invocation_cap.max_invocations = Some(11);
    assert!(!over_invocation_cap.is_subset_of(&parent));

    let mut currency_mismatch = child.clone();
    currency_mismatch.max_total_cost = Some(NormalizedMonetaryAmount {
        units: 250,
        currency: "EUR".to_string(),
    });
    assert!(!currency_mismatch.is_subset_of(&parent));

    let mut missing_dpop = child;
    missing_dpop.dpop_required = None;
    assert!(!missing_dpop.is_subset_of(&parent));
}

#[test]
fn normalized_scope_subset_requires_matching_resource_and_prompt_grants() {
    let child = NormalizedScope {
        grants: vec![normalized_tool(
            "srv-prod",
            "file_read",
            vec![NormalizedOperation::Invoke],
        )],
        resource_grants: vec![NormalizedResourceGrant {
            uri_pattern: "file://workspace/private/report.txt".to_string(),
            operations: vec![NormalizedOperation::Read],
        }],
        prompt_grants: vec![NormalizedPromptGrant {
            prompt_name: "review.security.quick".to_string(),
            operations: vec![NormalizedOperation::Get],
        }],
    };
    let parent = NormalizedScope {
        grants: vec![normalized_tool("*", "*", vec![NormalizedOperation::Invoke])],
        resource_grants: vec![NormalizedResourceGrant {
            uri_pattern: "file://workspace/private/*".to_string(),
            operations: vec![NormalizedOperation::Read, NormalizedOperation::Subscribe],
        }],
        prompt_grants: vec![NormalizedPromptGrant {
            prompt_name: "review.security.*".to_string(),
            operations: vec![NormalizedOperation::Get],
        }],
    };
    assert!(child.is_subset_of(&parent));

    let mut missing_resource_parent = parent.clone();
    missing_resource_parent.resource_grants.clear();
    assert!(!child.is_subset_of(&missing_resource_parent));

    let mut missing_prompt_parent = parent;
    missing_prompt_parent.prompt_grants.clear();
    assert!(!child.is_subset_of(&missing_prompt_parent));
}

#[test]
fn resolve_matching_grants_enforces_path_constraints_and_specificity() {
    let scope = ChioScope {
        grants: vec![
            grant("*", "*", vec![Operation::Invoke], Vec::new()),
            grant(
                "files",
                "read",
                vec![Operation::Invoke],
                vec![Constraint::PathPrefix("/workspace/private".to_string())],
            ),
        ],
        ..ChioScope::default()
    };
    let allowed = serde_json::json!({ "path": "/workspace/private/report.txt" });
    let matches = resolve_matching_grants(&scope, "read", "files", &allowed)
        .unwrap_or_else(|error| panic!("allowed path should match both grants: {error:?}"));
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].index, 1);
    assert_eq!(matches[0].specificity, (1, 1, 1));

    let denied = serde_json::json!({ "path": "/workspace/public/report.txt" });
    let matches =
        resolve_matching_grants(&scope, "read", "files", &denied).unwrap_or_else(|error| {
            panic!("denied path should still match unconstrained fallback: {error:?}")
        });
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].index, 0);
}

#[test]
fn resolve_matching_grants_enforces_domain_audience_and_memory_constraints() {
    let scope = ChioScope {
        grants: vec![grant(
            "web",
            "send",
            vec![Operation::Invoke],
            vec![
                Constraint::DomainGlob("*.example.com".to_string()),
                Constraint::AudienceAllowlist(vec!["security".to_string(), "ops".to_string()]),
                Constraint::MemoryStoreAllowlist(vec!["case-notes".to_string()]),
                Constraint::Custom("ticket".to_string(), "INC-123".to_string()),
            ],
        )],
        ..ChioScope::default()
    };

    let allowed = serde_json::json!({
        "url": "https://api.example.com/v1/events",
        "audience": ["security", "ops"],
        "memory_store": "case-notes",
        "meta": { "ticket": "INC-123" }
    });
    let matches = resolve_matching_grants(&scope, "send", "web", &allowed);
    assert!(matches.as_ref().is_ok_and(|matches| matches.len() == 1));

    let wrong_domain = serde_json::json!({
        "url": "https://api.evil.test/v1/events",
        "audience": ["security"],
        "memory_store": "case-notes",
        "meta": { "ticket": "INC-123" }
    });
    let matches = resolve_matching_grants(&scope, "send", "web", &wrong_domain);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));

    let wrong_audience = serde_json::json!({
        "url": "https://api.example.com/v1/events",
        "audience": ["finance"],
        "memory_store": "case-notes",
        "meta": { "ticket": "INC-123" }
    });
    let matches = resolve_matching_grants(&scope, "send", "web", &wrong_audience);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));

    let wrong_memory = serde_json::json!({
        "url": "https://api.example.com/v1/events",
        "audience": ["security"],
        "memory_store": "scratch",
        "meta": { "ticket": "INC-123" }
    });
    let matches = resolve_matching_grants(&scope, "send", "web", &wrong_memory);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));
}

#[test]
fn resolve_matching_grants_audience_allowlist_rejects_non_string_values() {
    // A non-string value under an audience-style key must fail closed
    // instead of silently widening scope. Mirrors the
    // `chio_kernel::request_matching` strict semantics so the portable
    // matcher and the full kernel agree on this trust-boundary case.
    let scope = ChioScope {
        grants: vec![grant(
            "web",
            "send",
            vec![Operation::Invoke],
            vec![Constraint::AudienceAllowlist(vec!["security".to_string()])],
        )],
        ..ChioScope::default()
    };

    let non_string = serde_json::json!({ "audience": 42 });
    let matches = resolve_matching_grants(&scope, "send", "web", &non_string);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));

    let object_under_key = serde_json::json!({ "audience": { "team": "security" } });
    let matches = resolve_matching_grants(&scope, "send", "web", &object_under_key);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));

    let empty_array = serde_json::json!({ "audience": [] });
    let matches = resolve_matching_grants(&scope, "send", "web", &empty_array);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));

    // Absent key still allows (constraint cannot apply).
    let no_key = serde_json::json!({ "subject": "ping" });
    let matches = resolve_matching_grants(&scope, "send", "web", &no_key)
        .unwrap_or_else(|e| panic!("absent audience key should not deny: {e:?}"));
    assert_eq!(matches.len(), 1);
}

#[test]
fn resolve_matching_grants_audience_null_fails_closed_and_missing_allows() {
    // Three observably distinct shapes:
    //   * `audience: null` -> relevant key with no string values, fails closed.
    //   * `audience: ""` -> relevant empty string (fails closed because no
    //     allowed value matches "").
    //   * `audience` missing -> "key not provided" (allows).
    // Null under a relevant key must not be treated like absence, or an
    // attacker can bypass an audience/store allowlist by sending an
    // explicit JSON null.
    let scope = ChioScope {
        grants: vec![grant(
            "web",
            "send",
            vec![Operation::Invoke],
            vec![Constraint::AudienceAllowlist(vec!["security".to_string()])],
        )],
        ..ChioScope::default()
    };

    let null_audience = serde_json::json!({ "audience": null });
    let matches = resolve_matching_grants(&scope, "send", "web", &null_audience);
    assert!(
        matches.as_ref().is_ok_and(Vec::is_empty),
        "audience: null is a relevant key with no string values and must fail closed"
    );

    let empty_audience = serde_json::json!({ "audience": "" });
    let matches = resolve_matching_grants(&scope, "send", "web", &empty_audience);
    assert!(
        matches.as_ref().is_ok_and(Vec::is_empty),
        "audience: \"\" is a relevant empty string and must fail closed"
    );

    let missing_audience = serde_json::json!({ "subject": "ping" });
    let matches = resolve_matching_grants(&scope, "send", "web", &missing_audience)
        .unwrap_or_else(|e| panic!("missing audience should not deny: {e:?}"));
    assert_eq!(matches.len(), 1, "missing audience should allow");

    // Memory-store allowlist parity: same three shapes, same outcomes.
    let memory_scope = ChioScope {
        grants: vec![grant(
            "memory",
            "write",
            vec![Operation::Invoke],
            vec![Constraint::MemoryStoreAllowlist(vec![
                "case-notes".to_string()
            ])],
        )],
        ..ChioScope::default()
    };

    let null_store = serde_json::json!({ "store": null });
    let matches = resolve_matching_grants(&memory_scope, "write", "memory", &null_store);
    assert!(
        matches.as_ref().is_ok_and(Vec::is_empty),
        "store: null is a relevant key with no string values and must fail closed"
    );

    let empty_store = serde_json::json!({ "store": "" });
    let matches = resolve_matching_grants(&memory_scope, "write", "memory", &empty_store);
    assert!(
        matches.as_ref().is_ok_and(Vec::is_empty),
        "store: \"\" is a relevant empty string and must fail closed"
    );

    let missing_store = serde_json::json!({ "subject": "ping" });
    let matches = resolve_matching_grants(&memory_scope, "write", "memory", &missing_store)
        .unwrap_or_else(|e| panic!("missing store should not deny: {e:?}"));
    assert_eq!(matches.len(), 1, "missing store should allow");
}

#[test]
fn resolve_matching_grants_audience_mixed_null_array_fails_closed() {
    // A mixed array `["security", null]` directly under an audience key must
    // poison the constraint to match the hosted matcher's strict semantics
    // (`chio_kernel::request_matching::collect_string_values_strict` rejects
    // any non-string, non-array leaf). Tolerating null array elements would let
    // an attacker who controls any nullable field in the array relax the
    // allowlist check on the sibling string elements compared to the hosted kernel.
    let scope = ChioScope {
        grants: vec![grant(
            "web",
            "send",
            vec![Operation::Invoke],
            vec![Constraint::AudienceAllowlist(vec!["security".to_string()])],
        )],
        ..ChioScope::default()
    };

    let mixed_null = serde_json::json!({ "audience": ["security", null] });
    let matches = resolve_matching_grants(&scope, "send", "web", &mixed_null);
    assert!(
        matches.as_ref().is_ok_and(Vec::is_empty),
        "mixed null in audience array must fail closed (saw {matches:?})"
    );

    // Memory-store allowlist parity.
    let memory_scope = ChioScope {
        grants: vec![grant(
            "memory",
            "write",
            vec![Operation::Invoke],
            vec![Constraint::MemoryStoreAllowlist(vec![
                "case-notes".to_string()
            ])],
        )],
        ..ChioScope::default()
    };

    let mixed_null_store = serde_json::json!({ "store": ["case-notes", null] });
    let matches = resolve_matching_grants(&memory_scope, "write", "memory", &mixed_null_store);
    assert!(
        matches.as_ref().is_ok_and(Vec::is_empty),
        "mixed null in store array must fail closed (saw {matches:?})"
    );
}

#[test]
fn resolve_matching_grants_memory_store_allowlist_rejects_non_string_values() {
    let scope = ChioScope {
        grants: vec![grant(
            "memory",
            "write",
            vec![Operation::Invoke],
            vec![Constraint::MemoryStoreAllowlist(vec![
                "case-notes".to_string()
            ])],
        )],
        ..ChioScope::default()
    };

    let non_string = serde_json::json!({ "store": true });
    let matches = resolve_matching_grants(&scope, "write", "memory", &non_string);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));

    let nested_object = serde_json::json!({ "namespace": { "id": "case-notes" } });
    let matches = resolve_matching_grants(&scope, "write", "memory", &nested_object);
    assert!(matches.as_ref().is_ok_and(Vec::is_empty));
}

#[test]
fn resolve_matching_grants_fails_closed_on_unsupported_constraints() {
    let scope = ChioScope {
        grants: vec![grant(
            "web",
            "send",
            vec![Operation::Invoke],
            vec![Constraint::RegexMatch("^safe$".to_string())],
        )],
        ..ChioScope::default()
    };
    let args = serde_json::json!({ "value": "safe" });

    assert!(matches!(
        resolve_matching_grants(&scope, "send", "web", &args),
        Err(ScopeMatchError::ConstraintError(_))
    ));
}

#[test]
fn resolve_matching_grants_rejects_cumulative_approval_until_enforced() {
    let scope = ChioScope {
        grants: vec![grant(
            "web",
            "send",
            vec![Operation::Invoke],
            vec![Constraint::RequireCumulativeApprovalAbove {
                threshold: MonetaryAmount {
                    units: 10,
                    currency: "USD".to_string(),
                },
                approval_budget_id: "budget-1".to_string(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            }],
        )],
        ..ChioScope::default()
    };

    let error =
        match resolve_matching_grants(&scope, "send", "web", &serde_json::json!({"amount": 10})) {
            Err(error) => error,
            Ok(_) => panic!("cumulative approval requires atomic enforcement"),
        };
    assert_eq!(
        error,
        ScopeMatchError::ConstraintError(
            "portable kernel cannot safely evaluate require_cumulative_approval_above".to_string()
        )
    );
}
