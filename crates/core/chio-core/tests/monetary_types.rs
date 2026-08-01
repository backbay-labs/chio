// Monetary type integration tests for chio-core.
//
// These tests verify MonetaryAmount, ToolGrant monetary budget fields,
// Attenuation cost-reduction variants, and is_subset_of monetary enforcement.
//
// Tests:
//   1. monetary_amount_serde_roundtrip
//   2. tool_grant_with_monetary_fields_roundtrip
//   3. tool_grant_without_monetary_fields_defaults_to_none
//   4. monetary_fields_skip_when_none
//   5. attenuation_reduce_cost_per_invocation_roundtrip
//   6. attenuation_reduce_total_cost_roundtrip
//   7. subset_monetary_child_within_parent
//   8. subset_monetary_child_exceeds_parent
//   9. subset_monetary_uncapped_child_of_capped_parent
//  10. subset_monetary_capped_child_of_uncapped_parent
//  11. subset_monetary_currency_mismatch
//  12. subset_per_invocation_cost
//  13. signed_token_with_monetary_grant_roundtrip

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::{
    capability::{
        attenuation::Attenuation,
        scope::{ChioScope, MonetaryAmount, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    Keypair,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn eur(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "EUR".to_string(),
    }
}

fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

// ---------------------------------------------------------------------------
// Test 1: monetary_amount_serde_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn monetary_amount_serde_roundtrip() {
    let amount = MonetaryAmount {
        units: 500,
        currency: "USD".to_string(),
    };

    let json = serde_json::to_string(&amount).unwrap();
    let restored: MonetaryAmount = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.units, 500);
    assert_eq!(restored.currency, "USD");
    assert_eq!(amount, restored);

    // Verify canonical JSON stability
    let json2 = serde_json::to_string(&restored).unwrap();
    assert_eq!(json, json2);
}

// ---------------------------------------------------------------------------
// Test 2: tool_grant_with_monetary_fields_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn tool_grant_with_monetary_fields_roundtrip() {
    let grant = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "process_payment".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(usd(1000)),
        max_total_cost: Some(usd(50_000)),
        dpop_required: None,
    };

    let json = serde_json::to_string_pretty(&grant).unwrap();
    let restored: ToolGrant = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.server_id, "srv-a");
    assert_eq!(restored.tool_name, "process_payment");

    let per_invocation = restored.max_cost_per_invocation.unwrap();
    assert_eq!(per_invocation.units, 1000);
    assert_eq!(per_invocation.currency, "USD");

    let total = restored.max_total_cost.unwrap();
    assert_eq!(total.units, 50_000);
    assert_eq!(total.currency, "USD");

    // Verify both monetary fields are present in JSON
    assert!(json.contains("max_cost_per_invocation"));
    assert!(json.contains("max_total_cost"));
    assert!(json.contains("\"units\""));
    assert!(json.contains("\"currency\""));
}

// ---------------------------------------------------------------------------
// Test 3: tool_grant_without_monetary_fields_defaults_to_none
// ---------------------------------------------------------------------------
#[test]
fn tool_grant_without_monetary_fields_defaults_to_none() {
    // Verify that a ToolGrant JSON without monetary keys deserializes correctly
    let v1_json = r#"{
        "server_id": "srv-a",
        "tool_name": "file_read",
        "operations": ["invoke"],
        "constraints": [],
        "max_invocations": 10
    }"#;

    let grant: ToolGrant = serde_json::from_str(v1_json).unwrap();

    assert_eq!(grant.server_id, "srv-a");
    assert_eq!(grant.tool_name, "file_read");
    assert_eq!(grant.max_invocations, Some(10));
    assert!(
        grant.max_cost_per_invocation.is_none(),
        "max_cost_per_invocation should default to None for v1.0 tokens"
    );
    assert!(
        grant.max_total_cost.is_none(),
        "max_total_cost should default to None for v1.0 tokens"
    );
}

// ---------------------------------------------------------------------------
// Test 4: monetary_fields_skip_when_none
// ---------------------------------------------------------------------------
#[test]
fn monetary_fields_skip_when_none() {
    let grant = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };

    let json = serde_json::to_string(&grant).unwrap();

    assert!(
        !json.contains("max_cost_per_invocation"),
        "max_cost_per_invocation key must be omitted when None, got: {json}"
    );
    assert!(
        !json.contains("max_total_cost"),
        "max_total_cost key must be omitted when None, got: {json}"
    );
    assert!(
        !json.contains("max_invocations"),
        "max_invocations key must be omitted when None, got: {json}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: attenuation_reduce_cost_per_invocation_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn attenuation_reduce_cost_per_invocation_roundtrip() {
    let attenuation = Attenuation::ReduceCostPerInvocation {
        server_id: "srv-payments".to_string(),
        tool_name: "charge_card".to_string(),
        max_cost_per_invocation: usd(500),
    };

    let json = serde_json::to_string_pretty(&attenuation).unwrap();
    let restored: Attenuation = serde_json::from_str(&json).unwrap();

    match restored {
        Attenuation::ReduceCostPerInvocation {
            server_id,
            tool_name,
            max_cost_per_invocation,
        } => {
            assert_eq!(server_id, "srv-payments");
            assert_eq!(tool_name, "charge_card");
            assert_eq!(max_cost_per_invocation.units, 500);
            assert_eq!(max_cost_per_invocation.currency, "USD");
        }
        other => panic!("unexpected attenuation variant: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 6: attenuation_reduce_total_cost_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn attenuation_reduce_total_cost_roundtrip() {
    let attenuation = Attenuation::ReduceTotalCost {
        server_id: "srv-billing".to_string(),
        tool_name: "generate_invoice".to_string(),
        max_total_cost: eur(25_000),
    };

    let json = serde_json::to_string_pretty(&attenuation).unwrap();
    let restored: Attenuation = serde_json::from_str(&json).unwrap();

    match restored {
        Attenuation::ReduceTotalCost {
            server_id,
            tool_name,
            max_total_cost,
        } => {
            assert_eq!(server_id, "srv-billing");
            assert_eq!(tool_name, "generate_invoice");
            assert_eq!(max_total_cost.units, 25_000);
            assert_eq!(max_total_cost.currency, "EUR");
        }
        other => panic!("unexpected attenuation variant: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 7: subset_monetary_child_within_parent
// ---------------------------------------------------------------------------
#[test]
fn subset_monetary_child_within_parent() {
    let parent = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "process".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: Some(usd(1000)),
        dpop_required: None,
    };
    let child = ToolGrant {
        max_total_cost: Some(usd(500)),
        ..parent.clone()
    };

    assert!(
        child.is_subset_of(&parent),
        "child with max_total_cost 500 USD should be subset of parent with 1000 USD"
    );
}

// ---------------------------------------------------------------------------
// Test 8: subset_monetary_child_exceeds_parent
// ---------------------------------------------------------------------------
#[test]
fn subset_monetary_child_exceeds_parent() {
    let parent = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "process".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: Some(usd(1000)),
        dpop_required: None,
    };
    let child = ToolGrant {
        max_total_cost: Some(usd(1500)),
        ..parent.clone()
    };

    assert!(
        !child.is_subset_of(&parent),
        "child with max_total_cost 1500 USD should NOT be subset of parent with 1000 USD"
    );
}

// ---------------------------------------------------------------------------
// Test 9: subset_monetary_uncapped_child_of_capped_parent
// ---------------------------------------------------------------------------
#[test]
fn subset_monetary_uncapped_child_of_capped_parent() {
    let parent = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "process".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: Some(usd(1000)),
        dpop_required: None,
    };
    let child = ToolGrant {
        max_total_cost: None,
        ..parent.clone()
    };

    assert!(
        !child.is_subset_of(&parent),
        "uncapped child (None) should NOT be subset of capped parent (Some 1000 USD)"
    );
}

// ---------------------------------------------------------------------------
// Test 10: subset_monetary_capped_child_of_uncapped_parent
// ---------------------------------------------------------------------------
#[test]
fn subset_monetary_capped_child_of_uncapped_parent() {
    let parent = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "process".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None, // parent has no total cost cap
        dpop_required: None,
    };
    let child = ToolGrant {
        max_total_cost: Some(usd(500)), // child restricts further
        ..parent.clone()
    };

    assert!(
        child.is_subset_of(&parent),
        "capped child should be subset of uncapped parent (parent does not restrict)"
    );
}

// ---------------------------------------------------------------------------
// Test 11: subset_monetary_currency_mismatch
// ---------------------------------------------------------------------------
#[test]
fn subset_monetary_currency_mismatch() {
    let parent = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "process".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: Some(usd(1000)),
        dpop_required: None,
    };
    let child = ToolGrant {
        max_total_cost: Some(eur(500)), // same units but different currency
        ..parent.clone()
    };

    assert!(
        !child.is_subset_of(&parent),
        "child with EUR currency should NOT be subset of parent with USD (currency mismatch)"
    );
}

// ---------------------------------------------------------------------------
// Test 12: subset_per_invocation_cost
// ---------------------------------------------------------------------------
#[test]
fn subset_per_invocation_cost() {
    let parent = ToolGrant {
        server_id: "srv-a".to_string(),
        tool_name: "call_api".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(usd(100)),
        max_total_cost: None,
        dpop_required: None,
    };

    // Child within per-invocation budget: OK
    let child_ok = ToolGrant {
        max_cost_per_invocation: Some(usd(50)),
        ..parent.clone()
    };
    assert!(
        child_ok.is_subset_of(&parent),
        "child with 50 USD per invocation should be subset of parent with 100 USD"
    );

    // Child exceeds per-invocation budget: NOT OK
    let child_exceed = ToolGrant {
        max_cost_per_invocation: Some(usd(200)),
        ..parent.clone()
    };
    assert!(
        !child_exceed.is_subset_of(&parent),
        "child with 200 USD per invocation should NOT be subset of parent with 100 USD"
    );

    // Uncapped child of capped parent: NOT OK
    let child_none = ToolGrant {
        max_cost_per_invocation: None,
        ..parent.clone()
    };
    assert!(
        !child_none.is_subset_of(&parent),
        "uncapped child should NOT be subset of per-invocation capped parent"
    );

    // Currency mismatch: NOT OK
    let child_wrong_currency = ToolGrant {
        max_cost_per_invocation: Some(eur(50)),
        ..parent.clone()
    };
    assert!(
        !child_wrong_currency.is_subset_of(&parent),
        "child with EUR should NOT be subset of parent with USD"
    );

    // Equal cap is OK (child matches parent exactly)
    let child_equal = ToolGrant {
        max_cost_per_invocation: Some(usd(100)),
        ..parent.clone()
    };
    assert!(
        child_equal.is_subset_of(&parent),
        "child with exact same cap as parent should be subset"
    );
}

// ---------------------------------------------------------------------------
// Test 13: signed_token_with_monetary_grant_roundtrip
// ---------------------------------------------------------------------------
#[test]
fn signed_token_with_monetary_grant_roundtrip() {
    let kp = Keypair::generate();
    let subject_kp = Keypair::generate();

    let monetary_grant = ToolGrant {
        server_id: "srv-payments".to_string(),
        tool_name: "authorize_charge".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: Some(10),
        max_cost_per_invocation: Some(usd(1500)),
        max_total_cost: Some(usd(10_000)),
        dpop_required: None,
    };

    let body = CapabilityTokenBody {
        id: "cap-monetary-001".to_string(),
        issuer: kp.public_key(),
        subject: subject_kp.public_key(),
        scope: make_scope(vec![monetary_grant]),
        issued_at: 1_000_000,
        expires_at: 2_000_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };

    let token = CapabilityToken::sign(body, &kp).unwrap();

    // Verify signature before serialization
    assert!(
        token.verify_signature().unwrap(),
        "token signature must be valid before serialization"
    );

    // Round-trip via JSON
    let json = serde_json::to_string(&token).unwrap();
    let restored: CapabilityToken = serde_json::from_str(&json).unwrap();

    // Verify signature still holds after deserialization
    assert!(
        restored.verify_signature().unwrap(),
        "token signature must be valid after JSON round-trip"
    );

    // Verify monetary fields survived the round-trip
    let grant = &restored.scope.grants[0];
    let per_invocation = grant
        .max_cost_per_invocation
        .as_ref()
        .expect("max_cost_per_invocation must be present");
    assert_eq!(per_invocation.units, 1500);
    assert_eq!(per_invocation.currency, "USD");

    let total = grant
        .max_total_cost
        .as_ref()
        .expect("max_total_cost must be present");
    assert_eq!(total.units, 10_000);
    assert_eq!(total.currency, "USD");

    assert_eq!(grant.max_invocations, Some(10));
    assert_eq!(grant.server_id, "srv-payments");
    assert_eq!(grant.tool_name, "authorize_charge");
}
