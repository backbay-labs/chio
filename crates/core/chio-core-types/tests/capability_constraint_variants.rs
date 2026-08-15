//! Serde and construction tests for `Constraint` variants (data-layer, communication,
//! financial, model-routing, and memory-governance kinds).
//!
//! These exercise the data-layer, communication, financial,
//! model-routing, and memory-governance variants added per
//! `docs/protocols/ADR-TYPE-EVOLUTION.md` section 3. Each variant must
//! participate in the existing
//! `#[serde(tag = "type", content = "value", rename_all = "snake_case")]`
//! envelope and round-trip through serde without information loss.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::{
    governance::ProvenanceEvidenceClass,
    scope::{
        Constraint, ContentReviewTier, FindingPurchaseMarkerV1, FindingRecoveryMarkerV1,
        FindingSettlementSelector, ModelMetadata, ModelSafetyTier, SqlOperationClass,
    },
};
use serde_json::{json, Value};

fn to_value(constraint: &Constraint) -> Value {
    serde_json::to_value(constraint).expect("constraint serializes")
}

fn roundtrip(constraint: Constraint) -> Constraint {
    let value = to_value(&constraint);
    serde_json::from_value(value).expect("constraint deserializes")
}

#[test]
fn table_allowlist_serializes_with_expected_tag() {
    let constraint = Constraint::TableAllowlist(vec!["users".to_string(), "orders".to_string()]);
    let value = to_value(&constraint);
    assert_eq!(
        value,
        json!({
            "type": "table_allowlist",
            "value": ["users", "orders"],
        })
    );
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn column_denylist_roundtrips() {
    let constraint = Constraint::ColumnDenylist(vec![
        "users.password_hash".to_string(),
        "users.ssn".to_string(),
    ]);
    let value = to_value(&constraint);
    assert_eq!(value["type"], "column_denylist");
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn operation_class_enum_serializes() {
    let constraint = Constraint::OperationClass(SqlOperationClass::ReadOnly);
    let value = to_value(&constraint);
    assert_eq!(
        value,
        json!({
            "type": "operation_class",
            "value": "read_only",
        })
    );
    assert_eq!(roundtrip(constraint.clone()), constraint);

    let rw = Constraint::OperationClass(SqlOperationClass::ReadWrite);
    assert_eq!(to_value(&rw)["value"], "read_write");

    let admin = Constraint::OperationClass(SqlOperationClass::Admin);
    assert_eq!(to_value(&admin)["value"], "admin");
}

#[test]
fn max_rows_returned_roundtrips() {
    let constraint = Constraint::MaxRowsReturned(1000);
    let value = to_value(&constraint);
    assert_eq!(
        value,
        json!({
            "type": "max_rows_returned",
            "value": 1000,
        })
    );
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn audience_allowlist_accepts_string_list() {
    let constraint =
        Constraint::AudienceAllowlist(vec!["#ops".to_string(), "alerts@example.com".to_string()]);
    let value = to_value(&constraint);
    assert_eq!(value["type"], "audience_allowlist");
    assert_eq!(value["value"][0], "#ops");
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn content_review_tier_roundtrips() {
    for tier in [
        ContentReviewTier::None,
        ContentReviewTier::Basic,
        ContentReviewTier::Strict,
    ] {
        let constraint = Constraint::ContentReviewTier(tier);
        let value = to_value(&constraint);
        assert_eq!(value["type"], "content_review_tier");
        assert_eq!(roundtrip(constraint.clone()), constraint);
    }
}

#[test]
fn max_transaction_amount_usd_roundtrips() {
    let constraint = Constraint::MaxTransactionAmountUsd("100.00".to_string());
    let value = to_value(&constraint);
    assert_eq!(
        value,
        json!({
            "type": "max_transaction_amount_usd",
            "value": "100.00",
        })
    );
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn require_dual_approval_roundtrips() {
    let constraint = Constraint::RequireDualApproval(true);
    let value = to_value(&constraint);
    assert_eq!(
        value,
        json!({
            "type": "require_dual_approval",
            "value": true,
        })
    );
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn model_constraint_with_both_fields_roundtrips() {
    let constraint = Constraint::ModelConstraint {
        allowed_model_ids: vec!["gpt-5".to_string(), "claude-opus-4".to_string()],
        min_safety_tier: Some(ModelSafetyTier::Standard),
    };
    let value = to_value(&constraint);
    assert_eq!(value["type"], "model_constraint");
    assert_eq!(value["value"]["allowed_model_ids"][0], "gpt-5");
    assert_eq!(value["value"]["min_safety_tier"], "standard");
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn model_constraint_with_only_allowed_ids() {
    let constraint = Constraint::ModelConstraint {
        allowed_model_ids: vec!["claude-haiku-4".to_string()],
        min_safety_tier: None,
    };
    let value = to_value(&constraint);
    assert_eq!(value["type"], "model_constraint");
    assert_eq!(value["value"]["allowed_model_ids"][0], "claude-haiku-4");
    assert!(value["value"]["min_safety_tier"].is_null());
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn memory_store_allowlist_roundtrips() {
    let constraint = Constraint::MemoryStoreAllowlist(vec![
        "conversation".to_string(),
        "scratchpad".to_string(),
    ]);
    let value = to_value(&constraint);
    assert_eq!(value["type"], "memory_store_allowlist");
    assert_eq!(value["value"][0], "conversation");
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn memory_write_deny_patterns_roundtrips() {
    let constraint = Constraint::MemoryWriteDenyPatterns(vec![
        r"\bAKIA[0-9A-Z]{16}\b".to_string(),
        r"-----BEGIN [A-Z ]+PRIVATE KEY-----".to_string(),
    ]);
    let value = to_value(&constraint);
    assert_eq!(value["type"], "memory_write_deny_patterns");
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

/// `ModelMetadata` carries the calling model's identity and
/// safety tier on `ToolCallRequest`. It must round-trip through serde
/// so wire edges (HTTP, A2A, MCP) can transport it verbatim.
#[test]
fn model_metadata_roundtrips_full() {
    let metadata = ModelMetadata {
        model_id: "claude-opus-4".to_string(),
        safety_tier: Some(ModelSafetyTier::High),
        provider: Some("anthropic".to_string()),
        provenance_class: ProvenanceEvidenceClass::Verified,
    };
    let value = serde_json::to_value(&metadata).expect("metadata serializes");
    assert_eq!(
        value,
        json!({
            "model_id": "claude-opus-4",
            "safety_tier": "high",
            "provider": "anthropic",
            "provenance_class": "verified",
        })
    );
    let round: ModelMetadata = serde_json::from_value(value).expect("metadata deserializes");
    assert_eq!(round, metadata);
}

#[test]
fn model_metadata_omits_absent_optional_fields() {
    let metadata = ModelMetadata {
        model_id: "small-uncensored".to_string(),
        safety_tier: None,
        provider: None,
        provenance_class: ProvenanceEvidenceClass::Asserted,
    };
    let value = serde_json::to_value(&metadata).expect("metadata serializes");
    assert_eq!(value, json!({"model_id": "small-uncensored"}));
    let round: ModelMetadata = serde_json::from_value(value).expect("metadata deserializes");
    assert_eq!(round, metadata);
}

#[test]
fn model_metadata_accepts_partial_payload_with_only_model_id() {
    // An edge that only populates `model_id` must still decode.
    let value = json!({"model_id": "gpt-5"});
    let metadata: ModelMetadata = serde_json::from_value(value).expect("decodes");
    assert_eq!(metadata.model_id, "gpt-5");
    assert!(metadata.safety_tier.is_none());
    assert!(metadata.provider.is_none());
    assert_eq!(metadata.provenance_class, ProvenanceEvidenceClass::Asserted);
}

/// Existing variants must still decode from their on-wire form after
/// adding the new `Constraint` variants, proving additive compatibility.
#[test]
fn existing_path_prefix_still_deserializes() {
    let value = json!({
        "type": "path_prefix",
        "value": "/workspace",
    });
    let constraint: Constraint = serde_json::from_value(value).expect("decodes");
    assert_eq!(constraint, Constraint::PathPrefix("/workspace".to_string()));
}

fn purchase_marker(
    finding_id: &str,
    listing_id: &str,
    settlement: FindingSettlementSelector,
) -> Constraint {
    Constraint::RequireFindingPurchase(Box::new(FindingPurchaseMarkerV1 {
        finding_id: finding_id.to_string(),
        listing_id: listing_id.to_string(),
        settlement,
    }))
}

#[test]
fn require_finding_purchase_local_serializes_with_expected_shape() {
    let constraint = purchase_marker(
        "finding-1",
        "listing-1",
        FindingSettlementSelector::LocalReversibleHold,
    );
    let value = to_value(&constraint);
    assert_eq!(
        value,
        json!({
            "type": "require_finding_purchase",
            "value": {
                "finding_id": "finding-1",
                "listing_id": "listing-1",
                "settlement": {"mode": "local_reversible_hold"},
            },
        })
    );
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn require_finding_purchase_escrow_selector_roundtrips() {
    let constraint = purchase_marker(
        "finding-1",
        "listing-1",
        FindingSettlementSelector::CrossOrgEscrow {
            settlement_profile_sha256: "ab".repeat(32),
        },
    );
    let value = to_value(&constraint);
    assert_eq!(
        value["value"]["settlement"],
        json!({
            "mode": "cross_org_escrow",
            "settlement_profile_sha256": "ab".repeat(32),
        })
    );
    assert_eq!(roundtrip(constraint.clone()), constraint);
}

#[test]
fn require_finding_purchase_rejects_unknown_marker_fields() {
    let value = json!({
        "type": "require_finding_purchase",
        "value": {
            "finding_id": "finding-1",
            "listing_id": "listing-1",
            "settlement": {"mode": "local_reversible_hold"},
            "payout_override": "attacker",
        },
    });
    assert!(serde_json::from_value::<Constraint>(value).is_err());
}

#[test]
fn require_finding_purchase_rejects_unknown_settlement_mode() {
    let value = json!({
        "type": "require_finding_purchase",
        "value": {
            "finding_id": "finding-1",
            "listing_id": "listing-1",
            "settlement": {"mode": "irreversible_transfer"},
        },
    });
    assert!(serde_json::from_value::<Constraint>(value).is_err());
}

#[test]
fn require_finding_purchase_is_preserved_only_by_the_identical_marker() {
    let base = |constraints: Vec<Constraint>| chio_core_types::capability::scope::ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "read_finding".to_string(),
        operations: vec![chio_core_types::capability::scope::Operation::Invoke],
        constraints,
        max_invocations: Some(1),
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: Some(true),
    };
    let parent = base(vec![purchase_marker(
        "finding-1",
        "listing-1",
        FindingSettlementSelector::LocalReversibleHold,
    )]);

    assert!(base(vec![purchase_marker(
        "finding-1",
        "listing-1",
        FindingSettlementSelector::LocalReversibleHold,
    )])
    .is_subset_of(&parent));
    for retargeted in [
        base(vec![purchase_marker(
            "finding-2",
            "listing-1",
            FindingSettlementSelector::LocalReversibleHold,
        )]),
        base(vec![purchase_marker(
            "finding-1",
            "listing-2",
            FindingSettlementSelector::LocalReversibleHold,
        )]),
        base(vec![purchase_marker(
            "finding-1",
            "listing-1",
            FindingSettlementSelector::CrossOrgEscrow {
                settlement_profile_sha256: "cd".repeat(32),
            },
        )]),
        base(Vec::new()),
    ] {
        assert!(
            !retargeted.is_subset_of(&parent),
            "a child may not retarget or drop the purchase marker"
        );
    }
}

#[test]
fn require_finding_recovery_serializes_with_closed_shape() {
    let constraint = Constraint::RequireFindingRecovery(Box::new(FindingRecoveryMarkerV1 {
        recovery_id: "a".repeat(64),
        finding_id: "b".repeat(64),
        listing_id: "listing-1".to_string(),
        original_capability_id: "capability-1".to_string(),
        original_delivery_receipt_id: "receipt-1".to_string(),
        purchase_key: "c".repeat(64),
        max_recoveries: 3,
    }));
    let value = serde_json::to_value(&constraint).expect("serialize recovery marker");
    assert_eq!(
        value,
        serde_json::json!({
            "type": "require_finding_recovery",
            "value": {
                "recovery_id": "a".repeat(64),
                "finding_id": "b".repeat(64),
                "listing_id": "listing-1",
                "original_capability_id": "capability-1",
                "original_delivery_receipt_id": "receipt-1",
                "purchase_key": "c".repeat(64),
                "max_recoveries": 3,
            }
        })
    );
    let decoded: Constraint = serde_json::from_value(value).expect("deserialize recovery marker");
    assert_eq!(decoded, constraint);
}

#[test]
fn require_finding_recovery_rejects_unknown_fields() {
    let value = serde_json::json!({
        "type": "require_finding_recovery",
        "value": {
            "recovery_id": "a".repeat(64),
            "finding_id": "b".repeat(64),
            "listing_id": "listing-1",
            "original_capability_id": "capability-1",
            "original_delivery_receipt_id": "receipt-1",
            "purchase_key": "c".repeat(64),
            "max_recoveries": 3,
            "extra": true,
        }
    });
    assert!(serde_json::from_value::<Constraint>(value).is_err());
}
