//! Kernel binding refusal integration tests (P4.T5).
//!
//! Locks the M10 P4 kernel binding refusal contract end to end:
//! provider bind verifies (a) weights_hash byte-equality against the
//! card, (b) requested capability set is a subset of the card's
//! allowed_capability_set, and (c) no requested tool intersects the
//! card's banned_tools. Any failing gate surfaces a stable
//! urn:chio:error:weights:* code.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_kernel::weights_binding::{evaluate_weights_binding, WeightsBindingRequest};
use chio_weights::card::{ModelCard, StringSet};
use chio_weights::error::WeightsError;
use chrono::{TimeZone, Utc};

fn good_card() -> ModelCard {
    let issued = Utc.with_ymd_and_hms(2026, 4, 30, 12, 0, 0).unwrap();
    ModelCard::new(
        "0000000000000000000000000000000000000000000000000000000000000001",
        StringSet::new(["tool:read", "tool:write", "tool:list"]),
        StringSet::new(["tool:exec", "tool:shell"]),
        "public-internet",
        "https://example.com/issuer",
        issued,
        issued + chrono::Duration::days(30),
    )
    .unwrap()
}

#[test]
fn bind_succeeds_when_weights_scope_and_tools_all_admissible() {
    let card = good_card();
    let scopes = StringSet::new(["tool:read", "tool:write"]);
    let tools = StringSet::new(["tool:read"]);
    let req = WeightsBindingRequest {
        loaded_weights_hash:
            "0000000000000000000000000000000000000000000000000000000000000001",
        requested_scopes: &scopes,
        requested_tools: &tools,
    };
    evaluate_weights_binding(&card, &req).unwrap();
}

#[test]
fn bind_rejects_weights_hash_mismatch() {
    let card = good_card();
    let scopes = StringSet::new(["tool:read"]);
    let tools = StringSet::new(["tool:read"]);
    let req = WeightsBindingRequest {
        loaded_weights_hash:
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        requested_scopes: &scopes,
        requested_tools: &tools,
    };
    let err = evaluate_weights_binding(&card, &req).unwrap_err();
    assert_eq!(err.urn(), "urn:chio:error:weights:card-mismatch");
    match err {
        WeightsError::CardMismatch { expected, found } => {
            assert_eq!(
                expected,
                "0000000000000000000000000000000000000000000000000000000000000001"
            );
            assert_eq!(
                found,
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn bind_rejects_scope_outside_allowed_set() {
    let card = good_card();
    let scopes = StringSet::new(["tool:read", "tool:admin"]);
    let tools = StringSet::default();
    let req = WeightsBindingRequest {
        loaded_weights_hash:
            "0000000000000000000000000000000000000000000000000000000000000001",
        requested_scopes: &scopes,
        requested_tools: &tools,
    };
    let err = evaluate_weights_binding(&card, &req).unwrap_err();
    assert_eq!(err.urn(), "urn:chio:error:weights:scope-not-subset");
    match err {
        WeightsError::ScopeNotSubset { scope } => assert_eq!(scope, "tool:admin"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn bind_rejects_banned_tool_intersection() {
    let card = good_card();
    let scopes = StringSet::new(["tool:read"]);
    let tools = StringSet::new(["tool:read", "tool:exec"]);
    let req = WeightsBindingRequest {
        loaded_weights_hash:
            "0000000000000000000000000000000000000000000000000000000000000001",
        requested_scopes: &scopes,
        requested_tools: &tools,
    };
    let err = evaluate_weights_binding(&card, &req).unwrap_err();
    assert_eq!(err.urn(), "urn:chio:error:weights:tool-banned");
    match err {
        WeightsError::ToolBanned { tool } => assert_eq!(tool, "tool:exec"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn banned_tool_first_overlap_is_returned_lexicographically() {
    // Card banned_tools = {tool:exec, tool:shell}. Iteration is
    // lexicographic per BTreeSet, so requesting both surfaces tool:exec
    // first.
    let card = good_card();
    let scopes = StringSet::default();
    let tools = StringSet::new(["tool:exec", "tool:shell"]);
    let req = WeightsBindingRequest {
        loaded_weights_hash:
            "0000000000000000000000000000000000000000000000000000000000000001",
        requested_scopes: &scopes,
        requested_tools: &tools,
    };
    let err = evaluate_weights_binding(&card, &req).unwrap_err();
    match err {
        WeightsError::ToolBanned { tool } => assert_eq!(tool, "tool:exec"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn weights_mismatch_short_circuits_before_scope_check() {
    // Both gates 1 and 2 would fail; the contract returns gate 1 first.
    let card = good_card();
    let scopes = StringSet::new(["tool:admin"]);
    let tools = StringSet::default();
    let req = WeightsBindingRequest {
        loaded_weights_hash:
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        requested_scopes: &scopes,
        requested_tools: &tools,
    };
    let err = evaluate_weights_binding(&card, &req).unwrap_err();
    assert!(matches!(err, WeightsError::CardMismatch { .. }));
}

#[test]
fn empty_request_accepts_when_card_matches_weights() {
    let card = good_card();
    let scopes = StringSet::default();
    let tools = StringSet::default();
    let req = WeightsBindingRequest {
        loaded_weights_hash:
            "0000000000000000000000000000000000000000000000000000000000000001",
        requested_scopes: &scopes,
        requested_tools: &tools,
    };
    evaluate_weights_binding(&card, &req).unwrap();
}
