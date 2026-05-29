//! Integration coverage for the `Verdict::Deny` enrichment.
//!
//! These tests verify three properties end-to-end at the HTTP-layer boundary:
//!
//! 1. A deny populated with structured context serializes every field and
//!    round-trips through serde without loss.
//! 2. A `Verdict::Deny` without a `details` key deserializes to an empty
//!    `DenyDetails` block. This is the current serde behavior for all
//!    `Verdict::deny()` callers (authority.rs, receipt.rs, etc.).
//! 3. The bare-bones `Verdict::deny` constructor used throughout the crate
//!    emits JSON with no `details` key (compact wire form, details omitted when empty).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_http_core::{DenyDetails, Verdict};

fn full_details() -> DenyDetails {
    DenyDetails {
        tool_name: Some("write_file".into()),
        tool_server: Some("filesystem".into()),
        requested_action: Some(r#"write_file(path=".env", content="SECRET=x")"#.into()),
        required_scope: Some(
            r#"ToolGrant(server_id="filesystem", tool_name="write_file", operations=[Invoke])"#
                .into(),
        ),
        granted_scope: Some(
            r#"ToolGrant(server_id="filesystem", tool_name="write_file", operations=[Invoke], constraints=[regex_match("^(?!.*(\\.env))")])"#
                .into(),
        ),
        reason_code: Some("guard.path_constraint".into()),
        receipt_id: Some("chio-receipt-7f3a9b2c".into()),
        hint: Some(
            "Remove the path_prefix constraint from the policy, or call write_file with a path inside the project root."
                .into(),
        ),
        docs_url: Some("https://docs.chio-protocol.dev/errors/Chio-DENIED".into()),
    }
}

#[test]
fn populated_deny_roundtrips_through_serde() {
    let verdict = Verdict::deny_detailed(
        "tool call denied by path-constraint guard",
        "path-constraint",
        full_details(),
    );

    let json = serde_json::to_string(&verdict).expect("serializes");

    // Every field must appear on the wire.
    for needle in [
        "\"verdict\":\"deny\"",
        "\"reason\":\"tool call denied by path-constraint guard\"",
        "\"guard\":\"path-constraint\"",
        "\"http_status\":403",
        "\"tool_name\":\"write_file\"",
        "\"tool_server\":\"filesystem\"",
        "\"requested_action\":",
        "\"required_scope\":",
        "\"granted_scope\":",
        "\"reason_code\":\"guard.path_constraint\"",
        "\"receipt_id\":\"chio-receipt-7f3a9b2c\"",
        "\"hint\":",
        "\"docs_url\":\"https://docs.chio-protocol.dev/errors/Chio-DENIED\"",
    ] {
        assert!(
            json.contains(needle),
            "missing `{needle}` in serialized verdict: {json}"
        );
    }

    let back: Verdict = serde_json::from_str(&json).expect("deserializes");
    assert_eq!(back, verdict);
}

#[test]
fn deny_without_details_deserializes_to_empty_deny_details() {
    // A Deny payload without a `details` key deserializes to an empty
    // DenyDetails block. This is the current serde behavior: `Verdict::deny`
    // callers omit the field entirely, and the `default` attribute fills it in.
    let json = r#"{
        "verdict": "deny",
        "reason": "no capability token provided",
        "guard": "CapabilityGuard",
        "http_status": 401
    }"#;

    let v: Verdict = serde_json::from_str(json).expect("payload deserializes");
    let Verdict::Deny {
        reason,
        guard,
        http_status,
        details,
    } = v
    else {
        panic!("expected Deny");
    };

    assert_eq!(reason, "no capability token provided");
    assert_eq!(guard, "CapabilityGuard");
    assert_eq!(http_status, 401);
    assert!(
        details.is_empty(),
        "payload without details key should yield empty DenyDetails, got {details:?}"
    );
}

#[test]
fn deny_without_details_omits_details_key() {
    // Ensure call sites that still use `Verdict::deny` produce a compact
    // payload with the details key omitted when empty.
    let v = Verdict::deny("side-effect route requires a capability", "CapabilityGuard");
    let json = serde_json::to_string(&v).expect("serializes");

    assert!(!json.contains("details"), "unexpected details key: {json}");
    assert!(json.contains("\"verdict\":\"deny\""));
    assert!(
        json.contains("\"reason\":\"side-effect route requires a capability\""),
        "reason missing: {json}"
    );
    assert!(json.contains("\"guard\":\"CapabilityGuard\""));
}

#[test]
fn partial_details_only_include_populated_fields() {
    let details = DenyDetails {
        tool_name: Some("read_file".into()),
        reason_code: Some("scope.missing".into()),
        hint: Some("Request scope filesystem::read_file from the authority.".into()),
        ..DenyDetails::default()
    };
    let v = Verdict::deny_detailed("scope missing", "ScopeGuard", details);
    let json = serde_json::to_string(&v).expect("serializes");

    assert!(json.contains("\"tool_name\":\"read_file\""));
    assert!(json.contains("\"reason_code\":\"scope.missing\""));
    assert!(json.contains("\"hint\":"));

    // Unset optional fields must be omitted entirely.
    for absent in [
        "tool_server",
        "requested_action",
        "required_scope",
        "granted_scope",
        "receipt_id",
        "docs_url",
    ] {
        assert!(
            !json.contains(absent),
            "unexpected `{absent}` in partial payload: {json}"
        );
    }
}

#[test]
fn with_deny_details_attaches_context_to_existing_verdict() {
    // Upstream code may build a plain deny first, then a later enrichment
    // layer populates the structured context.
    let details = DenyDetails {
        tool_name: Some("delete_resource".into()),
        tool_server: Some("vault".into()),
        reason_code: Some("tenant.mismatch".into()),
        hint: Some("Switch to a capability bound to tenant 'acme'.".into()),
        ..DenyDetails::default()
    };

    let v = Verdict::deny("tenant mismatch", "TenantGuard").with_deny_details(details.clone());

    let Verdict::Deny {
        details: attached, ..
    } = v
    else {
        panic!("expected Deny");
    };
    assert_eq!(*attached, details);
}

#[test]
fn enriched_deny_preserves_to_decision_mapping() {
    // Converting an enriched deny into the core Decision must drop the
    // HTTP-only details but preserve reason and guard so receipt signing
    // keeps working.
    let details = DenyDetails {
        reason_code: Some("scope.missing".into()),
        ..DenyDetails::default()
    };
    let v = Verdict::deny_detailed("scope missing", "ScopeGuard", details);
    let decision = v.to_decision();
    match decision {
        chio_core_types::Decision::Deny { reason, guard } => {
            assert_eq!(reason, "scope missing");
            assert_eq!(guard, "ScopeGuard");
        }
        other => panic!("expected Decision::Deny, got {other:?}"),
    }
}
