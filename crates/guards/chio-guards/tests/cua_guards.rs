//! Integration tests for the CUA + EmbeddingAnomaly guards.
//!
//! Exercises each guard through the real [`chio_kernel::Guard`] trait with
//! a realistic [`GuardContext`].  The tests verify the acceptance
//! criteria:
//!
//! * ComputerUseGuard - blocked-domain navigation denies; screenshot
//!   rate-limit enforced; Observe mode records but allows.
//! * InputInjectionCapabilityGuard - non-allowlisted input type
//!   denies; missing postcondition probe denies in strict mode.
//! * RemoteDesktopSideChannelGuard - disabled clipboard denies;
//!   oversized transfer denies; unknown channel denies (fail-closed).
//! * EmbeddingAnomalyGuard - embedding above upper bound denies; below
//!   lower bound allows; threshold configurable.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::{
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_guards::{
    AmbiguousPolicy, ComputerUseConfig, ComputerUseGuard, EmbeddingAnomalyConfig,
    EmbeddingAnomalyGuard, EmbeddingAnomalyPatternDb, EnforcementMode,
    InputInjectionCapabilityConfig, InputInjectionCapabilityGuard, RemoteDesktopSideChannelConfig,
    RemoteDesktopSideChannelGuard,
};
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

// Helpers

fn signed_cap(kp: &Keypair, scope: &ChioScope) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: "cap-cua-test".to_string(),
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

fn make_request(
    tool: &str,
    args: serde_json::Value,
) -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv-cua".to_string();
    let request = ToolCallRequest {
        request_id: "req-cua".to_string(),
        capability: signed_cap(&kp, &scope),
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
    (request, scope, agent_id, server_id)
}

fn eval<G: Guard>(guard: &G, tool: &str, args: serde_json::Value) -> Verdict {
    let (request, scope, agent_id, server_id) = make_request(tool, args);
    let ctx = GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };
    guard.evaluate(&ctx).expect("guard evaluate").verdict
}

// ComputerUseGuard

#[test]
fn computer_use_denies_navigation_to_blocked_domain() {
    let config = ComputerUseConfig {
        mode: EnforcementMode::FailClosed,
        blocked_domains: vec!["evil.example.com".to_string(), "*.malware.org".to_string()],
        ..ComputerUseConfig::default()
    };
    let guard = ComputerUseGuard::with_config(config);

    // Direct match
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://evil.example.com/login"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");

    // Wildcard subdomain match
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://sub.malware.org/x"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");

    // Benign domain allowed
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://docs.rs/tokio"}),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn computer_use_screenshot_rate_limit_enforced() {
    let config = ComputerUseConfig {
        mode: EnforcementMode::FailClosed,
        // Small burst, zero refill so the third capture is denied.
        screenshot_rate_per_second: Some(0.001),
        screenshot_burst: Some(2),
        ..ComputerUseConfig::default()
    };
    let guard = ComputerUseGuard::with_config(config);

    let args = || serde_json::json!({});
    assert!(matches!(eval(&guard, "screenshot", args()), Verdict::Allow));
    assert!(matches!(eval(&guard, "screenshot", args()), Verdict::Allow));
    let v = eval(&guard, "screenshot", args());
    assert!(
        matches!(v, Verdict::Deny),
        "3rd screenshot should Deny; got {v:?}"
    );
}

#[test]
fn computer_use_observe_mode_allows_unknown_actions() {
    let config = ComputerUseConfig {
        mode: EnforcementMode::Observe,
        allowed_action_types: vec![], // allow nothing explicitly
        blocked_domains: vec!["evil.example.com".to_string()],
        ..ComputerUseConfig::default()
    };
    let guard = ComputerUseGuard::with_config(config);

    // Unknown remote.* action - Observe allows
    let v = eval(&guard, "remote.unknown", serde_json::json!({}));
    assert!(
        matches!(v, Verdict::Allow),
        "Observe mode must allow, got {v:?}"
    );

    // Navigation to blocked domain - Observe allows (passive)
    let v = eval(
        &guard,
        "navigate",
        serde_json::json!({"url": "https://evil.example.com/x"}),
    );
    assert!(
        matches!(v, Verdict::Allow),
        "Observe mode must allow, got {v:?}"
    );
}

#[test]
fn computer_use_failclosed_denies_unlisted_action_type() {
    let config = ComputerUseConfig {
        mode: EnforcementMode::FailClosed,
        allowed_action_types: vec!["remote.clipboard".to_string()],
        ..ComputerUseConfig::default()
    };
    let guard = ComputerUseGuard::with_config(config);

    let v = eval(&guard, "remote.audio", serde_json::json!({}));
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn computer_use_guardrail_allows_warning_only() {
    // Default mode is Guardrail - always allow.
    let guard = ComputerUseGuard::new();
    // Not in allowlist, but Guardrail allows.
    let v = eval(&guard, "remote.unknown_side_channel", serde_json::json!({}));
    assert!(matches!(v, Verdict::Allow));
}

// InputInjectionCapabilityGuard

#[test]
fn input_injection_denies_non_allowlisted_input_type() {
    let guard = InputInjectionCapabilityGuard::new();
    let v = eval(
        &guard,
        "input.inject",
        serde_json::json!({"input_type": "gamepad"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn input_injection_allows_keyboard() {
    let guard = InputInjectionCapabilityGuard::new();
    let v = eval(
        &guard,
        "input.inject",
        serde_json::json!({"input_type": "keyboard", "key": "a"}),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");
}

#[test]
fn input_injection_strict_mode_denies_missing_input_type() {
    let guard = InputInjectionCapabilityGuard::new();
    let v = eval(
        &guard,
        "input.inject",
        serde_json::json!({"action": "click"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn input_injection_requires_postcondition_probe_when_configured() {
    let config = InputInjectionCapabilityConfig {
        require_postcondition_probe: true,
        ..InputInjectionCapabilityConfig::default()
    };
    let guard = InputInjectionCapabilityGuard::with_config(config);

    // Missing probe → Deny
    let v = eval(
        &guard,
        "input.inject",
        serde_json::json!({"input_type": "keyboard"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");

    // With probe → Allow
    let v = eval(
        &guard,
        "input.inject",
        serde_json::json!({
            "input_type": "keyboard",
            "postcondition_probe_hash": "sha256:abc123"
        }),
    );
    assert!(matches!(v, Verdict::Allow), "expected Allow, got {v:?}");

    // Empty probe treated as missing
    let v = eval(
        &guard,
        "input.inject",
        serde_json::json!({
            "input_type": "keyboard",
            "postconditionProbeHash": ""
        }),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn input_injection_passes_through_unrelated_actions() {
    let guard = InputInjectionCapabilityGuard::new();
    let v = eval(&guard, "read_file", serde_json::json!({"path": "/tmp/x"}));
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn input_injection_detects_injection_via_action_type_arg() {
    let guard = InputInjectionCapabilityGuard::new();
    let v = eval(
        &guard,
        "generic",
        serde_json::json!({"action_type": "input.inject", "input_type": "gamepad"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

// RemoteDesktopSideChannelGuard

#[test]
fn remote_desktop_denies_when_clipboard_disabled() {
    let config = RemoteDesktopSideChannelConfig {
        clipboard_enabled: false,
        ..RemoteDesktopSideChannelConfig::default()
    };
    let guard = RemoteDesktopSideChannelGuard::with_config(config);
    let v = eval(&guard, "remote.clipboard", serde_json::json!({}));
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn remote_desktop_allows_clipboard_when_enabled() {
    let guard = RemoteDesktopSideChannelGuard::new();
    let v = eval(&guard, "remote.clipboard", serde_json::json!({}));
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn remote_desktop_denies_file_transfer_exceeding_size_limit() {
    let config = RemoteDesktopSideChannelConfig {
        max_transfer_size_bytes: Some(1024),
        ..RemoteDesktopSideChannelConfig::default()
    };
    let guard = RemoteDesktopSideChannelGuard::with_config(config);
    let v = eval(
        &guard,
        "remote.file_transfer",
        serde_json::json!({"transfer_size": 2048}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn remote_desktop_allows_file_transfer_within_size_limit() {
    let config = RemoteDesktopSideChannelConfig {
        max_transfer_size_bytes: Some(4096),
        ..RemoteDesktopSideChannelConfig::default()
    };
    let guard = RemoteDesktopSideChannelGuard::with_config(config);
    let v = eval(
        &guard,
        "remote.file_transfer",
        serde_json::json!({"transferSize": 1024}),
    );
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn remote_desktop_denies_file_transfer_missing_size_when_limit_set() {
    let config = RemoteDesktopSideChannelConfig {
        max_transfer_size_bytes: Some(4096),
        ..RemoteDesktopSideChannelConfig::default()
    };
    let guard = RemoteDesktopSideChannelGuard::with_config(config);
    let v = eval(&guard, "remote.file_transfer", serde_json::json!({}));
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn remote_desktop_denies_unknown_channel_fail_closed() {
    let guard = RemoteDesktopSideChannelGuard::new();
    let v = eval(&guard, "remote.some_new_channel", serde_json::json!({}));
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

#[test]
fn remote_desktop_ignores_session_lifecycle() {
    // Session lifecycle is the coarse ComputerUseGuard's job, not this guard.
    let guard = RemoteDesktopSideChannelGuard::new();
    let v = eval(&guard, "remote.session.connect", serde_json::json!({}));
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn remote_desktop_ignores_non_remote_actions() {
    let guard = RemoteDesktopSideChannelGuard::new();
    let v = eval(&guard, "read_file", serde_json::json!({"path": "/tmp/x"}));
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn remote_desktop_denies_invalid_transfer_size_type() {
    let config = RemoteDesktopSideChannelConfig {
        max_transfer_size_bytes: Some(4096),
        ..RemoteDesktopSideChannelConfig::default()
    };
    let guard = RemoteDesktopSideChannelGuard::with_config(config);
    let v = eval(
        &guard,
        "remote.file_transfer",
        serde_json::json!({"transfer_size": "1024"}),
    );
    assert!(matches!(v, Verdict::Deny), "expected Deny, got {v:?}");
}

// EmbeddingAnomalyGuard

fn bundled_pattern_json() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/embedding_anomaly_patterns.json"
    ))
    .expect("bundled pattern DB present")
}

#[test]
fn embedding_anomaly_bundled_pattern_db_loads() {
    let guard =
        EmbeddingAnomalyGuard::from_json(&bundled_pattern_json()).expect("bundled DB must parse");
    assert!(
        guard.pattern_count() >= 9,
        "expected 10-20 entries from the bundled DB"
    );
    assert_eq!(guard.dim(), 6, "the bundled DB uses 6-dim embeddings");
}

#[test]
fn embedding_anomaly_known_bad_embedding_denies() {
    let guard =
        EmbeddingAnomalyGuard::from_json(&bundled_pattern_json()).expect("bundled DB parses");
    // First bundled pattern is prompt-injection system override.
    let exact_match = serde_json::json!({
        "embedding": [0.95, 0.05, 0.02, 0.03, 0.12, 0.01]
    });
    let v = eval(&guard, "inspect", exact_match);
    assert!(
        matches!(v, Verdict::Deny),
        "identical embedding must Deny, got {v:?}"
    );
}

#[test]
fn embedding_anomaly_benign_embedding_allows() {
    let guard =
        EmbeddingAnomalyGuard::from_json(&bundled_pattern_json()).expect("bundled DB parses");
    // Unit vector far from any pattern cluster.
    let benign = serde_json::json!({
        "embedding": [-1.0, -1.0, -1.0, -1.0, -1.0, -1.0]
    });
    let v = eval(&guard, "inspect", benign);
    assert!(
        matches!(v, Verdict::Allow),
        "orthogonal/opposite embedding must Allow, got {v:?}"
    );
}

#[test]
fn embedding_anomaly_no_embedding_is_allow() {
    let guard =
        EmbeddingAnomalyGuard::from_json(&bundled_pattern_json()).expect("bundled DB parses");
    let v = eval(&guard, "inspect", serde_json::json!({"other": 1}));
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn embedding_anomaly_malformed_explicit_embedding_denies() {
    let guard =
        EmbeddingAnomalyGuard::from_json(&bundled_pattern_json()).expect("bundled DB parses");
    for args in [
        serde_json::json!({"embedding": [0.1, "bad", 0.3]}),
        serde_json::json!({"vector": "bad"}),
        serde_json::json!({"embeddings": [[0.1, 0.2], ["bad", 0.4]]}),
    ] {
        let v = eval(&guard, "inspect", args);
        assert!(matches!(v, Verdict::Deny));
    }
}

#[test]
fn embedding_anomaly_threshold_configurable() {
    let db = EmbeddingAnomalyPatternDb::from_json(
        r#"[
            {"id":"a","category":"x","stage":"s","label":"l","embedding":[1.0,0.0,0.0]}
        ]"#,
    )
    .expect("small DB");
    // High threshold: near-identical vector with low ambiguity band → Deny
    let high = EmbeddingAnomalyConfig {
        similarity_threshold: 0.8,
        ambiguity_band: 0.05,
        top_k: 5,
        ambiguous_policy: AmbiguousPolicy::Allow,
    };
    let guard = EmbeddingAnomalyGuard::new(db.clone(), high).expect("high threshold");
    let v = eval(
        &guard,
        "inspect",
        serde_json::json!({"embedding": [1.0, 0.0, 0.0]}),
    );
    assert!(matches!(v, Verdict::Deny));

    // Very high threshold + narrow band: same 1.0 match still denies,
    // but weaker vectors (~0.707) land outside the upper bound and
    // default to Allow.
    let looser = EmbeddingAnomalyConfig {
        similarity_threshold: 0.9,
        ambiguity_band: 0.05,
        top_k: 5,
        ambiguous_policy: AmbiguousPolicy::Allow,
    };
    let guard = EmbeddingAnomalyGuard::new(db, looser).expect("looser");
    let v = eval(
        &guard,
        "inspect",
        serde_json::json!({"embedding": [1.0, 1.0, 0.0]}),
    );
    assert!(matches!(v, Verdict::Allow));
}

#[test]
fn embedding_anomaly_dimension_mismatch_denies() {
    let guard =
        EmbeddingAnomalyGuard::from_json(&bundled_pattern_json()).expect("bundled DB parses");
    let v = eval(
        &guard,
        "inspect",
        serde_json::json!({"embedding": [0.1, 0.2]}),
    );
    assert!(
        matches!(v, Verdict::Deny),
        "dim mismatch must fail-closed, got {v:?}"
    );
}

#[test]
fn embedding_anomaly_malformed_pattern_db_fails_closed_at_init() {
    // Empty array is invalid.
    assert!(EmbeddingAnomalyGuard::from_json("[]").is_err());
    // Dim mismatch.
    let bad = r#"[
        {"id":"a","category":"x","stage":"s","label":"l","embedding":[1.0]},
        {"id":"b","category":"y","stage":"s","label":"l","embedding":[1.0,0.0]}
    ]"#;
    assert!(EmbeddingAnomalyGuard::from_json(bad).is_err());
    // Totally malformed JSON.
    assert!(EmbeddingAnomalyGuard::from_json("{not json").is_err());
}
