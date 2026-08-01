use super::simple::default_patterns;
use super::validators::{is_luhn_valid_card_number, is_valid_ssn_fragments, shannon_entropy_ascii};
use super::*;
use chio_kernel::{Guard, Verdict};

#[test]
fn default_patterns_compile_to_full_set() {
    // Every built-in constant pattern must compile; a regression that
    // breaks one must fail CI here rather than silently shrink the
    // detector set at runtime.
    assert_eq!(default_patterns().len(), 7);
}

// ---- Simple (backwards-compatible) API tests ----

#[test]
fn guard_name() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
    assert_eq!(guard.name(), "response-sanitization");
}

#[test]
fn detects_ssn() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
    let findings = guard.scan("My SSN is 123-45-6789");
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|(name, _)| name == "SSN"));
}

#[test]
fn detects_email() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
    let findings = guard.scan("Contact john@example.com for info");
    assert!(findings.iter().any(|(name, _)| name == "email"));
}

#[test]
fn detects_mrn() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Block);
    let findings = guard.scan("Patient MRN: 123456789");
    assert!(findings.iter().any(|(name, _)| name == "MRN"));
}

#[test]
fn no_findings_on_clean_text() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
    let findings = guard.scan("This is perfectly clean text with no PII.");
    assert!(findings.is_empty());
}

#[test]
fn respects_minimum_sensitivity() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
    let findings = guard.scan("Contact john@example.com");
    assert!(!findings.iter().any(|(name, _)| name == "email"));
    let findings2 = guard.scan("SSN 123-45-6789");
    assert!(findings2.iter().any(|(name, _)| name == "SSN"));
}

#[test]
fn redacts_ssn() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Redact);
    let (redacted, count) = guard.redact("SSN is 123-45-6789 please");
    assert!(redacted.contains("[SSN REDACTED]"));
    assert!(!redacted.contains("123-45-6789"));
    assert!(count > 0);
}

#[test]
fn redacts_email() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::Low, SanitizationAction::Redact);
    let (redacted, _) = guard.redact("Email: jane@example.com");
    assert!(redacted.contains("[EMAIL REDACTED]"));
    assert!(!redacted.contains("jane@example.com"));
}

#[test]
fn scan_response_clean() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
    let response = serde_json::json!({"status": "ok", "data": "nothing sensitive"});
    let result = guard.scan_response(&response);
    assert!(matches!(result, ScanResult::Clean));
}

#[test]
fn scan_response_blocked() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
    let response = serde_json::json!({"patient": "SSN: 123-45-6789"});
    let result = guard.scan_response(&response);
    assert!(matches!(result, ScanResult::Blocked(_)));
}

#[test]
fn scan_response_redacted() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Redact);
    let response = serde_json::json!({"patient": "SSN: 123-45-6789"});
    let result = guard.scan_response(&response);
    match result {
        ScanResult::Redacted { redacted_text, .. } => {
            assert!(redacted_text.contains("[SSN REDACTED]"));
        }
        _ => panic!("expected Redacted result"),
    }
}

#[test]
fn guard_evaluate_denies_args_with_pii() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);

    let kp = chio_core::crypto::Keypair::generate();
    let scope = chio_core::capability::scope::ChioScope::default();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv".to_string();

    let cap_body = chio_core::capability::token::CapabilityTokenBody {
        id: "cap-test".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let cap = chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

    let request = chio_kernel::ToolCallRequest {
        request_id: "req-test".to_string(),
        capability: cap,
        tool_name: "write_file".to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: serde_json::json!({"content": "SSN is 123-45-6789"}),
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

    let ctx = chio_kernel::GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };

    assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
}

#[test]
fn guard_evaluate_allows_clean_args() {
    let guard = ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);

    let kp = chio_core::crypto::Keypair::generate();
    let scope = chio_core::capability::scope::ChioScope::default();
    let agent_id = kp.public_key().to_hex();
    let server_id = "srv".to_string();

    let cap_body = chio_core::capability::token::CapabilityTokenBody {
        id: "cap-test".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let cap = chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

    let request = chio_kernel::ToolCallRequest {
        request_id: "req-test".to_string(),
        capability: cap,
        tool_name: "read_file".to_string(),
        server_id: server_id.clone(),
        agent_id: agent_id.clone(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
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

    let ctx = chio_kernel::GuardContext {
        request: &request,
        scope: &scope,
        agent_id: &agent_id,
        server_id: &server_id,
        session_filesystem_roots: None,
        matched_grant_index: None,
    };

    assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
}

#[test]
fn custom_pattern() {
    let pattern = build_pattern(
        "custom-id",
        r"\bCUST-\d{8}\b",
        SensitivityLevel::High,
        "[CUST-ID REDACTED]",
    );
    assert!(pattern.is_some());

    let guard = ResponseSanitizationGuard::with_patterns(
        vec![pattern.unwrap()],
        SensitivityLevel::High,
        SanitizationAction::Block,
    );
    let findings = guard.scan("Customer CUST-12345678 record");
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|(name, _)| name == "custom-id"));
}

// ---- OutputSanitizer unit tests ----

#[test]
fn luhn_rejects_random_16_digit_number() {
    assert!(!is_luhn_valid_card_number("1234567890123456"));
    // Known-valid test card (Visa).
    assert!(is_luhn_valid_card_number("4111 1111 1111 1111"));
    // One digit flipped: no longer valid.
    assert!(!is_luhn_valid_card_number("4111 1111 1111 1112"));
}

#[test]
fn output_sanitizer_clone_preserves_token_vault() {
    let mut config = OutputSanitizerConfig::default();
    config
        .redaction_strategies
        .insert(SensitiveCategory::Pii, RedactionStrategy::Tokenize);
    let sanitizer = OutputSanitizer::with_config(config).unwrap();
    let cloned = sanitizer.clone();

    let result = cloned.sanitize_text("Contact john@example.com for access");
    let token = result
        .redactions
        .iter()
        .find_map(|redaction| {
            redaction
                .replacement
                .strip_prefix("[TOKEN:")
                .and_then(|value| value.strip_suffix(']'))
        })
        .unwrap();

    assert_eq!(
        sanitizer.token_vault().get(token).as_deref(),
        Some("john@example.com")
    );
}

#[test]
fn shannon_entropy_basic() {
    let e = shannon_entropy_ascii("aaaaaa").unwrap();
    assert!(e < 0.01);
    let e2 = shannon_entropy_ascii("abcdefghij0123456789").unwrap();
    assert!(e2 > 4.0);
}

#[test]
fn ssn_fragments_validator_rejects_invalid_areas() {
    assert!(!is_valid_ssn_fragments("000-12-3456"));
    assert!(!is_valid_ssn_fragments("666-12-3456"));
    assert!(!is_valid_ssn_fragments("900-12-3456"));
    assert!(!is_valid_ssn_fragments("123-00-4567"));
    assert!(!is_valid_ssn_fragments("123-45-0000"));
    assert!(is_valid_ssn_fragments("123-45-6789"));
}
