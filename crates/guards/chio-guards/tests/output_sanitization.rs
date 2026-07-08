//! Integration tests for the full output sanitizer.
//!
//! These tests exercise every detector, Luhn validation (including false
//! positives), allowlist / denylist, overlap resolution, each redaction
//! strategy, and evidence emission through the post-invocation pipeline.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_guards::{
    sanitize_json, AllowlistConfig, DenylistConfig, EntropyConfig, OutputSanitizer,
    OutputSanitizerConfig, OutputSanitizerConfigError, PostInvocationPipeline,
    PostInvocationVerdict, RedactionStrategy, SanitizerHook, SensitiveCategory,
};
use std::collections::HashMap;

fn sanitizer_with_config(cfg: OutputSanitizerConfig) -> OutputSanitizer {
    match OutputSanitizer::with_config(cfg) {
        Ok(sanitizer) => sanitizer,
        Err(error) => panic!("expected sanitizer config to compile: {error}"),
    }
}

// ---------------------------------------------------------------------------
// Per-detector sanity: every secret detector redacts a canonical example.
// ---------------------------------------------------------------------------

#[test]
fn detects_aws_access_key() {
    let s = OutputSanitizer::new();
    let input = "export AWS_KEY=AKIAIOSFODNN7EXAMPLE";
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(r
        .findings
        .iter()
        .any(|f| f.id == "secret_aws_access_key_id"));
}

#[test]
fn detects_aws_secret_access_key() {
    let s = OutputSanitizer::new();
    let input = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    assert!(!r
        .sanitized
        .contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
}

#[test]
fn detects_github_token() {
    let s = OutputSanitizer::new();
    let key = format!("ghp_{}", "a".repeat(36));
    let input = format!("GITHUB_TOKEN={key}");
    let r = s.sanitize_text(&input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains(&key));
    assert!(r.findings.iter().any(|f| f.id == "secret_github_token"));
}

#[test]
fn detects_slack_bot_token() {
    let s = OutputSanitizer::new();
    let tok = format!("xoxb-{}", "A".repeat(48));
    let input = format!("slack_token={tok}");
    let r = s.sanitize_text(&input);
    assert!(r.was_redacted, "expected redaction, got {:?}", r.sanitized);
    assert!(!r.sanitized.contains(&tok));
}

#[test]
fn detects_slack_webhook() {
    let s = OutputSanitizer::new();
    let url = "https://hooks.slack.com/services/T00000000/B11111111/XXXXXXXXXXXXXXXXXXXXXXXX";
    let input = format!("webhook: {url}");
    let r = s.sanitize_text(&input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains(url));
}

#[test]
fn detects_gcp_service_account_json() {
    let s = OutputSanitizer::new();
    let input = r#"{"type": "service_account", "project_id": "my-project"}"#;
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    // The default Drop strategy replaces the match with an empty string.
    assert!(!r.sanitized.contains(r#""type": "service_account""#));
}

#[test]
fn detects_gcp_service_account_object_through_pipeline() {
    let s = OutputSanitizer::new();
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(SanitizerHook::from_sanitizer(s)));

    let response = serde_json::json!({
        "type": "service_account",
        "project_id": "my-project",
        "client_email": "svc@example.com"
    });

    let outcome = pipeline.evaluate_with_evidence("tool", &response);
    match outcome.verdict {
        PostInvocationVerdict::Redact(v) => {
            assert!(v.is_null());
        }
        other => panic!("expected Redact, got {other:?}"),
    }
    assert_eq!(outcome.evidence.len(), 1);
    assert_eq!(outcome.evidence[0].guard_name, "output-sanitizer");
    assert!(outcome.evidence[0]
        .details
        .as_deref()
        .unwrap_or("")
        .contains("secret_gcp_service_account"));
}

#[test]
fn detects_password_assignment() {
    let s = OutputSanitizer::new();
    let input = "config: password=hunter2hunter2";
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("hunter2hunter2"));
}

#[test]
fn detects_pem_private_key() {
    let s = OutputSanitizer::new();
    let input = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...redacted...
-----END RSA PRIVATE KEY-----";
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("MIIEowIBAAKCAQEA"));
    assert!(r.findings.iter().any(|f| f.id == "secret_pem_private_key"));
}

#[test]
fn detects_jwt() {
    let s = OutputSanitizer::new();
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let input = format!("bearer token: {jwt}");
    let r = s.sanitize_text(&input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains(jwt));
    assert!(r.findings.iter().any(|f| f.id == "secret_jwt"));
}

#[test]
fn detects_oauth_bearer_header() {
    let s = OutputSanitizer::new();
    let input = "Authorization: Bearer sk_live_abcdefghijklmnopqrstuvwxyz";
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("sk_live_abcdefghijklmnopqrstuvwxyz"));
}

// ---------------------------------------------------------------------------
// PII detectors
// ---------------------------------------------------------------------------

#[test]
fn detects_dashed_ssn() {
    let s = OutputSanitizer::new();
    let r = s.sanitize_text("SSN 123-45-6789");
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("123-45-6789"));
    assert!(r.findings.iter().any(|f| f.id == "pii_ssn"));
}

#[test]
fn rejects_invalid_ssn_area() {
    let s = OutputSanitizer::new();
    // Area 000, 666, and 900-999 are invalid SSN areas -- the validator
    // should reject them so the dashed pattern doesn't flag them.
    let r = s.sanitize_text("SSN 000-12-3456");
    // The compact 9-digit detector can fire depending on surrounding context;
    // this case only needs to prove the dashed-SSN validator rejected the
    // invalid area.
    assert!(!r.findings.iter().any(|f| f.id == "pii_ssn"));
}

#[test]
fn detects_credit_card_with_luhn() {
    let s = OutputSanitizer::new();
    let r = s.sanitize_text("card: 4111 1111 1111 1111");
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("4111 1111 1111 1111"));
    assert!(r.findings.iter().any(|f| f.id == "pii_credit_card"));
}

#[test]
fn rejects_random_16_digit_number() {
    // Random 16-digit number that doesn't pass Luhn -- must NOT be flagged
    // as a credit card.
    let s = OutputSanitizer::new();
    let r = s.sanitize_text("order #1234567890123456");
    assert!(!r.findings.iter().any(|f| f.id == "pii_credit_card"));
}

#[test]
fn rejects_repeated_digit_16() {
    // "1111 1111 1111 1111" passes the naive Luhn check trivially. Our
    // implementation rejects all-same-digit strings on purpose.
    let s = OutputSanitizer::new();
    let r = s.sanitize_text("card: 1111 1111 1111 1111");
    assert!(!r.findings.iter().any(|f| f.id == "pii_credit_card"));
}

#[test]
fn detects_email() {
    let s = OutputSanitizer::new();
    let r = s.sanitize_text("Contact alice@example.com please");
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("alice@example.com"));
    assert!(r.findings.iter().any(|f| f.id == "pii_email"));
}

#[test]
fn detects_internal_private_ip() {
    let s = OutputSanitizer::new();
    let r = s.sanitize_text("upstream: 10.1.2.3");
    assert!(r.was_redacted);
    assert_eq!(r.sanitized, "upstream: [REDACTED:internal]");
    assert!(!r.sanitized.ends_with(".3"));
}

// ---------------------------------------------------------------------------
// High-entropy detector
// ---------------------------------------------------------------------------

#[test]
fn detects_high_entropy_token() {
    let s = OutputSanitizer::new();
    // 44-char base64-ish token with decent entropy.
    let tok = "aB3dEfGh7JklmNopQrStUvWxYz012345abcdEfGhijKl";
    let input = format!("opaque: {tok}");
    let r = s.sanitize_text(&input);
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains(tok));
    assert!(r
        .findings
        .iter()
        .any(|f| f.id == "secret_high_entropy_token"));
}

#[test]
fn low_entropy_token_not_flagged() {
    let s = OutputSanitizer::new();
    // Low-entropy run: all the same character after the prefix. Below the
    // 4.5-bit threshold.
    let input = "token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let r = s.sanitize_text(input);
    assert!(!r
        .findings
        .iter()
        .any(|f| f.id == "secret_high_entropy_token"));
}

#[test]
fn entropy_threshold_configurable() {
    // Lower threshold: lower-entropy tokens get flagged.
    let cfg = OutputSanitizerConfig {
        entropy: EntropyConfig {
            enabled: true,
            threshold: 1.0,
            min_token_len: 16,
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let r = s.sanitize_text("aaaabbbbccccddddeeeeffff");
    assert!(r.was_redacted);
}

// ---------------------------------------------------------------------------
// Allowlist / denylist
// ---------------------------------------------------------------------------

#[test]
fn allowlist_exact_suppresses_redaction() {
    let cfg = OutputSanitizerConfig {
        allowlist: AllowlistConfig {
            exact: vec!["alice@example.com".to_string()],
            patterns: vec![],
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let r = s.sanitize_text("alice@example.com");
    assert!(!r.was_redacted);
    assert_eq!(r.sanitized, "alice@example.com");
}

#[test]
fn allowlist_pattern_suppresses_redaction() {
    let cfg = OutputSanitizerConfig {
        allowlist: AllowlistConfig {
            exact: vec![],
            patterns: vec![r"@example\.com$".to_string()],
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let r = s.sanitize_text("bob@example.com");
    assert!(!r.was_redacted);
    assert_eq!(r.sanitized, "bob@example.com");
}

#[test]
fn denylist_exact_forces_redaction() {
    let cfg = OutputSanitizerConfig {
        denylist: DenylistConfig {
            exact: vec!["CONFIDENTIAL_TAG".to_string()],
            patterns: vec![],
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let r = s.sanitize_text("this message is CONFIDENTIAL_TAG bye");
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("CONFIDENTIAL_TAG"));
}

#[test]
fn denylist_pattern_forces_redaction() {
    let cfg = OutputSanitizerConfig {
        denylist: DenylistConfig {
            exact: vec![],
            patterns: vec![r"internal-[a-z]{6}".to_string()],
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let r = s.sanitize_text("code: internal-abcdef");
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("internal-abcdef"));
}

#[test]
fn denylist_exact_cannot_be_downgraded_by_secret_keep_default() {
    let mut strategies = HashMap::new();
    strategies.insert(SensitiveCategory::Secret, RedactionStrategy::Keep);
    strategies.insert(SensitiveCategory::Pii, RedactionStrategy::Keep);
    strategies.insert(SensitiveCategory::Internal, RedactionStrategy::Keep);
    let cfg = OutputSanitizerConfig {
        redaction_strategies: strategies,
        denylist: DenylistConfig {
            exact: vec!["CONFIDENTIAL_TAG".to_string()],
            patterns: vec![],
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let r = s.sanitize_text("this message is CONFIDENTIAL_TAG bye");
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("CONFIDENTIAL_TAG"));
    assert_eq!(r.redactions[0].strategy, RedactionStrategy::Mask);
}

#[test]
fn denylist_pattern_cannot_be_downgraded_by_secret_keep_default() {
    let mut strategies = HashMap::new();
    strategies.insert(SensitiveCategory::Secret, RedactionStrategy::Keep);
    strategies.insert(SensitiveCategory::Pii, RedactionStrategy::Keep);
    strategies.insert(SensitiveCategory::Internal, RedactionStrategy::Keep);
    let cfg = OutputSanitizerConfig {
        redaction_strategies: strategies,
        denylist: DenylistConfig {
            exact: vec![],
            patterns: vec![r"internal-[a-z]{6}".to_string()],
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let r = s.sanitize_text("code: internal-abcdef");
    assert!(r.was_redacted);
    assert!(!r.sanitized.contains("internal-abcdef"));
    assert_eq!(r.redactions[0].strategy, RedactionStrategy::Mask);
}

// ---------------------------------------------------------------------------
// Overlap resolution
// ---------------------------------------------------------------------------

#[test]
fn overlap_only_one_redaction_per_region() {
    // Put an AWS key inside a high-entropy-eligible string. The entropy
    // detector would also fire, but we must only get one redaction per
    // region (not two concatenated replacements).
    let s = OutputSanitizer::new();
    let input = "AKIAIOSFODNN7EXAMPLE";
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    // Should produce exactly one redaction covering the AWS key region.
    assert_eq!(r.redactions.len(), 1);
    // AWS key detector is stronger -- make sure the output is the AWS mask,
    // not the entropy placeholder-plus-aws double-write.
    assert_eq!(r.sanitized, "****");
}

#[test]
fn overlap_prefers_stronger_strategy() {
    // Custom overlapping denylist pattern at the same region as the AWS
    // detector. Strategy rank: denylist default is Mask; AWS detector asks
    // for Mask too, but the config override can elevate one. Verify the
    // final output contains exactly one replacement and doesn't leak the
    // raw key.
    let cfg = OutputSanitizerConfig {
        denylist: DenylistConfig {
            exact: vec![],
            patterns: vec![r"AKIA[0-9A-Z]{10,}".to_string()],
        },
        ..Default::default()
    };
    let s = sanitizer_with_config(cfg);
    let input = "AKIAIOSFODNN7EXAMPLE";
    let r = s.sanitize_text(input);
    assert!(r.was_redacted);
    assert_eq!(r.redactions.len(), 1);
    assert!(!r.sanitized.contains("AKIA"));
}

// ---------------------------------------------------------------------------
// Redaction strategies
// ---------------------------------------------------------------------------

fn sanitizer_with_secret_strategy(strategy: RedactionStrategy) -> OutputSanitizer {
    let mut strategies: HashMap<SensitiveCategory, RedactionStrategy> = HashMap::new();
    strategies.insert(SensitiveCategory::Secret, strategy);
    strategies.insert(SensitiveCategory::Pii, RedactionStrategy::Mask);
    strategies.insert(SensitiveCategory::Internal, RedactionStrategy::TypeLabel);
    let cfg = OutputSanitizerConfig {
        redaction_strategies: strategies,
        ..Default::default()
    };
    sanitizer_with_config(cfg)
}

#[test]
fn invalid_denylist_regex_is_rejected() {
    let cfg = OutputSanitizerConfig {
        denylist: DenylistConfig {
            exact: vec![],
            patterns: vec!["(".to_string()],
        },
        ..Default::default()
    };

    match OutputSanitizer::with_config(cfg) {
        Ok(_) => panic!("expected invalid denylist regex to be rejected"),
        Err(OutputSanitizerConfigError::InvalidPattern {
            list_name, pattern, ..
        }) => {
            assert_eq!(list_name, "denylist");
            assert_eq!(pattern, "(");
        }
    }
}

#[test]
fn strategy_mask_replaces_with_stars() {
    let s = sanitizer_with_secret_strategy(RedactionStrategy::Mask);
    let key = format!("ghp_{}", "a".repeat(36));
    let r = s.sanitize_text(&key);
    assert_eq!(r.sanitized, "****");
}

#[test]
fn strategy_fingerprint_replaces_with_hash() {
    let s = sanitizer_with_secret_strategy(RedactionStrategy::Fingerprint);
    let key = format!("ghp_{}", "a".repeat(36));
    let r = s.sanitize_text(&key);
    assert!(r.sanitized.starts_with("[FP:"));
    assert!(r.sanitized.ends_with(']'));
    // Same input yields same fingerprint.
    let r2 = s.sanitize_text(&key);
    assert_eq!(r.sanitized, r2.sanitized);
}

#[test]
fn strategy_drop_empties_string() {
    let s = sanitizer_with_secret_strategy(RedactionStrategy::Drop);
    let key = format!("ghp_{}", "a".repeat(36));
    let r = s.sanitize_text(&key);
    assert_eq!(r.sanitized, "");
}

#[test]
fn strategy_drop_collapses_field_to_null_in_json() {
    let s = sanitizer_with_secret_strategy(RedactionStrategy::Drop);
    let key = format!("ghp_{}", "a".repeat(36));
    let response = serde_json::json!({"token": key, "other": "clean"});
    let sv = s.sanitize_value(&response);
    assert!(sv.was_redacted);
    assert_eq!(sv.value["token"], serde_json::Value::Null);
    assert_eq!(
        sv.value["other"],
        serde_json::Value::String("clean".to_string())
    );
}

#[test]
fn strategy_tokenize_records_mapping() {
    let s = sanitizer_with_secret_strategy(RedactionStrategy::Tokenize);
    let key = format!("ghp_{}", "a".repeat(36));
    let r = s.sanitize_text(&key);
    assert!(r.sanitized.starts_with("[TOKEN:tok_"));
    assert!(r.sanitized.ends_with(']'));
    // Verify the vault contains the mapping.
    let vault = s.token_vault();
    // Extract token id from "[TOKEN:tok_...]".
    let id = r
        .sanitized
        .trim_start_matches("[TOKEN:")
        .trim_end_matches(']');
    let retrieved = vault.get(id).expect("token vault contains mapping");
    assert_eq!(retrieved, key);
}

#[test]
fn strategy_type_label_uses_data_type() {
    let s = sanitizer_with_secret_strategy(RedactionStrategy::TypeLabel);
    let key = format!("ghp_{}", "a".repeat(36));
    let r = s.sanitize_text(&key);
    assert!(
        r.sanitized.contains("[REDACTED:github_token]"),
        "got {}",
        r.sanitized
    );
}

#[test]
fn strategy_partial_keeps_prefix_suffix() {
    let s = sanitizer_with_secret_strategy(RedactionStrategy::Partial);
    let key = format!("ghp_{}", "a".repeat(36));
    let r = s.sanitize_text(&key);
    assert!(r.sanitized.starts_with("gh"));
    assert!(r.sanitized.ends_with("aa"));
    assert!(r.sanitized.contains("***"));
}

// ---------------------------------------------------------------------------
// JSON round-trip: structure is preserved.
// ---------------------------------------------------------------------------

#[test]
fn sanitize_value_preserves_json_structure() {
    let s = OutputSanitizer::new();
    let input = serde_json::json!({
        "ok": true,
        "nested": {
            "email": "alice@example.com",
            "items": [
                {"token": format!("ghp_{}", "a".repeat(36))},
                {"clean": "nothing"},
            ],
        },
        "numeric": 42,
    });
    let sv = s.sanitize_value(&input);
    assert!(sv.was_redacted);

    // Top-level keys preserved.
    assert!(sv.value.as_object().unwrap().contains_key("ok"));
    assert!(sv.value.as_object().unwrap().contains_key("nested"));
    assert!(sv.value.as_object().unwrap().contains_key("numeric"));

    // Numeric leaves untouched.
    assert_eq!(sv.value["numeric"], serde_json::json!(42));
    assert_eq!(sv.value["ok"], serde_json::json!(true));

    // Array has same length.
    let items = sv.value["nested"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[1], serde_json::json!({"clean": "nothing"}));

    // Raw secrets gone.
    let rendered = sv.value.to_string();
    assert!(!rendered.contains("alice@example.com"));
    assert!(!rendered.contains("ghp_aaaaaaaa"));

    // Round-trips through serde_json.
    let serialized = serde_json::to_string(&sv.value).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(reparsed, sv.value);
}

// ---------------------------------------------------------------------------
// Evidence emission through the post-invocation pipeline.
// ---------------------------------------------------------------------------

#[test]
fn sanitizer_hook_clean_response_no_evidence() {
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(SanitizerHook::new()));

    let response = serde_json::json!({"status": "ok"});
    let outcome = pipeline.evaluate_with_evidence("tool", &response);
    assert!(matches!(outcome.verdict, PostInvocationVerdict::Allow));
    assert!(outcome.evidence.is_empty());
}

#[test]
fn sanitizer_hook_dirty_response_emits_evidence() {
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(SanitizerHook::new()));

    let response = serde_json::json!({
        "summary": "Hello alice@example.com",
        "aws_key": "AKIAIOSFODNN7EXAMPLE",
    });
    let outcome = pipeline.evaluate_with_evidence("tool", &response);

    match &outcome.verdict {
        PostInvocationVerdict::Redact(v) => {
            let rendered = v.to_string();
            assert!(!rendered.contains("alice@example.com"));
            assert!(!rendered.contains("AKIAIOSFODNN7EXAMPLE"));
        }
        other => panic!("expected Redact, got {other:?}"),
    }

    assert_eq!(outcome.evidence.len(), 1);
    let ev = &outcome.evidence[0];
    assert_eq!(ev.guard_name, "output-sanitizer");
    assert!(ev.verdict);
    let details = ev.details.as_deref().unwrap_or("");
    // Evidence mentions detector ids so operators know what fired.
    assert!(details.contains("pii_email"), "got: {details}");
    assert!(
        details.contains("secret_aws_access_key_id"),
        "got: {details}"
    );
    // But not the raw secrets themselves.
    assert!(!details.contains("alice@example.com"));
    assert!(!details.contains("AKIAIOSFODNN7EXAMPLE"));
}

// ---------------------------------------------------------------------------
// sanitize_json helper
// ---------------------------------------------------------------------------

#[test]
fn sanitize_json_helper_aggregates_findings() {
    let s = OutputSanitizer::new();
    let input = serde_json::json!({
        "email": "alice@example.com",
        "nested": {"key": format!("ghp_{}", "a".repeat(36))},
    });
    let (value, result) = sanitize_json(&s, &input);
    assert!(result.was_redacted);
    assert!(result.findings.len() >= 2);

    let rendered = value.to_string();
    assert!(!rendered.contains("alice@example.com"));
    assert!(!rendered.contains("ghp_aaaaaa"));
}

#[test]
fn sanitize_json_helper_omits_object_findings_when_configured() {
    let s = sanitizer_with_config(OutputSanitizerConfig {
        include_findings: false,
        ..Default::default()
    });
    let input = serde_json::json!({
        "type": "service_account",
        "project_id": "my-project",
    });
    let (value, result) = sanitize_json(&s, &input);

    assert!(result.was_redacted);
    assert_eq!(value, serde_json::Value::Null);
    assert!(result.findings.is_empty());
    assert!(!result.redactions.is_empty());
}

// ---------------------------------------------------------------------------
// Post-invocation guard redaction.
// ---------------------------------------------------------------------------

#[test]
fn acceptance_post_invocation_guard_redacts_everything() {
    // The post-invocation guard redacts SSNs, credit cards (Luhn-validated),
    // API keys, and high-entropy strings from tool results.
    let mut pipeline = PostInvocationPipeline::new();
    pipeline.add(Box::new(SanitizerHook::new()));

    let response = serde_json::json!({
        "ssn": "123-45-6789",
        "card": "4111 1111 1111 1111",
        "api_key": "AKIAIOSFODNN7EXAMPLE",
        "opaque": "aB3dEfGh7JklmNopQrStUvWxYz012345abcdEfGh",
    });
    let outcome = pipeline.evaluate_with_evidence("tool", &response);

    match &outcome.verdict {
        PostInvocationVerdict::Redact(v) => {
            let rendered = v.to_string();
            assert!(!rendered.contains("123-45-6789"));
            assert!(!rendered.contains("4111 1111 1111 1111"));
            assert!(!rendered.contains("AKIAIOSFODNN7EXAMPLE"));
            assert!(!rendered.contains("aB3dEfGh7JklmNopQrStUvWxYz012345abcdEfGh"));
        }
        other => panic!("expected Redact, got {other:?}"),
    }
}
