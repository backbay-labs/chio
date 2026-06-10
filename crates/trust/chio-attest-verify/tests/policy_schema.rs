#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Structural-validation coverage for the per-tenant policy schema. Tests
//! live outside `src/` because the crate root forbids `unwrap_used` and
//! `expect_used` at the lint level.

use std::time::{Duration, SystemTime};

use chio_attest_verify::policy::{
    TenantPolicy, MAX_IDENTITY_REGEXPS, MAX_IDENTITY_REGEXP_BYTES, MAX_OIDC_ISSUERS,
    MAX_OIDC_ISSUER_BYTES, MAX_POLICY_SIGNATURE_BYTES, MAX_PQ_IDENTITY_REGEXPS,
    MAX_TENANT_POLICY_BYTES,
};
use chio_attest_verify::{AttestError, TENANT_POLICY_SCHEMA_VERSION};

fn sample_toml() -> &'static str {
    r#"
tenant_id = "acme"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#
}

fn assert_malformed_contains(err: AttestError, needle: &str) {
    let (is_malformed, message) = match err {
        AttestError::Malformed(message) => (true, message),
        other => (false, format!("{other:?}")),
    };

    assert!(
        is_malformed && message.contains(needle),
        "expected Malformed containing {needle}, got: {message}"
    );
}

#[test]
fn parses_minimal_policy() {
    let policy =
        TenantPolicy::from_toml_slice(sample_toml().as_bytes()).expect("sample policy must parse");
    assert_eq!(policy.tenant_id, "acme");
    assert_eq!(policy.version, TENANT_POLICY_SCHEMA_VERSION);
    assert!(policy.pq_identity_regexps.is_empty());
}

#[test]
fn rejects_unknown_field() {
    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = ["x"]
oidc_issuers = ["y"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
typo_field = true
"#;
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    assert!(matches!(err, AttestError::Malformed(_)));
}

#[test]
fn rejects_empty_identity_regexps() {
    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = []
oidc_issuers = ["y"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#;
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => {
            assert!(msg.contains("identity_regexps"), "got: {msg}");
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_blank_or_padded_policy_text_fields() {
    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = [""]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#;
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    assert_malformed_contains(err, "identity_regexp");

    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = [" https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#;
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    assert_malformed_contains(err, "oidc_issuer");
}

#[test]
fn rejects_oversized_policy_bytes_before_parse() {
    let bytes = vec![b'a'; MAX_TENANT_POLICY_BYTES + 1];
    let err = TenantPolicy::from_toml_slice(&bytes).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("exceeding"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_too_many_identity_regexps() {
    let regexps = (0..=MAX_IDENTITY_REGEXPS)
        .map(|i| format!("\"https://example.com/{i}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
tenant_id = "acme"
version = 1
identity_regexps = [{regexps}]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#
    );
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("identity_regexps"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_oversized_identity_regexp() {
    let pattern = "a".repeat(MAX_IDENTITY_REGEXP_BYTES + 1);
    let toml = format!(
        r#"
tenant_id = "acme"
version = 1
identity_regexps = ["{pattern}"]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#
    );
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("identity_regexp"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_too_many_or_oversized_issuers() {
    let issuers = (0..=MAX_OIDC_ISSUERS)
        .map(|i| format!("\"https://issuer{i}.example.com\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
tenant_id = "acme"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = [{issuers}]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#
    );
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("oidc_issuers"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }

    let issuer = format!("https://{}.example.com", "a".repeat(MAX_OIDC_ISSUER_BYTES));
    let toml = format!(
        r#"
tenant_id = "acme"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = ["{issuer}"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#
    );
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("oidc_issuer"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_oversized_signature_and_pq_regexps() {
    let signature = "A".repeat(MAX_POLICY_SIGNATURE_BYTES + 1);
    let toml = format!(
        r#"
tenant_id = "acme"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "{signature}"
"#
    );
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("signature"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }

    let pq_regexps = (0..=MAX_PQ_IDENTITY_REGEXPS)
        .map(|i| format!("\"pq:{i}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
tenant_id = "acme"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
pq_identity_regexps = [{pq_regexps}]
"#
    );
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("pq_identity_regexps"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_unsupported_version() {
    let toml = r#"
tenant_id = "acme"
version = 999
identity_regexps = ["x"]
oidc_issuers = ["y"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#;
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("version"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rejects_uncompilable_regex() {
    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = ["[unterminated"]
oidc_issuers = ["y"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#;
    let err = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("does not compile"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn canonical_bytes_excludes_signature() {
    let policy = TenantPolicy::from_toml_slice(sample_toml().as_bytes()).unwrap();
    let bytes = policy.canonical_signing_bytes().unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(
        !s.contains("signature"),
        "canonical form must omit signature: {s}"
    );
    assert!(s.contains("tenant_id"));
    assert_eq!(
        s,
        r#"{"identity_regexps":["https://github\\.com/acme/.*"],"oidc_issuers":["https://token.actions.githubusercontent.com"],"pq_identity_regexps":[],"signed_at":"2026-04-01T00:00:00Z","tenant_id":"acme","version":1}"#
    );
}

#[test]
fn signed_at_round_trips() {
    let policy = TenantPolicy::from_toml_slice(sample_toml().as_bytes()).unwrap();
    // Anchor "now" well past the signed_at timestamp so the future check passes.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    let parsed = policy.signed_at_system_time(now).unwrap();
    // 2026-04-01T00:00:00Z = 1_775_001_600 unix seconds.
    let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(1_775_001_600);
    assert_eq!(parsed, expected);
}

#[test]
fn signed_at_in_future_rejected() {
    let policy = TenantPolicy::from_toml_slice(sample_toml().as_bytes()).unwrap();
    // "now" anchored before 2026-04-01.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    let err = policy.signed_at_system_time(now).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("future"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn signed_at_malformed_rejected() {
    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = ["x"]
oidc_issuers = ["y"]
signed_at = "yesterday"
signature = "AAAA"
"#;
    let policy = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    let err = policy.signed_at_system_time(now).unwrap_err();
    assert!(matches!(err, AttestError::Malformed(_)));
}

#[test]
fn signed_at_rejects_impossible_calendar_dates() {
    for signed_at in [
        "2026-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-00-01T00:00:00Z",
    ] {
        let toml = format!(
            r#"
tenant_id = "acme"
version = 1
identity_regexps = ["x"]
oidc_issuers = ["y"]
signed_at = "{signed_at}"
signature = "AAAA"
"#
        );
        let policy = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let err = policy.signed_at_system_time(now).unwrap_err();
        assert!(
            matches!(err, AttestError::Malformed(_)),
            "{signed_at} must be rejected"
        );
    }
}

#[test]
fn signed_at_accepts_leap_day_in_leap_year() {
    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = ["x"]
oidc_issuers = ["y"]
signed_at = "2024-02-29T00:00:00Z"
signature = "AAAA"
"#;
    let policy = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    policy
        .signed_at_system_time(now)
        .expect("leap day in a leap year must parse");
}

#[test]
fn pq_identity_regexps_round_trip_when_present() {
    let toml = r#"
tenant_id = "acme"
version = 1
identity_regexps = ["x"]
oidc_issuers = ["y"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
pq_identity_regexps = ["pq:.*"]
"#;
    let policy = TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap();
    assert_eq!(policy.pq_identity_regexps, vec!["pq:.*".to_owned()]);
}
