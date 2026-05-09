#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Coverage for [`TenantPolicyResolver`] and [`StaticTenantPolicyMap`].
//! Demonstrates the production migration: callers resolve a tenant
//! identifier into an `ExpectedIdentity` rather than constructing one
//! inline.

use chio_attest_verify::policy::TenantPolicy;
use chio_attest_verify::{AttestError, StaticTenantPolicyMap, TenantPolicyResolver};

fn parse(toml: &str) -> TenantPolicy {
    TenantPolicy::from_toml_slice(toml.as_bytes()).unwrap()
}

fn acme_policy() -> TenantPolicy {
    parse(
        r#"
tenant_id = "acme"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "AAAA"
"#,
    )
}

fn beta_policy() -> TenantPolicy {
    parse(
        r#"
tenant_id = "beta"
version = 1
identity_regexps = ["https://gitlab\\.com/beta/.*"]
oidc_issuers = ["https://gitlab.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "BBBB"
"#,
    )
}

fn multi_regex_policy() -> TenantPolicy {
    parse(
        r#"
tenant_id = "multi-regex"
version = 1
identity_regexps = ["https://github\\.com/acme/.*", "https://gitlab\\.com/acme/.*"]
oidc_issuers = ["https://token.actions.githubusercontent.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "CCCC"
"#,
    )
}

fn multi_issuer_policy() -> TenantPolicy {
    parse(
        r#"
tenant_id = "multi-issuer"
version = 1
identity_regexps = ["https://github\\.com/acme/.*"]
oidc_issuers = ["https://token.actions.githubusercontent.com", "https://gitlab.com"]
signed_at = "2026-04-01T00:00:00Z"
signature = "DDDD"
"#,
    )
}

#[test]
fn resolves_known_tenant_to_regex_and_issuer() {
    let map = StaticTenantPolicyMap::from_verified(vec![acme_policy(), beta_policy()]).unwrap();
    let acme = map.expected_for_tenant("acme").unwrap();
    assert_eq!(
        acme.certificate_identity_regexp,
        r"https://github\.com/acme/.*"
    );
    assert_eq!(
        acme.certificate_oidc_issuer,
        "https://token.actions.githubusercontent.com"
    );
    let beta = map.expected_for_tenant("beta").unwrap();
    assert_eq!(
        beta.certificate_identity_regexp,
        r"https://gitlab\.com/beta/.*"
    );
    assert_eq!(beta.certificate_oidc_issuer, "https://gitlab.com");
}

#[test]
fn composes_multiple_identity_regexps() {
    let map = StaticTenantPolicyMap::from_verified(vec![multi_regex_policy()]).unwrap();
    let expected = map.expected_for_tenant("multi-regex").unwrap();
    assert_eq!(
        expected.certificate_identity_regexp,
        r"(?:https://github\.com/acme/.*)|(?:https://gitlab\.com/acme/.*)"
    );
    assert_eq!(
        expected.certificate_oidc_issuer,
        "https://token.actions.githubusercontent.com"
    );
}

#[test]
fn rejects_multiple_oidc_issuers_in_static_map() {
    let err = StaticTenantPolicyMap::from_verified(vec![multi_issuer_policy()]).unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("exactly one"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn unknown_tenant_fails_closed() {
    let map = StaticTenantPolicyMap::from_verified(vec![acme_policy()]).unwrap();
    let err = map.expected_for_tenant("ghost").unwrap_err();
    match err {
        AttestError::Malformed(msg) => assert!(msg.contains("ghost"), "got: {msg}"),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn duplicate_tenant_id_rejected() {
    let dup = StaticTenantPolicyMap::from_verified(vec![acme_policy(), acme_policy()]);
    match dup {
        Err(AttestError::Malformed(msg)) => assert!(msg.contains("duplicate"), "got: {msg}"),
        other => panic!("expected duplicate-tenant error, got {other:?}"),
    }
}

#[test]
fn empty_map_is_empty() {
    let map = StaticTenantPolicyMap::from_verified(vec![]).unwrap();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
    assert!(map.expected_for_tenant("anyone").is_err());
}

#[test]
fn populated_map_reports_len_and_is_not_empty() {
    // Kills:
    // - replace StaticTenantPolicyMap::is_empty -> bool with true
    //   (lib.rs:176): a populated map's is_empty() MUST be false.
    // - replace StaticTenantPolicyMap::len -> usize with 0 (lib.rs:170):
    //   a populated map's len() MUST equal the number of inserted
    //   policies, not zero.
    let single = StaticTenantPolicyMap::from_verified(vec![acme_policy()]).unwrap();
    assert_eq!(
        single.len(),
        1,
        "single-entry map must report len 1; mutant `len -> 0` would fail"
    );
    assert!(
        !single.is_empty(),
        "single-entry map must NOT be empty; mutant `is_empty -> true` would fail"
    );

    let pair = StaticTenantPolicyMap::from_verified(vec![acme_policy(), beta_policy()]).unwrap();
    assert_eq!(
        pair.len(),
        2,
        "two-entry map must report len 2; mutant `len -> 0` would fail"
    );
    assert!(
        !pair.is_empty(),
        "two-entry map must NOT be empty; mutant `is_empty -> true` would fail"
    );
}
