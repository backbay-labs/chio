#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Coverage for [`TenantPolicyResolver`] and [`StaticTenantPolicyMap`]
//! (M05.P4.T3). Demonstrates the production migration: callers resolve a
//! tenant identifier into an `ExpectedIdentity` rather than constructing
//! one inline.

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

#[test]
fn resolves_known_tenant_to_first_regex_and_issuer() {
    let map = StaticTenantPolicyMap::from_verified(vec![acme_policy(), beta_policy()]).unwrap();
    let acme = map.expected_for_tenant("acme").unwrap();
    assert_eq!(acme.certificate_identity_regexp, r"https://github\.com/acme/.*");
    assert_eq!(
        acme.certificate_oidc_issuer,
        "https://token.actions.githubusercontent.com"
    );
    let beta = map.expected_for_tenant("beta").unwrap();
    assert_eq!(beta.certificate_identity_regexp, r"https://gitlab\.com/beta/.*");
    assert_eq!(beta.certificate_oidc_issuer, "https://gitlab.com");
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
