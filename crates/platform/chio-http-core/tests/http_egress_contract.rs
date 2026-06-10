use std::collections::BTreeSet;

use chio_http_core::{HttpEgressContract, HttpEgressError};

fn strict_contract() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-a.prod".to_string(),
        allowed_schemes: BTreeSet::from(["https".to_string()]),
        allowed_authority_set: BTreeSet::from([
            "api.example.com".to_string(),
            "api.example.com:8443".to_string(),
            "127.0.0.1".to_string(),
            "169.254.169.254".to_string(),
            "[fd00::1]".to_string(),
            "[::ffff:127.0.0.1]".to_string(),
        ]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 2,
        max_response_bytes: 4096,
    }
}

#[test]
fn allows_declared_public_authority() {
    let contract = strict_contract();
    let target = match contract.enforce_attempt("https://api.example.com/v1/tools", 1, Some(4096)) {
        Ok(target) => target,
        Err(error) => panic!("public declared authority should pass: {error}"),
    };

    assert_eq!(target.tenant_egress_namespace, "tenant-a.prod");
    assert_eq!(target.scheme, "https");
    assert_eq!(target.authority, "api.example.com");
}

#[test]
fn allows_default_port_authority_entry() {
    let mut contract = strict_contract();
    contract.allowed_authority_set = BTreeSet::from(["api.example.com:443".to_string()]);

    let target = match contract.enforce_attempt("https://api.example.com:443/v1/tools", 0, None) {
        Ok(target) => target,
        Err(error) => panic!("default-port authority should pass: {error}"),
    };

    assert_eq!(target.authority, "api.example.com");
}

#[test]
fn missing_contract_fails_closed() {
    let err = match HttpEgressContract::enforce_required(
        None,
        "https://api.example.com/v1/tools",
        0,
        None,
    ) {
        Ok(_) => panic!("missing contract must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(err, HttpEgressError::MissingContract));
}

#[test]
fn loopback_target_fails_closed_even_when_declared() {
    let contract = strict_contract();
    let err = match contract.enforce_url("https://127.0.0.1/admin", 0) {
        Ok(_) => panic!("loopback target must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(err, HttpEgressError::LoopbackDenied { .. }));
}

#[test]
fn ipv4_mapped_loopback_fails_closed() {
    let contract = strict_contract();
    let err = match contract.enforce_url("https://[::ffff:127.0.0.1]/admin", 0) {
        Ok(_) => panic!("IPv4-mapped loopback target must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(err, HttpEgressError::LoopbackDenied { .. }));
}

#[test]
fn link_local_target_fails_closed_even_when_declared() {
    let contract = strict_contract();
    let err = match contract.enforce_url("https://169.254.169.254/latest/meta-data", 0) {
        Ok(_) => panic!("link-local target must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(err, HttpEgressError::LinkLocalDenied { .. }));
}

#[test]
fn ipv6_ula_target_fails_closed_even_when_declared() {
    let contract = strict_contract();
    let err = match contract.enforce_url("https://[fd00::1]/internal", 0) {
        Ok(_) => panic!("IPv6 ULA target must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(err, HttpEgressError::Ipv6UlaDenied { .. }));
}

#[test]
fn redirect_chain_limit_fails_closed() {
    let contract = strict_contract();
    let err = match contract.enforce_url("https://api.example.com/v1/tools", 3) {
        Ok(_) => panic!("overlong redirect chain must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(
        err,
        HttpEgressError::RedirectLimitExceeded {
            observed: 3,
            max: 2
        }
    ));
}

#[test]
fn oversized_response_fails_closed() {
    let contract = strict_contract();
    let err = match contract.enforce_attempt("https://api.example.com/v1/tools", 0, Some(4097)) {
        Ok(_) => panic!("oversized response must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(
        err,
        HttpEgressError::ResponseTooLarge {
            observed: 4097,
            max: 4096
        }
    ));
}

#[test]
fn undeclared_authority_fails_closed() {
    let contract = strict_contract();
    let err = match contract.enforce_url("https://api.example.com.evil.test/v1/tools", 0) {
        Ok(_) => panic!("undeclared authority must fail closed"),
        Err(error) => error,
    };

    assert!(matches!(err, HttpEgressError::AuthorityDenied { .. }));
}
