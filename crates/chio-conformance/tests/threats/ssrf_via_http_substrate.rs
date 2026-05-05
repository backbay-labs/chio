// DO NOT EDIT - regenerate via 'make regen-rust' or 'cargo xtask codegen rust'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:   typify =0.4.3 (see xtask/codegen-tools.lock.toml)
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration; the
// `_generated_check` integration test enforces this header on every file
// under `crates/chio-core-types/src/_generated/`.

//! Threat test for threat ID `ssrf_via_http_substrate` (SSRF via HTTP substrate).
//!
//! Surfaces: hosted_mcp, kernel_to_tool.
//!
//! Coverage strategy: the TRJ4 HTTP egress contract requires every substrate
//! caller to declare tenant namespace, scheme and authority allowlists,
//! redirect ceiling, response-size ceiling, and address-class denials. This
//! test pins the SSRF negative cases to the shared `chio-http-core` contract
//! so adapters exercise the same fail-closed substrate API.

use std::collections::BTreeSet;

use chio_http_core::{HttpEgressContract, HttpEgressError};

fn contract_for_threat_test() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-a.prod".to_string(),
        allowed_schemes: BTreeSet::from(["https".to_string()]),
        allowed_authority_set: BTreeSet::from([
            "api.example.com".to_string(),
            "127.0.0.1".to_string(),
            "169.254.169.254".to_string(),
            "[fd00::1]".to_string(),
        ]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 1024,
    }
}

fn denied(
    result: Result<chio_http_core::ValidatedHttpEgressTarget, HttpEgressError>,
) -> HttpEgressError {
    match result {
        Ok(target) => panic!("target should have been denied: {target:?}"),
        Err(error) => error,
    }
}

#[test]
fn threat_ssrf_via_http_substrate_is_covered() {
    // covers: ssrf_via_http_substrate
    let contract = contract_for_threat_test();

    assert!(matches!(
        denied(contract.enforce_url("https://127.0.0.1/admin", 0)),
        HttpEgressError::LoopbackDenied { .. }
    ));
    assert!(matches!(
        denied(contract.enforce_url("https://169.254.169.254/latest/meta-data", 0)),
        HttpEgressError::LinkLocalDenied { .. }
    ));
    assert!(matches!(
        denied(contract.enforce_url("https://[fd00::1]/internal", 0)),
        HttpEgressError::Ipv6UlaDenied { .. }
    ));
    assert!(matches!(
        denied(contract.enforce_url("https://api.example.com/redirect", 2)),
        HttpEgressError::RedirectLimitExceeded {
            observed: 2,
            max: 1
        }
    ));
    assert!(matches!(
        denied(contract.enforce_attempt("https://api.example.com/data", 0, Some(1025))),
        HttpEgressError::ResponseTooLarge {
            observed: 1025,
            max: 1024
        }
    ));
}
