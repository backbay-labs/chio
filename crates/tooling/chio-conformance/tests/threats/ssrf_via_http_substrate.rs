//! Threat test for threat ID `ssrf_via_http_substrate` (SSRF via HTTP substrate).
//!
//! Surfaces: hosted_mcp, kernel_to_tool.
//!
//! Production call site: this test imports
//! `chio_http_core::HttpEgressContract` directly and drives the production
//! `enforce_url` and `enforce_attempt` functions with attack inputs that
//! exercise four distinct deny variants of `HttpEgressError`:
//!   - LoopbackDenied (127.0.0.1 SSRF target),
//!   - LinkLocalDenied (169.254.169.254 instance metadata target),
//!   - Ipv6UlaDenied (fd00::/8 internal target),
//!   - RedirectLimitExceeded (chained redirect SSRF),
//!   - ResponseTooLarge (oversized response body amplification).
//!
//! Revert-to-prove-it-fails recipe: flip an early-return guard inside
//! `enforce_url` in `crates/chio-http-core/src/lib.rs` to return
//! `Ok(())` for one of the loopback / link-local / ULA / redirect /
//! body-size checks. The deny-arm assertion that pinned the affected
//! variant fails because the production contract no longer blocks
//! the corresponding SSRF target.

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
