// Threat test for threat ID `audience_confusion` (Audience confusion).
//
// Surfaces: trust_control, native_chio, hosted_mcp.
//
// Coverage strategy: import the production
// `chio_custody_hw::capability::PasskeyCapability::require_audience`
// function directly. Build a capability minted for audience A
// ("urn:chio:audience:kernel"), then drive the production `require_audience`
// fail-closed check by presenting it to a verifier that expects audience B
// ("urn:chio:audience:other"). The production code returns
// `Err(CustodyError::AudienceMismatch { expected, found })` when the
// audiences disagree; this is the deny path that closes audience-confusion
// at the application layer.
//
// Production call site:
// `crates/chio-custody-hw/src/capability.rs:172` (`require_audience`).
//
// Revert-to-prove-it-fails recipe: replace the body of
// `PasskeyCapability::require_audience` in
// `crates/chio-custody-hw/src/capability.rs` with `Ok(())` (drop the
// audience comparison). Both deny-arm assertions below then fail
// because the verifier accepts the cross-audience capability.

use chio_custody_hw::capability::{PasskeyCapability, ScopeSet};
use chio_custody_hw::error::CustodyError;
use chrono::{TimeZone, Utc};

fn fixed_iat() -> chrono::DateTime<Utc> {
    match Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0) {
        chrono::LocalResult::Single(t) => t,
        _ => panic!("fixed_iat fixture must construct"),
    }
}

#[test]
fn threat_audience_confusion_require_audience_rejects_mismatch() {
    // covers: audience_confusion
    //
    // Mint a capability for audience "kernel" and present it to a
    // verifier expecting audience "other". The production
    // `require_audience` call MUST return
    // `CustodyError::AudienceMismatch`.
    let cap = PasskeyCapability::new_stub_unsigned(
        "urn:chio:audience:kernel",
        "AAAA",
        ScopeSet::new(["tool:read"]),
        "nonce-abc",
        fixed_iat(),
    );

    let result = cap.require_audience("urn:chio:audience:other");
    let err = match result {
        Ok(()) => panic!(
            "production require_audience MUST reject when minted audience \
             differs from the verifier-expected audience; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, CustodyError::AudienceMismatch { .. }),
        "expected CustodyError::AudienceMismatch, got {err:?}"
    );

    // Sanity: the matched audience is accepted.
    if let Err(err) = cap.require_audience("urn:chio:audience:kernel") {
        panic!(
            "matched audience MUST verify (otherwise the deny guard \
             is over-rejecting); got {err:?}"
        );
    }
}

#[test]
fn threat_audience_confusion_carries_expected_and_found_audiences() {
    // covers: audience_confusion
    //
    // The `AudienceMismatch` variant carries the verifier-expected and
    // capability-found audiences so an auditor can see the bound
    // identities side-by-side. Pin both fields so a future variant
    // shape change cannot silently drop one of the two values.
    let cap = PasskeyCapability::new_stub_unsigned(
        "urn:chio:audience:tenant-a",
        "AAAA",
        ScopeSet::new(["tool:write"]),
        "nonce-xyz",
        fixed_iat(),
    );

    let err = match cap.require_audience("urn:chio:audience:tenant-b") {
        Ok(()) => panic!("cross-tenant audience MUST reject"),
        Err(err) => err,
    };
    match err {
        CustodyError::AudienceMismatch { expected, found } => {
            assert_eq!(expected, "urn:chio:audience:tenant-b");
            assert_eq!(found, "urn:chio:audience:tenant-a");
        }
        other => panic!(
            "expected CustodyError::AudienceMismatch with both fields, \
             got {other:?}"
        ),
    }
}
