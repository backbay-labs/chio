//! Load-time validation tests for `policy.crypto_floor`.
//!
//! `crypto_floor` is the kernel-side knob that selects the minimum
//! cryptographic posture for signed Chio artifacts. Invalid combinations
//! (`allow_hybrid` or `pq_required` with no PQ key provisioned) MUST reject
//! at load time, before the kernel accepts traffic. This file pins that
//! contract.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_policy::{CryptoFloor, CryptoFloorLoadError};

#[test]
fn allow_classical_loads_without_pq_key() {
    // Default deployments (no PQ key provisioned) MUST load successfully
    // under `allow_classical`.
    assert!(CryptoFloor::AllowClassical
        .validate_with_pq_key(false)
        .is_ok());
}

#[test]
fn allow_classical_loads_with_pq_key() {
    // Operators who provision a PQ key but keep the floor at
    // `allow_classical` are allowed (e.g. mid-rollout dual-write before
    // flipping to `allow_hybrid`).
    assert!(CryptoFloor::AllowClassical
        .validate_with_pq_key(true)
        .is_ok());
}

#[test]
fn allow_hybrid_without_pq_key_rejects_at_load() {
    let err = CryptoFloor::AllowHybrid
        .validate_with_pq_key(false)
        .expect_err("allow_hybrid without PQ key must fail at load");
    assert_eq!(
        err,
        CryptoFloorLoadError::HybridFloorRequiresPqKey {
            floor: CryptoFloor::AllowHybrid,
        }
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("allow_hybrid"),
        "error message must name the floor: {rendered}"
    );
    assert!(
        rendered.contains("post-quantum"),
        "error message must explain why: {rendered}"
    );
}

#[test]
fn allow_hybrid_with_pq_key_loads() {
    assert!(CryptoFloor::AllowHybrid.validate_with_pq_key(true).is_ok());
}

#[test]
fn pq_required_without_pq_key_rejects_at_load() {
    let err = CryptoFloor::PqRequired
        .validate_with_pq_key(false)
        .expect_err("pq_required without PQ key must fail at load");
    assert_eq!(
        err,
        CryptoFloorLoadError::HybridFloorRequiresPqKey {
            floor: CryptoFloor::PqRequired,
        }
    );
    let rendered = err.to_string();
    assert!(
        rendered.contains("pq_required"),
        "error message must name the floor: {rendered}"
    );
}

#[test]
fn pq_required_with_pq_key_loads() {
    assert!(CryptoFloor::PqRequired.validate_with_pq_key(true).is_ok());
}

#[test]
fn yaml_round_trip_each_variant() {
    for (variant, expected) in [
        (CryptoFloor::AllowClassical, "allow_classical"),
        (CryptoFloor::AllowHybrid, "allow_hybrid"),
        (CryptoFloor::PqRequired, "pq_required"),
    ] {
        let yaml = serde_yml::to_string(&variant).unwrap();
        assert!(
            yaml.contains(expected),
            "variant {variant:?} should serialize to {expected}, got {yaml}"
        );
        let yaml_quoted = format!("\"{expected}\"\n");
        let parsed: CryptoFloor = serde_yml::from_str(&yaml_quoted).unwrap();
        assert_eq!(parsed, variant);
    }
}

#[test]
fn unknown_string_rejected_at_parse() {
    // Unknown floor strings must fail at parse rather than silently
    // defaulting to `allow_classical`. Threat model row
    // `pq_signature_downgrade` depends on this.
    let result: Result<CryptoFloor, _> = serde_yml::from_str("\"none\"");
    assert!(
        result.is_err(),
        "unknown crypto_floor variant must reject at parse"
    );
}

#[test]
fn helper_predicates_match_state_table() {
    assert!(CryptoFloor::AllowClassical.allows_classical_only());
    assert!(!CryptoFloor::AllowClassical.allows_hybrid());
    assert!(!CryptoFloor::AllowClassical.requires_pq());

    assert!(CryptoFloor::AllowHybrid.allows_classical_only());
    assert!(CryptoFloor::AllowHybrid.allows_hybrid());
    assert!(!CryptoFloor::AllowHybrid.requires_pq());

    assert!(!CryptoFloor::PqRequired.allows_classical_only());
    assert!(CryptoFloor::PqRequired.allows_hybrid());
    assert!(CryptoFloor::PqRequired.requires_pq());
}
