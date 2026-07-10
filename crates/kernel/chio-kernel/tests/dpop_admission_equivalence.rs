use std::time::Duration;

use chio_kernel::dpop::{dpop_freshness_admits, DpopConfig, DpopNonceStore};
use chio_kernel_core::{dpop_admits, dpop_freshness_valid, dpop_verification_admits, nonce_admits};
use proptest::prelude::*;

use chio_test_support::prelude::*;

proptest! {
    #[test]
    fn freshness_projection_calls_verified_boundary(
        now in any::<u64>(),
        issued_at in any::<u64>(),
        ttl_secs in any::<u64>(),
        max_skew_secs in any::<u64>(),
    ) {
        let config = DpopConfig {
            proof_ttl_secs: ttl_secs,
            max_clock_skew_secs: max_skew_secs,
            nonce_store_capacity: 8,
        };

        prop_assert_eq!(
            dpop_freshness_admits(now, issued_at, &config),
            dpop_freshness_valid(now, issued_at, ttl_secs, max_skew_secs),
        );
    }

    #[test]
    fn requirement_fold_matches_runtime_control_flow(
        dpop_required in any::<bool>(),
        proof_present in any::<bool>(),
        proof_valid in any::<bool>(),
        nonce_fresh in any::<bool>(),
    ) {
        let runtime_decision = if dpop_required {
            proof_present && proof_valid && nonce_fresh
        } else {
            true
        };

        prop_assert_eq!(
            dpop_admits(dpop_required, proof_present, proof_valid, nonce_fresh),
            runtime_decision,
        );
    }

    #[test]
    fn atomic_verifier_projection_calls_four_axis_model(
        dpop_required in any::<bool>(),
        proof_present in any::<bool>(),
        verification_succeeded in any::<bool>(),
    ) {
        prop_assert_eq!(
            dpop_verification_admits(dpop_required, proof_present, verification_succeeded),
            dpop_admits(
                dpop_required,
                proof_present,
                verification_succeeded,
                verification_succeeded,
            ),
        );
    }

    #[test]
    fn nonce_decision_matches_live_entry_test(already_live in any::<bool>()) {
        prop_assert_eq!(nonce_admits(already_live), !already_live);
    }
}

#[test]
fn freshness_saturates_ttl_and_skew_edges() {
    let saturated = DpopConfig {
        proof_ttl_secs: u64::MAX,
        max_clock_skew_secs: u64::MAX,
        nonce_store_capacity: 8,
    };
    let no_skew = DpopConfig {
        proof_ttl_secs: u64::MAX,
        max_clock_skew_secs: 0,
        nonce_store_capacity: 8,
    };
    assert!(dpop_freshness_admits(u64::MAX, u64::MAX, &saturated));
    assert!(dpop_freshness_admits(u64::MAX, 1, &saturated));
    assert!(!dpop_freshness_admits(0, u64::MAX, &no_skew));
}

#[test]
fn nonce_store_matches_fresh_and_replayed_projections() {
    let store = DpopNonceStore::new(8, Duration::from_secs(60));

    assert_eq!(
        store.check_and_insert("nonce", "cap").test_unwrap(),
        nonce_admits(false),
    );
    assert_eq!(
        store.check_and_insert("nonce", "cap").test_unwrap(),
        nonce_admits(true),
    );
}
