use chio_web3::trust_profile::{
    Web3DisputePolicy, Web3DisputeWindow, Web3SettlementPath, CHIO_WEB3_TRUST_PROFILE_SCHEMA,
};

#[test]
fn web3_public_types_capture_dispute_window_shape() {
    let dispute_window = Web3DisputeWindow {
        settlement_path: Web3SettlementPath::DualSignature,
        challenge_window_secs: 600,
        recovery_window_secs: 1200,
        dispute_policy: Web3DisputePolicy::OffChainArbitration,
    };

    assert_eq!(dispute_window.challenge_window_secs, 600);
    assert_eq!(dispute_window.recovery_window_secs, 1200);
    assert_eq!(CHIO_WEB3_TRUST_PROFILE_SCHEMA, "chio.web3-trust-profile.v1");
}
