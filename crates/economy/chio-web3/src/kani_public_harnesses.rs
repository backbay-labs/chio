//! Public symbolic checks for settlement-state identifiers.
//!
//! The harness enumerates every lifecycle variant and calls the public helper
//! consumed by the settlement verifier. Exact byte-slice patterns avoid a
//! bounded string-comparison loop; no local model substitutes for production
//! code.

use crate::settlement::{settlement_state_id, Web3SettlementLifecycleState};

fn lifecycle_state_from_index(index: u8) -> Web3SettlementLifecycleState {
    match index {
        0 => Web3SettlementLifecycleState::PendingDispatch,
        1 => Web3SettlementLifecycleState::EscrowLocked,
        2 => Web3SettlementLifecycleState::PartiallySettled,
        3 => Web3SettlementLifecycleState::Settled,
        4 => Web3SettlementLifecycleState::Reversed,
        5 => Web3SettlementLifecycleState::ChargedBack,
        6 => Web3SettlementLifecycleState::TimedOut,
        7 => Web3SettlementLifecycleState::Failed,
        _ => Web3SettlementLifecycleState::Reorged,
    }
}

fn state_id_matches(index: u8, value: &[u8]) -> bool {
    match index {
        0 => matches!(
            value,
            [
                b'p', b'e', b'n', b'd', b'i', b'n', b'g', b'_', b'd', b'i', b's', b'p', b'a', b't',
                b'c', b'h'
            ]
        ),
        1 => matches!(
            value,
            [b'e', b's', b'c', b'r', b'o', b'w', b'_', b'l', b'o', b'c', b'k', b'e', b'd']
        ),
        2 => matches!(
            value,
            [
                b'p', b'a', b'r', b't', b'i', b'a', b'l', b'l', b'y', b'_', b's', b'e', b't', b't',
                b'l', b'e', b'd'
            ]
        ),
        3 => matches!(value, [b's', b'e', b't', b't', b'l', b'e', b'd']),
        4 => matches!(value, [b'r', b'e', b'v', b'e', b'r', b's', b'e', b'd']),
        5 => matches!(
            value,
            [b'c', b'h', b'a', b'r', b'g', b'e', b'd', b'_', b'b', b'a', b'c', b'k']
        ),
        6 => matches!(
            value,
            [b't', b'i', b'm', b'e', b'd', b'_', b'o', b'u', b't']
        ),
        7 => matches!(value, [b'f', b'a', b'i', b'l', b'e', b'd']),
        _ => matches!(value, [b'r', b'e', b'o', b'r', b'g', b'e', b'd']),
    }
}

#[kani::proof]
#[kani::unwind(8)]
pub fn public_settlement_state_id_fixed_point() {
    let index: u8 = kani::any();
    kani::assume(index < 9);

    let state = lifecycle_state_from_index(index);
    let observed = settlement_state_id(state);

    assert!(state_id_matches(index, observed.as_bytes()));
    assert!(state_id_matches(
        index,
        settlement_state_id(state).as_bytes()
    ));
}
