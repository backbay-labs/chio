//! Hand transcription of `chio-kernel-core/src/formal_aeneas.rs::ledger_apply`
//! into the Verus dialect. No drift hash binds this file to the production
//! module and no claim rests on it; it exists to calibrate proof effort
//! against the known Creusot and Lean proofs of the same algebra (FV-B5
//! Phase 1). Checked adds appear here as explicit boundary comparisons,
//! which Verus proves overflow-free; the accept/reject semantics are
//! unchanged.

use vstd::prelude::*;

verus! {

pub struct ReservationLedger {
    /// Exposure not yet assigned a terminal amount bucket.
    pub reserved: u64,
    /// Realized spend.
    pub committed: u64,
    /// Reversed exposure plus unused reconciliation remainder.
    pub released: u64,
    /// Deliberately non-unwound exposure.
    pub retained: u64,
}

pub open spec fn spec_total(l: ReservationLedger) -> int {
    l.reserved + l.committed + l.released + l.retained
}

pub open spec fn spec_is_terminal(l: ReservationLedger) -> bool {
    l.reserved == 0 && (l.committed != 0 || l.released != 0 || l.retained != 0)
}

/// Functional model of one reservation transition. Operations are
/// 0 = reserve, 1 = commit, 2 = release, 3 = retain. Unknown operations,
/// reserve-after-terminal, over-disposition, aggregate-overflow input
/// states, and any overflowing bucket addition return the exact input
/// state with `false`.
pub open spec fn spec_ledger_apply(
    state: ReservationLedger,
    op: u8,
    amount: u64,
) -> (ReservationLedger, bool) {
    if spec_total(state) > u64::MAX as int {
        (state, false)
    } else if op > 3 || (op == 0 && spec_is_terminal(state)) {
        (state, false)
    } else if op == 0 {
        if spec_total(state) + amount > u64::MAX as int {
            (state, false)
        } else {
            (
                ReservationLedger {
                    reserved: (state.reserved + amount) as u64,
                    committed: state.committed,
                    released: state.released,
                    retained: state.retained,
                },
                true,
            )
        }
    } else if amount > state.reserved {
        (state, false)
    } else if op == 1 {
        if state.committed + amount > u64::MAX as int {
            (state, false)
        } else {
            (
                ReservationLedger {
                    reserved: (state.reserved - amount) as u64,
                    committed: (state.committed + amount) as u64,
                    released: state.released,
                    retained: state.retained,
                },
                true,
            )
        }
    } else if op == 2 {
        if state.released + amount > u64::MAX as int {
            (state, false)
        } else {
            (
                ReservationLedger {
                    reserved: (state.reserved - amount) as u64,
                    committed: state.committed,
                    released: (state.released + amount) as u64,
                    retained: state.retained,
                },
                true,
            )
        }
    } else {
        if state.retained + amount > u64::MAX as int {
            (state, false)
        } else {
            (
                ReservationLedger {
                    reserved: (state.reserved - amount) as u64,
                    committed: state.committed,
                    released: state.released,
                    retained: (state.retained + amount) as u64,
                },
                true,
            )
        }
    }
}

pub fn ledger_is_terminal(state: &ReservationLedger) -> (result: bool)
    ensures
        result == spec_is_terminal(*state),
{
    state.reserved == 0 && (state.committed != 0 || state.released != 0 || state.retained != 0)
}

/// Executable transition. The single ensures clause binds it to the
/// functional model; every property below is then proved once, about the
/// model.
pub fn ledger_apply(state: ReservationLedger, op: u8, amount: u64) -> (res: (
    ReservationLedger,
    bool,
))
    ensures
        res == spec_ledger_apply(state, op, amount),
{
    if state.committed > u64::MAX - state.reserved {
        return (state, false);
    }
    let sum_rc = state.reserved + state.committed;
    if state.released > u64::MAX - sum_rc {
        return (state, false);
    }
    let sum_rcr = sum_rc + state.released;
    if state.retained > u64::MAX - sum_rcr {
        return (state, false);
    }
    let total = sum_rcr + state.retained;

    if op > 3 || (op == 0 && ledger_is_terminal(&state)) {
        return (state, false);
    }

    if op == 0 {
        if amount > u64::MAX - total {
            return (state, false);
        }
        return (
            ReservationLedger {
                reserved: state.reserved + amount,
                committed: state.committed,
                released: state.released,
                retained: state.retained,
            },
            true,
        );
    }

    if amount > state.reserved {
        return (state, false);
    }
    let outstanding = state.reserved - amount;

    if op == 1 {
        if amount > u64::MAX - state.committed {
            return (state, false);
        }
        (
            ReservationLedger {
                reserved: outstanding,
                committed: state.committed + amount,
                released: state.released,
                retained: state.retained,
            },
            true,
        )
    } else if op == 2 {
        if amount > u64::MAX - state.released {
            return (state, false);
        }
        (
            ReservationLedger {
                reserved: outstanding,
                committed: state.committed,
                released: state.released + amount,
                retained: state.retained,
            },
            true,
        )
    } else {
        if amount > u64::MAX - state.retained {
            return (state, false);
        }
        (
            ReservationLedger {
                reserved: outstanding,
                committed: state.committed,
                released: state.released,
                retained: state.retained + amount,
            },
            true,
        )
    }
}

/// Rejections are exact no-ops.
pub proof fn lemma_invalid_is_noop(state: ReservationLedger, op: u8, amount: u64)
    ensures
        !spec_ledger_apply(state, op, amount).1 ==> spec_ledger_apply(state, op, amount).0
            == state,
{
}

/// One step conserves the partition total: reserve grows it by exactly the
/// reserved amount, every disposition preserves it.
pub proof fn lemma_step_conservation(state: ReservationLedger, op: u8, amount: u64)
    ensures
        spec_ledger_apply(state, op, amount).1 && op == 0 ==> spec_total(
            spec_ledger_apply(state, op, amount).0,
        ) == spec_total(state) + amount,
        spec_ledger_apply(state, op, amount).1 && op != 0 ==> spec_total(
            spec_ledger_apply(state, op, amount).0,
        ) == spec_total(state),
{
}

/// Terminal ledgers are absorbing: no operation changes the state.
pub proof fn lemma_terminal_absorbing(state: ReservationLedger, op: u8, amount: u64)
    requires
        spec_is_terminal(state),
    ensures
        spec_ledger_apply(state, op, amount).0 == state,
{
}

/// Fold a whole operation sequence.
pub open spec fn apply_ops(state: ReservationLedger, ops: Seq<(u8, u64)>) -> ReservationLedger
    decreases ops.len(),
{
    if ops.len() == 0 {
        state
    } else {
        apply_ops(spec_ledger_apply(state, ops[0].0, ops[0].1).0, ops.drop_first())
    }
}

/// Total amount added by the valid reserve steps of a fold, threaded
/// through the intermediate states so validity is judged where each
/// operation actually applies.
pub open spec fn reserve_delta(state: ReservationLedger, ops: Seq<(u8, u64)>) -> int
    decreases ops.len(),
{
    if ops.len() == 0 {
        0
    } else {
        let step = spec_ledger_apply(state, ops[0].0, ops[0].1);
        (if step.1 && ops[0].0 == 0 {
            ops[0].1 as int
        } else {
            0
        }) + reserve_delta(step.0, ops.drop_first())
    }
}

/// Fold-level conservation: the analogue of the Lean `ledger_conservation`
/// theorem. Any operation sequence moves the partition total by exactly
/// the sum of its valid reserve amounts; dispositions and rejections move
/// nothing.
pub proof fn lemma_fold_conservation(state: ReservationLedger, ops: Seq<(u8, u64)>)
    ensures
        spec_total(apply_ops(state, ops)) == spec_total(state) + reserve_delta(state, ops),
    decreases ops.len(),
{
    if ops.len() == 0 {
    } else {
        let step = spec_ledger_apply(state, ops[0].0, ops[0].1);
        lemma_step_conservation(state, ops[0].0, ops[0].1);
        lemma_invalid_is_noop(state, ops[0].0, ops[0].1);
        lemma_fold_conservation(step.0, ops.drop_first());
    }
}

} // verus!
