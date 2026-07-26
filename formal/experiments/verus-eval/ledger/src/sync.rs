//! FV-B5 Phase 2: the FV-B3 conservation law for concurrently held
//! reservations, as a VerusSync tokenized state machine. Multiple actors
//! concurrently authorize, dispose, and reconcile distinct holds against
//! one ledger; the invariants below hold for every interleaving and every
//! amount, with no schedule, actor, or amount bound.
//!
//! Honesty boundary: this is a model of the concurrent store protocol, not
//! the production `budget_store.rs` call path (which is async and outside
//! Verus scope). Terminal uniqueness is enforced by token linearity: every
//! disposition consumes its hold token, and `used` prevents id reuse, so a
//! terminal hold admits no further transition by construction; the
//! mutation variants demonstrate the invariants fail when that discipline
//! is broken.

use verus_state_machines_macros::tokenized_state_machine;
use vstd::prelude::*;

verus! {

pub struct HoldState {
    pub amount: nat,
}

pub struct LedgerTotals {
    /// Total ever admitted; grows only by `authorize`.
    pub reserved: nat,
    /// Exposure awaiting a disposition.
    pub outstanding: nat,
    /// Realized spend.
    pub committed: nat,
    /// Reversed exposure plus unused reconciliation remainder.
    pub released: nat,
    /// Deliberately non-unwound exposure.
    pub retained: nat,
}

/// Sum of hold amounts over a finite map, defined by repeated removal of
/// an arbitrary element.
pub open spec fn holds_sum(m: Map<nat, HoldState>) -> nat
    decreases m.dom().len(),
{
    if m.dom().len() == 0 {
        0
    } else {
        let k = m.dom().choose();
        m[k].amount + holds_sum(m.remove(k))
    }
}

pub proof fn lemma_holds_sum_empty()
    ensures
        holds_sum(Map::<nat, HoldState>::empty()) == 0,
{
    assert(Map::<nat, HoldState>::empty().dom() =~= Set::<nat>::empty());
}

/// Removing a present key subtracts exactly its amount, independent of the
/// arbitrary removal order the definition uses.
pub proof fn lemma_holds_sum_remove(m: Map<nat, HoldState>, k: nat)
    requires
        m.dom().contains(k),
    ensures
        holds_sum(m) == m[k].amount + holds_sum(m.remove(k)),
    decreases m.dom().len(),
{
    let c = m.dom().choose();
    assert(m.dom().contains(c));
    assert(m.remove(c).dom() =~= m.dom().remove(c));
    if c == k {
    } else {
        assert(m.remove(c).dom().contains(k));
        lemma_holds_sum_remove(m.remove(c), k);
        lemma_holds_sum_remove(m.remove(k), c);
        assert(m.remove(c).remove(k) =~= m.remove(k).remove(c));
        assert(m.remove(k)[c] == m[c]);
        assert(m.remove(c)[k] == m[k]);
    }
}

/// Inserting a fresh key adds exactly its amount.
pub proof fn lemma_holds_sum_insert_fresh(m: Map<nat, HoldState>, k: nat, v: HoldState)
    requires
        !m.dom().contains(k),
    ensures
        holds_sum(m.insert(k, v)) == holds_sum(m) + v.amount,
{
    let m2 = m.insert(k, v);
    assert(m2.dom().contains(k));
    lemma_holds_sum_remove(m2, k);
    assert(m2.remove(k) =~= m);
    assert(m2[k] == v);
}

} // verus!

tokenized_state_machine! {
    ReservationLedgerSync {
        fields {
            #[sharding(variable)]
            pub totals: LedgerTotals,

            #[sharding(map)]
            pub holds: Map<nat, HoldState>,

            #[sharding(variable)]
            pub used: Set<nat>,
        }

        /// Clause 1 of the FV-B3 law at every reachable state.
        #[invariant]
        pub fn inv_conservation(&self) -> bool {
            self.totals.reserved == self.totals.outstanding + self.totals.committed
                + self.totals.released + self.totals.retained
        }

        /// The outstanding bucket is exactly the amount held by live
        /// (undisposed) holds.
        #[invariant]
        pub fn inv_outstanding_is_hold_sum(&self) -> bool {
            self.totals.outstanding == holds_sum(self.holds)
        }

        /// Every live hold id has been admitted; disposed ids stay in
        /// `used`, so no id is ever re-admitted (terminal uniqueness).
        #[invariant]
        pub fn inv_live_ids_admitted(&self) -> bool {
            self.holds.dom().subset_of(self.used)
        }

        /// Fail-closed arithmetic: the whole partition stays inside u64,
        /// so no transition performs unrepresentable arithmetic. With
        /// conservation, this bounds every bucket.
        #[invariant]
        pub fn inv_u64_bound(&self) -> bool {
            self.totals.reserved <= u64::MAX as nat
        }

        init! {
            initialize() {
                init totals = LedgerTotals {
                    reserved: 0,
                    outstanding: 0,
                    committed: 0,
                    released: 0,
                    retained: 0,
                };
                init holds = Map::<nat, HoldState>::empty();
                init used = Set::<nat>::empty();
            }
        }

        /// Admit a reservation. The explicit bound is the checked-add
        /// guard: an admission that would overflow the partition is not
        /// enabled.
        transition! {
            authorize(id: nat, amount: nat) {
                require !pre.used.contains(id);
                require pre.totals.reserved + amount <= u64::MAX as nat;
                update used = pre.used.insert(id);
                update totals = LedgerTotals {
                    reserved: pre.totals.reserved + amount,
                    outstanding: pre.totals.outstanding + amount,
                    committed: pre.totals.committed,
                    released: pre.totals.released,
                    retained: pre.totals.retained,
                };
                add holds += [ id => HoldState { amount } ] by {
                    assert(!pre.holds.dom().contains(id));
                };
            }
        }

        /// Full commit: the terminal disposition consumes the hold token.
        transition! {
            commit(id: nat) {
                remove holds -= [ id => let hold ];
                update totals = LedgerTotals {
                    reserved: pre.totals.reserved,
                    outstanding: (pre.totals.outstanding - hold.amount) as nat,
                    committed: pre.totals.committed + hold.amount,
                    released: pre.totals.released,
                    retained: pre.totals.retained,
                };
            }
        }

        /// Full release (pre-dispatch reversal or known reduction).
        transition! {
            release(id: nat) {
                remove holds -= [ id => let hold ];
                update totals = LedgerTotals {
                    reserved: pre.totals.reserved,
                    outstanding: (pre.totals.outstanding - hold.amount) as nat,
                    committed: pre.totals.committed,
                    released: pre.totals.released + hold.amount,
                    retained: pre.totals.retained,
                };
            }
        }

        /// Outcome-unknown retention: exposure deliberately not unwound.
        transition! {
            retain(id: nat) {
                remove holds -= [ id => let hold ];
                update totals = LedgerTotals {
                    reserved: pre.totals.reserved,
                    outstanding: (pre.totals.outstanding - hold.amount) as nat,
                    committed: pre.totals.committed,
                    released: pre.totals.released,
                    retained: pre.totals.retained + hold.amount,
                };
            }
        }

        /// Reconcile exposure E to realized spend S: S is committed, the
        /// unused E - S is released, and the hold has exactly one terminal
        /// disposition even though two amount buckets change.
        transition! {
            reconcile(id: nat, spend: nat) {
                remove holds -= [ id => let hold ];
                require spend <= hold.amount;
                update totals = LedgerTotals {
                    reserved: pre.totals.reserved,
                    outstanding: (pre.totals.outstanding - hold.amount) as nat,
                    committed: pre.totals.committed + spend,
                    released: (pre.totals.released + hold.amount - spend) as nat,
                    retained: pre.totals.retained,
                };
            }
        }

        #[inductive(initialize)]
        fn initialize_inductive(post: Self) {
            lemma_holds_sum_empty();
        }

        #[inductive(authorize)]
        fn authorize_inductive(pre: Self, post: Self, id: nat, amount: nat) {
            lemma_holds_sum_insert_fresh(pre.holds, id, HoldState { amount });
        }

        #[inductive(commit)]
        fn commit_inductive(pre: Self, post: Self, id: nat) {
            lemma_holds_sum_remove(pre.holds, id);
        }

        #[inductive(release)]
        fn release_inductive(pre: Self, post: Self, id: nat) {
            lemma_holds_sum_remove(pre.holds, id);
        }

        #[inductive(retain)]
        fn retain_inductive(pre: Self, post: Self, id: nat) {
            lemma_holds_sum_remove(pre.holds, id);
        }

        #[inductive(reconcile)]
        fn reconcile_inductive(pre: Self, post: Self, id: nat, spend: nat) {
            lemma_holds_sum_remove(pre.holds, id);
        }
    }
}
