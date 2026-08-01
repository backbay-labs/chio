//! FV-B5 Phase 3: deliberately broken variants of `ReservationLedgerSync`.
//! Each machine copies the green machine and alters exactly one
//! transition; each must FAIL verification, or the green property set is
//! too weak to count as evidence (standing rule 1). Exercised only through
//! `tools/run-falsification.sh`, which enforces the failure direction.

use verus_state_machines_macros::tokenized_state_machine;
use vstd::prelude::*;

use crate::sync::{holds_sum, lemma_holds_sum_empty, lemma_holds_sum_insert_fresh,
    lemma_holds_sum_remove, HoldState, LedgerTotals};

/// Terminal-uniqueness mutation: `commit` reads the hold token with `have`
/// instead of consuming it with `remove`, so a committed hold stays live
/// and can be committed again. The outstanding-equals-hold-sum invariant
/// must become unprovable.
#[cfg(mutation_terminal)]
tokenized_state_machine! {
    ReservationLedgerSyncTerminalMutation {
        fields {
            #[sharding(variable)]
            pub totals: LedgerTotals,

            #[sharding(map)]
            pub holds: Map<nat, HoldState>,

            #[sharding(variable)]
            pub used: Set<nat>,
        }

        #[invariant]
        pub fn inv_conservation(&self) -> bool {
            self.totals.reserved == self.totals.outstanding + self.totals.committed
                + self.totals.released + self.totals.retained
        }

        #[invariant]
        pub fn inv_outstanding_is_hold_sum(&self) -> bool {
            self.totals.outstanding == holds_sum(self.holds)
        }

        #[invariant]
        pub fn inv_live_ids_admitted(&self) -> bool {
            self.holds.dom().subset_of(self.used)
        }

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

        // MUTATION: `have` instead of `remove`. The single altered line.
        transition! {
            commit(id: nat) {
                have holds >= [ id => let hold ];
                update totals = LedgerTotals {
                    reserved: pre.totals.reserved,
                    outstanding: (pre.totals.outstanding - hold.amount) as nat,
                    committed: pre.totals.committed + hold.amount,
                    released: pre.totals.released,
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
    }
}

/// Overflow mutation: `authorize` drops the checked-add guard, the exact
/// mutation FV-B3 calls "skips a checked-add guard". The u64 bound
/// invariant must become unprovable.
#[cfg(mutation_overflow)]
tokenized_state_machine! {
    ReservationLedgerSyncOverflowMutation {
        fields {
            #[sharding(variable)]
            pub totals: LedgerTotals,

            #[sharding(map)]
            pub holds: Map<nat, HoldState>,

            #[sharding(variable)]
            pub used: Set<nat>,
        }

        #[invariant]
        pub fn inv_conservation(&self) -> bool {
            self.totals.reserved == self.totals.outstanding + self.totals.committed
                + self.totals.released + self.totals.retained
        }

        #[invariant]
        pub fn inv_outstanding_is_hold_sum(&self) -> bool {
            self.totals.outstanding == holds_sum(self.holds)
        }

        #[invariant]
        pub fn inv_live_ids_admitted(&self) -> bool {
            self.holds.dom().subset_of(self.used)
        }

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

        // MUTATION: no `require` bounding reserved + amount. The single
        // altered line.
        transition! {
            authorize(id: nat, amount: nat) {
                require !pre.used.contains(id);
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
    }
}
