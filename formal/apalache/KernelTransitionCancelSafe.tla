--------------------- MODULE KernelTransitionCancelSafe ---------------------
(***************************************************************************)
(* Bounded model of an interrupted kernel transition.                       *)
(* This model covers clean pre-dispatch cancellation. While cancellation is *)
(* pending, budget and receipt state must equal the pre-transition snapshot. *)
(* CancelTransition clears the flag without changing either state surface.  *)
(* Post-dispatch and fault cleanup may record receipts or retain             *)
(* reservations and are outside this model.                                 *)
(*                                                                          *)
(* Code mapping (full cross-reference in formal/MAPPING.md):               *)
(*   - crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs           *)
(*       PostAdmissionDropGuard                                            *)
(*       PostAdmissionDropGuard::new                                       *)
(*       PostAdmissionDropGuard::mark_dispatch_started                     *)
(*       PostAdmissionDropGuard::disarm                                    *)
(*       PostAdmissionDropGuard::handle_pre_dispatch_drop                  *)
(*       PostAdmissionDropGuard::record_pre_dispatch_cleanup_fault_receipt *)
(*       PostAdmissionDropGuard::drop                                      *)
(*   - crates/kernel/chio-kernel/src/kernel/validation.rs                  *)
(*       ChioKernel::reverse_pre_execution_budget_mutation                 *)
(* These are abstraction anchors registered in formal/proof-manifest.toml. *)
(* The model has no reversal action; snapshot equality is by construction. *)
(* The anchors identify the runtime handoff but do not prove restoration.  *)
(*                                                                          *)
(* Known modeling bound:                                                    *)
(*   `Commit` is guarded by `cancel_pending = FALSE`, so no action mutates  *)
(*   `budget_used` or `receipt_count` while a cancel is pending, and the    *)
(*   invariant holds by construction. The model does not exercise the Rust  *)
(*   reversal transition or concurrent Commit-vs-Cancel races.             *)
(*   PostAdmissionDropGuard.tla carries the broader pre-dispatch and         *)
(*   post-dispatch lifecycle model.                                         *)
(*   Credential commit failures after dispatch follow DropPostDispatch there *)
(*   and are outside this clean-cancellation abstraction.                    *)
(***************************************************************************)

EXTENDS Naturals, Common

VARIABLES
    \* @type: Int -> (Int -> Int);
    budget_used,
    \* @type: Int -> Int;
    receipt_count,
    \* @type: Bool;
    cancel_pending,
    \* @type: Int -> (Int -> Int);
    snapshot_budget,
    \* @type: Int -> Int;
    snapshot_receipts

vars == << budget_used, receipt_count, cancel_pending, snapshot_budget, snapshot_receipts >>

BudgetOK ==
    /\ DOMAIN budget_used = Authorities
    /\ DOMAIN snapshot_budget = Authorities
    /\ \A a \in Authorities :
        /\ DOMAIN budget_used[a] = CapSet
        /\ DOMAIN snapshot_budget[a] = CapSet
        /\ \A c \in CapSet :
            /\ budget_used[a][c] \in Epochs
            /\ snapshot_budget[a][c] \in Epochs

ReceiptsOK ==
    /\ DOMAIN receipt_count = Authorities
    /\ DOMAIN snapshot_receipts = Authorities
    /\ \A a \in Authorities :
        /\ receipt_count[a] \in Epochs
        /\ snapshot_receipts[a] \in Epochs

DomainsOK ==
    /\ BudgetOK
    /\ ReceiptsOK
    /\ cancel_pending \in BOOLEAN

Init ==
    /\ budget_used = [a \in Authorities |-> [c \in CapSet |-> 0]]
    /\ receipt_count = [a \in Authorities |-> 0]
    /\ cancel_pending = FALSE
    /\ snapshot_budget = [a \in Authorities |-> [c \in CapSet |-> 0]]
    /\ snapshot_receipts = [a \in Authorities |-> 0]

BeginCancel ==
    /\ cancel_pending = FALSE
    /\ snapshot_budget' = budget_used
    /\ snapshot_receipts' = receipt_count
    /\ cancel_pending' = TRUE
    /\ UNCHANGED << budget_used, receipt_count >>

CancelTransition ==
    /\ cancel_pending = TRUE
    /\ budget_used' = snapshot_budget
    /\ receipt_count' = snapshot_receipts
    /\ cancel_pending' = FALSE
    /\ UNCHANGED << snapshot_budget, snapshot_receipts >>

Commit(a, c) ==
    /\ cancel_pending = FALSE
    /\ a \in Authorities
    /\ c \in CapSet
    /\ budget_used[a][c] < EpochMax
    /\ receipt_count[a] < EpochMax
    /\ budget_used' = [budget_used EXCEPT ![a][c] = @ + 1]
    /\ receipt_count' = [receipt_count EXCEPT ![a] = @ + 1]
    /\ UNCHANGED << cancel_pending, snapshot_budget, snapshot_receipts >>

Stutter ==
    UNCHANGED vars

Next ==
    \/ BeginCancel
    \/ CancelTransition
    \/ \E a \in Authorities, c \in CapSet : Commit(a, c)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

KernelTransitionCancelSafe ==
    cancel_pending =>
        /\ budget_used = snapshot_budget
        /\ receipt_count = snapshot_receipts

SafetyInv ==
    /\ DomainsOK
    /\ KernelTransitionCancelSafe

=============================================================================
