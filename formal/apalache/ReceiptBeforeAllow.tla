------------------------ MODULE ReceiptBeforeAllow ------------------------
(***************************************************************************)
(* Abstract persist-before-publish ordering evidence. Concrete cross-row    *)
(* crash recovery remains outside the current formal claim boundary.       *)
(* A call may appear in an authority's allowed set only after the matching  *)
(* call receipt for that authority and capability exists in the log.        *)
(* Receipt persistence and allow publication are modeled as separate        *)
(* actions so the invariant is not satisfied by a fixture-only atomic       *)
(* update that records both facts in one transition.                        *)
(* PublishAllow corresponds to returning an allow response after receipt    *)
(* persistence completes.                                                   *)
(* The execution-nonce preflight response persists an incomplete decision,  *)
(* has no tool output, and remains in an incomplete terminal state. Its     *)
(* transport-level allow verdict only carries the nonce for a retry, so it  *)
(* is excluded from PublishAllow and cannot authorize tool execution.       *)
(*                                                                          *)
(* Code mapping (full cross-reference in formal/MAPPING.md):               *)
(*   - crates/kernel/chio-kernel/src/kernel/responses/                     *)
(*       allow_responses.rs                                                *)
(*       ChioKernel::build_allow_response_with_metadata_and_payee_binding  *)
(*       ChioKernel::build_execution_nonce_preflight_allow_response_with_metadata *)
(*   - crates/kernel/chio-kernel/src/kernel/responses/                     *)
(*       receipt_persistence.rs                                            *)
(*       ChioKernel::record_chio_receipt_with_federation                   *)
(*       ChioKernel::record_chio_receipt                                   *)
(* These are abstraction anchors registered in formal/proof-manifest.toml. *)
(*                                                                          *)
(* Proof obligation:                                                        *)
(*  - Spec Init implies SafetyInv.                                          *)
(*  - Every disjunct of Next preserves SafetyInv. The cross-action          *)
(*    obligation is on PublishAllow: the HasAllowReceipt(a, c, r) guard     *)
(*    must appear in the action body, otherwise an Allow may be published   *)
(*    without a prior allow receipt and the invariant is unsound.           *)
(*  - The Allow-step is split into PersistAllowReceipt followed by          *)
(*    PublishAllow. A single atomic Allow action would make                 *)
(*    ReceiptBeforeAllow tautologically true.                               *)
(*                                                                          *)
(* Non-tautology evidence:                                                 *)
(*  - formal/apalache/_negative_tests/ReceiptBeforeAllowBroken.tla mutates *)
(*    PublishAllow to drop the HasAllowReceipt guard. Apalache must report *)
(*    SafetyInv violated within 2 steps; if it reports NoError, this        *)
(*    property is unsound.                                                  *)
(***************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, Common

CONSTANT
    \* @type: Set(Int);
    CallSet

ASSUME CallSet = 1..2

VARIABLES
    \* @type: Int -> Seq({ call: Int, cap: Int, verdict: Str, t: Int, seen_epoch: Int });
    receipt_log,
    \* @type: Int -> Set({ call: Int, cap: Int });
    allowed,
    \* @type: Int -> Set({ call: Int, cap: Int });
    budget_checked,
    \* @type: Int;
    clock

vars == << receipt_log, allowed, budget_checked, clock >>

CallDecision(r, c) == [call |-> r, cap |-> c]

CallDecisions ==
    { CallDecision(r, c) : r \in CallSet, c \in CapSet }

DomainsOK ==
    /\ DOMAIN receipt_log = Authorities
    /\ DOMAIN allowed = Authorities
    /\ DOMAIN budget_checked = Authorities
    /\ \A a \in Authorities :
        /\ allowed[a] \subseteq CallDecisions
        /\ budget_checked[a] \subseteq CallDecisions
    /\ clock \in Ticks

Init ==
    /\ receipt_log = [a \in Authorities |-> << >>]
    /\ allowed = [a \in Authorities |-> {}]
    /\ budget_checked = [a \in Authorities |-> {}]
    /\ clock = 1

HasReceiptForCall(a, r) ==
    \E i \in 1..EpochMax :
        /\ i <= Len(receipt_log[a])
        /\ receipt_log[a][i].call = r

CheckBudget(a, c, r) ==
    /\ a \in Authorities
    /\ c \in CapSet
    /\ r \in CallSet
    /\ ~HasReceiptForCall(a, r)
    /\ \A decision \in budget_checked[a] \cup allowed[a] :
        decision.call /= r
    /\ budget_checked' = [budget_checked EXCEPT ![a] =
          @ \cup {CallDecision(r, c)}]
    /\ UNCHANGED << receipt_log, allowed, clock >>

HasAllowReceipt(a, c, r) ==
    \E i \in 1..EpochMax :
        /\ i <= Len(receipt_log[a])
        /\ receipt_log[a][i].call = r
        /\ receipt_log[a][i].cap = c
        /\ receipt_log[a][i].verdict = "allow"

PersistAllowReceipt(a, c, r) ==
    /\ a \in Authorities
    /\ CallDecision(r, c) \in budget_checked[a]
    /\ ~HasReceiptForCall(a, r)
    /\ clock < EpochMax
    /\ receipt_log' = [receipt_log EXCEPT ![a] =
          Append(@, [call |-> r,
                     cap |-> c,
                     verdict |-> "allow",
                     t |-> clock,
                     seen_epoch |-> 0])]
    /\ clock' = clock + 1
    /\ UNCHANGED << allowed, budget_checked >>

PublishAllow(a, c, r) ==
    /\ a \in Authorities
    /\ CallDecision(r, c) \in budget_checked[a]
    /\ CallDecision(r, c) \notin allowed[a]
    /\ HasAllowReceipt(a, c, r)
    /\ allowed' = [allowed EXCEPT ![a] =
          @ \cup {CallDecision(r, c)}]
    /\ UNCHANGED << receipt_log, budget_checked, clock >>

Deny(a, c, r) ==
    /\ a \in Authorities
    /\ c \in CapSet
    /\ r \in CallSet
    /\ ~HasReceiptForCall(a, r)
    /\ clock < EpochMax
    /\ receipt_log' = [receipt_log EXCEPT ![a] =
          Append(@, [call |-> r,
                     cap |-> c,
                     verdict |-> "deny",
                     t |-> clock,
                     seen_epoch |-> 0])]
    /\ clock' = clock + 1
    /\ UNCHANGED << allowed, budget_checked >>

Stutter ==
    UNCHANGED vars

Next ==
    \/ \E a \in Authorities, c \in CapSet, r \in CallSet : CheckBudget(a, c, r)
    \/ \E a \in Authorities, c \in CapSet, r \in CallSet : PersistAllowReceipt(a, c, r)
    \/ \E a \in Authorities, c \in CapSet, r \in CallSet : PublishAllow(a, c, r)
    \/ \E a \in Authorities, c \in CapSet, r \in CallSet : Deny(a, c, r)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

ReceiptBeforeAllow ==
    \A a \in Authorities :
        \A decision \in allowed[a] :
            HasAllowReceipt(a, decision.cap, decision.call)

AllowReceiptsBudgetChecked ==
    \A a \in Authorities :
        \A i \in 1..Len(receipt_log[a]) :
            receipt_log[a][i].verdict = "allow" =>
                CallDecision(
                    receipt_log[a][i].call,
                    receipt_log[a][i].cap
                ) \in budget_checked[a]

SafetyInv ==
    /\ DomainsOK
    /\ ReceiptBeforeAllow
    /\ AllowReceiptsBudgetChecked

=============================================================================
