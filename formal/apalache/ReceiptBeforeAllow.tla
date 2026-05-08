------------------------ MODULE ReceiptBeforeAllow ------------------------
(***************************************************************************)
(* Apalache invariant for the RETIRED-SQLITE-CROSS-ROW handoff.            *)
(* A capability may appear in an authority's allowed set only after an      *)
(* allow receipt for that authority and capability exists in the log.       *)
(* Receipt persistence and allow publication are modeled as separate        *)
(* actions so the invariant is not satisfied by a fixture-only atomic       *)
(* update that records both facts in one transition.                        *)
(*                                                                          *)
(* Proof obligation (release work-A4.1):                                            *)
(*  - Spec Init implies SafetyInv.                                          *)
(*  - Every disjunct of Next preserves SafetyInv. The cross-action          *)
(*    obligation is on PublishAllow: the HasAllowReceipt(a, c) guard must   *)
(*    appear in the action body, otherwise an Allow may be published       *)
(*    without a prior allow receipt and the invariant is unsound.           *)
(*  - The Allow-step has been split into PersistAllowReceipt followed by    *)
(*    PublishAllow, removing the prior trj4 erratum where a single atomic   *)
(*    Allow action made ReceiptBeforeAllow tautologically true.             *)
(*                                                                          *)
(* Non-tautology evidence:                                                 *)
(*  - formal/apalache/_negative_tests/ReceiptBeforeAllowBroken.tla mutates *)
(*    PublishAllow to drop the HasAllowReceipt guard. Apalache must report *)
(*    SafetyInv violated within 2 steps; if it reports NoError, this        *)
(*    property is unsound.                                                  *)
(***************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, Common

VARIABLES
    \* @type: Int -> Seq({ cap: Int, verdict: Str, t: Int, seen_epoch: Int });
    receipt_log,
    \* @type: Int -> Set(Int);
    allowed,
    \* @type: Int -> Set(Int);
    budget_checked,
    \* @type: Int;
    clock

vars == << receipt_log, allowed, budget_checked, clock >>

DomainsOK ==
    /\ DOMAIN receipt_log = Authorities
    /\ DOMAIN allowed = Authorities
    /\ DOMAIN budget_checked = Authorities
    /\ \A a \in Authorities :
        /\ allowed[a] \subseteq CapSet
        /\ budget_checked[a] \subseteq CapSet
    /\ clock \in Ticks

Init ==
    /\ receipt_log = [a \in Authorities |-> << >>]
    /\ allowed = [a \in Authorities |-> {}]
    /\ budget_checked = [a \in Authorities |-> {}]
    /\ clock = 1

CheckBudget(a, c) ==
    /\ a \in Authorities
    /\ c \in CapSet
    /\ budget_checked' = [budget_checked EXCEPT ![a] = @ \cup {c}]
    /\ UNCHANGED << receipt_log, allowed, clock >>

HasAllowReceipt(a, c) ==
    \E i \in 1..EpochMax :
        /\ i <= Len(receipt_log[a])
        /\ receipt_log[a][i].cap = c
        /\ receipt_log[a][i].verdict = "allow"

PersistAllowReceipt(a, c) ==
    /\ a \in Authorities
    /\ c \in budget_checked[a]
    /\ clock < EpochMax
    /\ receipt_log' = [receipt_log EXCEPT ![a] =
          Append(@, [cap |-> c,
                     verdict |-> "allow",
                     t |-> clock,
                     seen_epoch |-> 0])]
    /\ clock' = clock + 1
    /\ UNCHANGED << allowed, budget_checked >>

PublishAllow(a, c) ==
    /\ a \in Authorities
    /\ c \in budget_checked[a]
    /\ HasAllowReceipt(a, c)
    /\ allowed' = [allowed EXCEPT ![a] = @ \cup {c}]
    /\ UNCHANGED << receipt_log, budget_checked, clock >>

Deny(a, c) ==
    /\ a \in Authorities
    /\ c \in CapSet
    /\ clock < EpochMax
    /\ receipt_log' = [receipt_log EXCEPT ![a] =
          Append(@, [cap |-> c,
                     verdict |-> "deny",
                     t |-> clock,
                     seen_epoch |-> 0])]
    /\ clock' = clock + 1
    /\ UNCHANGED << allowed, budget_checked >>

Stutter ==
    UNCHANGED vars

Next ==
    \/ \E a \in Authorities, c \in CapSet : CheckBudget(a, c)
    \/ \E a \in Authorities, c \in CapSet : PersistAllowReceipt(a, c)
    \/ \E a \in Authorities, c \in CapSet : PublishAllow(a, c)
    \/ \E a \in Authorities, c \in CapSet : Deny(a, c)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

ReceiptBeforeAllow ==
    \A a \in Authorities :
        \A c \in CapSet :
            c \in allowed[a] => HasAllowReceipt(a, c)

SafetyInv ==
    /\ DomainsOK
    /\ ReceiptBeforeAllow

=============================================================================
