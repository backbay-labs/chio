--------------------- MODULE ReceiptBeforeAllowBroken ---------------------
(***************************************************************************)
(* DELIBERATELY BROKEN variant of ReceiptBeforeAllow used to demonstrate    *)
(* that the ReceiptBeforeAllow invariant is NOT tautologically satisfied.   *)
(* PublishAllow here omits the HasAllowReceipt(a, c) precondition, so an    *)
(* allow can be published without an allow receipt persisting first.        *)
(*                                                                          *)
(* Apalache MUST find a counterexample to SafetyInv on this spec. If it     *)
(* reports NoError, the property is unsound.                                *)
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

\* BROKEN: HasAllowReceipt precondition removed.
PublishAllowBroken(a, c) ==
    /\ a \in Authorities
    /\ c \in budget_checked[a]
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
    \/ \E a \in Authorities, c \in CapSet : PublishAllowBroken(a, c)
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
