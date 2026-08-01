--------------------- MODULE ReceiptBeforeAllowBroken ---------------------
(***************************************************************************)
(* DELIBERATELY BROKEN variant of ReceiptBeforeAllow used to demonstrate    *)
(* that the ReceiptBeforeAllow invariant is NOT tautologically satisfied.   *)
(* PublishAllow here omits the HasAllowReceipt(a, c, r) precondition, so a  *)
(* call can be published without its allow receipt persisting first.         *)
(*                                                                          *)
(* Apalache MUST find a counterexample to ReceiptBeforeAllow. If it         *)
(* reports NoError, the property is unsound.                                *)
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

\* BROKEN: HasAllowReceipt precondition removed.
PublishAllowBroken(a, c, r) ==
    /\ a \in Authorities
    /\ CallDecision(r, c) \in budget_checked[a]
    /\ CallDecision(r, c) \notin allowed[a]
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
    \/ \E a \in Authorities, c \in CapSet, r \in CallSet : PublishAllowBroken(a, c, r)
    \/ \E a \in Authorities, c \in CapSet, r \in CallSet : Deny(a, c, r)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

ReceiptBeforeAllow ==
    \A a \in Authorities :
        \A decision \in allowed[a] :
            HasAllowReceipt(a, decision.cap, decision.call)

SafetyInv ==
    /\ DomainsOK
    /\ ReceiptBeforeAllow

=============================================================================
