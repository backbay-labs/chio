------------------------ MODULE ReceiptBeforeAllow ------------------------
(***************************************************************************)
(* Single Apalache invariant for the RETIRED-SQLITE-CROSS-ROW handoff.     *)
(* A capability may appear in an authority's allowed set only after an      *)
(* allow receipt for that authority and capability exists in the log.       *)
(***************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, Common

VARIABLES
    \* @type: Int -> Seq({ cap: Int, verdict: Str, t: Int, seen_epoch: Int });
    receipt_log,
    \* @type: Int -> Set(Int);
    allow_recorded,
    \* @type: Int -> Set(Int);
    allowed,
    \* @type: Int -> Set(Int);
    budget_checked,
    \* @type: Int;
    clock

vars == << receipt_log, allow_recorded, allowed, budget_checked, clock >>

DomainsOK ==
    /\ DOMAIN receipt_log = Authorities
    /\ DOMAIN allow_recorded = Authorities
    /\ DOMAIN allowed = Authorities
    /\ DOMAIN budget_checked = Authorities
    /\ \A a \in Authorities :
        /\ allow_recorded[a] \subseteq CapSet
        /\ allowed[a] \subseteq CapSet
        /\ budget_checked[a] \subseteq CapSet
    /\ clock \in Ticks

Init ==
    /\ receipt_log = [a \in Authorities |-> << >>]
    /\ allow_recorded = [a \in Authorities |-> {}]
    /\ allowed = [a \in Authorities |-> {}]
    /\ budget_checked = [a \in Authorities |-> {}]
    /\ clock = 1

CheckBudget(a, c) ==
    /\ a \in Authorities
    /\ c \in CapSet
    /\ budget_checked' = [budget_checked EXCEPT ![a] = @ \cup {c}]
    /\ UNCHANGED << receipt_log, allow_recorded, allowed, clock >>

Allow(a, c) ==
    /\ a \in Authorities
    /\ c \in budget_checked[a]
    /\ clock < EpochMax
    /\ receipt_log' = [receipt_log EXCEPT ![a] =
          Append(@, [cap |-> c,
                     verdict |-> "allow",
                     t |-> clock,
                     seen_epoch |-> 0])]
    /\ allow_recorded' = [allow_recorded EXCEPT ![a] = @ \cup {c}]
    /\ allowed' = [allowed EXCEPT ![a] = @ \cup {c}]
    /\ clock' = clock + 1
    /\ UNCHANGED budget_checked

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
    /\ UNCHANGED << allow_recorded, allowed, budget_checked >>

Stutter ==
    UNCHANGED vars

Next ==
    \/ \E a \in Authorities, c \in CapSet : CheckBudget(a, c)
    \/ \E a \in Authorities, c \in CapSet : Allow(a, c)
    \/ \E a \in Authorities, c \in CapSet : Deny(a, c)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

ReceiptBeforeAllow ==
    \A a \in Authorities :
        allowed[a] \subseteq allow_recorded[a]

SafetyInv ==
    /\ DomainsOK
    /\ ReceiptBeforeAllow

=============================================================================
