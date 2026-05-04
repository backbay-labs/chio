-------------------- MODULE RevocationCutCompleteness --------------------
(***************************************************************************)
(* Bounded state-machine lift of Lean revocation_is_cut.                   *)
(* A revoked root or direct parent removes dispatch eligibility for every   *)
(* affected local authority view.                                           *)
(*                                                                          *)
(* Known modeling bound (trj3.2 review, 2026-05-03):                        *)
(*   `DescendsFrom` matches one level only (self or direct parent), so the  *)
(*   bounded model proves cut completeness for depth <= 1 of the delegation *)
(*   DAG. Transitive subtree cut is covered by `DepthBoundedByRoot` plus    *)
(*   `RevokedSubtreeNotObservable` in DelegationDepthBound.tla and by the   *)
(*   Lean `revocation_is_cut` theorem; the Apalache module here does not    *)
(*   re-prove the transitive case. Lifting to a transitive `DescendsFrom`   *)
(*   under Apalache 0.50.x requires a bounded TC unrolling and is deferred. *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Common

VARIABLES
    \* @type: Int -> Int;
    parent,
    \* @type: Set(Int);
    revoked,
    \* @type: Int -> (Int -> Bool);
    can_allow

vars == << parent, revoked, can_allow >>

ParentOK ==
    /\ DOMAIN parent = CapSet
    /\ \A c \in CapSet : parent[c] \in CapSet0

CanAllowOK ==
    /\ DOMAIN can_allow = Authorities
    /\ \A a \in Authorities :
        /\ DOMAIN can_allow[a] = CapSet
        /\ \A c \in CapSet : can_allow[a][c] \in BOOLEAN

DomainsOK ==
    /\ ParentOK
    /\ revoked \subseteq CapSet
    /\ CanAllowOK

Init ==
    /\ parent = [c \in CapSet |-> 0]
    /\ revoked = {}
    /\ can_allow = [a \in Authorities |-> [c \in CapSet |-> TRUE]]

DescendsFrom(child, root) ==
    \/ child = root
    \/ parent[child] = root

Delegate(child, root) ==
    /\ child \in CapSet
    /\ root \in CapSet
    /\ child # root
    /\ parent[child] = 0
    /\ root \notin revoked
    /\ parent' = [parent EXCEPT ![child] = root]
    /\ can_allow' = can_allow
    /\ UNCHANGED revoked

Revoke(root) ==
    /\ root \in CapSet
    /\ root \notin revoked
    /\ revoked' = revoked \cup {root}
    /\ can_allow' =
        [a \in Authorities |->
            [c \in CapSet |->
                IF DescendsFrom(c, root)
                THEN FALSE
                ELSE can_allow[a][c]]]
    /\ UNCHANGED parent

Stutter ==
    UNCHANGED vars

Next ==
    \/ \E child \in CapSet, root \in CapSet : Delegate(child, root)
    \/ \E root \in CapSet : Revoke(root)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

RevocationCutCompleteness ==
    \A a \in Authorities :
        \A c \in CapSet :
            \A r \in revoked :
                DescendsFrom(c, r) => can_allow[a][c] = FALSE

SafetyInv ==
    /\ DomainsOK
    /\ RevocationCutCompleteness

=============================================================================
