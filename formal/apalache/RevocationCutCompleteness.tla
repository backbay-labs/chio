-------------------- MODULE RevocationCutCompleteness --------------------
(***************************************************************************)
(* Bounded state-machine lift of Lean revocation_is_cut.                   *)
(* A revoked capability removes dispatch eligibility for every transitive   *)
(* descendant in each local authority view. The model maintains a bounded   *)
(* descendant closure across Delegate transitions so Revoke checks the      *)
(* whole subtree instead of only checking roots and direct parents.         *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Common

VARIABLES
    \* @type: Int -> Int;
    parent,
    \* @type: Int -> Set(Int);
    descendants,
    \* @type: Set(Int);
    revoked,
    \* @type: Int -> (Int -> Bool);
    can_allow

vars == << parent, descendants, revoked, can_allow >>

ParentOK ==
    /\ DOMAIN parent = CapSet
    /\ \A c \in CapSet : parent[c] \in CapSet0

DescendantsOK ==
    /\ DOMAIN descendants = CapSet
    /\ \A r \in CapSet :
        /\ descendants[r] \subseteq CapSet
        /\ r \in descendants[r]

CanAllowOK ==
    /\ DOMAIN can_allow = Authorities
    /\ \A a \in Authorities :
        /\ DOMAIN can_allow[a] = CapSet
        /\ \A c \in CapSet : can_allow[a][c] \in BOOLEAN

DomainsOK ==
    /\ ParentOK
    /\ DescendantsOK
    /\ revoked \subseteq CapSet
    /\ CanAllowOK

Init ==
    /\ parent = [c \in CapSet |-> 0]
    /\ descendants = [c \in CapSet |-> {c}]
    /\ revoked = {}
    /\ can_allow = [a \in Authorities |-> [c \in CapSet |-> TRUE]]

DescendsFrom(child, root) ==
    /\ child \in CapSet
    /\ root \in CapSet
    /\ child \in descendants[root]

NoRevokedAncestor(c) ==
    \A r \in revoked : ~DescendsFrom(c, r)

Delegate(child, root) ==
    /\ child \in CapSet
    /\ root \in CapSet
    /\ child # root
    /\ parent[child] = 0
    /\ descendants[child] = {child}
    /\ NoRevokedAncestor(child)
    /\ NoRevokedAncestor(root)
    /\ parent' = [parent EXCEPT ![child] = root]
    /\ descendants' =
        [ancestor \in CapSet |->
            IF root \in descendants[ancestor]
            THEN descendants[ancestor] \cup {child}
            ELSE descendants[ancestor]]
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
    /\ UNCHANGED << parent, descendants >>

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
