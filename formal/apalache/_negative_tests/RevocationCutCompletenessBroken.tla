------------------ MODULE RevocationCutCompletenessBroken ------------------
(***************************************************************************)
(* DELIBERATELY BROKEN variant of RevocationCutCompleteness used to        *)
(* demonstrate the property is NOT tautologically satisfied.               *)
(*                                                                          *)
(* The broken Revoke action below only flips can_allow for the root cap,   *)
(* not for transitive descendants. This mirrors the "shallow revoke" bug   *)
(* RevocationCutCompleteness is meant to catch. Apalache MUST find a        *)
(* counterexample to that named invariant if it is sound.                   *)
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

\* BROKEN: only the revoked root has can_allow flipped, descendants left TRUE.
RevokeShallow(root) ==
    /\ root \in CapSet
    /\ root \notin revoked
    /\ revoked' = revoked \cup {root}
    /\ can_allow' =
        [a \in Authorities |->
            [c \in CapSet |->
                IF c = root
                THEN FALSE
                ELSE can_allow[a][c]]]
    /\ UNCHANGED << parent, descendants >>

Stutter ==
    UNCHANGED vars

Next ==
    \/ \E child \in CapSet, root \in CapSet : Delegate(child, root)
    \/ \E root \in CapSet : RevokeShallow(root)
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
