-------------------- MODULE RevocationCutCompleteness --------------------
(***************************************************************************)
(* Bounded state-machine lift of Lean revocation_is_cut.                   *)
(* A revoked capability removes dispatch eligibility for every transitive   *)
(* descendant in each local authority view. The model maintains a bounded   *)
(* descendant closure across Delegate transitions so Revoke checks the      *)
(* whole subtree instead of only checking roots and direct parents.         *)
(*                                                                          *)
(* Code mapping (full cross-reference in formal/MAPPING.md):               *)
(*   - crates/kernel/chio-kernel/src/kernel/validation.rs                  *)
(*       ChioKernel::check_revocation                                      *)
(*   - crates/kernel/chio-kernel/src/kernel/delegation.rs                  *)
(*       consult_revocation_view, consult_revocation_view_at               *)
(*   - crates/kernel/chio-kernel-core/src/revocation_view.rs               *)
(*       RevocationSnapshot::is_revoked, RevocationView::is_revoked        *)
(* These are abstraction anchors registered in formal/proof-manifest.toml. *)
(*                                                                          *)
(* Bounded transitive closure encoding:                                     *)
(*  - Apalache 0.50.x cannot encode unbounded recursive set definitions    *)
(*    in finite SMT; instead the spec maintains the descendant relation    *)
(*    incrementally as a state variable. Delegate(child, root) updates     *)
(*    descendants[ancestor] for every ancestor whose descendant set        *)
(*    already contains root. This is bounded by |CapSet| = 6 and converges *)
(*    in at most |CapSet| Delegate steps because the relation is acyclic   *)
(*    (parent[child] = 0 guard).                                            *)
(*  - DescendsFrom(child, root) reads the precomputed descendants map      *)
(*    rather than recursing, keeping the SMT depth at 1.                   *)
(*  - --length=6 covers chains up to depth 6, beyond the |CapSet| bound;   *)
(*    no further unrolling is required for this state space.               *)
(*                                                                          *)
(* Proof obligation:                                                        *)
(*  - Spec Init implies SafetyInv.                                          *)
(*  - Delegate must preserve transitive-closure correctness: if the new    *)
(*    child is added to descendants[ancestor] for every ancestor that      *)
(*    contains root, the closure remains complete.                         *)
(*  - Revoke must flip can_allow[a][c] = FALSE for every c in              *)
(*    descendants[root], not just c = root. Otherwise descendants escape   *)
(*    the cut and the invariant is unsound.                                *)
(*                                                                          *)
(* Non-tautology evidence:                                                 *)
(*  - formal/apalache/_negative_tests/RevocationCutCompletenessBroken.tla *)
(*    mutates Revoke to flip can_allow only at the root cap. Apalache      *)
(*    must report SafetyInv violated; if it reports NoError, the property *)
(*    is unsound or the descendant closure is empty.                       *)
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

DirectParentInClosure ==
    \A child \in CapSet :
        parent[child] # 0 => child \in descendants[parent[child]]

SafetyInv ==
    /\ DomainsOK
    /\ RevocationCutCompleteness
    /\ DirectParentInClosure

=============================================================================
