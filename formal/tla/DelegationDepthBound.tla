-------------------------- MODULE DelegationDepthBound --------------------------
(***************************************************************************)
(* DelegationDepthBound - TLA+ model of Chio recursive delegation chains   *)
(* and the revocation-as-cut property.                                      *)
(*                                                                          *)
(* Source of truth for the design: planning trajectory phase doc            *)
(*   .planning/trajectory-2/04-recursive-delegation-revocation-oracle.md   *)
(*   (P4 section, theorems and Apalache invariants).                       *)
(*                                                                          *)
(* This module landed at M04.P4.T4 with state variables, initialization,   *)
(* the next-state relation, and the three named safety invariants:         *)
(*                                                                          *)
(*   - DepthBoundedByRoot                                                   *)
(*   - AttenuatedAtEachStep                                                 *)
(*   - RevokedSubtreeNotObservable                                          *)
(*                                                                          *)
(* Companion config: formal/tla/MCDelegationDepthBound.cfg pins DEPTH_MAX  *)
(* and PEERS to the small finite values the PR Apalache lane runs at       *)
(* (DEPTH_MAX = 4, PEERS = 3). The PR Apalache safety job scans this       *)
(* module via `apalache-mc check --config=...                              *)
(* --inv=DepthBoundedByRoot,AttenuatedAtEachStep,RevokedSubtreeNotObservable *)
(* --length=10`. Apalache 0.50.x accepts a comma-separated invariant list. *)
(*                                                                          *)
(* Code mapping (full cross-reference in formal/MAPPING.md, M04.P4.T6):    *)
(*   - links, attenuation -> crates/chio-core-types/src/capability.rs      *)
(*                            (DelegationLink, ScopeAttenuation,           *)
(*                             validate_delegation_chain)                   *)
(*   - revoked          -> crates/chio-revocation-oracle/src/api.rs        *)
(*   - observed         -> crates/chio-kernel-core/src/revocation_view.rs  *)
(*                          (RevocationView::is_revoked)                   *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    \* @type: Int;
    DEPTH_MAX,  \* maximum delegation depth (>= 1)
    \* @type: Int;
    PEERS       \* number of peer authorities participating (>= 1)

ASSUME
    /\ DEPTH_MAX \in Nat
    /\ PEERS     \in Nat
    /\ DEPTH_MAX >= 1
    /\ PEERS     >= 1

(***************************************************************************)
(* Internal index sets. PeerSet ranges over the participating authorities; *)
(* LinkIdSet ranges over delegation-link identifiers. We bound the link    *)
(* universe at PEERS * DEPTH_MAX so the model has a finite state space    *)
(* under Apalache's symbolic encoding. Id 0 is reserved as a sentinel for *)
(* "no parent" (root mints).                                               *)
(***************************************************************************)
PeerSet     == 1..PEERS
LinkIdSet   == 1..(PEERS * DEPTH_MAX)
LinkIdSet0  == LinkIdSet \cup {0}

(***************************************************************************)
(* Each delegation link record:                                             *)
(*   - minted     - TRUE once the link has been issued; FALSE in the       *)
(*                  initial all-fields-zero placeholder state.             *)
(*   - parent     - link id of the parent in the delegation DAG; 0 means   *)
(*                  the link is a root mint or a placeholder (minted=FALSE).*)
(*   - peer       - which authority owns the local view of this link.     *)
(*   - depth      - delegation depth from the root; 0 for roots.          *)
(*   - attenuated - TRUE iff the child scope is strictly weaker than its   *)
(*                  parent.  Roots are conventionally `attenuated = TRUE`. *)
(***************************************************************************)

VARIABLES
    \* @type: Int -> { minted: Bool, parent: Int, peer: Int, depth: Int, attenuated: Bool };
    links,        \* total function LinkIdSet -> Link record
    \* @type: Set(Int);
    revoked,      \* set of link ids the issuing authority has marked revoked
    \* @type: Int -> Set(Int);
    observed      \* per-peer observed-revoked set: PeerSet -> SUBSET LinkIdSet

vars == << links, revoked, observed >>

(***************************************************************************)
(* Domain shape invariant. Apalache 0.50.x rejects Seq(_) and SUBSET S    *)
(* as predicates over infinite sets; per-element shape is enforced by the *)
(* actions that produce values.                                            *)
(***************************************************************************)
DomainsOK ==
    /\ DOMAIN links     = LinkIdSet
    /\ revoked          \subseteq LinkIdSet
    /\ DOMAIN observed   = PeerSet
    /\ \A p \in PeerSet : observed[p] \subseteq LinkIdSet

(***************************************************************************)
(* Initial state: links is the all-placeholders function (every entry has *)
(* minted = FALSE), no revocations recorded, no peer observations.        *)
(***************************************************************************)
Init ==
    /\ links = [id \in LinkIdSet |->
                  [minted     |-> FALSE,
                   parent     |-> 0,
                   peer       |-> 1,
                   depth      |-> 0,
                   attenuated |-> TRUE]]
    /\ revoked  = {}
    /\ observed = [p \in PeerSet |-> {}]

(***************************************************************************)
(* MintRoot(id, peer): mint a fresh root capability owned by `peer` at    *)
(* delegation depth 0.  No parent.                                         *)
(***************************************************************************)
MintRoot(id, peer) ==
    /\ id \in LinkIdSet
    /\ links[id].minted = FALSE
    /\ peer \in PeerSet
    /\ links' = [links EXCEPT ![id] =
                   [minted     |-> TRUE,
                    parent     |-> 0,
                    peer       |-> peer,
                    depth      |-> 0,
                    attenuated |-> TRUE]]
    /\ UNCHANGED << revoked, observed >>

(***************************************************************************)
(* Delegate(child, parentId, peer, atten): mint a new delegation link with *)
(* parentId as its parent.  The new depth is the parent's + 1, capped at  *)
(* DEPTH_MAX (the delegation depth ceiling enforced by                    *)
(* validate_delegation_chain in chio-core-types).                          *)
(***************************************************************************)
Delegate(child, parentId, peer, atten) ==
    /\ child  \in LinkIdSet
    /\ links[child].minted = FALSE
    /\ parentId \in LinkIdSet
    /\ links[parentId].minted = TRUE
    /\ peer   \in PeerSet
    /\ atten \in BOOLEAN
    /\ atten = TRUE  \* Capability::delegate fails closed when the child scope
                     \* is not strictly weaker than the parent: non-attenuating
                     \* mint requests are rejected before the receipt is signed.
    /\ links[parentId].depth + 1 <= DEPTH_MAX
    /\ links' = [links EXCEPT ![child] =
                   [minted     |-> TRUE,
                    parent     |-> parentId,
                    peer       |-> peer,
                    depth      |-> links[parentId].depth + 1,
                    attenuated |-> atten]]
    /\ UNCHANGED << revoked, observed >>

(***************************************************************************)
(* Revoke(id): the issuing authority marks link `id` as revoked.  Once    *)
(* revoked, the link cannot be un-revoked (revocation is monotonic).      *)
(***************************************************************************)
Revoke(id) ==
    /\ id \in LinkIdSet
    /\ links[id].minted = TRUE
    /\ id \notin revoked
    /\ revoked' = revoked \cup {id}
    /\ UNCHANGED << links, observed >>

(***************************************************************************)
(* Propagate(p, id): peer `p` observes that link `id` has been revoked.   *)
(* Once observed, the peer's verifier MUST deny dispatch on that link.    *)
(***************************************************************************)
Propagate(p, id) ==
    /\ p  \in PeerSet
    /\ id \in LinkIdSet
    /\ links[id].minted = TRUE
    /\ id \in revoked
    /\ id \notin observed[p]
    /\ observed' = [observed EXCEPT ![p] = @ \cup {id}]
    /\ UNCHANGED << links, revoked >>

(***************************************************************************)
(* Next-state relation. Disjunction over the four action shapes.          *)
(***************************************************************************)
Next ==
    \/ \E id \in LinkIdSet, peer \in PeerSet         : MintRoot(id, peer)
    \/ \E child \in LinkIdSet, parentId \in LinkIdSet,
         peer \in PeerSet, atten \in BOOLEAN          : Delegate(child, parentId, peer, atten)
    \/ \E id \in LinkIdSet                            : Revoke(id)
    \/ \E p \in PeerSet, id \in LinkIdSet             : Propagate(p, id)

Spec ==
    /\ Init
    /\ [][Next]_vars

(***************************************************************************)
(*                          Safety invariants                              *)
(*                                                                          *)
(* The three names below MUST stay verbatim - the M04.P4.T4 gate_check    *)
(* greps for them, the formal-tla CI lane cites them by name, and          *)
(* formal/MAPPING.md (M04.P4.T6) cross-references them to Lean/Rust.      *)
(***************************************************************************)

(***************************************************************************)
(* DepthBoundedByRoot: every minted delegation link sits at depth at most  *)
(* DEPTH_MAX, and its depth equals its parent's depth + 1 unless it is a   *)
(* root (parent = 0, depth = 0).  Mirrors validate_delegation_chain's      *)
(* chainWithinDepth check.                                                  *)
(***************************************************************************)
DepthBoundedByRoot ==
    \A id \in LinkIdSet :
        links[id].minted = TRUE =>
            /\ links[id].depth \in 0..DEPTH_MAX
            /\ (links[id].parent = 0 => links[id].depth = 0)
            /\ (links[id].parent # 0 =>
                /\ links[id].parent \in LinkIdSet
                /\ links[links[id].parent].minted = TRUE
                /\ links[id].depth = links[links[id].parent].depth + 1)

(***************************************************************************)
(* AttenuatedAtEachStep: every minted link must mark itself attenuated     *)
(* relative to its parent.  Roots are vacuously attenuated.  Mirrors       *)
(* Capability::delegate's pre-mint scope-subset check.                     *)
(***************************************************************************)
AttenuatedAtEachStep ==
    \A id \in LinkIdSet :
        links[id].minted = TRUE => links[id].attenuated = TRUE

(***************************************************************************)
(* RevokedSubtreeNotObservable: every link a peer has observed as revoked *)
(* must in fact be in the issuing authority's revoked set.  Equivalently: *)
(* no peer can observe a revocation that has not been issued.  Mirrors    *)
(* RevocationView::install_if_newer's monotone-epoch fail-closed check.   *)
(***************************************************************************)
RevokedSubtreeNotObservable ==
    \A p \in PeerSet : observed[p] \subseteq revoked

(***************************************************************************)
(* SafetyInv: aggregate invariant referenced by                            *)
(* MCDelegationDepthBound.cfg's INVARIANT line. Conjunction of the three  *)
(* named invariants plus DomainsOK.                                       *)
(***************************************************************************)
SafetyInv ==
    /\ DomainsOK
    /\ DepthBoundedByRoot
    /\ AttenuatedAtEachStep
    /\ RevokedSubtreeNotObservable

==================================================================================
