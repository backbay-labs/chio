-------------------------- MODULE RevocationPropagation --------------------------
(***************************************************************************)
(* RevocationPropagation - TLA+ model of Chio capability revocation        *)
(* propagation across authorities.                                          *)
(*                                                                          *)
(* The module exposes state variables, initialization, the next-state      *)
(* relation, and four named safety invariants:                             *)
(*                                                                          *)
(*   - NoAllowAfterRevoke                                                   *)
(*   - MonotoneLog                                                          *)
(*   - AttenuationPreserving                                                *)
(*   - RevocationFreshness                                                  *)
(*                                                                          *)
(* It also names the liveness property RevocationEventuallySeen and adds   *)
(* a weak-fairness conjunct to Spec so that pending propagation messages   *)
(* cannot be starved indefinitely. The fairness conjunct is                *)
(* WF_vars(PropagateAny) where PropagateAny is the top-level named action  *)
(* `pending # {} /\ \E m \in pending : Propagate(m)`. The named-action     *)
(* form is required because Apalache's tableau encoding (PDR-017) supports *)
(* WF_vars(<named action>) but does not support an existential quantifier  *)
(* nested directly under WF_vars.  Liveness is checked in the nightly      *)
(* formal-tla-liveness lane at PROCS=4, CAPS=8 via Apalache's              *)
(* `--temporal=` flag; the PR job continues to check only the safety       *)
(* invariants via `--inv=`.                                                 *)
(*                                                                          *)
(* Code mapping (full cross-reference in formal/MAPPING.md):               *)
(*   - revocation admission and evaluation                                 *)
(*     crates/kernel/chio-kernel/src/kernel/validation.rs                  *)
(*       ChioKernel::check_revocation                                      *)
(*       ChioKernel::validate_delegation_admission                         *)
(*     crates/core/chio-core-types/src/capability/attenuation.rs           *)
(*       validate_delegation_chain                                         *)
(*     crates/kernel/chio-kernel/src/kernel/evaluation/                    *)
(*       async_evaluation_core.rs                                          *)
(*       ChioKernel::evaluate_tool_call_async_with_session_context         *)
(*     crates/kernel/chio-kernel/src/kernel/responses/                     *)
(*       receipt_persistence.rs, ChioKernel::record_chio_receipt           *)
(*   - revocation view and freshness                                       *)
(*     crates/kernel/chio-kernel-core/src/revocation_view.rs               *)
(*       RevocationSnapshot, RevocationSnapshot::is_revoked,               *)
(*       RevocationView::install_if_newer, RevocationView::is_revoked      *)
(*     crates/trust/chio-revocation-oracle/src/freshness.rs                *)
(*       FreshnessConfig, verify_fresh_epoch_root                          *)
(*   - propagation                                                         *)
(*     crates/trust/chio-federation/src/revocation_gossip.rs               *)
(*       RevocationGossipPushQueue::enqueue_signed_root,                   *)
(*       RevocationGossipPushQueue::flush_batches_at,                      *)
(*       RevocationCatchupResponse::validate_response, respond_to_catchup *)
(*   - attenuation                                                         *)
(*     crates/core/chio-core-types/src/capability/scope.rs                 *)
(*       ChioScope::is_subset_of                                           *)
(*     crates/kernel/chio-kernel-core/src/normalized.rs                    *)
(*       NormalizedScope::is_subset_of                                     *)
(*   - append-only receipt storage                                         *)
(*     crates/platform/chio-store-sqlite/src/receipt_store/                *)
(*       evidence_retention.rs                                             *)
(*       SqliteReceiptStore::append_chio_receipt_returning_seq             *)
(*     crates/platform/chio-store-sqlite/src/receipt_store.rs              *)
(*       append_chio_receipt_tx                                            *)
(*   - signed observation trace projection                                *)
(*     crates/tooling/chio-trace-validate/src/map/revocation.rs            *)
(*     formal/tla/trace/TraceCheckRevocationPropagation.tla                *)
(* These are abstraction anchors registered in formal/proof-manifest.toml. *)
(* The storage anchors do not enforce strict timestamp monotonicity.       *)
(* MonotoneLog uses the model clock and ASSUME-OS-CLOCK at that boundary. *)
(* Post-dispatch credential disposition is outside this model. Changes to *)
(* that tail preserve the revocation gate and append-only verdict surface. *)
(*                                                                          *)
(* CONSTANTS PROCS, CAPS, and DEPTH_MAX are bounded integer counts (set    *)
(* by the MCRevocationPropagation.cfg companions at PROCS=4, CAPS=8,      *)
(* DEPTH_MAX=4 for both safety and nightly liveness. Larger bounds remain *)
(* candidates for a future TLC lane. Internal sets ProcSet and CapSet are *)
(* derived from PROCS and CAPS.                                             *)
(***************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    \* @type: Int;
    PROCS,     \* number of authority/process identifiers (must be >= 1)
    \* @type: Int;
    CAPS,      \* number of capability identifiers (must be >= 1)
    \* @type: Int;
    DEPTH_MAX  \* maximum delegation depth per (authority, cap) pair (>= 0)

ASSUME
    /\ PROCS     \in Nat
    /\ CAPS      \in Nat
    /\ DEPTH_MAX \in Nat
    /\ PROCS     >= 1
    /\ CAPS      >= 1

(***************************************************************************)
(* Internal index sets. Derived from the integer-valued CONSTANTS so the   *)
(* cfg (PROCS = 4, CAPS = 8) loads as integers.                            *)
(***************************************************************************)
ProcSet == 1..PROCS
CapSet  == 1..CAPS

(***************************************************************************)
(* Per-process current view of a capability's lifecycle state. Three      *)
(* values:                                                                 *)
(*   - "active"     - issued, not attenuated, not revoked                  *)
(*   - "attenuated" - delegated at least once with narrowed scope          *)
(*   - "revoked"    - terminal; no further allow receipts permitted        *)
(***************************************************************************)
States == {"active", "attenuated", "revoked"}

(***************************************************************************)
(* Verdict alphabet for receipt_log entries. "allow" or "deny" only; the  *)
(* protocol does not emit indeterminate receipts.                          *)
(***************************************************************************)
Verdicts == {"allow", "deny"}

(***************************************************************************)
(* Receipt record shape. seen_epoch is the authority's local rev_epoch    *)
(* observation at the time the verdict was issued; it lets               *)
(* NoAllowAfterRevoke reason about per-process causal histories rather    *)
(* than global state.                                                      *)
(***************************************************************************)
Receipt == [cap: CapSet, verdict: Verdicts, t: Nat, seen_epoch: Nat]

(***************************************************************************)
(* In-flight propagation message. Emitted by Revoke, consumed by          *)
(* Propagate. epoch carries the issuing authority's revocation timestamp. *)
(***************************************************************************)
Message == [from: ProcSet, to: ProcSet, cap: CapSet, epoch: Nat]

VARIABLES
    \* @type: Int -> (Int -> Str);
    state,        \* per-process current view: ProcSet -> CapSet -> States
    \* @type: Int -> (Int -> Int);
    depth,        \* delegation depth: ProcSet -> CapSet -> 0..DEPTH_MAX
    \* @type: Int -> (Int -> Int);
    rev_epoch,    \* per-proc revocation epoch; 0 means not-yet-seen-revoked
    \* @type: Int -> Seq({ cap: Int, verdict: Str, t: Int, seen_epoch: Int });
    receipt_log,  \* append-only audit log per process
    \* @type: Set({ from: Int, to: Int, cap: Int, epoch: Int });
    pending,      \* unordered set of in-flight propagation messages
    \* @type: Int;
    clock         \* monotonic clock, advanced by Revoke and Evaluate

vars == << state, depth, rev_epoch, receipt_log, pending, clock >>

(***************************************************************************)
(* Domain shape invariant. Not part of the four named safety invariants   *)
(* the gate greps for. Avoids Seq(_) and SUBSET Message constraints       *)
(* because Apalache 0.50.x rejects those as infinite-set predicates;     *)
(* per-element shape is enforced by the type annotations on VARIABLES    *)
(* and by the action shapes that produce values in those domains.        *)
(***************************************************************************)
DomainsOK ==
    /\ DOMAIN state       = ProcSet
    /\ DOMAIN depth       = ProcSet
    /\ DOMAIN rev_epoch   = ProcSet
    /\ DOMAIN receipt_log = ProcSet
    /\ \A a \in ProcSet :
         /\ DOMAIN state[a]     = CapSet
         /\ DOMAIN depth[a]     = CapSet
         /\ DOMAIN rev_epoch[a] = CapSet
         /\ \A c \in CapSet :
              /\ state[a][c]     \in States
              /\ depth[a][c]     \in 0..DEPTH_MAX
              /\ rev_epoch[a][c] \in Nat
    /\ clock \in Nat

(***************************************************************************)
(* Initial state: every (proc, cap) pair starts active, depth 0, no       *)
(* revocations observed, empty receipt logs, no in-flight propagations,   *)
(* clock at 1 (so seen_epoch = 0 unambiguously means "never seen revoked" *)
(* under NoAllowAfterRevoke).                                              *)
(***************************************************************************)
Init ==
    /\ state       = [a \in ProcSet |-> [c \in CapSet |-> "active"]]
    /\ depth       = [a \in ProcSet |-> [c \in CapSet |-> 0]]
    /\ rev_epoch   = [a \in ProcSet |-> [c \in CapSet |-> 0]]
    /\ receipt_log = [a \in ProcSet |-> << >>]
    /\ pending     = {}
    /\ clock       = 1

(***************************************************************************)
(* Attenuate(a, c): authority a delegates capability c with narrowed      *)
(* scope, bumping the delegation depth. Cannot attenuate a revoked cap.   *)
(* Does not advance the clock or emit a receipt. Bounded by DEPTH_MAX.    *)
(***************************************************************************)
Attenuate(a, c) ==
    /\ state[a][c] # "revoked"
    /\ depth[a][c] < DEPTH_MAX
    /\ depth' = [depth EXCEPT ![a][c] = @ + 1]
    /\ state' = [state EXCEPT ![a][c] = "attenuated"]
    /\ UNCHANGED << rev_epoch, receipt_log, pending, clock >>

(***************************************************************************)
(* Revoke(a, c): authority a revokes capability c locally, stamps the    *)
(* revocation epoch with the current clock value, and broadcasts a       *)
(* propagation message to every other authority. Idempotent on already-  *)
(* revoked caps via the guard.                                            *)
(***************************************************************************)
Revoke(a, c) ==
    /\ state[a][c] # "revoked"
    /\ state'     = [state     EXCEPT ![a][c] = "revoked"]
    /\ rev_epoch' = [rev_epoch EXCEPT ![a][c] = clock]
    /\ pending'   = pending \cup
        { [from |-> a, to |-> b, cap |-> c, epoch |-> clock] : b \in ProcSet \ {a} }
    /\ clock'     = clock + 1
    /\ UNCHANGED << depth, receipt_log >>

(***************************************************************************)
(* Propagate(m): consume an in-flight propagation message. If the        *)
(* message's epoch is strictly newer than the receiver's local view,     *)
(* update the receiver's rev_epoch and flip its state to "revoked".      *)
(* Otherwise the message is just absorbed (older or duplicate).          *)
(***************************************************************************)
Propagate(m) ==
    /\ m \in pending
    /\ pending' = pending \ {m}
    /\ IF m.epoch > rev_epoch[m.to][m.cap]
       THEN /\ rev_epoch' = [rev_epoch EXCEPT ![m.to][m.cap] = m.epoch]
            /\ state'     = [state     EXCEPT ![m.to][m.cap] = "revoked"]
       ELSE /\ UNCHANGED << rev_epoch, state >>
    /\ UNCHANGED << depth, receipt_log, clock >>

(***************************************************************************)
(* Evaluate(a, c): authority a evaluates capability c. Issues "allow" if  *)
(* and only if a has not yet observed any revocation epoch for c         *)
(* (rev_epoch = 0). Appends a receipt with the current seen_epoch and    *)
(* timestamp. Always advances the clock so receipts are timestamp-       *)
(* ordered (load-bearing for MonotoneLog).                                *)
(***************************************************************************)
Evaluate(a, c) ==
    LET v == IF rev_epoch[a][c] = 0 THEN "allow" ELSE "deny" IN
    /\ receipt_log' = [receipt_log EXCEPT ![a] =
         Append(@, [cap        |-> c,
                    verdict    |-> v,
                    t          |-> clock,
                    seen_epoch |-> rev_epoch[a][c]])]
    /\ clock' = clock + 1
    /\ UNCHANGED << state, depth, rev_epoch, pending >>

(***************************************************************************)
(* PropagateAny: existentially-quantified Propagate as a top-level named  *)
(* action so that weak fairness can be expressed without nesting an       *)
(* existential under WF_vars. Apalache's tableau-based temporal encoding  *)
(* (PDR-017) accepts WF_vars(<named action>) but does not support         *)
(* WF_vars(\E ... : <action>) because the existential under ENABLED       *)
(* defeats its SMT translation. Lifting the existential to a named        *)
(* action preserves the intended semantics: PropagateAny is enabled iff   *)
(* pending is non-empty, exactly the precondition the original           *)
(* WF_vars(\E m \in pending : Propagate(m)) was asserting.                *)
(***************************************************************************)
PropagateAny ==
    /\ pending # {}
    /\ \E m \in pending : Propagate(m)

(***************************************************************************)
(* Next-state relation. Disjunction over all action shapes. Existential  *)
(* quantifications are bounded by ProcSet, CapSet, and pending (a finite  *)
(* subset of Message at every reachable state).                           *)
(***************************************************************************)
Next ==
    \/ \E a \in ProcSet, c \in CapSet : Attenuate(a, c)
    \/ \E a \in ProcSet, c \in CapSet : Revoke(a, c)
    \/ \E a \in ProcSet, c \in CapSet : Evaluate(a, c)
    \/ PropagateAny

(***************************************************************************)
(* Spec is the temporal formula characterizing valid behaviors:            *)
(*                                                                          *)
(*   - Init: the initial-state predicate.                                   *)
(*   - [][Next]_vars: every step is either a Next-allowed action or a      *)
(*     stuttering step on vars.                                             *)
(*   - WF_vars(PropagateAny): weak fairness on the top-level named         *)
(*     action PropagateAny. PropagateAny is enabled exactly when pending   *)
(*     is non-empty; weak fairness then says that a continuously enabled   *)
(*     PropagateAny eventually fires, which is the load-bearing            *)
(*     assumption for RevocationEventuallySeen below. Apalache's           *)
(*     tableau-based fairness encoding (PDR-017) supports                  *)
(*     WF_vars(<named action>) but rejects WF_vars(\E ... : <action>);     *)
(*     PropagateAny is the named-action workaround.                         *)
(*                                                                          *)
(* Strong fairness is not required: PropagateAny is enabled whenever       *)
(* pending is non-empty, so the standard "continuously enabled implies     *)
(* eventually taken" weak-fairness rule suffices. Strengthening to SF      *)
(* would only be needed if some other action could disable PropagateAny    *)
(* by emptying pending infinitely often, which Revoke-broadcasts make      *)
(* impossible once any unseen revocation is in flight.                     *)
(***************************************************************************)
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(PropagateAny)

(***************************************************************************)
(*                          Safety invariants                              *)
(*                                                                          *)
(* The three names below MUST stay verbatim: the formal-tla CI lane       *)
(* greps for them by name, and formal/MAPPING.md cross-references them     *)
(* to Lean/Rust.                                                            *)
(***************************************************************************)

(***************************************************************************)
(* NoAllowAfterRevoke: every "allow" receipt was issued at a time when   *)
(* the issuing authority had not yet observed any revocation for that    *)
(* capability (seen_epoch = 0). Causal allow-before-revoke histories are  *)
(* admitted; allows after the issuer's local revoke-view are forbidden.   *)
(***************************************************************************)
NoAllowAfterRevoke ==
    \A a \in ProcSet :
        \A i \in 1..Len(receipt_log[a]) :
            LET r == receipt_log[a][i] IN
                r.verdict = "allow" => r.seen_epoch = 0

(***************************************************************************)
(* MonotoneLog: per-authority receipt timestamps are strictly increasing. *)
(* The append-only structural shape is enforced by every Evaluate using   *)
(* Append and no other action touching receipt_log. The strict t-order    *)
(* invariant additionally forbids logical reordering inside the sequence. *)
(***************************************************************************)
MonotoneLog ==
    \A a \in ProcSet :
        \A i, j \in 1..Len(receipt_log[a]) :
            i < j => receipt_log[a][i].t < receipt_log[a][j].t

(***************************************************************************)
(* AttenuationPreserving: depth stays bounded by DEPTH_MAX, and any cap   *)
(* in the "attenuated" state must have been delegated at least once       *)
(* (depth > 0). Ensures Attenuate is the only depth-incrementing action   *)
(* and that Revoke does not accidentally flip a fresh active cap into an  *)
(* attenuated-state-with-zero-depth contradiction.                        *)
(***************************************************************************)
AttenuationPreserving ==
    \A a \in ProcSet, c \in CapSet :
        /\ depth[a][c] \in 0..DEPTH_MAX
        /\ (state[a][c] = "attenuated" => depth[a][c] > 0)

(***************************************************************************)
(* RevocationFreshness: every recorded local revocation epoch fits in    *)
(* the past relative to the global clock. Concretely, for every          *)
(* authority a and capability c, if a's local rev_epoch[a][c] is         *)
(* non-zero (a has revoked c locally or absorbed a propagation), then    *)
(* that epoch value is strictly smaller than the global clock. Combined  *)
(* with MonotoneLog this discharges the oracle freshness gate: an        *)
(* observed revocation epoch never exceeds any clock value the model's   *)
(* actions could have produced.                                           *)
(*                                                                          *)
(* Apalache checks it in the same `--inv=` set as the other safety        *)
(* invariants.                                                             *)
(***************************************************************************)
RevocationFreshness ==
    \A a \in ProcSet, c \in CapSet :
        rev_epoch[a][c] # 0 => rev_epoch[a][c] < clock

RevocationStateCoupled ==
    \A a \in ProcSet, c \in CapSet :
        (rev_epoch[a][c] # 0) = (state[a][c] = "revoked")

(***************************************************************************)
(* SafetyInv: aggregate invariant referenced by                            *)
(* MCRevocationPropagation.cfg's INVARIANT line. Conjunction of the three *)
(* named safety invariants plus the RevocationFreshness invariant and     *)
(* DomainsOK.                                                              *)
(***************************************************************************)
SafetyInv ==
    /\ DomainsOK
    /\ NoAllowAfterRevoke
    /\ MonotoneLog
    /\ AttenuationPreserving
    /\ RevocationFreshness
    /\ RevocationStateCoupled

(***************************************************************************)
(*                          Liveness property                              *)
(*                                                                          *)
(* RevocationEventuallySeen is the named liveness property checked by the *)
(* nightly formal-tla-liveness lane. The name MUST stay verbatim: CI      *)
(* greps for it, the nightly job cites it via                              *)
(* --temporal=RevocationEventuallySeen (Apalache reserves --inv= for      *)
(* state invariants), and formal/MAPPING.md cross-references it back to   *)
(* the propagation-lag clause in spec/PROTOCOL.md.                         *)
(*                                                                          *)
(* Statement (PROCS/CAPS are integer-count CONSTANTS in this module so    *)
(* ProcSet and CapSet are finite): if any authority observes a non-zero   *)
(* local revocation epoch, the model eventually reaches a state where     *)
(* every authority has caught up to every observed revocation epoch.       *)
(*                                                                          *)
(* The property quantifies over (a, b, c) inside the named state          *)
(* predicates below rather than outside the leads-to operator: Apalache   *)
(* 0.50.1 rejects free variables bound outside `~>` ("SubstRule: Variable *)
(* a$1 is not assigned a value"), so the leads-to property must carry no  *)
(* temporal-bound variables.                                               *)
(*                                                                          *)
(* The leads-to (~>) operator is shorthand for                             *)
(*   P ~> Q  ==  [](P => <>Q)                                              *)
(* so the property reads: once any revocation has been observed, some     *)
(* later state satisfies the global catch-up predicate. The model admits  *)
(* only finitely many Revoke actions per bounded (authority, capability)  *)
(* pair, so this aggregate property is equivalent to the per-pair         *)
(* eventual catch-up obligation under the weak fairness assumption below. *)
(*                                                                          *)
(* The property is gated on WF_vars(PropagateAny) declared in Spec above. *)
(* Without that fairness conjunct the model admits behaviors where         *)
(* pending Propagate messages are starved forever and                      *)
(* RevocationEventuallySeen would not hold.                                 *)
(*                                                                          *)
(* The a = b case is trivially satisfied (rev_epoch[a][c] >=               *)
(* rev_epoch[a][c]) and is left in the quantifier rather than excluded.    *)
(***************************************************************************)
AnyRevocationObserved ==
    \E a \in ProcSet, c \in CapSet :
        rev_epoch[a][c] # 0

AllObservedRevocationsCaughtUp ==
    \A a, b \in ProcSet :
        \A c \in CapSet :
            rev_epoch[a][c] # 0 => rev_epoch[b][c] >= rev_epoch[a][c]

RevocationEventuallySeen ==
    AnyRevocationObserved ~> AllObservedRevocationsCaughtUp

==================================================================================
