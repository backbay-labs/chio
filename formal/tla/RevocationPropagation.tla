-------------------------- MODULE RevocationPropagation --------------------------
(***************************************************************************)
(* RevocationPropagation - TLA+ model of Chio capability revocation        *)
(* propagation across authorities.                                          *)
(*                                                                          *)
(* Source of truth for the design: planning trajectory phase doc            *)
(*   .planning/trajectory/03-capability-algebra-properties.md (Phase 3,    *)
(*   lines 137-256).                                                        *)
(*                                                                          *)
(* This module landed at M03.P3.T2 with state variables, initialization,   *)
(* the next-state relation, and the three named safety invariants:         *)
(*                                                                          *)
(*   - NoAllowAfterRevoke                                                   *)
(*   - MonotoneLog                                                          *)
(*   - AttenuationPreserving                                                *)
(*                                                                          *)
(* M03.P3.T3 extends the module with the named liveness property          *)
(* RevocationEventuallySeen and adds a weak-fairness conjunct to Spec so   *)
(* that pending propagation messages cannot be starved indefinitely.       *)
(* The fairness conjunct is WF_vars(PropagateAny) where PropagateAny is    *)
(* the top-level named action `pending # {} /\ \E m \in pending :          *)
(* Propagate(m)`. The named-action form is required because Apalache's     *)
(* tableau encoding (PDR-017) supports WF_vars(<named action>) but does    *)
(* not support an existential quantifier nested directly under WF_vars     *)
(* (the [cleanup-c9] follow-up replaced the former                         *)
(* WF_vars(\E m \in pending : Propagate(m)) with this lifted form).        *)
(* Liveness is checked in the nightly formal-tla-liveness lane             *)
(* (M03.P3.T4) at PROCS=4, CAPS=8 via Apalache's `--temporal=` flag; the   *)
(* PR job continues to check only the safety invariants via `--inv=`.      *)
(*                                                                          *)
(* Code mapping (full cross-reference in formal/MAPPING.md, landed at      *)
(* M03.P3.T5):                                                              *)
(*   - state, depth     -> crates/chio-core-types/src/capability.rs        *)
(*   - rev_epoch        -> crates/chio-kernel/src/capability_lineage.rs    *)
(*   - receipt_log      -> crates/chio-kernel/src/receipt_store.rs         *)
(*   - clock            -> kernel monotonic receipt counter                *)
(*                                                                          *)
(* CONSTANTS PROCS, CAPS, and DEPTH_MAX are bounded integer counts (set    *)
(* by the MCRevocationPropagation.cfg companion at PROCS=4, CAPS=8,        *)
(* DEPTH_MAX=4 for the PR job and PROCS=6, CAPS=16, DEPTH_MAX=4 for the    *)
(* nightly liveness lane). Internal index sets ProcSet and CapSet are     *)
(* derived from PROCS and CAPS. DEPTH_MAX matches the trajectory phase    *)
(* doc spec at .planning/trajectory/03-capability-algebra-properties.md   *)
(* (Phase 3, lines 137-256).                                               *)
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
(* T1-landed cfg (PROCS = 4, CAPS = 8) loads as integers.                  *)
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
(* Domain shape invariant. Not part of the three named safety invariants  *)
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
(* The three names below MUST stay verbatim - the M03.P3.T2 gate_check    *)
(* greps for them, the formal-tla CI lane (M03.P3.T4) cites them by name,  *)
(* and formal/MAPPING.md (M03.P3.T5) cross-references them to Lean/Rust.   *)
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
(* SafetyInv: aggregate invariant referenced by                            *)
(* MCRevocationPropagation.cfg's INVARIANT line. Conjunction of the three *)
(* named invariants plus DomainsOK. Defined here so the existing T1-landed *)
(* cfg loads against this module without modification.                    *)
(***************************************************************************)
SafetyInv ==
    /\ DomainsOK
    /\ NoAllowAfterRevoke
    /\ MonotoneLog
    /\ AttenuationPreserving

(***************************************************************************)
(*                          Liveness property                              *)
(*                                                                          *)
(* RevocationEventuallySeen is the named liveness property checked by the *)
(* nightly formal-tla-liveness lane (M03.P3.T4). The name MUST stay        *)
(* verbatim: the M03.P3.T3 gate_check greps for it, the nightly job cites *)
(* it via --temporal=RevocationEventuallySeen (corrected in [cleanup-c9]   *)
(* from the original --inv=, which Apalache reserves for state             *)
(* invariants), and formal/MAPPING.md (M03.P3.T5) cross-references it     *)
(* back to the propagation-lag clause in spec/PROTOCOL.md.                 *)
(*                                                                          *)
(* Statement (matching the phase doc verbatim, modulo PROCS/CAPS being    *)
(* integer-count CONSTANTS in this module so the pair-quantifier ranges   *)
(* over ProcSet/CapSet rather than the constants directly):                *)
(*                                                                          *)
(*   For every pair of authorities (a, b) and every capability c, if a's  *)
(*   local revocation epoch for c becomes non-zero (a has revoked, or has *)
(*   already absorbed a Revoke message for c), then b's local revocation  *)
(*   epoch for c eventually catches up to at least a's value.              *)
(*                                                                          *)
(* The leads-to (~>) operator is shorthand for                             *)
(*   P ~> Q  ==  [](P => <>Q)                                              *)
(* so the property reads: in every state where rev_epoch[a][c] is         *)
(* non-zero, some later state satisfies rev_epoch[b][c] >= rev_epoch[a][c].*)
(*                                                                          *)
(* The property is gated on WF_vars(PropagateAny) declared in Spec above. *)
(* Without that fairness conjunct the model admits behaviors where         *)
(* pending Propagate messages are starved forever and                      *)
(* RevocationEventuallySeen would not hold.                                 *)
(*                                                                          *)
(* The a = b case is trivially satisfied (rev_epoch[a][c] >=               *)
(* rev_epoch[a][c]) and is left in the quantifier rather than excluded so *)
(* the statement matches the phase doc verbatim.                            *)
(***************************************************************************)
RevocationEventuallySeen ==
    \A a, b \in ProcSet :
        \A c \in CapSet :
            rev_epoch[a][c] # 0 ~> rev_epoch[b][c] >= rev_epoch[a][c]

==================================================================================
