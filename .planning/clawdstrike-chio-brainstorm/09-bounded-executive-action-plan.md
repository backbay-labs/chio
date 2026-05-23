# Plan: Programmable Sovereignty Over Reversible Action

Converts the brainstorm convergence (concept 5 in `05-concepts-to-steal.md`, paper N1 in `06-next-papers-from-clawdstrike.md`) into a Lean draft and a §-by-§ outline. No proofs; no prose.

## Lean theorem draft (`ExecutiveAction.lean`)

Lifts the response side of the amendment cycle into the same type-level discipline `Intersection.lean` imposes on the input side. The construction mirrors `ConstitutionalDelta`: a structure that cannot be built without the witnesses that make the headline theorem true.

```lean
/-
  Bounded executive action with type-level TTL and rollback obligations.

  Mirrors the amendment lifecycle: `enactAmendment` requires a
  `ConstitutionalDelta` carrying a refinement witness; `ExecutiveAction`
  requires `ttlPositive : 0 < ttl` and an optional rollback receipt.

  Companion to paper N1. The headline theorem
  `bounded_executive_action_safety_requires_ttl_and_rollback` is the
  output-side counterpart of `amendment_admissible_iff_backward_refinement`.
-/

import Chio.Treaty.Intersection
import Chio.Treaty.PredicateLang

set_option autoImplicit false

namespace Chio.Treaty.ExecutiveAction

open Chio.Treaty
open Chio.Treaty.PredicateLang

/-- Duration of an executive action's authorised window, in seconds. -/
abbrev Duration := Nat

/-- Wall-clock instant at which a receipt was signed, in seconds since epoch. -/
abbrev Instant := Nat

/-- Action class. Destructive variants require bilateral cosignature;
    reversible variants are enactable under a single-party receipt-backed
    witness. -/
inductive ActionKind where
  | observation
  | restrictEgress
  | quarantineFile
  | disablePersistence
  | suspendProcessTree
  | terminateProcessTree
  | isolateNetwork
  | revokeGrant
  deriving Repr, BEq, DecidableEq

/-- A rollback receipt closes an action by referencing the original
    receipt id and the executor key that signed the rollback. -/
structure RollbackReceipt where
  rollbackOf : ReceiptId
  rolledBackAt : Instant
  executorKey : String
  deriving Repr, BEq, DecidableEq, Inhabited

/-- An executive action with issued-at, positive TTL (proof-carrying),
    action class, and either a rollback receipt or `none` (still-open).
    An unbounded act is not constructable. -/
structure ExecutiveAction where
  receiptId : ReceiptId
  issuedAt : Instant
  ttl : Duration
  ttlPositive : 0 < ttl
  actionKind : ActionKind
  rollback : Option RollbackReceipt
  deriving Inhabited

/-- Expiry derived from issued-at plus TTL. The invariant
    `expiresAt = issuedAt + ttl` is structural by definition. -/
def ExecutiveAction.expiresAt (act : ExecutiveAction) : Instant :=
  act.issuedAt + act.ttl

/-- Closed at `t` iff rollback receipt is present and ≤ t, or TTL
    window has elapsed by t. -/
def ExecutiveAction.closedAt (act : ExecutiveAction) (t : Instant) : Prop :=
  (∃ rb : RollbackReceipt, act.rollback = some rb ∧ rb.rolledBackAt ≤ t)
  ∨ act.expiresAt ≤ t

/-- Still-open before expiry and before any rollback receipt. -/
def ExecutiveAction.openAt (act : ExecutiveAction) (t : Instant) : Prop :=
  t < act.expiresAt ∧ act.rollback = none

/-- Destructive classes require bilateral quorum at admission. -/
def ActionKind.isDestructive : ActionKind -> Bool
  | .terminateProcessTree => true
  | .isolateNetwork => true
  | .revokeGrant => true
  | _ => false

/-- Witness pairing an action with its admitting constitution. -/
structure EnactmentWitness where
  action : ExecutiveAction
  admittingConstitution : SyntacticConstitution
  deriving Inhabited

/-- Build an enactment witness. By analogy to `enactAmendment`, the
    constructor *is the proof*: no witness exists without the typed
    fields the headline theorem reads. -/
def enactAction
    (act : ExecutiveAction)
    (c : SyntacticConstitution) : EnactmentWitness :=
  { action := act, admittingConstitution := c }

/-- Headline theorem: every witness has a strictly positive TTL and is
    either closed by a rollback receipt or remains open only before expiry.

    Proof sketch: destructure the witness, extract `ttlPositive`,
    case on `act.rollback`. The `none` branch reduces to the typed
    pre-expiry window; expiry closure is the runtime obligation in §5. -/
theorem bounded_executive_action_safety_requires_ttl_and_rollback
    (w : EnactmentWitness) :
    0 < w.action.ttl ∧
    ((∃ rb : RollbackReceipt, w.action.rollback = some rb) ∨
     (∀ t : Instant, t < w.action.expiresAt -> w.action.openAt t)) := by
  sorry

/-- Bridge: every well-typed action carries a positive-TTL witness.
    Trivial structural projection (`act.ttlPositive`); documents the
    proof-inventory mapping. -/
theorem bounded_iff_ttl_positive
    (act : ExecutiveAction) :
    0 < act.ttl := by
  sorry

/-- Rollback composes with amendment refinement: a rollback admissible
    under the pre-amendment constitution is admissible under the post-
    amendment constitution when the amendment is backward-refining.
    Supporting theorem 1.

    Proof sketch: rollback is a receipt id with an admission predicate.
    By `amendment_admissible_iff_backward_refinement` the new admits
    when old admits. Structural induction on the predicate list. -/
theorem rollback_admissible_under_refinement
    (rb : RollbackReceipt)
    (cOld cNew : SyntacticConstitution)
    (h_preserved :
      admits cOld rb.rollbackOf = true ->
      admits cNew rb.rollbackOf = true)
    (h_old_admits : admits cOld rb.rollbackOf = true) :
    admits cNew rb.rollbackOf = true := by
  exact h_preserved h_old_admits

/-- Bilateral quorum on destructive class: a destructive enactment
    witness admits only as treaty intersection between device polity
    and operator polity. The paper's load-bearing reduction.

    Proof sketch: by `treaty_admission_iff_predicate_intersection`,
    treaty admission is the conjunction of both polities' predicates;
    case-split on `actionKind.isDestructive`. -/
theorem destructive_requires_bilateral_admission
    (w : EnactmentWitness)
    (treaty : BilateralTreaty)
    (hDestructive : w.action.actionKind.isDestructive = true) :
    treatyAdmits treaty w.action.receiptId = true ↔
      treatyPredicateIntersection treaty w.action.receiptId = true := by
  exact treaty_admission_iff_predicate_intersection treaty w.action.receiptId

/-- TTL monotonicity under partition: under a degraded sensor witness
    (modeled as partition-contingency ladder rank), TTL cannot widen
    silently. Operationalises parent paper's ladder-floor stability on
    the response side: an extension beyond the partition-contingency
    bound requires a fresh admission, not a silent renewal.

    Proof sketch: induction on the extension chain; the partition-
    contingency rank predicate denies extension without a fresh
    receipt. Runtime obligation pending TTL-auto-expiry scheduler. -/
theorem ttl_monotone_under_partition
    (w : EnactmentWitness) (extendedTtl : Duration)
    (hExtend : extendedTtl > w.action.ttl) :
    ∃ freshWitness : EnactmentWitness,
      freshWitness.action.ttl = extendedTtl ∧
      freshWitness.action.actionKind = w.action.actionKind := by
  sorry

end Chio.Treaty.ExecutiveAction
```

## Theorem provability triage

| Theorem | Difficulty | Proof shape | PredicateLang.lean extension |
|---|---|---|---|
| `bounded_iff_ttl_positive` | easy | `rfl` after unfolding | none |
| `bounded_executive_action_safety_requires_ttl_and_rollback` | moderate | destructure witness, case on `rollback` | none |
| `rollback_admissible_under_refinement` | moderate | apply `amendment_admissible_iff_backward_refinement` plus structural induction on predicate list | none; uses existing `BackwardRefines` |
| `destructive_requires_bilateral_admission` | moderate-hard | reduces to `treaty_admission_iff_predicate_intersection` via an `ActionKind`-to-predicate bridge | add `actionPredicate : ActionKind -> Predicate` to `PredicateLang.lean` |
| `ttl_monotone_under_partition` | hard | induction over extension chain; ladder rank exposed as a `Predicate` | extend `AtomTag` with `ladderRankAtLeast (rank : Nat)`; the existing `ladderModeAtLeastRank` is close but not identical |

Two of the five are runtime-enforcement obligations rather than properties of the deployed binary: the headline theorem requires a TTL auto-expiry scheduler (currently missing), and `ttl_monotone_under_partition` requires the partition-contingency reconnect protocol that the parent paper's §9 already lists as future work. The Lean draft can land before those ship; the runtime obligations become §5 axioms.

## Paper outline (§-by-§)

### Abstract

The amendment side of constitutional admission is type-conditioned on a refinement witness; the response side has been informally constrained. This paper closes the asymmetry. Every authorised enforcement action carries a positive TTL, a rollback executor reference, and an acknowledgement obligation; admission of a destructive class reduces to bilateral predicate intersection between a device polity and an operator polity. Five theorems lift the response side to the same discipline as the amendment side: `bounded_executive_action_safety_requires_ttl_and_rollback`, `rollback_admissible_under_refinement`, `destructive_requires_bilateral_admission`, `ttl_monotone_under_partition`, `bounded_iff_ttl_positive`. The implementation grounds the model in an endpoint substrate with twelve action variants, four reversible OS executors, and a typed receipt taxonomy distinguishing request, execution, rollback, and acknowledgement. Evaluation reports TTL enforcement latency, rollback success rate, and acknowledgement round-trip on the network-extension verdict path. Load-bearing claim: human-in-the-loop endpoint response is bilateral predicate intersection in the same sense as cross-vendor tool calls, falling out of the same theorem.

### §1 Introduction

The parent paper's §4 admission relation has half a cycle. Constitutional change carries a refinement obligation; runtime denial carries a fail-closed obligation; the positive enforcement act has neither. The gap is named in the parent paper's §9 as "override authority for false negatives" and "operational observability." Bounded executive action with mandatory TTL and rollback closes both bullets and adds a positive response-side theorem. The contribution is not a new EDR; it is a typed-structure reduction of operational discipline to a constructable witness that cannot be built without TTL and rollback. Cites: parent paper §3, §4, §9; concept 5 in `05-concepts-to-steal.md`; paper N1 in `06-next-papers-from-clawdstrike.md`.

### §2 Background

Three threads. (i) The amendment lifecycle: `enactAmendment` requires `ConstitutionalDelta` carrying `proofTerm : BackwardRefines new old`. (ii) Endpoint detection-and-response systems and their informal response-engine discipline. TTL fields exist in vendor schemas; no system reduces TTL enforcement to a typed invariant, and rollback is documented as operational practice. (iii) Capability-bound action systems (Karger, EROS, seL4, Capsicum) approach the same problem from access control, not from constitutional admission. Cites: in-toto and SLSA from parent paper §3; the seL4 revocation lineage; recent agentic-AI-safety literature on bounded autonomy. The response-side gap is universal, not Chio-specific.

### §3 Substrate

What an endpoint polity is. Receipts are typed into seventeen families; four constitute the executive-action lifecycle: ResponseRequest, ResponseExecution, ResponseRollback, ResponseAcknowledgement. Twelve action variants partition into reversible (observe, warn, alert, collect-evidence, restrict-egress, quarantine-file, disable-persistence, suspend-process-tree, revoke-grant) and destructive (terminate-process-tree, isolate-network, irreversible-quarantine). Four reversible variants have OS executors: file quarantine via `fs::rename`, persistence disable via `fs::rename`, process-tree suspension via SIGSTOP, egress restriction via the network-extension policy file. The trust ladder's receipt-backed floor blocks destructive variants below it. Anchoring, selective disclosure, and capability attenuation inherit from the parent paper. The section closes with the bilateral DSSE structure on a destructive action: two independent signers (device-polity key, operator-polity key) binding the same canonical receipt body. Empirical anchors: the seventeen-family receipt taxonomy in `clawdstrike-policy-event/src/edr.rs`; the network-extension verdict path in `ContentFilterProvider.swift`; the four OS executors in the executor module.

### §4 Model

Four paragraphs over `ExecutiveAction.lean`.

*Bounded action.* The `ExecutiveAction` structure cannot be constructed without `ttlPositive : 0 < ttl`. The headline theorem \thm{bounded_executive_action_safety_requires_ttl_and_rollback} says every enactment witness either has a rollback receipt closing it or remains in its TTL window. The definitional bridge \thm{bounded_iff_ttl_positive} ties the type-level field to the propositional claim.

*Rollback composition.* \thm{rollback_admissible_under_refinement} says a rollback admissible under the pre-amendment constitution is admissible under the post-amendment constitution whenever the amendment is backward-refining. The runtime-side counterpart of \thm{amendment_admissible_iff_backward_refinement}; passes through the same `BackwardRefines` witness.

*Bilateral destructive admission.* \thm{destructive_requires_bilateral_admission} reduces human-in-the-loop endpoint response to treaty intersection. A destructive action admits only if device-polity and operator-polity predicates jointly admit; the same theorem as \thm{treaty_admission_iff_predicate_intersection} restricted to destructive `ActionKind`. Not new EDR engineering; a typed formulation of the bilateral cosignature requirement that every existing system enforces by policy.

*TTL monotonicity under partition.* \thm{ttl_monotone_under_partition} composes ladder-floor stability with the bounded-action invariant. Under partition-contingency mode, a TTL extension cannot widen silently; the proof exposes the ladder rank as a predicate and rides on the parent paper's ladder-floor stability theorem.

### §5 Implementation

(i) The Rust enforcement crate. Twelve action variants in `EndpointDecisionAction`; the executor module dispatches reversible variants to OS calls; destructive variants compile-error without bilateral cosignature. Type-level invariants map to Rust struct fields via the proof-manifest bridge. (ii) The TTL scheduler obligation. The Lean model requires a positive TTL; the runtime requires a background task calling `/expire` when the window elapses. The current binary does not ship the scheduler; this section names it as the load-bearing runtime obligation. (iii) The four-receipt grammar. Every enactment emits a request receipt; the executor emits an execution receipt; on rollback or expiry, a rollback or acknowledgement receipt closes the chain. This is the empirical anchor for the headline theorem.

### §6 Evaluation

Three measurements achievable on the current binary. (i) TTL enforcement latency: from `/expire` to executor completion across the four reversible variants. Expected numbers: microseconds for `fs::rename`, network-extension policy reload, SIGCONT. (ii) Rollback executor success rate: fraction of fixture-corpus rollbacks completing within their declared TTL. (iii) Acknowledgement round-trip: executor completion to signed acknowledgement receipt. Corpus is the parent paper's replay-fixture set; destructive variants are excluded because executors are absent for terminate-process-tree, isolate-network, revoke-grant. The macOS Endpoint Security sensor stub bounds the empirical chapter to the network-extension verdict path, the tool-preflight admission hook, and the package-manager runtime guard. Numbers come from the fixture corpus translated into bilateral DSSE envelopes plus the live NE flow verdict path.

### §7 Discussion

Three threads. (i) Bounded executive action and constitutional emergency powers. The amendment lifecycle requires backward refinement; emergency powers break refinement and are recorded as explicit crisis artifacts. Bounded action does not change that story; it adds a response-side discipline applying to admission-time enforcement, not constitutional change. The two compose: an emergency amendment may authorise a new class of executive action; the action itself remains bounded. (ii) Hart conditions (b)+(c) and operational uptake. Hart's sociological question is whether officials apply the rule of recognition; bounded action makes officials' obligations machine-checkable. An operator who fails to cosign a destructive action does not delay an alert; the action does not admit. Strengthening, not substitute, for the sociological question. (iii) Agentic-AI-safety direction. An AI agent taking a destructive action without a paired rollback is exactly the bounded-action failure mode. The bilateral-cosignature reduction applies: an agent's destructive action admits only with a second-party predicate (operator polity, deploying-organisation polity, third-party safety auditor). Not a new safety claim; a typed substrate for safety claims other systems make informally.

### §8 Related Work

Four blocks. (i) Capability revocation in operating systems (EROS, seL4, Capsicum): bounded action shares revocation semantics, adds the constitutional-admission layer. (ii) Endpoint detection-and-response engines: bounded action shares the four-receipt grammar, adds the type-level invariant. (iii) Workflow-engine compensation and sagas: bounded action shares the rollback obligation, adds the bilateral-cosignature reduction for destructive admission. (iv) Anchored capability tokens (Macaroons, biscuits): bounded action shares attenuation discipline (inherited from parent paper), adds the response-side TTL invariant those systems leave to the runtime.

### §9 Limitations

Five bullets. (i) macOS Endpoint Security sensor stub. The current binary does not subscribe to ES events; the empirical chapter is bounded to the NE verdict path, the tool-preflight hook, and the package-manager runtime guard. The sensor-state attestation primitive (brainstorm concept 1) is theoretical, not measured. (ii) TTL auto-expiry scheduler is missing. The Lean theorem requires a positive TTL; the runtime relies on operator-triggered `/expire`. The headline theorem stands as a runtime-enforcement obligation discharged by the implementation refinement program (parent paper §9). (iii) Bilateral cosignature party-independence problem. Two kernels under a single actor satisfy two-key DSSE but not party-independence. Re-inherited from the parent paper; the bounded-action paper narrows but does not solve it. The destructive-class reduction is sharper than the cross-vendor reduction because the operator polity is institutionally distinct from the device polity in any reasonable deployment. (iv) Destructive-variant executors absent for terminate-process-tree, isolate-network, revoke-grant. The evaluation excludes those variants; the theorems apply as obligations but not measurements. (v) Two-step rollback chains (rollback of rollback) are unmodeled. `RollbackReceipt` has a single `rollbackOf` field; a chain requires an inductive structure not introduced here.

### §10 Conclusion

Amendment side and response side now share a type-level discipline. `ConstitutionalDelta` carries a refinement witness; `ExecutiveAction` carries a TTL witness and an optional rollback receipt. The headline theorem is the response-side counterpart of `amendment_admissible_iff_backward_refinement`. The bilateral-destructive reduction makes human-in-the-loop endpoint response a special case of treaty intersection; the substrate already supports it. A closure of an asymmetry the parent paper itself named.

## Empirical chapter (what is actually measurable today)

Three numbers the current binary can produce. (i) TTL enforcement latency on the NE verdict path: from policy-file write to verdict change observed by `handleNewFlow`. OS plumbing is real; the measurement is a stopwatch around policy reload. (ii) Rollback executor success rate on file quarantine, persistence disable, process suspension: each is `fs::rename` or SIGCONT; the success rate is the fraction of fixture-corpus rollbacks completing without error. (iii) Acknowledgement round-trip latency: executor completion to signed acknowledgement receipt. The signing path is Ed25519 over canonical JSON; latency is dominated by canonical-JSON serialisation.

Three numbers requiring code to ship. (i) Sensor-to-decision latency: requires the macOS ES extension to actually subscribe; the current Monitor.swift is a state accountant, not an event source. (ii) Destructive-variant executor latency: requires implementing terminate-process-tree, isolate-network, revoke-grant executors. (iii) TTL auto-expiry latency: requires the missing scheduler that invokes `/expire` automatically.

The honest empirical chapter is the first three numbers; the second three are §9 future-work bullets.

## Sequencing

New paper N1, no replacement for paper 1-5. `06-next-papers-from-clawdstrike.md` already targets USENIX Security 2027 full track. USENIX Security 2027 has multiple submission cycles; the Feb 2026 cycle cannot accommodate this paper because (a) the macOS ES extension has not shipped, so the empirical chapter is incomplete, and (b) the TTL auto-expiry scheduler is missing, so the headline theorem is a runtime obligation, not a measured property. Realistic target: the Sept 2026 cycle (Aug 2027 conference); CCS 2027 (May 2027 submission, Nov 2027 conference) as backup. The Feb 2026 short-paper cycle is the parent paper's paper 2 (bilateral receipts), not this one.

Dependencies before submission. (i) TTL auto-expiry scheduler, so the headline theorem is measurable. (ii) At least one destructive-variant executor with a bilateral cosignature path, so `destructive_requires_bilateral_admission` has an empirical anchor beyond the reversible four. (iii) The macOS ES extension's first real subscription, so sensor-state attestation is not entirely theoretical. None block the Lean draft; all block the empirical chapter.

Co-author candidates. The parent paper's deferred Anthropic memo (Bowman / Perez / Grosse / Kaplan) is a *better* fit for this paper than for parent v2. The bounded-action invariant maps directly to agentic-AI bounded autonomy; the bilateral-cosignature reduction maps to human-in-the-loop oversight; the agentic-safety thread in §7 is the natural lead for an Anthropic-affiliated co-author. Parent v2 is broader (anchoring, BBS, selective disclosure) and harder to co-author cleanly; this paper is narrower and tighter. Recommendation: defer the Anthropic outreach from parent v2 to this paper.

## What the parent paper inherits from this paper

Two §9 bullets retire or rewrite. (i) "Override authority for false negatives": the bounded-action structure names what the override is (a fresh enactment witness with a new TTL and a new rollback executor), the crisis artifact (denial receipt then enactment-witness receipt), and the audit path (the four-receipt grammar). (ii) "Operational observability": the four-receipt grammar plus the acknowledgement obligation is a non-leaking telemetry path. Every executive action emits four receipts whose canonical bytes a verifier-owned correlator can ingest. One assumption-table row may be added: "Bounded-action receipts faithfully witness OS executor completion," residual risk: "an executor that signs an acknowledgement without performing the OS call collapses the witness to self-report; out-of-band executor-coverage audit is the recovery path." Lean inventory gains five theorems, assumption ledger gains one row, two §9 bullets retire. Net: the parent paper's response-side gap is named by name in the new paper, not absorbed into the implementation-refinement program.
