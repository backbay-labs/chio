# Programmable Sovereignty Over Reversible Action

Draft submission directory for a new paper.

- Provisional title: "Programmable Sovereignty Over Reversible Action"
- Target venue: USENIX Security 2027 (Sept 2026 submission cycle)
- Backup venue: CCS 2027 (May 2027 submission cycle)
- Sibling to: `papers/programmable-sovereignty/` (the parent paper). The parent is finalized. Nothing here modifies it.

## Synopsis

The parent paper conditions constitutional amendment at the type level on a
backward-refinement witness: `enactAmendment` does not type-check without a
`ConstitutionalDelta` carrying `proofTerm : BackwardRefines new old`. The
response side of the same lifecycle (the positive enforcement act that
follows admission) is described in the parent's `crates/chio-chiodos-runtime`
admission hook but is not lifted to a corresponding type-level invariant.
The candidate here closes that asymmetry. An executive action is a type
that cannot be constructed without a positive TTL witness and an action
class tag; reversible variants carry an optional rollback receipt closing
the action chain; destructive variants reduce admission to bilateral
predicate intersection between a device polity and an operator polity.

The paper's empirical anchor is an endpoint substrate in which four
reversible variants (file quarantine, persistence disable, process-tree
suspend, egress restriction) have real OS executors with content-hash-gated
rollback constructors, and a fifth (process-tree terminate, irreversible)
has the executor but no rollback path. The empirical chapter measures the
four reversible paths; the destructive path is reported as a deployment
gap rather than a measurement.

## Status

### rfl-gate verdict on the headline composition theorem

The prior adversarial review correctly identified the structural risk: a
flagship theorem patterned on `amendment_admissible_iff_backward_refinement`
discharges to `rfl` for the same reason the parent's flagship does. The
candidate Lean statements in `theorems.lean` make the verdict explicit.

- **Candidate 1** (`bounded_executive_action_carries_ttl_and_rollback_slot`)
  is `rfl` by projection on the `ttlPositive` field. It restates a
  constructor precondition as a property of outputs. Retained as a
  definitional bridge, not as the headline.
- **Candidate 2** (`rollback_closes_or_ttl_window_active`) is `rfl` after
  unfolding `closedAt`. Retained as a definitional bridge.
- **Candidate 3** (`ttl_bounded_amendment_chain_preserves_baseline`) is the
  load-bearing candidate. It composes per-step `BackwardRefines` with the
  TTL-positivity invariant over a chain of TTL-bounded amendments. Proof
  shape is induction over the chain with a case split on whether `t`
  falls inside or outside each amendment's window. **Plausibly non-`rfl`
  in this author's reading**: the conclusion ranges over an instant `t`,
  the predicate involves the `activeAt` case analysis at each step, and
  the discharge requires threading per-step witnesses through. It is in
  the same difficulty class as the parent paper's `essential_preserved_chain`,
  which is itself non-`rfl` (it uses `induction` and step witnesses).
- **Candidate 4** (`rollback_admission_composes_with_refinement`) is a
  short proof that applies `BackwardRefines` (in the right direction)
  to the rollback receipt's admission witness. It is **not `rfl`** in
  the sense that it consumes the refinement hypothesis non-trivially,
  but it is a one-liner once the hypothesis is supplied. It is the
  supporting reduction the headline leans on.
- **Candidate 5** (`destructive_action_requires_bilateral_admission`) is
  a specialization of `treaty_admission_iff_predicate_intersection`. NOT
  `rfl`, but also not novel: it is the parent paper's theorem renamed.
  Retained as a typed bridge.

**Honest read:** Candidates 1 and 2 are `rfl` and inherit the parent's
worst critique. Candidates 3 and 4 are plausibly non-`rfl`, with
Candidate 3 as the headline. If, on closer inspection, Candidate 3
discharges to `rfl` (for instance, if the `activeAt` definition collapses
the trajectory to a single conditional whose two arms are both trivial),
the paper has no headline and should be killed. A short Lean session is
required to confirm the difficulty class; the present draft assumes
non-`rfl` based on the structural parallel to `essential_preserved_chain`.

### Empirical claims that rest on missing code

Per the response-engine code review at
`.planning/clawdstrike-chio-brainstorm/07-response-engine-code-review.md`,
the following deployment-side claims are at risk in the empirical chapter:

1. **Background TTL scheduler does not exist.** The `/expire` endpoint is
   present (`api_server.rs:18030`) but no `tokio::time::interval` or
   background task invokes it. "Terminates within its TTL" is therefore
   operator-dependent, not type-level. The headline candidate composition
   theorem is unfalsifiable against the current binary without a scheduler.
2. **Three of seven executors have no rollback constructor.** Process-tree
   terminate, revoke-grant, and collect-evidence have forward executors
   but no `execute_*_rollback`. The bilateral-destructive theorem applies
   as an obligation, not as a measurement.
3. **macOS Endpoint Security sensor is a stub.** `Monitor.swift` declares
   the entitlement but does not subscribe via `es_new_client`/`es_subscribe`.
   Sensor-state attestation on response receipts is bounded to the
   Network Extension verdict path, the tool-preflight admission hook, and
   the package-manager runtime guard.
4. **Ledger append happens after the side effect.** `fs::rename` and
   `libc::kill` precede `append_and_receipt_edr_response_execution`. A
   crash between effect and ledger leaves a live side effect with no
   execution record. A write-ahead ledger pattern closes this.

### Estimated submission readiness

Months to publishable polish on the Sept 2026 cycle:

- v0 draft (this directory): present.
- Lean discharge of Candidate 3 and Candidate 4: 2-3 weeks of focused
  Lean work, gating on whether Candidate 3 is non-`rfl` as assumed.
- TTL auto-expiry scheduler: 4-6 weeks of Rust work, gating on whether
  the empirical chapter is honest.
- Two missing rollback executors (terminate-process-tree, revoke-grant)
  with bilateral cosignature: 8-12 weeks of OS work plus operator-key
  custody design. Without these, the destructive-class theorem has no
  empirical anchor.
- macOS Endpoint Security extension's first real subscription: 4-6
  weeks; without this, the sensor-state attestation paragraph is
  theoretical.

Realistic minimum to a defensible submission: 4-5 months of focused
work after the rfl-gate is confirmed. The Feb 2026 USENIX Security
cycle is out of reach; Sept 2026 is the earliest defensible target, and
only if the missing executors and the TTL scheduler ship.

## Anthropic co-authorship note

The parent paper's deferred Anthropic outreach (Bowman / Perez / Grosse
/ Kaplan) is plausibly a tighter fit for this paper than for the parent.
The bounded-action invariant maps to agentic bounded-autonomy work; the
bilateral-cosignature reduction maps to human-in-the-loop oversight; the
agentic-AI thread in the Discussion section is a natural lead for an
Anthropic-affiliated co-author. The prior adversarial review countered
that those authors publish on alignment evaluation, scaling, mech
interp, and RLHF rather than on operational security; the rebuttal is
that the Responsible Scaling Policy team and the alignment-evaluation
infrastructure team have publication venues, and the paper's typed
substrate is a tool those teams could cite even when they do not
co-author. The recommendation is to defer the outreach until Candidate
3 is confirmed non-`rfl` and at least one missing executor has shipped.

## Files

- `paper.tex` - LaTeX shell, `article` class, light dependencies.
- `sections/01-introduction.tex` through `sections/10-conclusion.tex`.
- `theorems.lean` - draft theorem statements with `sorry` proofs. Not
  registered in any lakefile. This is a planning artifact.

## House rules inherited from the parent

- No em dashes anywhere.
- Voice rules: describe what IS, not project history. No "this paper",
  no "we extend", no internal version notes, no branch names, no counts
  of internal artifacts as headline content.
- `\codepath{...}` and `\thm{...}` macros defined at the top of `paper.tex`.
- Citations use placeholders; no `bib.bib` is written here.
