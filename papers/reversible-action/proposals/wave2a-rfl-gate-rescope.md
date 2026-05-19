# Wave 2A: rfl-gate-driven fixes to Candidate 3 and Candidate 4

Build: 0 errors, 15 pages.

## 1. Weaken `h_chain_base` to remove the trivialization risk

Wave 1A finding #6 (item 2): the equality form
`h_chain_base : ∀ a ∈ chain, a.delta.old = baseline` nearly trivializes
the post-expiry arm of Candidate 3. `activeAt a t = a.delta.old =
baseline` reduces to `BackwardRefines baseline baseline`, which
discharges by reflexivity; only the in-window arm carries substance.

Original statement:

```
(h_chain_base : ∀ a ∈ chain, a.delta.old = baseline)
```

New statement:

```
(h_chain_base : ∀ a ∈ chain, BackwardRefines a.delta.old baseline)
```

Rationale: this is Wave 1A's recommended Option A. Both arms now
consume `h_chain_base` as a `BackwardRefines` witness rather than as a
substitutable equality. Outside the window the conclusion is the
hypothesis applied directly; inside the window the conclusion composes
the per-step witness with the hypothesis through `BackwardRefines`
transitivity. The headline-theorem framing is preserved; the
substantive content is genuine across both arms. Proof body remains
`sorry` (README acknowledges 2-3 weeks of focused Lean work).

## 2. Rescope §4 prose to match the corrected theorem

Wave 1A finding #1 (caveat) and finding #6 (item 3): the §4 phrasing
"structurally inductive over the chain" and "induction on the chain"
overclaims. The Lean statement is pointwise over `a ∈ chain` under a
universal quantifier, not an induction over an evolving state.

Original phrase, §4 line 76-79:

> Both theorems are structurally inductive over the chain rather than
> definitional on a single step. The discharge in each case threads
> the per-step witness through the case analysis on the inductive
> variable.

New phrase, §4 line 75-80:

> The parent theorem ranges over receipts and a chain of constitutions
> and is structurally inductive over the chain; this theorem ranges
> over instants and a chain of TTL-bounded amendments and discharges
> pointwise per amendment with a case split on the TTL window.

The proof-shape paragraph is also rewritten to name the two hypotheses
separately and describe both arms as substantive consumers of
witnesses (no longer reflexivity on either side). The claim that both
arms "consume the per-step witnesses as data rather than discharging
by reflexivity" is now stated explicitly.

Rationale: Wave 1A's verdict that the rfl-gate is favorable but the
inductive framing is overclaimed. The corrected prose matches the
weakened hypothesis from Fix 1 and acknowledges pointwise quantification.

## 3. Closure-to-syntactic bridge for Candidate 4

Wave 1A finding #3: Candidate 3 ranges over `Constitution` via
`BackwardRefines`; Candidate 4 ranges over `SyntacticConstitution` via
`admits`. The two do not mechanically compose without the bridge that
lives in `PredicateLang.lean`. Wave 1A also flagged the first
Candidate 4 variant (`rollback_receipt_admissible_across_amendment`)
as dead weight: an unused `_h_refines` parameter and a tautological
conjunction.

Lean change: dropped the dead-weight variant entirely. Added a stub
`closure_to_syntactic_admission_bridge` that states the bridge as a
hypothesis-fed equivalence between `constitutionAllows cClosure rid =
true` and `admits cSyntactic rid = true`. Doc comment cites the
parent paper's `PredicateLang.lean` for the actual discharge.

§4 change: added a paragraph to the rollback-admissibility section
acknowledging that the composition theorem ranges over
`Constitution` while the rollback reduction ranges over
`SyntacticConstitution`, that the parent paper's `PredicateLang`
supplies the soundness bridge, and that "the substrate inherits it
from `PredicateLang`" rather than reproving it here.

Rationale: Wave 1A's Option A. The contribution claim is preserved
(Candidate 4 exists and composes with the headline) while the bridge
itself is honestly attributed to the parent substrate.

## 4. §4 line 92 voice fix

Wave 1C finding #2: §4 line 92 "The theorem's role in the paper is
the load-bearing reduction" treats the article as artifact.

Original, line 91-93:

> The theorem's role in the paper is the load-bearing reduction the
> headline composition leans on

New, in the rewritten paragraph:

> The reduction supplies the rollback-preservation step the headline
> composition leans on

Rationale: describes what the reduction supplies, not what role the
theorem plays in a project artifact. Matches the README rule
"Describe what IS, not project history".
