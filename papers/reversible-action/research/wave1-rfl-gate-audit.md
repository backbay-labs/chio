# Wave 1A: rfl-gate audit of theorem candidates

## 1. Candidate 3 (`ttl_bounded_amendment_chain_preserves_baseline`): actually non-`rfl`?

The Lean statement:

```
theorem ttl_bounded_amendment_chain_preserves_baseline
    (baseline : Constitution) (chain : List TtlBoundedAmendment)
    (h_chain_base    : ∀ a ∈ chain, a.delta.old = baseline)
    (h_chain_refines : ∀ a ∈ chain, BackwardRefines a.delta.new a.delta.old)
    (t : Instant) :
    ∀ a ∈ chain, BackwardRefines (a.activeAt t) baseline := by sorry
```

`activeAt` is `if a.issuedAt + a.ttl ≤ t then a.delta.old else a.delta.new`. `BackwardRefines new old` unfolds to `∀ rid, constitutionAllows new rid -> constitutionAllows old rid`. The statement does not collapse to `rfl`: the conclusion is quantified over `a` and `t`, the `activeAt` conditional needs an `if`-case split, and the two arms use distinct hypotheses (`h_chain_base` for the post-expiry arm, `h_chain_refines` for the in-window arm). A plausible proof is `intro a ha t; unfold activeAt; split_ifs with hle`, rewrite by `h_chain_base a ha`, apply `h_chain_refines`. Four to eight tactic lines, not `rfl`.

Verdict: non-`rfl`. Caveat: the conclusion is pointwise over `a ∈ chain`, not inductive. The "structural parallel to `essential_preserved_chain`" framing in §4 and the README overstates this; the actual obligation is one case split per element under a universal quantifier.

## 2. Candidates 1 and 2: framed as definitional bridges in the prose?

Candidate 1 is `(act : ExecutiveAction) : 0 < act.ttl := act.ttlPositive`, a field projection. Candidate 2 is a one-step `by_cases` on `act.expiresAt ≤ t`. Both are tagged `rfl`-class in the Lean comments.

§4 handles this honestly. The executive-action paragraph names Candidate 2 with "discharges to \emph{rfl} after case analysis on the rollback option. The bridge is not the headline theorem; it documents the relationship between the type-level fields and the propositional closure claim, in the same role \thm{amendment_admissible_iff_backward_refinement} plays for the amendment side of the parent paper." Candidate 1 is folded silently into the structure declaration. §1 cites "two definitional bridges retained to anchor the type-level discipline" without claiming load-bearing status. The abstract omits them.

Verdict: honestly framed.

## 3. Candidate 4: supporting reduction or window dressing?

Two theorems carry the Candidate 4 banner. The first, `rollback_receipt_admissible_across_amendment`, takes the refines hypothesis with an underscore prefix (unused) and concludes a conjunction of two hypotheses already in scope. Dead weight.

The second is the real Candidate 4:

```
theorem rollback_admission_composes_with_refinement
    (pair : ActionReceiptPair) (cOld cNew : SyntacticConstitution)
    (h_refines : ∀ rid, admits cNew rid = true -> admits cOld rid = true)
    (h_new_admits_rollback : admits cNew pair.rollbackReceiptId = true) :
    admits cOld pair.rollbackReceiptId = true :=
  h_refines pair.rollbackReceiptId h_new_admits_rollback
```

Non-`rfl` (consumes `h_refines` as a function applied to the receipt id), one-liner once supplied. README's "one-liner" characterization is accurate.

The two theorems do NOT mechanically compose. Candidate 3 ranges over `Constitution` via `BackwardRefines`; Candidate 4 ranges over `SyntacticConstitution` via `admits`. The bridge lives in `PredicateLang.lean` but is not invoked. §4 should either supply the bridge or rescope to "Candidate 4 is an independent receipt-level lemma; the headline composition is Candidate 3 over the constitutional trajectory."

## 4. Candidate 5: renamed parent theorem?

Candidate 5's proof is `exact ⟨h_device, h_operator⟩` over two in-scope hypotheses. The Lean comment is candid: "NOT `rfl`, but also NOT novel: the novelty is the typed envelope, not the underlying theorem." §4 matches: "this theorem renames it for the destructive class. The contribution at this point is the typed envelope, not a new theorem." Honest rename. Nit: the proof does not actually invoke `treaty_admission_iff_predicate_intersection`; either the proof should call the parent theorem or the comment should drop that phrasing.

## 5. Headline composition theorem in the paper's prose

Abstract: "a composition theorem stating that a chain of time-bounded amendments, each carrying a per-step refinement witness, preserves the baseline constitution at every instant under the auto-reversion semantics of the TTL window." §1's contributions cite `\thm{ttl_bounded_amendment_chain_preserves_baseline}` by name. §4 names the same theorem under `\paragraph{The composition theorem.}`. Headline confirmed: Candidate 3.

## 6. If Candidate 3 turns out to be `rfl`, where would it collapse?

Three definitional details matter:

1. **`activeAt` is a closed conditional.** Both arms are `Constitution`. If the predicate lists were syntactically equal after `unfold BackwardRefines`, the kernel could discharge by `rfl`. The defense: predicates inside `Constitution` are opaque `ReceiptId -> Bool` closures (per `Treaty/Intersection.lean`), which Lean cannot peel.
2. **`h_chain_base : ∀ a ∈ chain, a.delta.old = baseline`.** This nearly trivializes the post-expiry arm: `activeAt a t = a.delta.old = baseline`, leaving `BackwardRefines baseline baseline`, which discharges by reflexivity. The in-window arm still has substance, but Candidate 3 reduces to `BackwardRefines.refl` plus one application of `h_chain_refines`. The fix is to weaken `h_chain_base` to `BackwardRefines a.delta.old baseline`.
3. **No induction.** The statement is pointwise over `a ∈ chain`; §4 and the README promise induction. A reviewer will flag the mismatch.

Likely outcome on close inspection: not pure `rfl`, but thinner than the structural-parallel framing. Honest restatement: "case split per amendment over the TTL conditional, post-window arm trivial by reflexivity, in-window arm by the per-step witness."

## 7. The rfl-gate methodology

Sound as a heuristic, unsafe as a verdict. It correctly flags constructor-precondition restatements (Candidates 1 and 5 qualify even when the surface tactic is not the literal `rfl` keyword). It mishandles two real cases: reflexivity over non-trivially-equivalent definitions, and single-rewrite-after-hypothesis discharges (Candidate 4's `h_refines pair.rollbackReceiptId h_new_admits_rollback` is not `rfl` but is one-line). Better gate: "does the kernel's discharge consume an external hypothesis as data, or only structurally unfold the goal?" Under that gate, Candidate 3 is substantive (consumes `h_chain_refines`) and Candidate 1 is trivial (only a field projection).

## Bottom line

Candidate 3 is non-`rfl` as written, but thinner than the README's "structural parallel to `essential_preserved_chain`" claim: pointwise over the chain rather than inductive, and `h_chain_base` makes the post-expiry arm collapse to reflexivity. Candidates 1 and 2 are honestly framed as definitional bridges in §4 and §1. Candidate 4's headline-supporting role exists in prose but not in mechanical Lean composition with Candidate 3; the syntactic-to-closure bridge is missing. Candidate 5 is honestly disclosed as a typed rename.

The paper is NOT safe to submit at the headline-theorem level in the present draft. The rfl-gate verdict is favorable, but a deeper Lean review will land on a thinner critique: the headline is non-`rfl` but pointwise rather than inductive, and Candidate 4 does not mechanically compose with it. Two corrective edits close the gap: (1) weaken `h_chain_base` to a `BackwardRefines a.delta.old baseline` hypothesis OR add an explicit induction on the chain with a per-step composition lemma; (2) supply the closure-to-syntactic bridge that lets Candidate 4 reduce a step of Candidate 3, or rescope the §4 prose to stop claiming the two compose. Without one of each, the paper inherits a weaker version of the parent's critique: not "the flagship is `rfl`," but "the flagship is non-`rfl` and the framing is overclaimed."

No engineering-meta voice violations found in §4 or §1 prose related to these theorems.
