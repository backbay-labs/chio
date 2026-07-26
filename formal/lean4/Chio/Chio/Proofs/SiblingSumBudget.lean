/-
  Sibling-sum budget soundness.

  Models `theorem.budget.sibling_sum_soundness`: a parent capability with
  share `s_p` cannot mint a set of children whose admitted shares sum to
  more than `s_p`. Per-token validation alone enforces only the
  `<= MAX_SHARE` cap on each child; without sibling tracking, two
  children at `4000 bps` each could be admitted under a parent at
  `5000 bps`, and per-token validation would happily accept both.

  The verifier consults a `BudgetRegistry` before issuing a verified
  capability for any delegated child. The registry rejects a child whose
  admission would push the running sum past the parent's share. This
  proof models the registry as a pure list of admitted shares and shows
  that a registry that admits never lets the sum exceed the parent's
  share.

  The root-imported theorem contains no proof placeholders, is exercised by
  the nightly Lean gate, and is recorded as `proved`. The Rust shell is
  exercised by
  `crates/tooling/chio-conformance/tests/budget_split_rejects_oversubscribed_siblings.rs`
  and the cross-hop case by
  `crates/tooling/chio-conformance/tests/budget_split_cross_hop_rejects_amplification.rs`.
  The protocol-side check is implemented in
  `chio_kernel_core::budget_split::BudgetSplit::try_admit_child`.
-/

set_option autoImplicit false

namespace Chio.Proofs.SiblingSumBudget

/-- A budget split for a single parent: parent's share and the list of
    admitted children's shares. Shares are basis points; the per-token
    cap (`<= 10000`) is enforced by the per-token validator and is not
    re-modeled here. -/
structure BudgetSplit where
  parentShare : Nat
  childShares : List Nat
deriving Repr

/-- Sum of admitted child shares. -/
def BudgetSplit.totalChild (s : BudgetSplit) : Nat :=
  s.childShares.foldl (fun acc x => acc + x) 0

/-- Verdict for an admit attempt. -/
inductive AdmitVerdict
  | admitted
  | rejectedOversubscribed
deriving DecidableEq, Repr

/-- Pure model of `BudgetSplit::try_admit_child`. The registry admits
    iff the running sum plus the proposed share is at most the parent's
    share. Otherwise the verdict is `rejectedOversubscribed`. -/
def admitChild (s : BudgetSplit) (proposed : Nat) : AdmitVerdict :=
  if s.totalChild + proposed <= s.parentShare then
    AdmitVerdict.admitted
  else
    AdmitVerdict.rejectedOversubscribed

/-- An empty split admits any single share that is not over the parent
    share. -/
theorem admit_first_child_under_cap_admits
    (parentShare proposed : Nat) (h : proposed <= parentShare) :
    admitChild { parentShare := parentShare, childShares := [] } proposed
      = AdmitVerdict.admitted := by
  unfold admitChild
  simp [BudgetSplit.totalChild]
  exact h

/-- Attack scenario: parent at 5000 bps already admitted a
    child at 4000 bps. A second child at 4000 bps is rejected because
    4000 + 4000 = 8000 > 5000. -/
theorem admit_second_oversubscribed_sibling_rejected :
    admitChild { parentShare := 5_000, childShares := [4_000] } 4_000
      = AdmitVerdict.rejectedOversubscribed := by
  unfold admitChild
  decide

/-- Headline theorem named in `formal/theorem-inventory.json` and
    `formal/proof-manifest.toml`. Sibling-sum soundness: when the
    registry returns `admitted`, the running sum after admission is
    bounded by the parent's share. -/
theorem sibling_sum_soundness
    (s : BudgetSplit) (proposed : Nat) :
    admitChild s proposed = AdmitVerdict.admitted ->
      s.totalChild + proposed <= s.parentShare := by
  intro h_admit
  unfold admitChild at h_admit
  by_cases h : s.totalChild + proposed <= s.parentShare
  · exact h
  · simp [h] at h_admit

/-- Cross-hop composition: when `admitChild` admits, the sum-after
    bound carries through to `(s.childShares ++ [proposed]).foldl`.
    Closes the cross-hop amplification attack: even if individual
    grandchild shares are below the cap, their sum cannot exceed the
    intermediate parent's admitted share. -/
theorem sibling_sum_after_admit_bounded
    (s : BudgetSplit) (proposed : Nat) :
    admitChild s proposed = AdmitVerdict.admitted ->
      (BudgetSplit.totalChild
        { parentShare := s.parentShare
        , childShares := s.childShares ++ [proposed] })
      <= s.parentShare := by
  intro h_admit
  -- The total-after equals totalChild + proposed; this is the
  -- definitional property of foldl over append.
  have h_bound := sibling_sum_soundness s proposed h_admit
  -- Convert foldl over append to addition on the running sum.
  have h_total :
      (BudgetSplit.totalChild
        { parentShare := s.parentShare
        , childShares := s.childShares ++ [proposed] })
      = s.totalChild + proposed := by
    unfold BudgetSplit.totalChild
    simp [List.foldl_append]
  rw [h_total]
  exact h_bound

end Chio.Proofs.SiblingSumBudget
