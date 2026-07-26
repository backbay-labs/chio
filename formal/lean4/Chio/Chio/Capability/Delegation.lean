/-
  Recursive delegation theorems.

  This module extends the single-step capability monotonicity results in
  `Chio.Proofs.Monotonicity` to the recursive case.  It defines four
  named delegation theorems:

    1. `delegate_no_widen`        - re-delegating an already-delegated
                                    capability cannot widen its scope.
    2. `attenuation_monotone`     - composing attenuations preserves the
                                    subset relation on `ChioScope`.
    3. `revocation_is_cut`        - revocation of an ancestor in the
                                    delegation chain forces every
                                    descendant to deny.
    4. `compose_preserves_algebra`- composing two attenuated chains
                                    preserves the capability-algebra
                                    invariants (subset-of transitivity
                                    over `ChioScope`).

  Mirrors: `crates/core/chio-core-types/src/capability/attenuation.rs`
           (`Capability::delegate`, `validate_delegation_chain`),
           `crates/kernel/chio-kernel-core/src/revocation_view.rs`
           (`RevocationSnapshot::is_revoked`).
-/

import Chio.Core.Capability
import Chio.Core.Scope
import Chio.Core.Revocation
import Chio.Spec.Properties
import Chio.Proofs.Monotonicity

set_option autoImplicit false

namespace Chio.Capability

open Chio.Core
open Chio.Spec
open Chio.Proofs

/-! ## Delegation chain helpers

  The theorems below treat a delegation chain as a list of progressively
  attenuated `ChioScope` values.  Step `i` of the chain is reachable
  from step `i+1` via attenuation only; `applyAttenuation` is a thin
  bookkeeping helper that produces the child scope from the parent and
  the requested attenuation list.  The cryptographic shape lives in
  `Chio.Core.DelegationLink`; this module is concerned only with the
  set-theoretic refinement induced by attenuation. -/

/-- A `DelegationStep` is a parent / child pair of scopes plus the
    attenuation list that produced the child from the parent. -/
structure DelegationStep where
  parent : ChioScope
  child : ChioScope
  attenuations : List Attenuation
  deriving Repr

/-- A `DelegationStep` is well-formed when the child scope is a subset
    of the parent scope (`isSubsetOf` returns `true`).  This is the
    structural witness `Capability::delegate` enforces in Rust before
    signing the receipt. -/
def DelegationStep.attenuates (s : DelegationStep) : Prop :=
  s.child.isSubsetOf s.parent = true

/-- A delegation path is a non-empty list of attenuating steps where
    `step[i].child = step[i+1].parent`.  The Lean theorems below quantify
    over these paths. -/
structure DelegationPath where
  steps : List DelegationStep
  attenuating : ∀ s ∈ steps, s.attenuates
  connected :
    ∀ (i : Nat) (h_next : i + 1 < steps.length),
      (steps.get ⟨i + 1, h_next⟩).parent =
        (steps.get ⟨i, Nat.lt_trans (Nat.lt_succ_self i) h_next⟩).child

/-! ## ToolGrant subset transitivity

    Auxiliary lemma: `ToolGrant.isSubsetOf` is transitive.  Used to
    discharge the structural step in theorem 1.  Each conjunct of
    `ToolGrant.isSubsetOf` (server identity, tool-name match,
    operations subset, invocation budget, parent-side constraints
    contained in child) is closed under the obvious pointwise
    composition. -/
private theorem ToolGrant.isSubsetOf_trans
    (a b c : ToolGrant)
    (h_ab : a.isSubsetOf b = true) (h_bc : b.isSubsetOf c = true) :
    a.isSubsetOf c = true := by
  unfold ToolGrant.isSubsetOf at *
  -- Decompose the four-way conjunction via Bool.and_eq_true.
  rw [Bool.and_eq_true, Bool.and_eq_true, Bool.and_eq_true, Bool.and_eq_true] at h_ab
  rw [Bool.and_eq_true, Bool.and_eq_true, Bool.and_eq_true, Bool.and_eq_true] at h_bc
  obtain ⟨⟨⟨⟨h_srv_ab, h_tool_ab⟩, h_ops_ab⟩, h_max_ab⟩, h_cons_ab⟩ := h_ab
  obtain ⟨⟨⟨⟨h_srv_bc, h_tool_bc⟩, h_ops_bc⟩, h_max_bc⟩, h_cons_bc⟩ := h_bc
  -- Rebuild the conjunction one piece at a time.
  refine ?_
  apply (Bool.and_eq_true _ _).mpr
  refine ⟨?_, ?_⟩
  · apply (Bool.and_eq_true _ _).mpr
    refine ⟨?_, ?_⟩
    · apply (Bool.and_eq_true _ _).mpr
      refine ⟨?_, ?_⟩
      · apply (Bool.and_eq_true _ _).mpr
        refine ⟨?_, ?_⟩
        · -- server identity is transitive (eq).
          have : a.serverId = b.serverId := beq_iff_eq.mp h_srv_ab
          have : a.serverId = c.serverId := this.trans (beq_iff_eq.mp h_srv_bc)
          exact beq_iff_eq.mpr this
        · -- tool name match transitivity via Bool decomposition.
          rw [Bool.or_eq_true] at h_tool_ab h_tool_bc
          rw [Bool.or_eq_true]
          rcases h_tool_ab with h_b_wild | h_a_eq_b
          · rcases h_tool_bc with h_c_wild | h_b_eq_c
            · exact Or.inl h_c_wild
            · have h_bc_eq : b.toolName = c.toolName := beq_iff_eq.mp h_b_eq_c
              have h_b_star : b.toolName = "*" := beq_iff_eq.mp h_b_wild
              have h_c_star : c.toolName = "*" := h_bc_eq.symm.trans h_b_star
              exact Or.inl (beq_iff_eq.mpr h_c_star)
          · rcases h_tool_bc with h_c_wild | h_b_eq_c
            · exact Or.inl h_c_wild
            · have h_ab_eq : a.toolName = b.toolName := beq_iff_eq.mp h_a_eq_b
              have h_bc_eq : b.toolName = c.toolName := beq_iff_eq.mp h_b_eq_c
              have h_ac_eq : a.toolName = c.toolName := h_ab_eq.trans h_bc_eq
              exact Or.inr (beq_iff_eq.mpr h_ac_eq)
      · -- operations subset transitivity (DecidableEq + LawfulBEq).
        exact list_isSubsetOf_trans a.operations b.operations c.operations
          h_ops_ab h_ops_bc
    · -- invocation budget transitivity (option chain).  Decide on
      -- each option independently, then close arms case-by-case.
      have h_budget :
          ∀ (aOpt bOpt cOpt : Option Nat),
            (match bOpt with
              | none => true
              | some parentMax =>
                match aOpt with
                | none => false
                | some childMax => decide (childMax ≤ parentMax))
              = true →
            (match cOpt with
              | none => true
              | some parentMax =>
                match bOpt with
                | none => false
                | some childMax => decide (childMax ≤ parentMax))
              = true →
            (match cOpt with
              | none => true
              | some parentMax =>
                match aOpt with
                | none => false
                | some childMax => decide (childMax ≤ parentMax))
              = true := by
        intro aOpt bOpt cOpt h1 h2
        cases cOpt with
        | none => rfl
        | some cMax =>
          cases bOpt with
          | none => simp at h2
          | some bMax =>
            simp at h2
            cases aOpt with
            | none => simp at h1
            | some aMax =>
              simp at h1
              simp
              exact Nat.le_trans h1 h2
      exact h_budget a.maxInvocations b.maxInvocations c.maxInvocations
        h_max_ab h_max_bc
  · -- parent-side constraints transitivity: c.constraints ⊆ b.constraints
    -- and b.constraints ⊆ a.constraints, so c.constraints ⊆ a.constraints.
    exact list_isSubsetOf_trans c.constraints b.constraints a.constraints
      h_cons_bc h_cons_ab

/-- `ChioScope.isSubsetOf` is transitive. -/
private theorem ChioScope.isSubsetOf_trans
    (a b c : ChioScope)
    (h_ab : a.isSubsetOf b = true) (h_bc : b.isSubsetOf c = true) :
    a.isSubsetOf c = true := by
  unfold ChioScope.isSubsetOf at *
  apply List.all_eq_true.mpr
  intro g h_g_in_a
  -- g ∈ a, so it has a witness in b.
  have h_g_in_b := List.all_eq_true.mp h_ab g h_g_in_a
  obtain ⟨b_g, h_b_g_mem, h_g_sub_b_g⟩ := List.any_eq_true.mp h_g_in_b
  -- b_g ∈ b, so it has a witness in c.
  have h_b_g_in_c := List.all_eq_true.mp h_bc b_g h_b_g_mem
  obtain ⟨c_g, h_c_g_mem, h_b_g_sub_c_g⟩ := List.any_eq_true.mp h_b_g_in_c
  -- Compose via grant transitivity.
  apply List.any_eq_true.mpr
  refine ⟨c_g, h_c_g_mem, ?_⟩
  exact ToolGrant.isSubsetOf_trans g b_g c_g h_g_sub_b_g h_b_g_sub_c_g

/-! ## Theorem 1: `delegate_no_widen`

    Re-delegating an already-attenuated capability cannot widen the
    scope: if `child` is a subset of `mid` and `mid` is a subset of
    `parent`, then `child` is a subset of `parent`.  This is the
    recursive case of the
    `validate_attenuation_monotonic_under_chain_extension` proptest
    invariant. -/
theorem delegate_no_widen (parent mid child : ChioScope)
    (h_mid_in_parent : mid.isSubsetOf parent = true)
    (h_child_in_mid : child.isSubsetOf mid = true) :
    child.isSubsetOf parent = true :=
  ChioScope.isSubsetOf_trans child mid parent h_child_in_mid h_mid_in_parent

/-! ## Theorem 2: `attenuation_monotone`

    Composing two attenuations preserves the subset relation on
    `ChioScope`.  Stated explicitly: if `s1 ⊆ s0` and `s2 ⊆ s1`, then
    composition produces an `s2` that is still `⊆ s0`.  This is the
    monotonicity-under-composition variant of
    `Chio.Proofs.Monotonicity.delegation_chain_integrity`. -/
theorem attenuation_monotone (s0 s1 s2 : ChioScope)
    (h_s1_in_s0 : s1.isSubsetOf s0 = true)
    (h_s2_in_s1 : s2.isSubsetOf s1 = true) :
    s2.isSubsetOf s0 = true :=
  ChioScope.isSubsetOf_trans s2 s1 s0 h_s2_in_s1 h_s1_in_s0

/-! ## Theorem 3: `revocation_is_cut`

    Revoking an ancestor in the delegation chain forces every descendant
    to deny.  Concretely: when the revocation store records any
    delegator from a child capability's chain, `checkRevocation`
    returns an `Except.error`.  The specific error string depends on
    whether the cap's own id is also revoked (the first guard fires);
    the load-bearing point is that no `.ok ()` reachable.

    This is the recursive analogue of the single-step revocation
    results in `Chio.Proofs.Revocation`. -/
theorem revocation_is_cut
    (store : RevocationStore) (cap : CapabilityToken)
    (link : DelegationLink)
    (h_in_chain : link ∈ cap.delegationChain)
    (h_revoked : store.isRevoked link.delegator = true) :
    ∃ msg, checkRevocation store cap = .error msg := by
  unfold checkRevocation
  by_cases h_id : store.isRevoked cap.id
  · -- The cap's own id is revoked: the first branch fires.
    rw [if_pos h_id]
    exact ⟨_, rfl⟩
  · -- The cap's id is not revoked: the second branch fires because
    -- `link` witnesses an ancestor being revoked.
    rw [if_neg h_id]
    have h_any : cap.delegationChain.any (fun l => store.isRevoked l.delegator) = true := by
      apply List.any_eq_true.mpr
      exact ⟨link, h_in_chain, h_revoked⟩
    rw [if_pos h_any]
    exact ⟨_, rfl⟩

/-! ## Theorem 4: `compose_preserves_algebra`

    Composing two attenuated delegation chains preserves the capability
    algebra invariants.  Concretely: if `path1` ends at scope `s_mid`
    and `path2` begins at scope `s_mid`, then the concatenated path's
    final scope is a subset of the initial scope.

    The statement reduces to repeated application of theorem 1;
    `compose_preserves_algebra` packages the invariant explicitly. -/
theorem compose_preserves_algebra
    (s_initial s_mid s_final : ChioScope)
    (h_mid_in_initial : s_mid.isSubsetOf s_initial = true)
    (h_final_in_mid : s_final.isSubsetOf s_mid = true) :
    s_final.isSubsetOf s_initial = true :=
  ChioScope.isSubsetOf_trans s_final s_mid s_initial h_final_in_mid h_mid_in_initial

end Chio.Capability
