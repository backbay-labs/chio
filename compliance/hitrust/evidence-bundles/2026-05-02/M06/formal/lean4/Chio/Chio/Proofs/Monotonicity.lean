/-
  Proofs for capability monotonicity (P1) and related properties.
  Mirrors: chio-kernel-core/src/capability.rs (is_subset_of)
-/

import Chio.Core.Capability
import Chio.Core.Scope
import Chio.Core.Revocation
import Chio.Spec.Properties

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Core
open Chio.Spec

private theorem any_eq_true_of_mem {α : Type} [BEq α] [LawfulBEq α]
    {x : α} {xs : List α} (h_mem : x ∈ xs) :
    xs.any (fun y => x == y) = true := by
  exact List.any_eq_true.mpr ⟨x, h_mem, by simp⟩

-- P1: Capability Monotonicity -- standalone proofs

/-- Transitivity of list subset. -/
theorem list_isSubsetOf_trans {α : Type} [BEq α] [DecidableEq α] [LawfulBEq α]
    (a b c : List α)
    (h_ab : a.isSubsetOf b = true)
    (h_bc : b.isSubsetOf c = true) :
    a.isSubsetOf c = true := by
  unfold List.isSubsetOf at *
  apply List.all_eq_true.mpr
  intro x h_mem
  have h_x_in_b := List.all_eq_true.mp h_ab x h_mem
  -- x is in b via any, so there exists some y in b with x == y
  have ⟨y, h_y_mem, h_xy⟩ := List.any_eq_true.mp h_x_in_b
  -- y is in c via the b-subset-c hypothesis
  have h_y_in_c := List.all_eq_true.mp h_bc y h_y_mem
  have ⟨z, h_z_mem, h_yz⟩ := List.any_eq_true.mp h_y_in_c
  -- x == y and y == z, so x == z by transitivity
  apply List.any_eq_true.mpr
  have h_xy_eq : x = y := by
    exact beq_iff_eq.mp h_xy
  have h_yz_eq : y = z := by
    exact beq_iff_eq.mp h_yz
  exact ⟨z, h_z_mem, beq_iff_eq.mpr (h_xy_eq.trans h_yz_eq)⟩

/-- If child.grants is a sublist of parent.grants (in the subset sense),
    then ChioScope.isSubsetOf holds. This is the key structural lemma. -/
theorem scope_subset_of_grants_subset (child parent : ChioScope)
    (h : ∀ g, g ∈ child.grants →
      ∃ pg, pg ∈ parent.grants ∧ g.isSubsetOf pg = true) :
    child.isSubsetOf parent = true := by
  unfold ChioScope.isSubsetOf
  apply List.all_eq_true.mpr
  intro g h_mem
  have ⟨pg, h_pg_mem, h_sub⟩ := h g h_mem
  apply List.any_eq_true.mpr
  exact ⟨pg, h_pg_mem, h_sub⟩

/-- Wildcard tool name subsumes any tool name on the same server. -/
theorem wildcard_subsumes (serverId : ServerId) (childTool : ToolName)
    (ops : List Operation) (constraints : List Constraint) :
    ToolGrant.isSubsetOf
      { serverId := serverId, toolName := childTool,
        operations := ops, constraints := constraints,
        maxInvocations := none }
      { serverId := serverId, toolName := "*",
        operations := ops, constraints := constraints,
        maxInvocations := none } = true := by
  unfold ToolGrant.isSubsetOf
  simp [List.isSubsetOf]

/-- Reducing max_invocations produces a subset. -/
theorem reduced_budget_is_subset
    (serverId : ServerId) (toolName : ToolName)
    (ops : List Operation) (constraints : List Constraint)
    (parentMax childMax : Nat)
    (h_le : childMax ≤ parentMax) :
    ToolGrant.isSubsetOf
      { serverId := serverId, toolName := toolName,
        operations := ops, constraints := constraints,
        maxInvocations := some childMax }
      { serverId := serverId, toolName := toolName,
        operations := ops, constraints := constraints,
        maxInvocations := some parentMax } = true := by
  unfold ToolGrant.isSubsetOf
  simp [h_le, List.isSubsetOf]

/-- Adding a constraint to the child makes it more restrictive (subset). -/
theorem added_constraint_is_subset
    (serverId : ServerId) (toolName : ToolName)
    (ops : List Operation)
    (parentConstraints : List Constraint)
    (extra : Constraint) :
    ToolGrant.isSubsetOf
      { serverId := serverId, toolName := toolName,
        operations := ops,
        constraints := parentConstraints ++ [extra],
        maxInvocations := none }
      { serverId := serverId, toolName := toolName,
        operations := ops,
        constraints := parentConstraints,
        maxInvocations := none } = true := by
  unfold ToolGrant.isSubsetOf
  simp [List.isSubsetOf]
  intro c h_mem
  exact Or.inl h_mem

-- Delegation chain integrity

/-- A delegation chain where each step attenuates produces monotonically
    narrowing scopes. For every adjacent step, every child grant is covered
    by some parent grant. This is the bounded chain-integrity property used
    by Chio's delegation model today. -/
theorem delegation_chain_integrity
    (scopes : List ChioScope)
    (h_chain : ∀ (i : Nat) (h_next : i + 1 < scopes.length),
      ∀ (h_parent : i < scopes.length),
        (scopes.get ⟨i + 1, h_next⟩).isSubsetOf
          (scopes.get ⟨i, h_parent⟩) = true)
    (i : Nat) (h_next : i + 1 < scopes.length) :
    ∀ g, g ∈ (scopes.get ⟨i + 1, h_next⟩).grants →
      ∃ pg, pg ∈ (scopes.get ⟨i, Nat.lt_trans (Nat.lt_succ_self i) h_next⟩).grants
        ∧ g.isSubsetOf pg = true := by
  have h_parent : i < scopes.length :=
    Nat.lt_trans (Nat.lt_succ_self i) h_next
  exact capability_monotonicity
    (scopes.get ⟨i, Nat.lt_trans (Nat.lt_succ_self i) h_next⟩)
    (scopes.get ⟨i + 1, h_next⟩)
    (h_chain i h_next h_parent)

end Chio.Proofs
