/-
  Chio capability properties proven in the bounded phase-300 proof lane.

  P1: Capability monotonicity (delegation can only attenuate)
  P1a: Empty scope monotonicity
  P1b: Explicit budgets are non-negative in the current model
-/

import Chio.Core.Capability
import Chio.Core.Scope

set_option autoImplicit false

namespace Chio.Spec

open Chio.Core

/-- P1: Capability monotonicity -- if a child scope is a subset of a parent
    scope, then every grant in the child is covered by some grant in the
    parent.

    This is the core Chio safety property: delegation can only attenuate,
    never amplify. -/
theorem capability_monotonicity (parent child : ChioScope)
    (h : child.isSubsetOf parent = true) :
    ∀ g, g ∈ child.grants →
      ∃ pg, pg ∈ parent.grants ∧ g.isSubsetOf pg = true := by
  intro g h_mem
  unfold ChioScope.isSubsetOf at h
  exact List.any_eq_true.mp (List.all_eq_true.mp h g h_mem)

/-- P1a: Empty scope is always a valid attenuation. -/
theorem empty_scope_monotonicity (parent : ChioScope) :
    ChioScope.isSubsetOf ChioScope.empty parent = true :=
  ChioScope.empty_isSubsetOf parent

/-- P1b: Any explicit invocation budget in the bounded capability model is
    non-negative because budgets are represented as `Nat`. -/
theorem scope_budgets_nonnegative (scope : ChioScope) :
    ∀ g, g ∈ scope.grants →
      ∀ limit, g.maxInvocations = some limit → 0 ≤ limit := by
  intro g _ limit _
  exact Nat.zero_le limit

end Chio.Spec
