/-
  Scope subsumption logic: ToolGrant.isSubsetOf, ChioScope.isSubsetOf.
  Mirrors: chio-kernel-core/src/capability.rs (ToolGrant::is_subset_of, ChioScope::is_subset_of)

  This is the core of Chio's capability monotonicity guarantee.
-/

import Chio.Core.Capability

set_option autoImplicit false

namespace List

/-- Check if every element of `child` appears in `parent`. -/
def isSubsetOf {α : Type} [BEq α] (child parent : List α) : Bool :=
  child.all (fun c => parent.any (fun p => c == p))

end List

namespace Chio.Core

private theorem any_eq_true_of_mem {α : Type} [BEq α] [LawfulBEq α]
    {x : α} {xs : List α} (h_mem : x ∈ xs) :
    xs.any (fun y => x == y) = true := by
  exact List.any_eq_true.mpr ⟨x, h_mem, by simp⟩

/-- Mirrors: ToolGrant::is_subset_of in capability.rs.

    A child grant is a subset when:
    - It targets the same server.
    - Parent tool is "*" (wildcard) or matches child tool.
    - Child operations are a subset of parent operations.
    - If parent has an invocation cap, child must too and child <= parent.
    - Every parent constraint appears in child (child is more restrictive). -/
def ToolGrant.isSubsetOf (child parent : ToolGrant) : Bool :=
  -- Same server
  child.serverId == parent.serverId
  -- Tool name match (wildcard or exact)
  && (parent.toolName == "*" || child.toolName == parent.toolName)
  -- Operations subset
  && child.operations.isSubsetOf parent.operations
  -- Invocation budget
  && (match parent.maxInvocations with
      | none => true  -- parent uncapped, any child is fine
      | some parentMax =>
        match child.maxInvocations with
        | none => false  -- child uncapped but parent is capped
        | some childMax => childMax ≤ parentMax)
  -- Constraints: parent's constraints must all appear in child
  && parent.constraints.isSubsetOf child.constraints

/-- Mirrors: ChioScope::is_subset_of in capability.rs.

    Returns true if every grant in `child` is covered by some grant in `parent`. -/
def ChioScope.isSubsetOf (child parent : ChioScope) : Bool :=
  child.grants.all (fun cg =>
    parent.grants.any (fun pg => cg.isSubsetOf pg))

/-- The empty scope: no grants at all. -/
def ChioScope.empty : ChioScope := { grants := [] }

/-- Empty scope is a subset of any scope. -/
theorem ChioScope.empty_isSubsetOf (parent : ChioScope) :
    ChioScope.isSubsetOf ChioScope.empty parent = true := by
  unfold ChioScope.isSubsetOf ChioScope.empty
  simp [List.all]

/-- Reflexivity: a scope is a subset of itself. -/
theorem ToolGrant.isSubsetOf_refl (g : ToolGrant) :
    g.isSubsetOf g = true := by
  cases g with
  | mk serverId toolName operations constraints maxInvocations =>
    unfold ToolGrant.isSubsetOf
    simp [List.isSubsetOf]
    cases maxInvocations with
    | none => simp
    | some n => simp

end Chio.Core
