/-
  Recursive delegation theorems (M04 Phase 4).

  This module extends the single-step capability monotonicity results in
  `Chio.Proofs.Monotonicity` to the recursive case introduced by
  trajectory-2 milestone 04.  It defines the four named delegation
  theorems that the milestone freeze (`m04-delegation-pivot`) commits
  to:

    1. `delegate_no_widen`        - re-delegating an already-delegated
                                    capability cannot widen its scope.
    2. `attenuation_monotone`     - composing attenuations preserves the
                                    subset relation on `ChioScope`.
    3. `revocation_is_cut`        - revocation of an ancestor in the
                                    delegation chain forces every
                                    descendant to deny.
    4. `compose_preserves_algebra`- composing two attenuated chains
                                    preserves the trajectory-1 M03
                                    capability-algebra invariants
                                    (subset-of transitivity over
                                    `ChioScope`).

  T1 (the present file) ships these theorems as STATEMENTS ONLY, behind
  `sorry`.  T2 closes proofs 1 and 2; T3 closes proofs 3 and 4 (theorem 3
  may ship as `axiom` if the auxiliary graph theory blows past budget,
  per the milestone risk note).

  Mirrors: `crates/chio-core-types/src/capability.rs`
           (`Capability::delegate`, `validate_delegation_chain`),
           `crates/chio-kernel-core/src/revocation_view.rs`
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

/-! ## Theorem 1: `delegate_no_widen`

    Re-delegating an already-attenuated capability cannot widen the
    scope: if `child` is a subset of `mid` and `mid` is a subset of
    `parent`, then `child` is a subset of `parent`.  This is the
    recursive case of trajectory-1 M03's
    `validate_attenuation_monotonic_under_chain_extension` proptest
    invariant. -/
theorem delegate_no_widen (parent mid child : ChioScope)
    (h_mid_in_parent : mid.isSubsetOf parent = true)
    (h_child_in_mid : child.isSubsetOf mid = true) :
    child.isSubsetOf parent = true := by
  sorry

/-! ## Theorem 2: `attenuation_monotone`

    Composing two attenuations preserves the subset relation on
    `ChioScope`.  Stated explicitly: if `s1 ⊆ s0` and `s2 ⊆ s1`, then
    composition produces an `s2` that is still `⊆ s0`.  This is the
    monotonicity-under-composition variant of
    `Chio.Proofs.Monotonicity.delegation_chain_integrity`. -/
theorem attenuation_monotone (s0 s1 s2 : ChioScope)
    (h_s1_in_s0 : s1.isSubsetOf s0 = true)
    (h_s2_in_s1 : s2.isSubsetOf s1 = true) :
    s2.isSubsetOf s0 = true := by
  sorry

/-! ## Theorem 3: `revocation_is_cut`

    Revoking an ancestor in the delegation chain forces every descendant
    to deny.  Concretely: when the revocation store records any
    delegator from a child capability's chain, `checkRevocation` returns
    an error.  This is the recursive analogue of
    `Chio.Proofs.Revocation` results restricted to
    direct-token revocation. -/
theorem revocation_is_cut
    (store : RevocationStore) (cap : CapabilityToken)
    (link : DelegationLink)
    (h_in_chain : link ∈ cap.delegationChain)
    (h_revoked : store.isRevoked link.delegator = true) :
    checkRevocation store cap = .error "delegation chain contains revoked ancestor" := by
  sorry

/-! ## Theorem 4: `compose_preserves_algebra`

    Composing two attenuated delegation chains preserves the capability
    algebra invariants from trajectory-1 M03.  Concretely: if `path1`
    ends at scope `s_mid` and `path2` begins at scope `s_mid`, then the
    concatenated path's final scope is a subset of the initial scope.

    The statement reduces to repeated application of theorem 1; theorem
    4 packages the invariant for the audit-doc cross-reference. -/
theorem compose_preserves_algebra
    (s_initial s_mid s_final : ChioScope)
    (h_mid_in_initial : s_mid.isSubsetOf s_initial = true)
    (h_final_in_mid : s_final.isSubsetOf s_mid = true) :
    s_final.isSubsetOf s_initial = true := by
  sorry

end Chio.Capability
