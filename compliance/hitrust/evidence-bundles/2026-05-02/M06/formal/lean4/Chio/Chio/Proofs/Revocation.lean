/-
  Proofs for the bounded revocation lane.

  These theorems cover the pure revocation model in `Chio.Core.Revocation`.
  Store-backed runtime revocation still needs the Rust qualification and
  refinement lanes listed in `formal/proof-manifest.toml`.
-/

import Chio.Core.Revocation

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Core

theorem revoke_marks_capability_revoked
    (store : RevocationStore) (capId : CapabilityId) :
    (store.revoke capId).isRevoked capId = true := by
  cases h_existing : store.isRevoked capId with
  | false =>
      unfold RevocationStore.revoke
      rw [h_existing]
      simp [RevocationStore.isRevoked]
  | true =>
      unfold RevocationStore.revoke
      rw [h_existing]
      exact h_existing

theorem revoke_preserves_existing_revocation
    (store : RevocationStore) (newCapId existingCapId : CapabilityId)
    (h_existing : store.isRevoked existingCapId = true) :
    (store.revoke newCapId).isRevoked existingCapId = true := by
  cases h_new : store.isRevoked newCapId with
  | false =>
      unfold RevocationStore.revoke
      rw [h_new]
      unfold RevocationStore.isRevoked at h_existing ⊢
      simp [h_existing]
  | true =>
      unfold RevocationStore.revoke
      rw [h_new]
      exact h_existing

theorem checkRevocation_revoked_token_errors
    (store : RevocationStore) (cap : CapabilityToken)
    (h_revoked : store.isRevoked cap.id = true) :
    checkRevocation store cap = .error s!"capability {cap.id} is revoked" := by
  unfold checkRevocation
  simp [h_revoked]

theorem checkRevocation_revoked_ancestor_never_ok
    (store : RevocationStore) (cap : CapabilityToken)
    (h_ancestor :
      cap.delegationChain.any (fun link => store.isRevoked link.delegator) = true) :
  checkRevocation store cap ≠ .ok () := by
  unfold checkRevocation
  cases store.isRevoked cap.id <;> simp [h_ancestor]

theorem checkRevocation_ok_implies_not_revoked
    (store : RevocationStore) (cap : CapabilityToken)
    (h_ok : checkRevocation store cap = .ok ()) :
    store.isRevoked cap.id = false ∧
      cap.delegationChain.any (fun link => store.isRevoked link.delegator) = false := by
  unfold checkRevocation at h_ok
  cases h_cap : store.isRevoked cap.id with
  | true =>
      simp [h_cap] at h_ok
  | false =>
      cases h_ancestor :
        cap.delegationChain.any (fun link => store.isRevoked link.delegator) with
      | true =>
          simp [h_cap, h_ancestor] at h_ok
      | false =>
          exact ⟨rfl, rfl⟩

end Chio.Proofs
