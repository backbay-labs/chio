/-
  Proofs for the bounded evaluation lane.

  The model is intentionally pure: `evalToolCall` has no IO, database access,
  network transport, or subprocess effects. These theorems make the P3
  fail-closed claim machine-checked for that model and connect revoked tokens
  to denial results for P2.
-/

import Chio.Core.Revocation

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Core

theorem evalToolCall_total
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp) :
    evalToolCall trustedKeys store cap toolName serverId now = .allow ∨
      ∃ reason, evalToolCall trustedKeys store cap toolName serverId now = .deny reason := by
  generalize h_eval : evalToolCall trustedKeys store cap toolName serverId now = result
  cases result with
  | allow => exact Or.inl rfl
  | deny reason => exact Or.inr ⟨reason, rfl⟩

theorem evalToolCall_invalid_signature_denies
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    (h_sig : verifyCapabilitySignature cap trustedKeys = false) :
    evalToolCall trustedKeys store cap toolName serverId now =
      .deny "invalid capability signature" := by
  unfold evalToolCall
  simp [h_sig]

theorem evalToolCall_not_yet_valid_denies
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    (h_sig : verifyCapabilitySignature cap trustedKeys = true)
    (h_not_yet : now < cap.issuedAt) :
    evalToolCall trustedKeys store cap toolName serverId now =
      .deny "capability not yet valid" := by
  unfold evalToolCall
  simp [h_sig, h_not_yet]

theorem evalToolCall_expired_denies
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    (h_sig : verifyCapabilitySignature cap trustedKeys = true)
    (h_started : ¬ now < cap.issuedAt)
    (h_expired : now ≥ cap.expiresAt) :
    evalToolCall trustedKeys store cap toolName serverId now =
      .deny "capability expired" := by
  unfold evalToolCall
  simp [h_sig, h_started, h_expired]

theorem evalToolCall_revoked_token_never_allows
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    (h_revoked : store.isRevoked cap.id = true) :
    evalToolCall trustedKeys store cap toolName serverId now ≠ .allow := by
  unfold evalToolCall
  cases verifyCapabilitySignature cap trustedKeys <;> simp
  by_cases h_not_yet : now < cap.issuedAt <;> simp [h_not_yet]
  by_cases h_expired : now ≥ cap.expiresAt <;> simp [h_expired, h_revoked]

theorem evalToolCall_revoked_ancestor_never_allows
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    (h_ancestor :
      cap.delegationChain.any (fun link => store.isRevoked link.delegator) = true) :
    evalToolCall trustedKeys store cap toolName serverId now ≠ .allow := by
  unfold evalToolCall
  cases verifyCapabilitySignature cap trustedKeys <;> simp
  by_cases h_not_yet : now < cap.issuedAt <;> simp [h_not_yet]
  by_cases h_expired : now ≥ cap.expiresAt <;> simp [h_expired]
  cases h_cap : store.isRevoked cap.id with
  | true =>
      simp
  | false =>
      simp
      have h_exists :
          ∃ link, link ∈ cap.delegationChain ∧ store.isRevoked link.delegator = true :=
        List.any_eq_true.mp h_ancestor
      simp [h_exists]

theorem evalToolCall_out_of_scope_denies
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    (h_sig : verifyCapabilitySignature cap trustedKeys = true)
    (h_started : ¬ now < cap.issuedAt)
    (h_not_expired : ¬ now ≥ cap.expiresAt)
    (h_cap : store.isRevoked cap.id = false)
    (h_ancestor :
      cap.delegationChain.any (fun link => store.isRevoked link.delegator) = false)
    (h_scope : checkScope cap toolName serverId = false) :
    evalToolCall trustedKeys store cap toolName serverId now =
      .deny s!"tool {toolName} on {serverId} not in scope" := by
  unfold evalToolCall
  simp [h_sig, h_started, h_not_expired, h_cap, h_ancestor, h_scope]

theorem evalToolCall_all_checks_pass_allow
    (trustedKeys : List PublicKeyHex)
    (store : RevocationStore)
    (cap : CapabilityToken)
    (toolName : ToolName)
    (serverId : ServerId)
    (now : Timestamp)
    (h_sig : verifyCapabilitySignature cap trustedKeys = true)
    (h_started : ¬ now < cap.issuedAt)
    (h_not_expired : ¬ now ≥ cap.expiresAt)
    (h_cap : store.isRevoked cap.id = false)
    (h_ancestor :
      cap.delegationChain.any (fun link => store.isRevoked link.delegator) = false)
    (h_scope : checkScope cap toolName serverId = true) :
    evalToolCall trustedKeys store cap toolName serverId now = .allow := by
  unfold evalToolCall
  simp [h_sig, h_started, h_not_expired, h_cap, h_ancestor, h_scope]

end Chio.Proofs
