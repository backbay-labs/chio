/-
  Proofs for the bounded receipt lane:
  - Merkle inclusion soundness
  - checkpoint consistency
  - receipt immutability
-/

import Chio.Core.Receipt

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Core

theorem applyProof_append (start : MerkleHash)
    (proofPrefix proofSuffix : ReceiptProof) :
    applyProof start (proofPrefix ++ proofSuffix) =
      applyProof (applyProof start proofPrefix) proofSuffix := by
  induction proofPrefix generalizing start with
  | nil =>
      simp [applyProof]
  | cons step rest ih =>
      simp [applyProof, ih]

/-- A proof produced from a receipt tree verifies against that tree's root. -/
theorem membership_proof_sound
    (tree : ReceiptTree) (receipt : ReceiptBody) (proof : ReceiptProof)
    (h_proof : membershipProof tree receipt = some proof) :
    provesInclusion receipt proof tree.root := by
  induction tree generalizing proof with
  | leaf leafReceipt =>
      simp [membershipProof, provesInclusion, ReceiptTree.root] at h_proof ⊢
      rcases h_proof with ⟨rfl, rfl⟩
      rfl
  | node left right ihLeft ihRight =>
      cases h_left : membershipProof left receipt with
      | some leftProof =>
          simp [membershipProof, h_left] at h_proof
          cases h_proof
          have h_left_sound : provesInclusion receipt leftProof left.root :=
            ihLeft leftProof h_left
          calc
            applyProof (leafHash receipt)
                (leftProof ++ [{ siblingRoot := right.root, direction := ProofDirection.right }]) =
              applyProof (applyProof (leafHash receipt) leftProof)
                [{ siblingRoot := right.root, direction := ProofDirection.right }] := by
                  simpa using applyProof_append (leafHash receipt) leftProof
                    [{ siblingRoot := right.root, direction := ProofDirection.right }]
            _ = applyProof left.root
                [{ siblingRoot := right.root, direction := ProofDirection.right }] := by
                  simpa [provesInclusion] using congrArg
                    (fun root => applyProof root [{ siblingRoot := right.root, direction := ProofDirection.right }])
                    h_left_sound
            _ = nodeHash left.root right.root := by
                  simp [applyProof]
      | none =>
          cases h_right : membershipProof right receipt with
          | some rightProof =>
              simp [membershipProof, h_left, h_right] at h_proof
              cases h_proof
              have h_right_sound : provesInclusion receipt rightProof right.root :=
                ihRight rightProof h_right
              calc
                applyProof (leafHash receipt)
                    (rightProof ++ [{ siblingRoot := left.root, direction := ProofDirection.left }]) =
                  applyProof (applyProof (leafHash receipt) rightProof)
                    [{ siblingRoot := left.root, direction := ProofDirection.left }] := by
                      simpa using applyProof_append (leafHash receipt) rightProof
                        [{ siblingRoot := left.root, direction := ProofDirection.left }]
                _ = applyProof right.root
                    [{ siblingRoot := left.root, direction := ProofDirection.left }] := by
                      simpa [provesInclusion] using congrArg
                        (fun root => applyProof root [{ siblingRoot := left.root, direction := ProofDirection.left }])
                        h_right_sound
                _ = nodeHash left.root right.root := by
                      simp [applyProof]
          | none =>
              simp [membershipProof, h_left, h_right] at h_proof

theorem membership_proof_verifies
    (tree : ReceiptTree) (receipt : ReceiptBody) (proof : ReceiptProof)
    (h_proof : membershipProof tree receipt = some proof) :
    verifyInclusion receipt proof tree.root = true := by
  have h_sound : provesInclusion receipt proof tree.root :=
    membership_proof_sound tree receipt proof h_proof
  unfold verifyInclusion
  exact if_pos h_sound

/-- A checkpoint store keyed by `checkpointSeq` cannot yield two different
    roots for the same sequence. -/
theorem checkpoint_consistency
    (store : CheckpointStore) (checkpointSeq : Nat)
    (cp₁ cp₂ : KernelCheckpoint)
    (h₁ : store checkpointSeq = some cp₁)
    (h₂ : store checkpointSeq = some cp₂) :
    cp₁.merkleRoot = cp₂.merkleRoot := by
  have h_same : some cp₁ = some cp₂ := by
    rw [← h₁, h₂]
  have h_eq : cp₁ = cp₂ := by
    exact Option.some.inj h_same
  cases h_eq
  rfl

theorem receipt_sign_then_verify (body : ReceiptBody) :
    verifyReceipt (signReceipt body) = true := by
  simp [verifyReceipt, signReceipt]

/-- Mutating a signed receipt body while reusing the original signature fails
    verification in the symbolic signature-binding model. -/
theorem receipt_immutability
    (body tampered : ReceiptBody)
    (h_tampered : tampered ≠ body) :
    verifyReceipt { signReceipt body with body := tampered } = false := by
  have h_body_ne : body ≠ tampered := by
    intro h_eq
    apply h_tampered
    exact h_eq.symm
  simp [verifyReceipt, signReceipt, h_body_ne]

end Chio.Proofs
