/-
  Proofs for the bounded receipt lane:
  - Merkle inclusion soundness
  - checkpoint consistency
  - receipt immutability
-/

import Chio.Core.Receipt
import Chio.Proofs.CanonicalInjective

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

theorem indexed_inclusion_rejects_leaf_index_mismatch
    (receipt : ReceiptBody) (proof : ReceiptInclusionProof)
    (expectedRoot : MerkleHash)
    (h : proof.leafIndex ≠ proof.proofLeafIndex) :
    proof.verify receipt expectedRoot = false := by
  simp [ReceiptInclusionProof.verify, h]

theorem indexed_inclusion_accepts_matching_membership_proof
    (tree : ReceiptTree) (receipt : ReceiptBody) (path : ReceiptProof)
    (leafIndex : Nat)
    (h : membershipProof tree receipt = some path) :
    (ReceiptInclusionProof.mk 1 1 leafIndex tree.root leafIndex path).verify
        receipt tree.root = true := by
  simp [ReceiptInclusionProof.verify]
  exact membership_proof_verifies tree receipt path h

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

private theorem receiptIdProjection_toJValue_inj
    {left right : ReceiptIdProjection}
    (equal : left.toJValue = right.toJValue) :
    left = right := by
  have encodedEqual : some left = some right := by
    rw [← left.fromJValue_toJValue, equal, right.fromJValue_toJValue]
  exact Option.some.inj encodedEqual

/-- On the modeled domain, equal symbolic identifiers bind all 20 modeled
    fields of production `ChioReceiptIdInput`. -/
theorem receipt_id_input_collision_resistant
    {left right : ReceiptIdProjection}
    (identifiersEqual : receiptId left = receiptId right) :
    left = right := by
  have canonicalEqual :
      Chio.Json.canonical left.toJValue =
        Chio.Json.canonical right.toJValue := by
    apply Chio.Json.digest_injective
    simpa [receiptId] using identifiersEqual
  exact receiptIdProjection_toJValue_inj (canonical_inj canonicalEqual)

#print axioms receipt_id_input_collision_resistant

/-- Equal modeled receipt identifiers bind equal content and policy hashes. -/
theorem receipt_id_collision_resistant
    (idInput₁ idInput₂ : ReceiptBody) :
    idInput₁.id = idInput₂.id →
      idInput₁.contentHash = idInput₂.contentHash ∧
        idInput₁.policyHash = idInput₂.policyHash := by
  intro identifiersEqual
  have inputsEqual : idInput₁ = idInput₂ := by
    apply receipt_id_input_collision_resistant
    simpa [ReceiptBody.id, ReceiptBody.idProjection] using identifiersEqual
  exact ⟨congrArg ReceiptIdProjection.contentHash inputsEqual,
    congrArg ReceiptIdProjection.policyHash inputsEqual⟩

#print axioms receipt_id_collision_resistant

end Chio.Proofs
