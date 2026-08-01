/-
  Equivalence and soundness proofs for the executable receipt inclusion walk.
-/

import Chio.Core.MerkleWalk
import Chio.Proofs.Receipt

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Core

theorem stepFoldLoop_eq_directedProofLoop_map
    (fuel : Nat) (start : MerkleHash) (leafIndex treeSize : Nat)
    (path : List MerkleHash) :
    stepFoldLoop fuel start leafIndex treeSize path =
      (directedProofLoop fuel leafIndex treeSize path).map (applyProof start) := by
  induction fuel generalizing start leafIndex treeSize path with
  | zero =>
      rfl
  | succ fuel ih =>
      simp only [stepFoldLoop, directedProofLoop]
      split
      next h_terminal =>
        cases path <;> rfl
      next h_nonterminal =>
        split
        next h_consume =>
          cases path with
          | nil => rfl
          | cons sibling rest =>
              simp only
              rw [ih]
              cases h_proof : directedProofLoop fuel
                  (inclusionStep leafIndex treeSize).nextIndex
                  (inclusionStep leafIndex treeSize).nextSize rest with
              | none => rfl
              | some proof =>
                  cases h_left :
                      (inclusionStep leafIndex treeSize).siblingOnLeft <;>
                    simp [applyProof, StepDecision.direction, h_left]
        next h_carry =>
          exact ih start
            (inclusionStep leafIndex treeSize).nextIndex
            (inclusionStep leafIndex treeSize).nextSize path

theorem stepFold_eq_directedProof_map
    (start : MerkleHash) (leafIndex treeSize : Nat)
    (path : List MerkleHash) :
    stepFold start leafIndex treeSize path =
      (directedProof leafIndex treeSize path).map (applyProof start) := by
  simp only [stepFold, directedProof]
  split
  next h_invalid => rfl
  next h_valid =>
    exact stepFoldLoop_eq_directedProofLoop_map
      treeSize start leafIndex treeSize path

theorem stepFold_eq_applyProof
    (leafIndex treeSize : Nat) (path : List MerkleHash)
    (start : MerkleHash) (proof : ReceiptProof)
    (h_directed : directedProof leafIndex treeSize path = some proof) :
    stepFold start leafIndex treeSize path = some (applyProof start proof) := by
  rw [stepFold_eq_directedProof_map, h_directed]
  rfl

/-- Conditional composition with the legacy membership proof. The separate
    bounded geometry theorem below discharges traversal shape for the complete
    supported domain. -/
theorem stepFold_membership_sound_if_geometry_agrees
    (tree : ReceiptTree) (receipt : ReceiptBody)
    (leafIndex treeSize : Nat) (path : List MerkleHash)
    (proof : ReceiptProof)
    (h_membership : membershipProof tree receipt = some proof)
    (h_directed : directedProof leafIndex treeSize path = some proof) :
    stepFold (leafHash receipt) leafIndex treeSize path = some tree.root := by
  have h_fold :
      stepFold (leafHash receipt) leafIndex treeSize path =
        some (applyProof (leafHash receipt) proof) :=
    stepFold_eq_applyProof leafIndex treeSize path (leafHash receipt) proof h_directed
  have h_sound : applyProof (leafHash receipt) proof = tree.root := by
    simpa [provesInclusion] using
      membership_proof_sound tree receipt proof h_membership
  calc
    stepFold (leafHash receipt) leafIndex treeSize path =
        some (applyProof (leafHash receipt) proof) := h_fold
    _ = some tree.root := congrArg some h_sound

/-- Every carry-last-node geometry with one through eight leaves decodes to a
    direction-tagged proof whose application is the declared root. -/
theorem boundedWalkGeometry_decodes
    {start : MerkleHash} {leafIndex treeSize : Nat}
    {path : List MerkleHash} {root : MerkleHash}
    (h_geometry : BoundedWalkGeometry start leafIndex treeSize path root) :
    ∃ proof : ReceiptProof,
      directedProof leafIndex treeSize path = some proof ∧
        applyProof start proof = root := by
  cases h_geometry <;> simp [directedProof, directedProofLoop, inclusionStep,
    StepDecision.direction, applyProof]

/-- The checked fold reaches the declared root for every supported geometry;
    no caller-provided equality between a decoded path and a proof is needed. -/
theorem bounded_stepFold_sound
    {start : MerkleHash} {leafIndex treeSize : Nat}
    {path : List MerkleHash} {root : MerkleHash}
    (h_geometry : BoundedWalkGeometry start leafIndex treeSize path root) :
    stepFold start leafIndex treeSize path = some root := by
  cases h_geometry <;> rfl

end Chio.Proofs
