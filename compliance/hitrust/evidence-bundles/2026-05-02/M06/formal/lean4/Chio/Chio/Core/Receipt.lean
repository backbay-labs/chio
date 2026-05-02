/-
  Bounded receipt/checkpoint model for the formal receipt-proof lane.
  Mirrors the structural contracts in:
  - chio-kernel-core/src/receipt.rs
  - chio-kernel/src/checkpoint.rs
-/

set_option autoImplicit false

namespace Chio.Core

structure ReceiptBody where
  id : String
  contentHash : String
  policyHash : String
  deriving Repr, DecidableEq

abbrev ReceiptSignature := ReceiptBody

structure SignedReceipt where
  body : ReceiptBody
  signature : ReceiptSignature
  deriving Repr, DecidableEq

def signReceipt (body : ReceiptBody) : SignedReceipt :=
  { body, signature := body }

def ReceiptValid (receipt : SignedReceipt) : Prop :=
  receipt.signature = receipt.body

def verifyReceipt (receipt : SignedReceipt) : Bool :=
  if receipt.signature = receipt.body then true else false

inductive MerkleHash where
  | leaf : ReceiptBody → MerkleHash
  | node : MerkleHash → MerkleHash → MerkleHash
  deriving Repr, DecidableEq

def leafHash (receipt : ReceiptBody) : MerkleHash :=
  .leaf receipt

def nodeHash (left right : MerkleHash) : MerkleHash :=
  .node left right

inductive ReceiptTree where
  | leaf : ReceiptBody → ReceiptTree
  | node : ReceiptTree → ReceiptTree → ReceiptTree
  deriving Repr, DecidableEq

def ReceiptTree.root : ReceiptTree → MerkleHash
  | .leaf receipt => leafHash receipt
  | .node left right => nodeHash left.root right.root

inductive ProofDirection where
  | left
  | right
  deriving Repr, DecidableEq

structure ProofStep where
  siblingRoot : MerkleHash
  direction : ProofDirection
  deriving Repr, DecidableEq

abbrev ReceiptProof := List ProofStep

def applyProof : MerkleHash → ReceiptProof → MerkleHash
  | current, [] => current
  | current, step :: rest =>
      let next :=
        match step.direction with
        | .left => nodeHash step.siblingRoot current
        | .right => nodeHash current step.siblingRoot
      applyProof next rest

def provesInclusion (receipt : ReceiptBody) (proof : ReceiptProof)
    (expectedRoot : MerkleHash) : Prop :=
  applyProof (leafHash receipt) proof = expectedRoot

def verifyInclusion (receipt : ReceiptBody) (proof : ReceiptProof)
    (expectedRoot : MerkleHash) : Bool :=
  if applyProof (leafHash receipt) proof = expectedRoot then true else false

def membershipProof : ReceiptTree → ReceiptBody → Option ReceiptProof
  | .leaf leafReceipt, target =>
      if target = leafReceipt then some [] else none
  | .node left right, target =>
      match membershipProof left target with
      | some proof =>
          some (proof ++ [{ siblingRoot := right.root, direction := .right }])
      | none =>
          match membershipProof right target with
          | some proof =>
              some (proof ++ [{ siblingRoot := left.root, direction := .left }])
          | none => none

structure KernelCheckpoint where
  checkpointSeq : Nat
  merkleRoot : MerkleHash
  deriving Repr, DecidableEq

def buildCheckpoint (checkpointSeq : Nat) (tree : ReceiptTree) : KernelCheckpoint :=
  { checkpointSeq, merkleRoot := tree.root }

abbrev CheckpointStore := Nat → Option KernelCheckpoint

end Chio.Core
