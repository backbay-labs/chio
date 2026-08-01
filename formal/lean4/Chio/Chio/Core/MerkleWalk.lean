/-
  Executable model of the RFC 6962 receipt inclusion walk.

  Hashes remain symbolic. This module models only sibling consumption,
  ordering, and index/size evolution.

  Enforced by paired [[mirror]] entries for the production scalar step and
  its extraction-safe copy in formal/proof-manifest.toml.
-/

import Chio.Core.Receipt

set_option autoImplicit false

namespace Chio.Core

structure StepDecision where
  consumeSibling : Bool
  siblingOnLeft : Bool
  nextIndex : Nat
  nextSize : Nat
  deriving Repr, DecidableEq

def inclusionStep (index size : Nat) : StepDecision :=
  let siblingOnLeft := index % 2 != 0
  let rightSiblingExists := index + 1 < size
  {
    consumeSibling := siblingOnLeft || rightSiblingExists
    siblingOnLeft
    nextIndex := index / 2
    nextSize := size / 2 + size % 2
  }

def StepDecision.direction (decision : StepDecision) : ProofDirection :=
  if decision.siblingOnLeft then .left else .right

def directedProofLoop : Nat -> Nat -> Nat -> List MerkleHash -> Option ReceiptProof
  | 0, _, _, _ => none
  | fuel + 1, index, size, path =>
      if size <= 1 then
        match path with
        | [] => some []
        | _ => none
      else
        let decision := inclusionStep index size
        if decision.consumeSibling then
          match path with
          | [] => none
          | sibling :: rest =>
              match directedProofLoop fuel decision.nextIndex decision.nextSize rest with
              | none => none
              | some proof =>
                  some ({ siblingRoot := sibling, direction := decision.direction } :: proof)
        else
          directedProofLoop fuel decision.nextIndex decision.nextSize path

def directedProof (leafIndex treeSize : Nat)
    (path : List MerkleHash) : Option ReceiptProof :=
  if treeSize = 0 || treeSize <= leafIndex then
    none
  else
    directedProofLoop treeSize leafIndex treeSize path

def stepFoldLoop : Nat -> MerkleHash -> Nat -> Nat ->
    List MerkleHash -> Option MerkleHash
  | 0, _, _, _, _ => none
  | fuel + 1, current, index, size, path =>
      if size <= 1 then
        match path with
        | [] => some current
        | _ => none
      else
        let decision := inclusionStep index size
        if decision.consumeSibling then
          match path with
          | [] => none
          | sibling :: rest =>
              let next :=
                if decision.siblingOnLeft then
                  nodeHash sibling current
                else
                  nodeHash current sibling
              stepFoldLoop fuel next decision.nextIndex decision.nextSize rest
        else
          stepFoldLoop fuel current decision.nextIndex decision.nextSize path

def stepFold (start : MerkleHash) (leafIndex treeSize : Nat)
    (path : List MerkleHash) : Option MerkleHash :=
  if treeSize = 0 || treeSize <= leafIndex then
    none
  else
    stepFoldLoop treeSize start leafIndex treeSize path

/-- Complete carry-last-node geometries for every tree with at most eight
    leaves. Constructor parameters are symbolic hashes, so the relation fixes
    only traversal shape and does not constrain hash contents. -/
inductive BoundedWalkGeometry :
    MerkleHash -> Nat -> Nat -> List MerkleHash -> MerkleHash -> Prop where
  | size1Index0 (a : MerkleHash) :
      BoundedWalkGeometry a 0 1 [] a
  | size2Index0 (a b : MerkleHash) :
      BoundedWalkGeometry a 0 2 [b] (nodeHash a b)
  | size2Index1 (a b : MerkleHash) :
      BoundedWalkGeometry b 1 2 [a] (nodeHash a b)
  | size3Index0 (a b c : MerkleHash) :
      BoundedWalkGeometry a 0 3 [b, c] (nodeHash (nodeHash a b) c)
  | size3Index1 (a b c : MerkleHash) :
      BoundedWalkGeometry b 1 3 [a, c] (nodeHash (nodeHash a b) c)
  | size3Index2 (a b c : MerkleHash) :
      BoundedWalkGeometry c 2 3 [nodeHash a b] (nodeHash (nodeHash a b) c)
  | size4Index0 (a b c d : MerkleHash) :
      BoundedWalkGeometry a 0 4 [b, nodeHash c d]
        (nodeHash (nodeHash a b) (nodeHash c d))
  | size4Index1 (a b c d : MerkleHash) :
      BoundedWalkGeometry b 1 4 [a, nodeHash c d]
        (nodeHash (nodeHash a b) (nodeHash c d))
  | size4Index2 (a b c d : MerkleHash) :
      BoundedWalkGeometry c 2 4 [d, nodeHash a b]
        (nodeHash (nodeHash a b) (nodeHash c d))
  | size4Index3 (a b c d : MerkleHash) :
      BoundedWalkGeometry d 3 4 [c, nodeHash a b]
        (nodeHash (nodeHash a b) (nodeHash c d))
  | size5Index0 (a b c d e : MerkleHash) :
      BoundedWalkGeometry a 0 5 [b, nodeHash c d, e]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) e)
  | size5Index1 (a b c d e : MerkleHash) :
      BoundedWalkGeometry b 1 5 [a, nodeHash c d, e]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) e)
  | size5Index2 (a b c d e : MerkleHash) :
      BoundedWalkGeometry c 2 5 [d, nodeHash a b, e]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) e)
  | size5Index3 (a b c d e : MerkleHash) :
      BoundedWalkGeometry d 3 5 [c, nodeHash a b, e]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) e)
  | size5Index4 (a b c d e : MerkleHash) :
      BoundedWalkGeometry e 4 5 [nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) e)
  | size6Index0 (a b c d e f : MerkleHash) :
      BoundedWalkGeometry a 0 6 [b, nodeHash c d, nodeHash e f]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) (nodeHash e f))
  | size6Index1 (a b c d e f : MerkleHash) :
      BoundedWalkGeometry b 1 6 [a, nodeHash c d, nodeHash e f]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) (nodeHash e f))
  | size6Index2 (a b c d e f : MerkleHash) :
      BoundedWalkGeometry c 2 6 [d, nodeHash a b, nodeHash e f]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) (nodeHash e f))
  | size6Index3 (a b c d e f : MerkleHash) :
      BoundedWalkGeometry d 3 6 [c, nodeHash a b, nodeHash e f]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) (nodeHash e f))
  | size6Index4 (a b c d e f : MerkleHash) :
      BoundedWalkGeometry e 4 6 [f, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) (nodeHash e f))
  | size6Index5 (a b c d e f : MerkleHash) :
      BoundedWalkGeometry f 5 6 [e, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d)) (nodeHash e f))
  | size7Index0 (a b c d e f g : MerkleHash) :
      BoundedWalkGeometry a 0 7 [b, nodeHash c d, nodeHash (nodeHash e f) g]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) g))
  | size7Index1 (a b c d e f g : MerkleHash) :
      BoundedWalkGeometry b 1 7 [a, nodeHash c d, nodeHash (nodeHash e f) g]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) g))
  | size7Index2 (a b c d e f g : MerkleHash) :
      BoundedWalkGeometry c 2 7 [d, nodeHash a b, nodeHash (nodeHash e f) g]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) g))
  | size7Index3 (a b c d e f g : MerkleHash) :
      BoundedWalkGeometry d 3 7 [c, nodeHash a b, nodeHash (nodeHash e f) g]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) g))
  | size7Index4 (a b c d e f g : MerkleHash) :
      BoundedWalkGeometry e 4 7 [f, g, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) g))
  | size7Index5 (a b c d e f g : MerkleHash) :
      BoundedWalkGeometry f 5 7 [e, g, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) g))
  | size7Index6 (a b c d e f g : MerkleHash) :
      BoundedWalkGeometry g 6 7 [nodeHash e f, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) g))
  | size8Index0 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry a 0 8 [b, nodeHash c d, nodeHash (nodeHash e f) (nodeHash g h)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))
  | size8Index1 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry b 1 8 [a, nodeHash c d, nodeHash (nodeHash e f) (nodeHash g h)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))
  | size8Index2 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry c 2 8 [d, nodeHash a b, nodeHash (nodeHash e f) (nodeHash g h)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))
  | size8Index3 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry d 3 8 [c, nodeHash a b, nodeHash (nodeHash e f) (nodeHash g h)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))
  | size8Index4 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry e 4 8 [f, nodeHash g h, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))
  | size8Index5 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry f 5 8 [e, nodeHash g h, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))
  | size8Index6 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry g 6 8 [h, nodeHash e f, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))
  | size8Index7 (a b c d e f g h : MerkleHash) :
      BoundedWalkGeometry h 7 8 [g, nodeHash e f, nodeHash (nodeHash a b) (nodeHash c d)]
        (nodeHash (nodeHash (nodeHash a b) (nodeHash c d))
          (nodeHash (nodeHash e f) (nodeHash g h)))

end Chio.Core
