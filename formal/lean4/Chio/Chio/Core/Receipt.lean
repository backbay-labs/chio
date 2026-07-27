/-
  Bounded receipt/checkpoint model for the formal receipt-proof lane.
  Mirrors the structural contracts in:
  - crates/kernel/chio-kernel-core/src/receipts.rs
  - crates/core/chio-core-types/src/receipt/body.rs
  - crates/core/chio-core-types/src/merkle.rs
  - crates/kernel/chio-kernel/src/checkpoint.rs
  Enforced by the matching [[mirror]] entries in formal/proof-manifest.toml.
-/

import Chio.Json.Hash

set_option autoImplicit false

namespace Chio.Core

open Chio.Json

/-- Bounded model of all 20 fields in Rust's `ChioReceiptIdInput`.
    Compound serde values are modeled only when they inhabit `JValue`; this is
    a tagged formal projection, not an asserted refinement of Rust serde. -/
structure ReceiptIdProjection where
  timestamp : BoundedUInt
  capabilityId : ScalarSeq
  toolServer : ScalarSeq
  toolName : ScalarSeq
  action : JValue
  decision : Option JValue
  receiptKind : ScalarSeq
  boundaryClass : ScalarSeq
  observationOutcome : Option ScalarSeq
  toolOrigin : ScalarSeq
  redactionMode : ScalarSeq
  actorChain : JArray
  contentHash : ScalarSeq
  policyHash : ScalarSeq
  evidence : JArray
  metadata : Option JValue
  trustLevel : ScalarSeq
  tenantId : Option ScalarSeq
  kernelKey : JValue
  bbsProjectionVersion : Option ScalarSeq
  deriving Repr, DecidableEq

private def fieldKey : (values : List Nat) →
    (∀ value ∈ values, IsLiteralScalar value) → ScalarSeq
  | [], _ => []
  | head :: tail, valid =>
      .literal head (valid head (by simp)) ::
        fieldKey tail (by
          intro value member
          exact valid value (by simp [member]))

@[simp] private theorem fieldKey_values (values : List Nat)
    (valid : ∀ value ∈ values, IsLiteralScalar value) :
    (fieldKey values valid).map JScalar.value = values := by
  induction values with
  | nil => rfl
  | cons head tail ih =>
      simp only [fieldKey, List.map_cons, JScalar.value, List.cons.injEq,
        true_and]
      exact ih _

private inductive ReceiptField where
  | action
  | actorChain
  | bbsProjectionVersion
  | boundaryClass
  | capabilityId
  | contentHash
  | decision
  | evidence
  | kernelKey
  | metadata
  | observationOutcome
  | policyHash
  | receiptKind
  | redactionMode
  | tenantId
  | timestamp
  | toolName
  | toolOrigin
  | toolServer
  | trustLevel
  deriving DecidableEq

private def ReceiptField.keyCodes : ReceiptField → List Nat
  | .action => [97, 99, 116, 105, 111, 110]
  | .actorChain => [97, 99, 116, 111, 114, 95, 99, 104, 97, 105, 110]
  | .bbsProjectionVersion =>
      [98, 98, 115, 95, 112, 114, 111, 106, 101, 99, 116, 105, 111, 110,
        95, 118, 101, 114, 115, 105, 111, 110]
  | .boundaryClass =>
      [98, 111, 117, 110, 100, 97, 114, 121, 95, 99, 108, 97, 115, 115]
  | .capabilityId =>
      [99, 97, 112, 97, 98, 105, 108, 105, 116, 121, 95, 105, 100]
  | .contentHash =>
      [99, 111, 110, 116, 101, 110, 116, 95, 104, 97, 115, 104]
  | .decision => [100, 101, 99, 105, 115, 105, 111, 110]
  | .evidence => [101, 118, 105, 100, 101, 110, 99, 101]
  | .kernelKey => [107, 101, 114, 110, 101, 108, 95, 107, 101, 121]
  | .metadata => [109, 101, 116, 97, 100, 97, 116, 97]
  | .observationOutcome =>
      [111, 98, 115, 101, 114, 118, 97, 116, 105, 111, 110, 95, 111, 117,
        116, 99, 111, 109, 101]
  | .policyHash => [112, 111, 108, 105, 99, 121, 95, 104, 97, 115, 104]
  | .receiptKind =>
      [114, 101, 99, 101, 105, 112, 116, 95, 107, 105, 110, 100]
  | .redactionMode =>
      [114, 101, 100, 97, 99, 116, 105, 111, 110, 95, 109, 111, 100, 101]
  | .tenantId => [116, 101, 110, 97, 110, 116, 95, 105, 100]
  | .timestamp => [116, 105, 109, 101, 115, 116, 97, 109, 112]
  | .toolName => [116, 111, 111, 108, 95, 110, 97, 109, 101]
  | .toolOrigin => [116, 111, 111, 108, 95, 111, 114, 105, 103, 105, 110]
  | .toolServer => [116, 111, 111, 108, 95, 115, 101, 114, 118, 101, 114]
  | .trustLevel => [116, 114, 117, 115, 116, 95, 108, 101, 118, 101, 108]

private theorem ReceiptField.keyCodes_valid (field : ReceiptField) :
    ∀ value ∈ field.keyCodes, IsLiteralScalar value := by
  cases field <;> decide

private theorem ReceiptField.keyCodes_injective :
    Function.Injective ReceiptField.keyCodes := by
  intro left right equal
  cases left <;> cases right <;> simp_all [ReceiptField.keyCodes]

private def ReceiptField.key (field : ReceiptField) : ScalarSeq :=
  fieldKey field.keyCodes field.keyCodes_valid

private theorem ReceiptField.key_injective :
    Function.Injective ReceiptField.key := by
  intro left right equal
  apply ReceiptField.keyCodes_injective
  have valuesEqual := congrArg (List.map JScalar.value) equal
  simpa [ReceiptField.key] using valuesEqual

private def ReceiptField.canonicalOrder : List ReceiptField :=
  [ .action, .actorChain, .bbsProjectionVersion, .boundaryClass,
    .capabilityId, .contentHash, .decision, .evidence, .kernelKey, .metadata,
    .observationOutcome, .policyHash, .receiptKind, .redactionMode, .tenantId,
    .timestamp, .toolName, .toolOrigin, .toolServer, .trustLevel ]

private def ReceiptField.strictlySorted : List ReceiptField → Bool
  | [] => true
  | head :: tail =>
      tail.all (fun field => utf16Less head.key field.key) &&
        ReceiptField.strictlySorted tail

#guard ReceiptField.strictlySorted ReceiptField.canonicalOrder

private abbrev actionKey := ReceiptField.action.key
private abbrev actorChainKey := ReceiptField.actorChain.key
private abbrev bbsProjectionVersionKey := ReceiptField.bbsProjectionVersion.key
private abbrev boundaryClassKey := ReceiptField.boundaryClass.key
private abbrev capabilityIdKey := ReceiptField.capabilityId.key
private abbrev contentHashKey := ReceiptField.contentHash.key
private abbrev decisionKey := ReceiptField.decision.key
private abbrev evidenceKey := ReceiptField.evidence.key
private abbrev kernelKeyKey := ReceiptField.kernelKey.key
private abbrev metadataKey := ReceiptField.metadata.key
private abbrev observationOutcomeKey := ReceiptField.observationOutcome.key
private abbrev policyHashKey := ReceiptField.policyHash.key
private abbrev receiptKindKey := ReceiptField.receiptKind.key
private abbrev redactionModeKey := ReceiptField.redactionMode.key
private abbrev tenantIdKey := ReceiptField.tenantId.key
private abbrev timestampKey := ReceiptField.timestamp.key
private abbrev toolNameKey := ReceiptField.toolName.key
private abbrev toolOriginKey := ReceiptField.toolOrigin.key
private abbrev toolServerKey := ReceiptField.toolServer.key
private abbrev trustLevelKey := ReceiptField.trustLevel.key

private def optionalStringValue : Option ScalarSeq → Option JValue
  | none => none
  | some value => some (.str value)

private def optionalArrayValue : JArray → Option JValue
  | .nil => none
  | values@(.cons _ _) => some (.arr values)

private def materializeEntries :
    List (ReceiptField × Option JValue) → List (ScalarSeq × JValue)
  | [] => []
  | (_, none) :: tail => materializeEntries tail
  | (field, some value) :: tail =>
      (field.key, value) :: materializeEntries tail

private def objectOfList : List (ScalarSeq × JValue) → JObject
  | [] => .nil
  | (key, value) :: tail => .cons key value (objectOfList tail)

private def objectLookup (target : ScalarSeq) : JObject → Option JValue
  | .nil => none
  | .cons key value tail =>
      if key = target then some value else objectLookup target tail

private def slotLookup (target : ReceiptField) :
    List (ReceiptField × Option JValue) → Option JValue
  | [] => none
  | (field, value) :: tail =>
      if field = target then value else slotLookup target tail

private theorem objectLookup_materializeEntries_absent
    (target : ReceiptField) (slots : List (ReceiptField × Option JValue))
    (absent : target ∉ slots.map Prod.fst) :
    objectLookup target.key (objectOfList (materializeEntries slots)) = none := by
  induction slots with
  | nil => rfl
  | cons slot tail ih =>
      rcases slot with ⟨field, value⟩
      have fieldsDiffer : field ≠ target := by
        intro equal
        subst field
        exact absent (by simp)
      have keysDiffer : field.key ≠ target.key := by
        intro keysEqual
        exact fieldsDiffer (ReceiptField.key_injective keysEqual)
      have tailAbsent : target ∉ tail.map Prod.fst := by
        intro member
        exact absent (by simp [member])
      cases value with
      | none => simpa [materializeEntries] using ih tailAbsent
      | some value =>
          simp [materializeEntries, objectOfList, objectLookup, keysDiffer,
            ih tailAbsent]

@[simp] private theorem objectLookup_materializeEntries
    (target : ReceiptField) (slots : List (ReceiptField × Option JValue))
    (unique : (slots.map Prod.fst).Nodup) :
    objectLookup target.key (objectOfList (materializeEntries slots)) =
      slotLookup target slots := by
  induction slots with
  | nil => rfl
  | cons slot tail ih =>
      rcases slot with ⟨field, value⟩
      have headAbsent : field ∉ tail.map Prod.fst := by
        simpa using (List.nodup_cons.mp unique).1
      have tailUnique : (tail.map Prod.fst).Nodup := by
        simpa using (List.nodup_cons.mp unique).2
      by_cases equal : field = target
      · subst field
        cases value with
        | none =>
            have absentResult := objectLookup_materializeEntries_absent
              target tail headAbsent
            simp [materializeEntries, slotLookup, absentResult]
        | some value =>
            simp [materializeEntries, objectOfList, objectLookup, slotLookup]
      · have keysDiffer : field.key ≠ target.key := by
          intro keysEqual
          exact equal (ReceiptField.key_injective keysEqual)
        cases value with
        | none => simpa [materializeEntries, slotLookup, equal] using ih tailUnique
        | some value =>
            simp [materializeEntries, objectOfList, objectLookup, slotLookup,
              equal, keysDiffer, ih tailUnique]

private def decodeOptionalStringField (entries : JObject)
    (key : ScalarSeq) : Option (Option ScalarSeq) :=
  match objectLookup key entries with
  | none => some none
  | some (.str value) => some (some value)
  | _ => none

private def decodeArrayField (entries : JObject)
    (key : ScalarSeq) : Option JArray :=
  match objectLookup key entries with
  | none => some .nil
  | some (.arr values) => some values
  | _ => none

@[simp] private theorem decodeOptionalStringValue_roundtrip
    (value : Option ScalarSeq) :
    (match optionalStringValue value with
      | none => some none
      | some (.str decoded) => some (some decoded)
      | _ => none) = some value := by
  cases value <;> rfl

@[simp] private theorem decodeOptionalArrayValue_roundtrip (value : JArray) :
    (match optionalArrayValue value with
      | none => some .nil
      | some (.arr decoded) => some decoded
      | _ => none) = some value := by
  cases value <;> rfl

/-- The 20 production fields as fixed canonical-order slots. A `none` slot is
    omitted when materializing the serde object. -/
private def ReceiptIdProjection.fieldValue (input : ReceiptIdProjection) :
    ReceiptField → Option JValue
  | .action => some input.action
  | .actorChain => optionalArrayValue input.actorChain
  | .bbsProjectionVersion =>
      optionalStringValue input.bbsProjectionVersion
  | .boundaryClass => some (.str input.boundaryClass)
  | .capabilityId => some (.str input.capabilityId)
  | .contentHash => some (.str input.contentHash)
  | .decision => input.decision
  | .evidence => optionalArrayValue input.evidence
  | .kernelKey => some input.kernelKey
  | .metadata => input.metadata
  | .observationOutcome => optionalStringValue input.observationOutcome
  | .policyHash => some (.str input.policyHash)
  | .receiptKind => some (.str input.receiptKind)
  | .redactionMode => some (.str input.redactionMode)
  | .tenantId => optionalStringValue input.tenantId
  | .timestamp => some (.int input.timestamp.toBoundedInt)
  | .toolName => some (.str input.toolName)
  | .toolOrigin => some (.str input.toolOrigin)
  | .toolServer => some (.str input.toolServer)
  | .trustLevel => some (.str input.trustLevel)

def ReceiptIdProjection.fieldSlots (input : ReceiptIdProjection) :
    List (ReceiptField × Option JValue) :=
  ReceiptField.canonicalOrder.map fun field => (field, input.fieldValue field)

/-- The production `ChioReceiptIdInput` object in canonical UTF-16 key order.
    Optional values and empty vectors follow the Rust serde omission rules. -/
def ReceiptIdProjection.toEntries (input : ReceiptIdProjection) :
    List (ScalarSeq × JValue) :=
  materializeEntries input.fieldSlots

private theorem ReceiptIdProjection.fieldSlots_unique
  (input : ReceiptIdProjection) :
    (input.fieldSlots.map Prod.fst).Nodup := by
  simp [ReceiptIdProjection.fieldSlots, ReceiptField.canonicalOrder]

@[simp] private theorem ReceiptIdProjection.slotLookup_fieldSlots
    (input : ReceiptIdProjection) (target : ReceiptField) :
    slotLookup target input.fieldSlots = input.fieldValue target := by
  cases target <;>
    simp [ReceiptIdProjection.fieldSlots, ReceiptIdProjection.fieldValue,
      ReceiptField.canonicalOrder, slotLookup]

@[simp] private theorem ReceiptIdProjection.objectLookup_toEntries
    (input : ReceiptIdProjection) (target : ReceiptField) :
    objectLookup target.key (objectOfList input.toEntries) =
      slotLookup target input.fieldSlots := by
  apply objectLookup_materializeEntries
  exact input.fieldSlots_unique

@[simp] private theorem ReceiptIdProjection.decodeObservationOutcome
    (input : ReceiptIdProjection) :
    decodeOptionalStringField (objectOfList input.toEntries)
      observationOutcomeKey = some input.observationOutcome := by
  simp [decodeOptionalStringField, ReceiptIdProjection.fieldSlots,
    ReceiptIdProjection.fieldValue, ReceiptField.canonicalOrder, slotLookup]

@[simp] private theorem ReceiptIdProjection.decodeTenantId
    (input : ReceiptIdProjection) :
    decodeOptionalStringField (objectOfList input.toEntries) tenantIdKey =
      some input.tenantId := by
  simp [decodeOptionalStringField, ReceiptIdProjection.fieldSlots,
    ReceiptIdProjection.fieldValue, ReceiptField.canonicalOrder, slotLookup]

@[simp] private theorem ReceiptIdProjection.decodeBbsProjectionVersion
    (input : ReceiptIdProjection) :
    decodeOptionalStringField (objectOfList input.toEntries)
      bbsProjectionVersionKey = some input.bbsProjectionVersion := by
  simp [decodeOptionalStringField, ReceiptIdProjection.fieldSlots,
    ReceiptIdProjection.fieldValue, ReceiptField.canonicalOrder, slotLookup]

@[simp] private theorem ReceiptIdProjection.decodeActorChain
    (input : ReceiptIdProjection) :
    decodeArrayField (objectOfList input.toEntries) actorChainKey =
      some input.actorChain := by
  simp [decodeArrayField, ReceiptIdProjection.fieldSlots,
    ReceiptIdProjection.fieldValue, ReceiptField.canonicalOrder, slotLookup]

@[simp] private theorem ReceiptIdProjection.decodeEvidence
    (input : ReceiptIdProjection) :
    decodeArrayField (objectOfList input.toEntries) evidenceKey =
      some input.evidence := by
  simp [decodeArrayField, ReceiptIdProjection.fieldSlots,
    ReceiptIdProjection.fieldValue, ReceiptField.canonicalOrder, slotLookup]

def ReceiptIdProjection.toJValue (input : ReceiptIdProjection) : JValue :=
  .obj (objectOfList input.toEntries)

def ReceiptIdProjection.fromJValue : JValue → Option ReceiptIdProjection
  | .obj entries =>
      match objectLookup timestampKey entries,
          objectLookup capabilityIdKey entries,
          objectLookup toolServerKey entries,
          objectLookup toolNameKey entries,
          objectLookup actionKey entries,
          objectLookup receiptKindKey entries,
          objectLookup boundaryClassKey entries,
          decodeOptionalStringField entries observationOutcomeKey,
          objectLookup toolOriginKey entries,
          objectLookup redactionModeKey entries,
          decodeArrayField entries actorChainKey,
          objectLookup contentHashKey entries,
          objectLookup policyHashKey entries,
          decodeArrayField entries evidenceKey,
          objectLookup trustLevelKey entries,
          decodeOptionalStringField entries tenantIdKey,
          objectLookup kernelKeyKey entries,
          decodeOptionalStringField entries bbsProjectionVersionKey with
      | some (.int encodedTimestamp), some (.str capabilityId),
          some (.str toolServer), some (.str toolName), some action,
          some (.str receiptKind), some (.str boundaryClass),
          some observationOutcome, some (.str toolOrigin),
          some (.str redactionMode), some actorChain,
          some (.str contentHash), some (.str policyHash), some evidence,
          some (.str trustLevel), some tenantId, some kernelKey,
          some bbsProjectionVersion =>
          match encodedTimestamp.toBoundedUInt? with
          | some timestamp =>
              some {
                timestamp,
                capabilityId,
                toolServer,
                toolName,
                action,
                decision := objectLookup decisionKey entries,
                receiptKind,
                boundaryClass,
                observationOutcome,
                toolOrigin,
                redactionMode,
                actorChain,
                contentHash,
                policyHash,
                evidence,
                metadata := objectLookup metadataKey entries,
                trustLevel,
                tenantId,
                kernelKey,
                bbsProjectionVersion }
          | none => none
      | _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ => none
  | _ => none

theorem ReceiptIdProjection.fromJValue_toJValue
    (input : ReceiptIdProjection) :
    ReceiptIdProjection.fromJValue input.toJValue = some input := by
  rcases input with
    ⟨timestamp, capabilityId, toolServer, toolName, action, decision,
      receiptKind, boundaryClass, observationOutcome, toolOrigin,
      redactionMode, actorChain, contentHash, policyHash, evidence, metadata,
      trustLevel, tenantId, kernelKey, bbsProjectionVersion⟩
  rcases timestamp with ⟨digits, valid⟩
  simp [ReceiptIdProjection.fromJValue, ReceiptIdProjection.toJValue,
    ReceiptIdProjection.fieldValue]

noncomputable def receiptId (input : ReceiptIdProjection) : HashVal :=
  digest input.toJValue

abbrev ReceiptBody := ReceiptIdProjection

def ReceiptBody.idProjection (body : ReceiptBody) : ReceiptIdProjection :=
  body

noncomputable def ReceiptBody.id (body : ReceiptBody) : HashVal :=
  receiptId body.idProjection

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

structure ReceiptInclusionProof where
  checkpointSeq : Nat
  receiptSeq : Nat
  leafIndex : Nat
  merkleRoot : MerkleHash
  proofLeafIndex : Nat
  proof : ReceiptProof
  deriving Repr, DecidableEq

def ReceiptInclusionProof.verify (self : ReceiptInclusionProof)
    (receipt : ReceiptBody) (expectedRoot : MerkleHash) : Bool :=
  if self.leafIndex = self.proofLeafIndex then
    verifyInclusion receipt self.proof expectedRoot
  else
    false

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
