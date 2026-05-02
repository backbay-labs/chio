/-
  Bounded protocol-core model for implementation-linked verification.

  This file models the pure decisions that sit around the portable kernel
  core: DPoP/session admission, budget precheck, governed approvals,
  provenance labels, receipt lineage, and local certification registry state.
  External cryptography, clocks, stores, transports, and hosted services are
  tracked in formal/assumptions.toml.
-/

import Chio.Core.Capability
import Chio.Core.Receipt

set_option autoImplicit false

namespace Chio.Core

inductive AdmissionDecision where
  | admit
  | reject (reason : String)
  deriving Repr, BEq

structure AdmissionFacts where
  dpopRequired : Bool
  dpopValid : Bool
  sessionAnchorRequired : Bool
  sessionAnchorValid : Bool
  deriving Repr, BEq

def admitSession (facts : AdmissionFacts) : AdmissionDecision :=
  if facts.dpopRequired && !facts.dpopValid then
    .reject "dpop proof invalid"
  else if facts.sessionAnchorRequired && !facts.sessionAnchorValid then
    .reject "session anchor invalid"
  else
    .admit

structure BudgetState where
  remainingInvocations : Nat
  remainingUnits : Nat
  deriving Repr, BEq

structure BudgetRequest where
  invocationCost : Nat
  unitCost : Nat
  deriving Repr, BEq

def budgetPrecheck (state : BudgetState) (request : BudgetRequest) : Bool :=
  request.invocationCost <= state.remainingInvocations
    && request.unitCost <= state.remainingUnits

def budgetCommit (state : BudgetState) (request : BudgetRequest) : Option BudgetState :=
  if budgetPrecheck state request then
    some {
      remainingInvocations := state.remainingInvocations - request.invocationCost,
      remainingUnits := state.remainingUnits - request.unitCost,
    }
  else
    none

def budgetTwoCommit
    (state : BudgetState)
    (first : BudgetRequest)
    (second : BudgetRequest) : Option BudgetState :=
  match budgetCommit state first with
  | some next => budgetCommit next second
  | none => none

def clusterOverrunBound (maxCostPerInvocation : Nat) (nodeCount : Nat) : Nat :=
  maxCostPerInvocation * nodeCount

structure ApprovalFacts where
  approvalRequired : Bool
  approvalTokenValid : Bool
  deriving Repr, BEq

def governedApprovalPasses (facts : ApprovalFacts) : Bool :=
  !facts.approvalRequired || facts.approvalTokenValid

structure DpopNonceFacts where
  dpopRequired : Bool
  proofPresent : Bool
  proofValid : Bool
  nonceFresh : Bool
  deriving Repr, BEq

def dpopNonceAdmits (facts : DpopNonceFacts) : Bool :=
  !facts.dpopRequired || (facts.proofPresent && facts.proofValid && facts.nonceFresh)

def nonceReplayAdmits (alreadyLive : Bool) : Bool :=
  !alreadyLive

structure RevocationSnapshotFacts where
  tokenRevoked : Bool
  ancestorRevoked : Bool
  deriving Repr, BEq

def revocationSnapshotDenies (facts : RevocationSnapshotFacts) : Bool :=
  facts.tokenRevoked || facts.ancestorRevoked

inductive GuardResult where
  | allow
  | deny
  | error
  deriving Repr, BEq, DecidableEq, ReflBEq, LawfulBEq

def guardResultAllows (result : GuardResult) : Bool :=
  result == .allow

def guardPipelineAllows (coreAuthorized : Bool) (guards : List GuardResult) : Bool :=
  coreAuthorized && guards.all guardResultAllows

structure ReceiptCouplingFacts where
  capabilityMatches : Bool
  requestMatches : Bool
  verdictMatches : Bool
  policyHashMatches : Bool
  evidenceClassMatches : Bool
  deriving Repr, BEq

def receiptFieldsCoupled (facts : ReceiptCouplingFacts) : Bool :=
  facts.capabilityMatches
    && facts.requestMatches
    && facts.verdictMatches
    && facts.policyHashMatches
    && facts.evidenceClassMatches

inductive EvidenceLabel where
  | asserted
  | observed
  | verified
  deriving Repr, BEq, DecidableEq, ReflBEq, LawfulBEq

structure LocalParentEdge where
  label : EvidenceLabel
  parentRequestExists : Bool
  sameAuthenticatedSession : Bool
  deriving Repr, BEq

def observedParentEdgeValid (edge : LocalParentEdge) : Bool :=
  edge.label == .observed
    && edge.parentRequestExists
    && edge.sameAuthenticatedSession

structure ReceiptLineageEvidence where
  label : EvidenceLabel
  parentReceiptVerifies : Bool
  childReceiptVerifies : Bool
  trustedKernelSignature : Bool
  linkageSigned : Bool
  deriving Repr, BEq

def verifiedReceiptLineage (evidence : ReceiptLineageEvidence) : Bool :=
  evidence.label == .verified
    && evidence.parentReceiptVerifies
    && evidence.childReceiptVerifies
    && evidence.trustedKernelSignature
    && evidence.linkageSigned

structure SessionContinuation where
  label : EvidenceLabel
  sessionAnchorValid : Bool
  continuationArtifactValid : Bool
  deriving Repr, BEq

def verifiedSessionContinuation (continuation : SessionContinuation) : Bool :=
  continuation.label == .verified
    && continuation.sessionAnchorValid
    && continuation.continuationArtifactValid

structure CapabilityLineage where
  verifiedCallChain : Bool
  subjectsConsistent : Bool
  parentCapabilityReferencesConsistent : Bool
  deriving Repr, BEq

def capabilityLineageConsistent (lineage : CapabilityLineage) : Bool :=
  lineage.verifiedCallChain
    && lineage.subjectsConsistent
    && lineage.parentCapabilityReferencesConsistent

def reportMayUseVerifiedLabel (inputLabel : EvidenceLabel) : Bool :=
  inputLabel == .verified

inductive RegistryStatus where
  | active
  | revoked
  deriving Repr, BEq, DecidableEq, ReflBEq, LawfulBEq

structure CertificationRecord where
  artifactId : String
  subjectId : String
  signatureValid : Bool
  status : RegistryStatus
  deriving Repr, BEq

abbrev CertificationRegistry := List CertificationRecord

def CertificationRegistry.resolve
    (registry : CertificationRegistry)
    (artifactId : String) : Option CertificationRecord :=
  registry.find? (fun record => record.artifactId == artifactId)

def CertificationRegistry.publish
    (registry : CertificationRegistry)
    (record : CertificationRecord) : CertificationRegistry :=
  if record.signatureValid then
    record :: registry
  else
    registry

def CertificationRegistry.revoke
    (registry : CertificationRegistry)
    (artifactId : String) : CertificationRegistry :=
  registry.map (fun record =>
    if record.artifactId == artifactId then
      { record with status := .revoked }
    else
      record)

def CertificationRegistry.active
    (registry : CertificationRegistry)
    (artifactId : String) : Bool :=
  match registry.resolve artifactId with
  | some record => record.signatureValid && record.status == .active
  | none => false

end Chio.Core
