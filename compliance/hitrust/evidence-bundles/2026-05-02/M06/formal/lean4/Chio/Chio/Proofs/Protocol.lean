/-
  Proofs for the bounded implementation-linked protocol model.

  These theorems cover P6-P10 and adjacent pure admission, budget,
  governance, and local registry transitions. They are model proofs; the
  Rust linkage and external-system assumptions are tracked by the proof
  manifest and assumption registry.
-/

import Chio.Core.Protocol

set_option autoImplicit false

namespace Chio.Proofs

open Chio.Core

theorem admitSession_invalid_dpop_rejects
    (facts : AdmissionFacts)
    (h_required : facts.dpopRequired = true)
    (h_invalid : facts.dpopValid = false) :
    admitSession facts = .reject "dpop proof invalid" := by
  unfold admitSession
  simp [h_required, h_invalid]

theorem admitSession_invalid_anchor_rejects
    (facts : AdmissionFacts)
    (h_dpop_ok : ¬ (facts.dpopRequired && !facts.dpopValid) = true)
    (h_required : facts.sessionAnchorRequired = true)
    (h_invalid : facts.sessionAnchorValid = false) :
    admitSession facts = .reject "session anchor invalid" := by
  unfold admitSession
  simp [h_dpop_ok, h_required, h_invalid]

theorem budgetPrecheck_commit_preserves_bounds
    (state : BudgetState)
    (request : BudgetRequest)
    (next : BudgetState)
    (h_commit : budgetCommit state request = some next) :
    next.remainingInvocations <= state.remainingInvocations
      ∧ next.remainingUnits <= state.remainingUnits := by
  unfold budgetCommit at h_commit
  cases h_check : budgetPrecheck state request with
  | false =>
      simp [h_check] at h_commit
  | true =>
      simp [h_check] at h_commit
      cases h_commit
      exact ⟨Nat.sub_le state.remainingInvocations request.invocationCost,
        Nat.sub_le state.remainingUnits request.unitCost⟩

theorem budgetCommit_none_when_precheck_fails
    (state : BudgetState)
    (request : BudgetRequest)
    (h_precheck : budgetPrecheck state request = false) :
    budgetCommit state request = none := by
  unfold budgetCommit
  simp [h_precheck]

theorem budgetTwoCommit_preserves_bounds
    (state : BudgetState)
    (first : BudgetRequest)
    (second : BudgetRequest)
    (next : BudgetState)
    (h_commit : budgetTwoCommit state first second = some next) :
    next.remainingInvocations <= state.remainingInvocations
      ∧ next.remainingUnits <= state.remainingUnits := by
  unfold budgetTwoCommit at h_commit
  cases h_first : budgetCommit state first with
  | none =>
      simp [h_first] at h_commit
  | some mid =>
      simp [h_first] at h_commit
      have h_mid := budgetPrecheck_commit_preserves_bounds state first mid h_first
      have h_next := budgetPrecheck_commit_preserves_bounds mid second next h_commit
      exact ⟨Nat.le_trans h_next.left h_mid.left,
        Nat.le_trans h_next.right h_mid.right⟩

theorem clusterOverrun_bound_is_explicit
    (observedOverrun : Nat)
    (maxCostPerInvocation : Nat)
    (nodeCount : Nat)
    (h_bound : observedOverrun <= clusterOverrunBound maxCostPerInvocation nodeCount) :
    observedOverrun <= maxCostPerInvocation * nodeCount := by
  unfold clusterOverrunBound at h_bound
  exact h_bound

theorem governedApproval_required_without_token_fails
    (facts : ApprovalFacts)
    (h_required : facts.approvalRequired = true)
    (h_token : facts.approvalTokenValid = false) :
    governedApprovalPasses facts = false := by
  unfold governedApprovalPasses
  simp [h_required, h_token]

theorem governedApproval_valid_token_passes
    (facts : ApprovalFacts)
    (h_token : facts.approvalTokenValid = true) :
    governedApprovalPasses facts = true := by
  unfold governedApprovalPasses
  simp [h_token]

theorem dpop_required_missing_proof_rejects
    (facts : DpopNonceFacts)
    (h_required : facts.dpopRequired = true)
    (h_missing : facts.proofPresent = false) :
    dpopNonceAdmits facts = false := by
  cases facts with
  | mk dpopRequired proofPresent proofValid nonceFresh =>
      simp [dpopNonceAdmits] at h_required h_missing ⊢
      simp [h_required, h_missing]

theorem dpop_required_invalid_proof_rejects
    (facts : DpopNonceFacts)
    (h_required : facts.dpopRequired = true)
    (h_present : facts.proofPresent = true)
    (h_invalid : facts.proofValid = false) :
    dpopNonceAdmits facts = false := by
  cases facts with
  | mk dpopRequired proofPresent proofValid nonceFresh =>
      simp [dpopNonceAdmits] at h_required h_present h_invalid ⊢
      simp [h_required, h_present, h_invalid]

theorem dpop_reused_nonce_rejects :
    nonceReplayAdmits true = false := by
  rfl

theorem revocationSnapshot_revoked_token_denies
    (facts : RevocationSnapshotFacts)
    (h_revoked : facts.tokenRevoked = true) :
    revocationSnapshotDenies facts = true := by
  cases facts with
  | mk tokenRevoked ancestorRevoked =>
      simp [revocationSnapshotDenies] at h_revoked ⊢
      simp [h_revoked]

theorem revocationSnapshot_revoked_ancestor_denies
    (facts : RevocationSnapshotFacts)
    (h_revoked : facts.ancestorRevoked = true) :
    revocationSnapshotDenies facts = true := by
  cases facts with
  | mk tokenRevoked ancestorRevoked =>
      simp [revocationSnapshotDenies] at h_revoked ⊢
      cases tokenRevoked <;> simp [h_revoked]

theorem guardPipeline_deny_dominates
    (coreAuthorized : Bool) :
    guardPipelineAllows coreAuthorized [.deny] = false := by
  cases coreAuthorized <;> rfl

theorem guardPipeline_error_dominates
    (coreAuthorized : Bool) :
    guardPipelineAllows coreAuthorized [.error] = false := by
  cases coreAuthorized <;> rfl

theorem guardPipeline_allow_requires_core_authorized
    (coreAuthorized : Bool)
    (guards : List GuardResult)
    (h_allowed : guardPipelineAllows coreAuthorized guards = true) :
    coreAuthorized = true := by
  cases coreAuthorized <;> simp [guardPipelineAllows] at h_allowed ⊢

theorem receiptFieldsCoupled_preserves_all_fields
    (facts : ReceiptCouplingFacts)
    (h_coupled : receiptFieldsCoupled facts = true) :
    facts.capabilityMatches = true
      ∧ facts.requestMatches = true
      ∧ facts.verdictMatches = true
      ∧ facts.policyHashMatches = true
      ∧ facts.evidenceClassMatches = true := by
  cases facts with
  | mk capabilityMatches requestMatches verdictMatches policyHashMatches evidenceClassMatches =>
      cases capabilityMatches <;> cases requestMatches <;> cases verdictMatches
      <;> cases policyHashMatches <;> cases evidenceClassMatches
      <;> simp [receiptFieldsCoupled] at h_coupled ⊢

theorem observed_parent_edge_sound
    (edge : LocalParentEdge)
    (h_valid : observedParentEdgeValid edge = true) :
    edge.label = .observed
      ∧ edge.parentRequestExists = true
      ∧ edge.sameAuthenticatedSession = true := by
  cases edge with
  | mk label parentRequestExists sameAuthenticatedSession =>
      cases label <;> cases parentRequestExists <;> cases sameAuthenticatedSession
      <;> simp [observedParentEdgeValid] at h_valid ⊢

theorem verified_receipt_lineage_sound
    (evidence : ReceiptLineageEvidence)
    (h_valid : verifiedReceiptLineage evidence = true) :
    evidence.label = .verified
      ∧ evidence.parentReceiptVerifies = true
      ∧ evidence.childReceiptVerifies = true
      ∧ evidence.trustedKernelSignature = true
      ∧ evidence.linkageSigned = true := by
  cases evidence with
  | mk label parentReceiptVerifies childReceiptVerifies trustedKernelSignature linkageSigned =>
      cases label <;> cases parentReceiptVerifies <;> cases childReceiptVerifies
      <;> cases trustedKernelSignature <;> cases linkageSigned
      <;> simp [verifiedReceiptLineage] at h_valid ⊢

theorem session_continuity_sound
    (continuation : SessionContinuation)
    (h_valid : verifiedSessionContinuation continuation = true) :
    continuation.label = .verified
      ∧ continuation.sessionAnchorValid = true
      ∧ continuation.continuationArtifactValid = true := by
  cases continuation with
  | mk label sessionAnchorValid continuationArtifactValid =>
      cases label <;> cases sessionAnchorValid <;> cases continuationArtifactValid
      <;> simp [verifiedSessionContinuation] at h_valid ⊢

theorem capability_lineage_consistency_sound
    (lineage : CapabilityLineage)
    (h_valid : capabilityLineageConsistent lineage = true) :
    lineage.verifiedCallChain = true
      ∧ lineage.subjectsConsistent = true
      ∧ lineage.parentCapabilityReferencesConsistent = true := by
  cases lineage with
  | mk verifiedCallChain subjectsConsistent parentCapabilityReferencesConsistent =>
      cases verifiedCallChain <;> cases subjectsConsistent
      <;> cases parentCapabilityReferencesConsistent
      <;> simp [capabilityLineageConsistent] at h_valid ⊢

theorem report_truthfulness_asserted_not_verified :
    reportMayUseVerifiedLabel EvidenceLabel.asserted = false := by
  rfl

theorem report_truthfulness_observed_not_verified :
    reportMayUseVerifiedLabel EvidenceLabel.observed = false := by
  rfl

theorem registry_publish_requires_valid_signature
    (registry : CertificationRegistry)
    (record : CertificationRecord)
    (h_invalid : record.signatureValid = false) :
    CertificationRegistry.publish registry record = registry := by
  unfold CertificationRegistry.publish
  simp [h_invalid]

theorem registry_resolve_published_valid_record
    (registry : CertificationRegistry)
    (record : CertificationRecord)
    (h_valid : record.signatureValid = true) :
    CertificationRegistry.resolve
      (CertificationRegistry.publish registry record)
      record.artifactId = some record := by
  unfold CertificationRegistry.publish CertificationRegistry.resolve
  simp [h_valid]

theorem registry_revoke_deactivates_published_record
    (record : CertificationRecord) :
    CertificationRegistry.active
      (CertificationRegistry.revoke [record] record.artifactId)
      record.artifactId = false := by
  unfold CertificationRegistry.active CertificationRegistry.resolve CertificationRegistry.revoke
  simp

end Chio.Proofs
