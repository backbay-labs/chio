# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 63696e53010dca489dd90f0f71166c42511e6e9734e364a6e3cd564e8d04693b
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

"""Generated Pydantic v2 models for the Chio wire protocol (chio-wire/v1).

Re-exports every subpackage so callers can write
``from chio_sdk._generated import CapabilityToken`` for the canonical
capability token shapes without knowing the per-subpackage layout. Class
names that collide across subpackages (for example ``Kind`` defined in
both ``anchor`` and ``capability``) are re-exported under a
``<Subpkg><Class>`` alias (``AnchorKind``, ``CapabilityKind``) so
neither definition silently shadows the other. The SCHEMA_SHA256
constant pins the schema set this build was generated from; the
spec-drift CI lane reads it to detect tampering.
"""

from __future__ import annotations

from pydantic import TypeAdapter
from pydantic_core import core_schema

#: SHA-256 of the lexicographically sorted concatenation of every
#: ``spec/schemas/chio-wire/v1/**/*.schema.json`` byte stream that was
#: fed into datamodel-code-generator at build time.
SCHEMA_SHA256 = "63696e53010dca489dd90f0f71166c42511e6e9734e364a6e3cd564e8d04693b"

from .agent import Body as AgentBody, Body3, ChioAgentmessageHeartbeat, ChioAgentmessageListCapabilities, ChioAgentmessageToolCallRequest, ChioGovernedActiveResponseIntentBody, ChioGovernedTransactionIntent, MaxAmount, OrderedEffect
from .anchor import Body as AnchorBody, CheckpointId, ChioAnchorBatchV1, Inclusion, Kind as AnchorKind, Witness, WitnessReceipt, WitnessState, WitnessState1, WitnessState2, WitnessState3
from .capability import AggregateRootPublicKey, AggregateRootSignature, AggregateRootSigningAlgorithm, Algorithm as CapabilityAlgorithm, Attenuation, AttenuationProof, AttenuationWitness, Body as CapabilityBody, Caveat, ChioAggregateBudgetRootBinding, ChioAggregateInvocationBudget, ChioAggregateInvocationBudget1, ChioAggregateInvocationBudget2, ChioCapabilityGrant, ChioCapabilityNegotiationV1, ChioCapabilityRevocationEntry, ChioCapabilitytoken, ChioCumulativeApprovalRootBinding, ChioGovernedApprovalToken, ChioOpaqueSupplementalAuthorization, ChioScope, ChioThresholdApprovalProposal, ChioVerifiedApprovalSetBody, Constraint, CumulativeApprovalDelegableConstraint, CumulativeApprovalDirectConstraint, CumulativeRootMonetaryAmount, CumulativeRootPublicKey, CumulativeRootSignature, CumulativeRootSigningAlgorithm, Decision as CapabilityDecision, DelegationLink, GenericConstraint, GovernedApprovalPublicKey, GovernedApprovalSignature, GrantKind, GrantSubsetRelation, Kind as CapabilityKind, LegacyApprovalConstraint, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ScopeAttenuation, Subset, ThresholdProposalPublicKey, ThresholdProposalSignature, TokenDigest, ToolGrant, Value, Value1, Value2
from .error import ChioToolcallerrorCapabilityDenied, ChioToolcallerrorCapabilityExpired, ChioToolcallerrorCapabilityRevoked, ChioToolcallerrorInternalError, ChioToolcallerrorPolicyDenied, ChioToolcallerrorToolServerError, Detail as ErrorDetail
from .federation import CapabilityLeaseRef, ChioBilateralDsseSignatureSliceEnvelope, ChioBilateralDsseSignatureSliceStatement, CoSign, CrossOrgVisibility, Digest as FederationDigest, GovernanceReceiptRef, HashRecord, JointDisposition, KernelIdentity, PolicyEvaluationSummary, PolicyVerdict, Predicate, Signature, SubjectItem, Verdict as FederationVerdict
from .jsonrpc import ChioJsonRpc20Notification, ChioJsonRpc20Request, ChioJsonRpc20Response, ChioJsonRpc20Response1, ChioJsonRpc20Response2, Error as JsonrpcError
from .kernel import BoundTo, ChioCombinedAdmissionCaptureMetadata, ChioKernelmessageCapabilityList, ChioKernelmessageCapabilityRevoked, ChioKernelmessageHeartbeat, ChioKernelmessageToolCallChunk, ChioKernelmessageToolCallResponse, ChioSignedExecutionNonce, Detail as KernelDetail, Error as KernelError, Error10, Error11, Error12, Error13, Error9, Nonce, QuotaKey, Result, Result1, Result2, Result3, Result4
from .provenance import ChioProvenanceAttestationBundle, ChioProvenanceCallChainContext, ChioProvenanceStamp, ChioProvenanceVerdictLink, ChioProvenanceVerdictLink1, ChioProvenanceVerdictLink2, ChioProvenanceVerdictLink3, ChioProvenanceVerdictLink4, CredentialKind as ProvenanceCredentialKind, EvidenceClass as ProvenanceEvidenceClass, Scheme as ProvenanceScheme, Statement, Tier as ProvenanceTier, Verdict as ProvenanceVerdict, WorkloadIdentity as ProvenanceWorkloadIdentity
from .receipt import ActorRef, Algorithm as ReceiptAlgorithm, BbsReceiptSignature, BoundaryClass, ChioDurableAdmissionReceiptMetadata, ChioReceiptLineageStatement, ChioReceiptMerkleInclusionProof, ChioReceiptRecord, CompensationStatus, Decision as ReceiptDecision, Decision1, Decision2, Decision3, Decision4, Digest as ReceiptDigest, DispatchCommit, EvidenceClass as ReceiptEvidenceClass, GuardEvidence, Identifier, ObservationOutcome, PositiveIJsonInteger, ProjectedDispatchState, ProjectedState, ProviderAttempt, ReceiptKind, RedactionMode, RelationKind, SessionAnchorReference, StoreFence, ToolCallAction, ToolOrigin, TrustLevel
from .result import ChioToolcallresultCancelled, ChioToolcallresultErr, ChioToolcallresultIncomplete, ChioToolcallresultOk, ChioToolcallresultStreamComplete, Detail as ResultDetail, Error as ResultError, Error1, Error2, Error3, Error4, Error5
from .trust_control import BudgetSnapshotAnchorProvenance, ChioTrustControlAuthorityLease, ChioTrustControlLeaseHeartbeat, ChioTrustControlLeaseTermination, ChioTrustControlRuntimeAttestationEvidence, Commitment, CredentialKind as TrustControlCredentialKind, Digest as TrustControlDigest, Reason, Scheme as TrustControlScheme, SignedCommitment, Tier as TrustControlTier, WorkloadIdentity as TrustControlWorkloadIdentity

CapabilityToken = ChioCapabilitytoken
Decision = ReceiptDecision
CapabilityConstraint = Constraint
CapabilityOperation = Operation
CapabilityPromptGrant = PromptGrant
CapabilityResourceGrant = ResourceGrant

__all__ = [
    "ActorRef",
    "AgentBody",
    "AggregateRootPublicKey",
    "AggregateRootSignature",
    "AggregateRootSigningAlgorithm",
    "AnchorBody",
    "AnchorKind",
    "Attenuation",
    "AttenuationProof",
    "AttenuationWitness",
    "BbsReceiptSignature",
    "Body3",
    "BoundTo",
    "BoundaryClass",
    "BudgetSnapshotAnchorProvenance",
    "CapabilityAlgorithm",
    "CapabilityBody",
    "CapabilityConstraint",
    "CapabilityDecision",
    "CapabilityKind",
    "CapabilityLeaseRef",
    "CapabilityOperation",
    "CapabilityPromptGrant",
    "CapabilityResourceGrant",
    "CapabilityToken",
    "Caveat",
    "CheckpointId",
    "ChioAgentmessageHeartbeat",
    "ChioAgentmessageListCapabilities",
    "ChioAgentmessageToolCallRequest",
    "ChioAggregateBudgetRootBinding",
    "ChioAggregateInvocationBudget",
    "ChioAggregateInvocationBudget1",
    "ChioAggregateInvocationBudget2",
    "ChioAnchorBatchV1",
    "ChioBilateralDsseSignatureSliceEnvelope",
    "ChioBilateralDsseSignatureSliceStatement",
    "ChioCapabilityGrant",
    "ChioCapabilityNegotiationV1",
    "ChioCapabilityRevocationEntry",
    "ChioCapabilitytoken",
    "ChioCombinedAdmissionCaptureMetadata",
    "ChioCumulativeApprovalRootBinding",
    "ChioDurableAdmissionReceiptMetadata",
    "ChioGovernedActiveResponseIntentBody",
    "ChioGovernedApprovalToken",
    "ChioGovernedTransactionIntent",
    "ChioJsonRpc20Notification",
    "ChioJsonRpc20Request",
    "ChioJsonRpc20Response",
    "ChioJsonRpc20Response1",
    "ChioJsonRpc20Response2",
    "ChioKernelmessageCapabilityList",
    "ChioKernelmessageCapabilityRevoked",
    "ChioKernelmessageHeartbeat",
    "ChioKernelmessageToolCallChunk",
    "ChioKernelmessageToolCallResponse",
    "ChioOpaqueSupplementalAuthorization",
    "ChioProvenanceAttestationBundle",
    "ChioProvenanceCallChainContext",
    "ChioProvenanceStamp",
    "ChioProvenanceVerdictLink",
    "ChioProvenanceVerdictLink1",
    "ChioProvenanceVerdictLink2",
    "ChioProvenanceVerdictLink3",
    "ChioProvenanceVerdictLink4",
    "ChioReceiptLineageStatement",
    "ChioReceiptMerkleInclusionProof",
    "ChioReceiptRecord",
    "ChioScope",
    "ChioSignedExecutionNonce",
    "ChioThresholdApprovalProposal",
    "ChioToolcallerrorCapabilityDenied",
    "ChioToolcallerrorCapabilityExpired",
    "ChioToolcallerrorCapabilityRevoked",
    "ChioToolcallerrorInternalError",
    "ChioToolcallerrorPolicyDenied",
    "ChioToolcallerrorToolServerError",
    "ChioToolcallresultCancelled",
    "ChioToolcallresultErr",
    "ChioToolcallresultIncomplete",
    "ChioToolcallresultOk",
    "ChioToolcallresultStreamComplete",
    "ChioTrustControlAuthorityLease",
    "ChioTrustControlLeaseHeartbeat",
    "ChioTrustControlLeaseTermination",
    "ChioTrustControlRuntimeAttestationEvidence",
    "ChioVerifiedApprovalSetBody",
    "CoSign",
    "Commitment",
    "CompensationStatus",
    "Constraint",
    "CrossOrgVisibility",
    "CumulativeApprovalDelegableConstraint",
    "CumulativeApprovalDirectConstraint",
    "CumulativeRootMonetaryAmount",
    "CumulativeRootPublicKey",
    "CumulativeRootSignature",
    "CumulativeRootSigningAlgorithm",
    "Decision",
    "Decision1",
    "Decision2",
    "Decision3",
    "Decision4",
    "DelegationLink",
    "DispatchCommit",
    "Error1",
    "Error10",
    "Error11",
    "Error12",
    "Error13",
    "Error2",
    "Error3",
    "Error4",
    "Error5",
    "Error9",
    "ErrorDetail",
    "FederationDigest",
    "FederationVerdict",
    "GenericConstraint",
    "GovernanceReceiptRef",
    "GovernedApprovalPublicKey",
    "GovernedApprovalSignature",
    "GrantKind",
    "GrantSubsetRelation",
    "GuardEvidence",
    "HashRecord",
    "Identifier",
    "Inclusion",
    "JointDisposition",
    "JsonrpcError",
    "KernelDetail",
    "KernelError",
    "KernelIdentity",
    "LegacyApprovalConstraint",
    "MaxAmount",
    "MonetaryAmount",
    "Nonce",
    "ObservationOutcome",
    "Operation",
    "OrderedEffect",
    "PolicyEvaluationSummary",
    "PolicyVerdict",
    "PositiveIJsonInteger",
    "Predicate",
    "ProjectedDispatchState",
    "ProjectedState",
    "PromptGrant",
    "ProvenanceCredentialKind",
    "ProvenanceEvidenceClass",
    "ProvenanceScheme",
    "ProvenanceTier",
    "ProvenanceVerdict",
    "ProvenanceWorkloadIdentity",
    "ProviderAttempt",
    "QuotaKey",
    "Reason",
    "ReceiptAlgorithm",
    "ReceiptDecision",
    "ReceiptDigest",
    "ReceiptEvidenceClass",
    "ReceiptKind",
    "RedactionMode",
    "RelationKind",
    "ResourceGrant",
    "Result",
    "Result1",
    "Result2",
    "Result3",
    "Result4",
    "ResultDetail",
    "ResultError",
    "SCHEMA_SHA256",
    "ScopeAttenuation",
    "SessionAnchorReference",
    "Signature",
    "SignedCommitment",
    "Statement",
    "StoreFence",
    "SubjectItem",
    "Subset",
    "ThresholdProposalPublicKey",
    "ThresholdProposalSignature",
    "TokenDigest",
    "ToolCallAction",
    "ToolGrant",
    "ToolOrigin",
    "TrustControlCredentialKind",
    "TrustControlDigest",
    "TrustControlScheme",
    "TrustControlTier",
    "TrustControlWorkloadIdentity",
    "TrustLevel",
    "Value",
    "Value1",
    "Value2",
    "Witness",
    "WitnessReceipt",
    "WitnessState",
    "WitnessState1",
    "WitnessState2",
    "WitnessState3",
]
