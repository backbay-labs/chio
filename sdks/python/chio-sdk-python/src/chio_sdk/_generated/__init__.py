# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9d7b17b15b33f7dcc9d52da37c9fb906c57911cdfd78424c344f5ce58b160468
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
SCHEMA_SHA256 = "9d7b17b15b33f7dcc9d52da37c9fb906c57911cdfd78424c344f5ce58b160468"

from .agent import Algorithm as AgentAlgorithm, AttenuationProof as AgentAttenuationProof, Caveat as AgentCaveat, ChioAgentmessageHeartbeat, ChioAgentmessageListCapabilities, ChioAgentmessageToolCallRequest, Constraint as AgentConstraint, DelegationChainItem as AgentDelegationChainItem, Grant as AgentGrant, MaxCostPerInvocation as AgentMaxCostPerInvocation, MaxTotalCost as AgentMaxTotalCost, Operation as AgentOperation, PromptGrant as AgentPromptGrant, ResourceGrant as AgentResourceGrant, Scope as AgentScope, ScopeAttenuation as AgentScopeAttenuation
from .anchor import Body, CheckpointId, ChioAnchorBatchV1, Inclusion, Kind as AnchorKind, Witness, WitnessReceipt, WitnessState, WitnessState1, WitnessState2, WitnessState3
from .capability import Algorithm as CapabilityAlgorithm, Attenuation, AttenuationProof as CapabilityAttenuationProof, AttenuationWitness, Caveat as CapabilityCaveat, ChioCapabilityGrant, ChioCapabilityNegotiationV1, ChioCapabilityRevocationEntry, ChioCapabilitytoken, ChioScope, Constraint as CapabilityConstraint, DelegationLink, GrantKind, GrantSubsetRelation, Kind as CapabilityKind, MonetaryAmount, Operation as CapabilityOperation, PromptGrant as CapabilityPromptGrant, ResourceGrant as CapabilityResourceGrant, ScopeAttenuation as CapabilityScopeAttenuation, Subset, ToolGrant
from .error import ChioToolcallerrorCapabilityDenied, ChioToolcallerrorCapabilityExpired, ChioToolcallerrorCapabilityRevoked, ChioToolcallerrorInternalError, ChioToolcallerrorPolicyDenied, ChioToolcallerrorToolServerError, Detail as ErrorDetail
from .federation import CapabilityLeaseRef, ChioBilateralDsseSignatureSliceEnvelope, ChioBilateralDsseSignatureSliceStatement, CoSign, CrossOrgVisibility, Digest, GovernanceReceiptRef, HashRecord, JointDisposition, KernelIdentity, PolicyEvaluationSummary, PolicyVerdict, Predicate, Signature, SubjectItem, Verdict as FederationVerdict
from .jsonrpc import ChioJsonRpc20Notification, ChioJsonRpc20Request, ChioJsonRpc20Response, ChioJsonRpc20Response1, ChioJsonRpc20Response2, Error as JsonrpcError
from .kernel import Algorithm as KernelAlgorithm, AttenuationProof as KernelAttenuationProof, Capability, Caveat as KernelCaveat, ChioKernelmessageCapabilityList, ChioKernelmessageCapabilityRevoked, ChioKernelmessageHeartbeat, ChioKernelmessageToolCallChunk, ChioKernelmessageToolCallResponse, Constraint as KernelConstraint, DelegationChainItem as KernelDelegationChainItem, Detail as KernelDetail, Error as KernelError, Error10, Error11, Error12, Error13, Error9, Grant as KernelGrant, MaxCostPerInvocation as KernelMaxCostPerInvocation, MaxTotalCost as KernelMaxTotalCost, Operation as KernelOperation, PromptGrant as KernelPromptGrant, ResourceGrant as KernelResourceGrant, Result, Result1, Result2, Result3, Result4, Scope as KernelScope, ScopeAttenuation as KernelScopeAttenuation
from .provenance import ChioProvenanceAttestationBundle, ChioProvenanceCallChainContext, ChioProvenanceStamp, ChioProvenanceVerdictLink, ChioProvenanceVerdictLink1, ChioProvenanceVerdictLink2, ChioProvenanceVerdictLink3, ChioProvenanceVerdictLink4, CredentialKind as ProvenanceCredentialKind, EvidenceClass as ProvenanceEvidenceClass, Scheme as ProvenanceScheme, Statement, Tier as ProvenanceTier, Verdict as ProvenanceVerdict, WorkloadIdentity as ProvenanceWorkloadIdentity
from .receipt import ActorRef, Algorithm as ReceiptAlgorithm, BbsReceiptSignature, BoundaryClass, ChioReceiptLineageStatement, ChioReceiptMerkleInclusionProof, ChioReceiptRecord, Decision, Decision1, Decision2, Decision3, Decision4, EvidenceClass as ReceiptEvidenceClass, GuardEvidence, ObservationOutcome, ReceiptKind, RedactionMode, RelationKind, SessionAnchorReference, ToolCallAction, ToolOrigin, TrustLevel
from .result import ChioToolcallresultCancelled, ChioToolcallresultErr, ChioToolcallresultIncomplete, ChioToolcallresultOk, ChioToolcallresultStreamComplete, Detail as ResultDetail, Error as ResultError, Error1, Error2, Error3, Error4, Error5
from .trust_control import ChioTrustControlAuthorityLease, ChioTrustControlLeaseHeartbeat, ChioTrustControlLeaseTermination, ChioTrustControlRuntimeAttestationEvidence, CredentialKind as TrustControlCredentialKind, Reason, Scheme as TrustControlScheme, Tier as TrustControlTier, WorkloadIdentity as TrustControlWorkloadIdentity

CapabilityToken = ChioCapabilitytoken

__all__ = [
    "ActorRef",
    "AgentAlgorithm",
    "AgentAttenuationProof",
    "AgentCaveat",
    "AgentConstraint",
    "AgentDelegationChainItem",
    "AgentGrant",
    "AgentMaxCostPerInvocation",
    "AgentMaxTotalCost",
    "AgentOperation",
    "AgentPromptGrant",
    "AgentResourceGrant",
    "AgentScope",
    "AgentScopeAttenuation",
    "AnchorKind",
    "Attenuation",
    "AttenuationWitness",
    "BbsReceiptSignature",
    "Body",
    "BoundaryClass",
    "Capability",
    "CapabilityAlgorithm",
    "CapabilityAttenuationProof",
    "CapabilityCaveat",
    "CapabilityConstraint",
    "CapabilityKind",
    "CapabilityLeaseRef",
    "CapabilityOperation",
    "CapabilityPromptGrant",
    "CapabilityResourceGrant",
    "CapabilityScopeAttenuation",
    "CapabilityToken",
    "CheckpointId",
    "ChioAgentmessageHeartbeat",
    "ChioAgentmessageListCapabilities",
    "ChioAgentmessageToolCallRequest",
    "ChioAnchorBatchV1",
    "ChioBilateralDsseSignatureSliceEnvelope",
    "ChioBilateralDsseSignatureSliceStatement",
    "ChioCapabilityGrant",
    "ChioCapabilityNegotiationV1",
    "ChioCapabilityRevocationEntry",
    "ChioCapabilitytoken",
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
    "CoSign",
    "CrossOrgVisibility",
    "Decision",
    "Decision1",
    "Decision2",
    "Decision3",
    "Decision4",
    "DelegationLink",
    "Digest",
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
    "FederationVerdict",
    "GovernanceReceiptRef",
    "GrantKind",
    "GrantSubsetRelation",
    "GuardEvidence",
    "HashRecord",
    "Inclusion",
    "JointDisposition",
    "JsonrpcError",
    "KernelAlgorithm",
    "KernelAttenuationProof",
    "KernelCaveat",
    "KernelConstraint",
    "KernelDelegationChainItem",
    "KernelDetail",
    "KernelError",
    "KernelGrant",
    "KernelIdentity",
    "KernelMaxCostPerInvocation",
    "KernelMaxTotalCost",
    "KernelOperation",
    "KernelPromptGrant",
    "KernelResourceGrant",
    "KernelScope",
    "KernelScopeAttenuation",
    "MonetaryAmount",
    "ObservationOutcome",
    "PolicyEvaluationSummary",
    "PolicyVerdict",
    "Predicate",
    "ProvenanceCredentialKind",
    "ProvenanceEvidenceClass",
    "ProvenanceScheme",
    "ProvenanceTier",
    "ProvenanceVerdict",
    "ProvenanceWorkloadIdentity",
    "Reason",
    "ReceiptAlgorithm",
    "ReceiptEvidenceClass",
    "ReceiptKind",
    "RedactionMode",
    "RelationKind",
    "Result",
    "Result1",
    "Result2",
    "Result3",
    "Result4",
    "ResultDetail",
    "ResultError",
    "SCHEMA_SHA256",
    "SessionAnchorReference",
    "Signature",
    "Statement",
    "SubjectItem",
    "Subset",
    "ToolCallAction",
    "ToolGrant",
    "ToolOrigin",
    "TrustControlCredentialKind",
    "TrustControlScheme",
    "TrustControlTier",
    "TrustControlWorkloadIdentity",
    "TrustLevel",
    "Witness",
    "WitnessReceipt",
    "WitnessState",
    "WitnessState1",
    "WitnessState2",
    "WitnessState3",
]
