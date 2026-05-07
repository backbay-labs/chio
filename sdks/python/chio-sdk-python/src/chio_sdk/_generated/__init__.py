# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 33035d85d1be112ab0feff412b8183f2916dc2c03dd89271104beebb8ea8bc2d
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

#: SHA-256 of the lexicographically sorted concatenation of every
#: ``spec/schemas/chio-wire/v1/**/*.schema.json`` byte stream that was
#: fed into datamodel-code-generator at build time.
SCHEMA_SHA256 = "33035d85d1be112ab0feff412b8183f2916dc2c03dd89271104beebb8ea8bc2d"

from .agent import Algorithm as AgentAlgorithm, ChioAgentmessageHeartbeat, ChioAgentmessageListCapabilities, ChioAgentmessageToolCallRequest, Constraint as AgentConstraint, DelegationChainItem as AgentDelegationChainItem, Grant as AgentGrant, MaxCostPerInvocation as AgentMaxCostPerInvocation, MaxTotalCost as AgentMaxTotalCost, Operation as AgentOperation, PromptGrant as AgentPromptGrant, ResourceGrant as AgentResourceGrant, Scope as AgentScope
from .anchor import Body, CheckpointId, ChioAnchorBatchV1, Inclusion, Kind as AnchorKind, Witness
from .capability import Algorithm as CapabilityAlgorithm, Attenuation, AttenuationProof, AttenuationWitness, Caveat, ChioCapabilityGrant, ChioCapabilityNegotiationV1, ChioCapabilityRevocationEntry, ChioCapabilitytoken, ChioCapabilitytokenV1, ChioCapabilitytokenV2, ChioScope, Constraint as CapabilityConstraint, DelegationLink, GrantKind, GrantSubsetRelation, Kind as CapabilityKind, MaxCapabilitySchema, MonetaryAmount, Operation as CapabilityOperation, PromptGrant as CapabilityPromptGrant, ResourceGrant as CapabilityResourceGrant, ScopeAttenuation, ToolGrant
from .error import ChioToolcallerrorCapabilityDenied, ChioToolcallerrorCapabilityExpired, ChioToolcallerrorCapabilityRevoked, ChioToolcallerrorInternalError, ChioToolcallerrorPolicyDenied, ChioToolcallerrorToolServerError, Detail as ErrorDetail
from .jsonrpc import ChioJsonRpc20Notification, ChioJsonRpc20Request, ChioJsonRpc20Response, ChioJsonRpc20Response1, ChioJsonRpc20Response2, Error as JsonrpcError
from .kernel import Action, Capability, ChioKernelmessageCapabilityList, ChioKernelmessageCapabilityRevoked, ChioKernelmessageHeartbeat, ChioKernelmessageToolCallChunk, ChioKernelmessageToolCallResponse, Constraint as KernelConstraint, Decision as KernelDecision, Decision6, Decision7, Decision8, DelegationChainItem as KernelDelegationChainItem, Detail as KernelDetail, Error as KernelError, Error10, Error11, Error12, Error13, Error9, EvidenceItem, Grant as KernelGrant, MaxCostPerInvocation as KernelMaxCostPerInvocation, MaxTotalCost as KernelMaxTotalCost, Operation as KernelOperation, PromptGrant as KernelPromptGrant, Receipt, ResourceGrant as KernelResourceGrant, Result, Result1, Result2, Result3, Result4, Scope as KernelScope
from .provenance import ChioProvenanceAttestationBundle, ChioProvenanceCallChainContext, ChioProvenanceStamp, ChioProvenanceVerdictLink, ChioProvenanceVerdictLink1, ChioProvenanceVerdictLink2, ChioProvenanceVerdictLink3, ChioProvenanceVerdictLink4, CredentialKind as ProvenanceCredentialKind, EvidenceClass, Scheme as ProvenanceScheme, Statement, Tier as ProvenanceTier, Verdict, WorkloadIdentity as ProvenanceWorkloadIdentity
from .receipt import Algorithm as ReceiptAlgorithm, ChioReceiptLineageStatementV2, ChioReceiptMerkleInclusionProof, ChioReceiptRecord, ChioReceiptV2, Decision as ReceiptDecision, Decision1, Decision2, Decision3, Decision4, GuardEvidence, Hlc, ParentReceiptId, ReceiptV2BodyHashInput, ToolCallAction, TrustLevel
from .result import ChioToolcallresultCancelled, ChioToolcallresultErr, ChioToolcallresultIncomplete, ChioToolcallresultOk, ChioToolcallresultStreamComplete, Detail as ResultDetail, Error as ResultError, Error1, Error2, Error3, Error4, Error5
from .trust_control import ChioTrustControlAuthorityLease, ChioTrustControlLeaseHeartbeat, ChioTrustControlLeaseTermination, ChioTrustControlRuntimeAttestationEvidence, CredentialKind as TrustControlCredentialKind, Reason, Scheme as TrustControlScheme, Tier as TrustControlTier, WorkloadIdentity as TrustControlWorkloadIdentity

CapabilityToken = ChioCapabilitytoken | ChioCapabilitytokenV2

__all__ = [
    "Action",
    "AgentAlgorithm",
    "AgentConstraint",
    "AgentDelegationChainItem",
    "AgentGrant",
    "AgentMaxCostPerInvocation",
    "AgentMaxTotalCost",
    "AgentOperation",
    "AgentPromptGrant",
    "AgentResourceGrant",
    "AgentScope",
    "AnchorKind",
    "Attenuation",
    "AttenuationProof",
    "AttenuationWitness",
    "Body",
    "Capability",
    "CapabilityAlgorithm",
    "CapabilityConstraint",
    "CapabilityKind",
    "CapabilityOperation",
    "CapabilityPromptGrant",
    "CapabilityResourceGrant",
    "CapabilityToken",
    "Caveat",
    "CheckpointId",
    "ChioAgentmessageHeartbeat",
    "ChioAgentmessageListCapabilities",
    "ChioAgentmessageToolCallRequest",
    "ChioAnchorBatchV1",
    "ChioCapabilityGrant",
    "ChioCapabilityNegotiationV1",
    "ChioCapabilityRevocationEntry",
    "ChioCapabilitytoken",
    "ChioCapabilitytokenV1",
    "ChioCapabilitytokenV2",
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
    "ChioReceiptLineageStatementV2",
    "ChioReceiptMerkleInclusionProof",
    "ChioReceiptRecord",
    "ChioReceiptV2",
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
    "Decision1",
    "Decision2",
    "Decision3",
    "Decision4",
    "Decision6",
    "Decision7",
    "Decision8",
    "DelegationLink",
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
    "EvidenceClass",
    "EvidenceItem",
    "GrantKind",
    "GrantSubsetRelation",
    "GuardEvidence",
    "Hlc",
    "Inclusion",
    "JsonrpcError",
    "KernelConstraint",
    "KernelDecision",
    "KernelDelegationChainItem",
    "KernelDetail",
    "KernelError",
    "KernelGrant",
    "KernelMaxCostPerInvocation",
    "KernelMaxTotalCost",
    "KernelOperation",
    "KernelPromptGrant",
    "KernelResourceGrant",
    "KernelScope",
    "MaxCapabilitySchema",
    "MonetaryAmount",
    "ParentReceiptId",
    "ProvenanceCredentialKind",
    "ProvenanceScheme",
    "ProvenanceTier",
    "ProvenanceWorkloadIdentity",
    "Reason",
    "Receipt",
    "ReceiptAlgorithm",
    "ReceiptDecision",
    "ReceiptV2BodyHashInput",
    "Result",
    "Result1",
    "Result2",
    "Result3",
    "Result4",
    "ResultDetail",
    "ResultError",
    "SCHEMA_SHA256",
    "ScopeAttenuation",
    "Statement",
    "ToolCallAction",
    "ToolGrant",
    "TrustControlCredentialKind",
    "TrustControlScheme",
    "TrustControlTier",
    "TrustControlWorkloadIdentity",
    "TrustLevel",
    "Verdict",
    "Witness",
]
