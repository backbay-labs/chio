# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 168c92102b530411f244aeff273362ff27544e7ce7b3c6623f51c9ecb4d58e62
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

"""Generated Pydantic v2 models for the Chio wire protocol (chio-wire/v1).

Re-exports every subpackage so callers can write
``from chio_sdk._generated import CapabilityToken`` for the canonical
capability token shape without knowing the per-subpackage layout. The
SCHEMA_SHA256 constant pins the schema set this build was generated from;
the spec-drift CI lane reads it to detect tampering.
"""

from __future__ import annotations

#: SHA-256 of the lexicographically sorted concatenation of every
#: ``spec/schemas/chio-wire/v1/**/*.schema.json`` byte stream that was
#: fed into datamodel-code-generator at build time.
SCHEMA_SHA256 = "168c92102b530411f244aeff273362ff27544e7ce7b3c6623f51c9ecb4d58e62"

from .agent import ChioAgentmessageHeartbeat, ChioAgentmessageListCapabilities, ChioAgentmessageToolCallRequest, Constraint, DelegationChainItem, Grant, MaxCostPerInvocation, MaxTotalCost, Operation, PromptGrant, ResourceGrant, Scope
from .anchor import Body, CheckpointId, ChioAnchorBatchV1, Inclusion, Kind, Witness
from .capability import Algorithm, Attenuation, AttenuationProof, AttenuationWitness, Caveat, ChioCapabilityGrant, ChioCapabilityNegotiationV1, ChioCapabilityRevocationEntry, ChioCapabilitytoken, ChioCapabilitytokenV1, ChioCapabilitytokenV2, ChioScope, Constraint, DelegationLink, GrantKind, GrantSubsetRelation, Kind, MaxCapabilitySchema, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ScopeAttenuation, ToolGrant
from .error import ChioToolcallerrorCapabilityDenied, ChioToolcallerrorCapabilityExpired, ChioToolcallerrorCapabilityRevoked, ChioToolcallerrorInternalError, ChioToolcallerrorPolicyDenied, ChioToolcallerrorToolServerError, Detail
from .jsonrpc import ChioJsonRpc20Notification, ChioJsonRpc20Request, ChioJsonRpc20Response, ChioJsonRpc20Response1, ChioJsonRpc20Response2, Error
from .kernel import Action, Capability, ChioKernelmessageCapabilityList, ChioKernelmessageCapabilityRevoked, ChioKernelmessageHeartbeat, ChioKernelmessageToolCallChunk, ChioKernelmessageToolCallResponse, Constraint, Decision, Decision6, Decision7, Decision8, DelegationChainItem, Detail, Error, Error10, Error11, Error12, Error13, Error9, EvidenceItem, Grant, MaxCostPerInvocation, MaxTotalCost, Operation, PromptGrant, Receipt, ResourceGrant, Result, Result1, Result2, Result3, Result4, Scope
from .provenance import ChioProvenanceAttestationBundle, ChioProvenanceCallChainContext, ChioProvenanceStamp, ChioProvenanceVerdictLink, ChioProvenanceVerdictLink1, ChioProvenanceVerdictLink2, ChioProvenanceVerdictLink3, ChioProvenanceVerdictLink4, CredentialKind, EvidenceClass, Scheme, Statement, Tier, Verdict, WorkloadIdentity
from .receipt import Algorithm, ChioReceiptLineageStatementV2, ChioReceiptMerkleInclusionProof, ChioReceiptRecord, ChioReceiptV2, Decision, Decision1, Decision2, Decision3, Decision4, GuardEvidence, Hlc, ParentReceiptId, ReceiptV2BodyHashInput, ToolCallAction, TrustLevel
from .result import ChioToolcallresultCancelled, ChioToolcallresultErr, ChioToolcallresultIncomplete, ChioToolcallresultOk, ChioToolcallresultStreamComplete, Detail, Error, Error1, Error2, Error3, Error4, Error5
from .trust_control import ChioTrustControlAuthorityLease, ChioTrustControlLeaseHeartbeat, ChioTrustControlLeaseTermination, ChioTrustControlRuntimeAttestationEvidence, CredentialKind, Reason, Scheme, Tier, WorkloadIdentity

CapabilityToken = ChioCapabilitytoken

__all__ = [
    "Action",
    "Algorithm",
    "Attenuation",
    "AttenuationProof",
    "AttenuationWitness",
    "Body",
    "Capability",
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
    "Constraint",
    "CredentialKind",
    "Decision",
    "Decision1",
    "Decision2",
    "Decision3",
    "Decision4",
    "Decision6",
    "Decision7",
    "Decision8",
    "DelegationChainItem",
    "DelegationLink",
    "Detail",
    "Error",
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
    "EvidenceClass",
    "EvidenceItem",
    "Grant",
    "GrantKind",
    "GrantSubsetRelation",
    "GuardEvidence",
    "Hlc",
    "Inclusion",
    "Kind",
    "MaxCapabilitySchema",
    "MaxCostPerInvocation",
    "MaxTotalCost",
    "MonetaryAmount",
    "Operation",
    "ParentReceiptId",
    "PromptGrant",
    "Reason",
    "Receipt",
    "ReceiptV2BodyHashInput",
    "ResourceGrant",
    "Result",
    "Result1",
    "Result2",
    "Result3",
    "Result4",
    "SCHEMA_SHA256",
    "Scheme",
    "Scope",
    "ScopeAttenuation",
    "Statement",
    "Tier",
    "ToolCallAction",
    "ToolGrant",
    "TrustLevel",
    "Verdict",
    "Witness",
    "WorkloadIdentity",
]
