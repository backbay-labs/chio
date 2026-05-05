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

Re-exports unambiguous generated models so callers can write
``from chio_sdk._generated import CapabilityToken`` for the canonical
capability token shape without knowing the per-subpackage layout.
Generic names that collide across schemas stay scoped to their
subpackages. The SCHEMA_SHA256 constant pins the schema set this build
was generated from; the spec-drift CI lane reads it to detect tampering.
"""

from __future__ import annotations

#: SHA-256 of the lexicographically sorted concatenation of every
#: ``spec/schemas/chio-wire/v1/**/*.schema.json`` byte stream that was
#: fed into datamodel-code-generator at build time.
SCHEMA_SHA256 = "168c92102b530411f244aeff273362ff27544e7ce7b3c6623f51c9ecb4d58e62"

from .agent import ChioAgentmessageHeartbeat, ChioAgentmessageListCapabilities, ChioAgentmessageToolCallRequest
from .anchor import Body, CheckpointId, ChioAnchorBatchV1, Inclusion, Witness
from .capability import AttenuationProof, AttenuationWitness, Caveat, ChioCapabilityGrant, ChioCapabilityNegotiationV1, ChioCapabilityRevocationEntry, ChioCapabilitytoken, ChioCapabilitytokenV1, ChioCapabilitytokenV2, GrantKind, GrantSubsetRelation, MaxCapabilitySchema, ScopeAttenuation
from .error import ChioToolcallerrorCapabilityDenied, ChioToolcallerrorCapabilityExpired, ChioToolcallerrorCapabilityRevoked, ChioToolcallerrorInternalError, ChioToolcallerrorPolicyDenied, ChioToolcallerrorToolServerError
from .jsonrpc import ChioJsonRpc20Notification, ChioJsonRpc20Request, ChioJsonRpc20Response, ChioJsonRpc20Response1, ChioJsonRpc20Response2
from .kernel import Action, Capability, ChioKernelmessageCapabilityList, ChioKernelmessageCapabilityRevoked, ChioKernelmessageHeartbeat, ChioKernelmessageToolCallChunk, ChioKernelmessageToolCallResponse, Decision6, Decision7, Decision8, Error10, Error11, Error12, Error13, Error9, EvidenceItem, Receipt, Result, Result1, Result2, Result3, Result4
from .provenance import ChioProvenanceAttestationBundle, ChioProvenanceCallChainContext, ChioProvenanceStamp, ChioProvenanceVerdictLink, ChioProvenanceVerdictLink1, ChioProvenanceVerdictLink2, ChioProvenanceVerdictLink3, ChioProvenanceVerdictLink4, Statement, Verdict
from .receipt import ChioReceiptLineageStatementV2, ChioReceiptMerkleInclusionProof, ChioReceiptRecord, ChioReceiptV2, Decision1, Decision2, Decision3, Decision4, GuardEvidence, Hlc, ReceiptV2BodyHashInput, ToolCallAction
from .result import ChioToolcallresultCancelled, ChioToolcallresultErr, ChioToolcallresultIncomplete, ChioToolcallresultOk, ChioToolcallresultStreamComplete, Error1, Error2, Error3, Error4, Error5
from .trust_control import ChioTrustControlAuthorityLease, ChioTrustControlLeaseHeartbeat, ChioTrustControlLeaseTermination, ChioTrustControlRuntimeAttestationEvidence, Reason

CapabilityToken = ChioCapabilitytoken

__all__ = [
    "Action",
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
    "EvidenceItem",
    "GrantKind",
    "GrantSubsetRelation",
    "GuardEvidence",
    "Hlc",
    "Inclusion",
    "MaxCapabilitySchema",
    "Reason",
    "Receipt",
    "ReceiptV2BodyHashInput",
    "Result",
    "Result1",
    "Result2",
    "Result3",
    "Result4",
    "SCHEMA_SHA256",
    "ScopeAttenuation",
    "Statement",
    "ToolCallAction",
    "Verdict",
    "Witness",
]
