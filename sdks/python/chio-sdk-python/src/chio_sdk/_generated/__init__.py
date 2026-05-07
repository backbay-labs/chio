# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d680571b15f2c519e43943d2ec4e7754e54e544f1245ac1e25d16952856342c9
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
SCHEMA_SHA256 = "d680571b15f2c519e43943d2ec4e7754e54e544f1245ac1e25d16952856342c9"

from .agent import Algorithm as AgentAlgorithm, AttenuationProof as AgentAttenuationProof, CapabilityToken1, Caveat as AgentCaveat, ChioAgentmessageHeartbeat, ChioAgentmessageListCapabilities, ChioAgentmessageToolCallRequest, Constraint as AgentConstraint, DelegationChainItem as AgentDelegationChainItem, Grant as AgentGrant, Grant3, MaxCostPerInvocation as AgentMaxCostPerInvocation, MaxTotalCost as AgentMaxTotalCost, Operation as AgentOperation, PromptGrant as AgentPromptGrant, PromptGrant3, ResourceGrant as AgentResourceGrant, ResourceGrant3, Schema as AgentSchema, Scope as AgentScope, Scope3, ScopeAttenuation as AgentScopeAttenuation
from .anchor import Body, CheckpointId, ChioAnchorBatchV1, Inclusion, Kind as AnchorKind, Witness, WitnessReceipt, WitnessState, WitnessState1, WitnessState2, WitnessState3
from .capability import Algorithm as CapabilityAlgorithm, Attenuation, AttenuationProof as CapabilityAttenuationProof, AttenuationWitness, Caveat as CapabilityCaveat, ChioCapabilityGrant, ChioCapabilityNegotiationV1, ChioCapabilityRevocationEntry, ChioCapabilitytoken, ChioCapabilitytokenV1, ChioCapabilitytokenV2, ChioScope, Constraint as CapabilityConstraint, DelegationLink, GrantKind, GrantSubsetRelation, Kind as CapabilityKind, MaxCapabilitySchema, MonetaryAmount, Operation as CapabilityOperation, PromptGrant as CapabilityPromptGrant, ResourceGrant as CapabilityResourceGrant, ScopeAttenuation as CapabilityScopeAttenuation, ToolGrant
from .error import ChioToolcallerrorCapabilityDenied, ChioToolcallerrorCapabilityExpired, ChioToolcallerrorCapabilityRevoked, ChioToolcallerrorInternalError, ChioToolcallerrorPolicyDenied, ChioToolcallerrorToolServerError, Detail as ErrorDetail
from .jsonrpc import ChioJsonRpc20Notification, ChioJsonRpc20Request, ChioJsonRpc20Response, ChioJsonRpc20Response1, ChioJsonRpc20Response2, Error as JsonrpcError
from .kernel import Action, Algorithm as KernelAlgorithm, AttenuationProof as KernelAttenuationProof, Capabilities, Capabilities1, Caveat as KernelCaveat, ChioKernelmessageCapabilityList, ChioKernelmessageCapabilityRevoked, ChioKernelmessageHeartbeat, ChioKernelmessageToolCallChunk, ChioKernelmessageToolCallResponse, Constraint as KernelConstraint, Decision as KernelDecision, Decision6, Decision7, Decision8, DelegationChainItem as KernelDelegationChainItem, Detail as KernelDetail, Error as KernelError, Error10, Error11, Error12, Error13, Error9, EvidenceItem, Grant as KernelGrant, Grant1, MaxCostPerInvocation as KernelMaxCostPerInvocation, MaxTotalCost as KernelMaxTotalCost, Operation as KernelOperation, PromptGrant as KernelPromptGrant, PromptGrant1, Receipt, ResourceGrant as KernelResourceGrant, ResourceGrant1, Result, Result1, Result2, Result3, Result4, Schema as KernelSchema, Scope as KernelScope, Scope1, ScopeAttenuation as KernelScopeAttenuation
from .provenance import ChioProvenanceAttestationBundle, ChioProvenanceCallChainContext, ChioProvenanceStamp, ChioProvenanceVerdictLink, ChioProvenanceVerdictLink1, ChioProvenanceVerdictLink2, ChioProvenanceVerdictLink3, ChioProvenanceVerdictLink4, CredentialKind as ProvenanceCredentialKind, EvidenceClass, Scheme as ProvenanceScheme, Statement, Tier as ProvenanceTier, Verdict, WorkloadIdentity as ProvenanceWorkloadIdentity
from .receipt import Algorithm as ReceiptAlgorithm, ChioReceiptLineageStatementV2, ChioReceiptMerkleInclusionProof, ChioReceiptRecord, ChioReceiptV2, Decision as ReceiptDecision, Decision1, Decision2, Decision3, Decision4, GuardEvidence, Hlc, ParentReceiptId, ReceiptV2BodyHashInput, ToolCallAction, TrustLevel
from .result import ChioToolcallresultCancelled, ChioToolcallresultErr, ChioToolcallresultIncomplete, ChioToolcallresultOk, ChioToolcallresultStreamComplete, Detail as ResultDetail, Error as ResultError, Error1, Error2, Error3, Error4, Error5
from .trust_control import ChioTrustControlAuthorityLease, ChioTrustControlLeaseHeartbeat, ChioTrustControlLeaseTermination, ChioTrustControlRuntimeAttestationEvidence, CredentialKind as TrustControlCredentialKind, Reason, Scheme as TrustControlScheme, Tier as TrustControlTier, WorkloadIdentity as TrustControlWorkloadIdentity

class _CapabilityTokenMeta(type):
    def __instancecheck__(cls, instance):
        return isinstance(instance, (ChioCapabilitytoken, ChioCapabilitytokenV2))


class CapabilityToken(metaclass=_CapabilityTokenMeta):
    """Version-aware facade for canonical Chio capability tokens."""

    def __new__(cls, *args, **kwargs):
        if len(args) > 1:
            raise TypeError("CapabilityToken accepts at most one positional value")
        if args and kwargs:
            raise TypeError("CapabilityToken accepts a value or keyword fields, not both")
        obj = args[0] if args else kwargs
        return cls.model_validate(obj)

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        return core_schema.union_schema(
            [
                handler.generate_schema(ChioCapabilitytokenV2),
                handler.generate_schema(ChioCapabilitytoken),
            ]
        )

    @classmethod
    def __get_pydantic_json_schema__(cls, schema, handler):
        return handler(schema)

    @classmethod
    def _adapter(cls):
        return TypeAdapter(cls)

    @classmethod
    def model_validate(cls, obj, *args, **kwargs):
        return cls._adapter().validate_python(obj, *args, **kwargs)

    @classmethod
    def model_validate_json(cls, json_data, *args, **kwargs):
        return cls._adapter().validate_json(json_data, *args, **kwargs)

    @classmethod
    def model_json_schema(cls, *args, **kwargs):
        return cls._adapter().json_schema(*args, **kwargs)

__all__ = [
    "Action",
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
    "AgentSchema",
    "AgentScope",
    "AgentScopeAttenuation",
    "AnchorKind",
    "Attenuation",
    "AttenuationWitness",
    "Body",
    "Capabilities",
    "Capabilities1",
    "CapabilityAlgorithm",
    "CapabilityAttenuationProof",
    "CapabilityCaveat",
    "CapabilityConstraint",
    "CapabilityKind",
    "CapabilityOperation",
    "CapabilityPromptGrant",
    "CapabilityResourceGrant",
    "CapabilityScopeAttenuation",
    "CapabilityToken",
    "CapabilityToken1",
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
    "Grant1",
    "Grant3",
    "GrantKind",
    "GrantSubsetRelation",
    "GuardEvidence",
    "Hlc",
    "Inclusion",
    "JsonrpcError",
    "KernelAlgorithm",
    "KernelAttenuationProof",
    "KernelCaveat",
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
    "KernelSchema",
    "KernelScope",
    "KernelScopeAttenuation",
    "MaxCapabilitySchema",
    "MonetaryAmount",
    "ParentReceiptId",
    "PromptGrant1",
    "PromptGrant3",
    "ProvenanceCredentialKind",
    "ProvenanceScheme",
    "ProvenanceTier",
    "ProvenanceWorkloadIdentity",
    "Reason",
    "Receipt",
    "ReceiptAlgorithm",
    "ReceiptDecision",
    "ReceiptV2BodyHashInput",
    "ResourceGrant1",
    "ResourceGrant3",
    "Result",
    "Result1",
    "Result2",
    "Result3",
    "Result4",
    "ResultDetail",
    "ResultError",
    "SCHEMA_SHA256",
    "Scope1",
    "Scope3",
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
    "WitnessReceipt",
    "WitnessState",
    "WitnessState1",
    "WitnessState2",
    "WitnessState3",
]
